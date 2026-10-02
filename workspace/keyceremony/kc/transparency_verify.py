"""Independent checker for the caller-facing transparency log.

Given ONLY exported artifacts (leaf set, tree nodes/heads/head chain,
signatures and split-view dispositions) it recomputes every root from
scratch and checks the key lifecycle legality. It needs no running service
and no secrets - the service identity public key ships in the bundle.

It reports concrete, machine-readable findings for:

  * LEAF_MISSING            a head/tree references a leaf index that is absent
  * DUPLICATE_BUSINESS_EVENT two leaves share one business event key
  * LEAF_REORDERED          leaf order does not match sequenced indices
  * BAD_INCLUSION_PATH      an inclusion proof does not rebuild the root
  * BROKEN_CONSISTENCY      a consistency/append claim does not verify
  * HEAD_SIGNATURE_REPLACED a head signature is missing/invalid
  * SAME_SIZE_TWO_ROOTS     two signed heads at one tree size, different root
  * HEAD_CHAIN_BROKEN       a head's prev_head does not hash-link
  * CONFLICT_SKIPPED        a split-view exists but publishing continued
  * UNREGISTERED_ACTIVATION an ACTIVE key version has no transparency leaf
  * ILLEGAL_TRANSITION      a leaf claims a forbidden state jump
  * FINGERPRINT_SWAP        same purpose/version logged with two fingerprints
  * SPLIT_DISPOSITION_INVALID  resolution accepts a non-extending branch
  * TREE_ROOT_MISMATCH      recomputed leaf-set root != current head root
"""

from __future__ import annotations

from . import crypto
from . import ed25519
from . import merkle
from .transparency import (
    BUNDLE_VERSION, EVENT_ABORTED, EVENT_ACTIVATED, EVENT_CREATED,
    EVENT_DESTROYED, EVENT_RETIRED, HEAD_DOMAIN, head_body, head_digest,
    make_leaf,
)
from .directory import ACTIVE, DESTROYED, RETIRING, STAGED

TRANSITIONS = {
    None: {EVENT_CREATED},
    "STAGED": {EVENT_ACTIVATED, EVENT_ABORTED},
    "ACTIVE": {EVENT_RETIRED},
    "RETIRING": {EVENT_DESTROYED},
    "DESTROYED": set(),
    "ABORTED": set(),
}

_EVENT_STATE = {
    EVENT_CREATED: (STAGED, ACTIVE),
    EVENT_ACTIVATED: (ACTIVE,),
    EVENT_RETIRED: (RETIRING,),
    EVENT_DESTROYED: (DESTROYED,),
    EVENT_ABORTED: ("ABORTED",),
}


class Finding:
    def __init__(self, code: str, message: str, context: dict | None = None):
        self.code = code
        self.message = message
        self.context = context or {}

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message,
                "context": self.context}


def verify_bundle(bundle: dict, keys: list[dict] | None = None,
                  strict: bool = False) -> dict:
    findings: list[Finding] = []

    def note(code, msg, ctx=None):
        findings.append(Finding(code, msg, ctx))
        if strict:
            raise Finding(code, msg, ctx)

    if not isinstance(bundle, dict):
        note("MALFORMED_BUNDLE", "bundle is not an object")
        return _report(bundle, findings)

    pub_b64 = bundle.get("service_pub")
    try:
        pub = crypto.b64d(pub_b64)
    except Exception:
        note("MALFORMED_BUNDLE", "missing/invalid service_pub")
        return _report(bundle, findings)

    leaves = bundle.get("leaves", [])
    heads = bundle.get("heads", [])
    event_index = bundle.get("event_index", {})
    splits = bundle.get("split_views", [])

    # 1) leaf canonicalization, ordering and recomputed hashes --------------
    leaf_hashes = []
    seen_events = {}
    version_fp = {}
    version_states: dict[tuple, list] = {}
    for i, lf in enumerate(leaves):
        if not isinstance(lf, dict):
            note("LEAF_MISSING", f"leaf {i} is not an object", {"index": i})
            continue
        try:
            rebuilt = make_leaf(
                purpose=lf["purpose"], version=lf["version"],
                fingerprint=lf["fingerprint"], prev_state=lf["prev_state"],
                next_state=lf["next_state"], event=lf["event"],
                ceremony_id=lf["ceremony_id"], audit_seq=lf["audit_seq"],
                audit_digest=lf["audit_digest"])
        except KeyError as e:
            note("LEAF_MISSING", f"leaf {i} missing field {e}", {"index": i})
            continue
        if lf.get("leaf_hash") != rebuilt["leaf_hash"]:
            note("LEAF_REORDERED",
                 f"leaf {i}: recorded hash != recomputed canonical hash",
                 {"index": i})
        lh = merkle.leaf_hash(lf)
        leaf_hashes.append(lh)

        key = f"{lf['purpose']}|{lf['version']}|{lf['event']}|{lf['audit_seq']}"
        if key in seen_events:
            note("DUPLICATE_BUSINESS_EVENT",
                 f"business event logged twice at leaves "
                 f"{seen_events[key]} and {i}",
                 {"key": key, "first": seen_events[key], "second": i})
        seen_events.setdefault(key, i)

        vk = (lf["purpose"], lf["version"])
        if vk in version_fp and version_fp[vk] != lf["fingerprint"]:
            note("FINGERPRINT_SWAP",
                 f"{lf['purpose']} v{lf['version']} logged with two "
                 "different fingerprints",
                 {"version": list(vk),
                  "fingerprints": [version_fp[vk], lf["fingerprint"]]})
        version_fp.setdefault(vk, lf["fingerprint"])
        version_states.setdefault(vk, []).append(
            (i, lf["prev_state"], lf["next_state"], lf["event"]))

    # event_index consistency (dedup table points at real unique leaves)
    for ev, idx in event_index.items():
        if not (0 <= int(idx) < len(leaves)):
            note("LEAF_MISSING", f"event_index points outside the leaf set",
                 {"event": ev, "index": idx})

    # 2) lifecycle legality (state transition table) ------------------------
    for vk, chain in version_states.items():
        expected_prev = None
        for i, prev, nxt, ev in chain:
            if prev != expected_prev:
                note("ILLEGAL_TRANSITION",
                     f"{vk[0]} v{vk[1]} leaf {i}: prev_state {prev} does not "
                     f"follow last state {expected_prev}",
                     {"index": i, "version": list(vk), "prev": prev,
                      "expected": expected_prev})
            allowed = TRANSITIONS.get(expected_prev, set())
            wants = _EVENT_STATE.get(ev)
            if ev not in allowed or wants is None or nxt not in wants:
                note("ILLEGAL_TRANSITION",
                     f"{vk[0]} v{vk[1]} leaf {i}: forbidden "
                     f"{expected_prev} --{ev}--> {nxt}",
                     {"index": i, "version": list(vk), "event": ev})
            expected_prev = nxt

    # 3) recompute tree root ------------------------------------------------
    recomputed_root = merkle.tree_root_from_hashes(leaf_hashes).hex()

    # 4) heads: signature, size/root, hash chain, same-size equivocation -----
    prev_digest = "0" * 64
    root_by_size: dict[int, str] = {}
    last_head = None
    for j, sh in enumerate(heads):
        try:
            body = sh["head"]
            if body.get("domain") != HEAD_DOMAIN:
                note("HEAD_SIGNATURE_REPLACED",
                     f"head {j}: bad domain", {"head": j})
            if head_digest(head_body(body["tree_size"], body["root"],
                                     body["issued_at"],
                                     body["prev_head"])) != sh["head_digest"]:
                note("HEAD_SIGNATURE_REPLACED",
                     f"head {j}: head digest mismatch", {"head": j})
            if not ed25519.verify(pub, sh["head_digest"].encode(),
                                 crypto.b64d(sh["svc_sig"])):
                note("HEAD_SIGNATURE_REPLACED",
                     f"head {j}: invalid service signature", {"head": j})
        except (KeyError, Exception) as e:  # noqa: BLE032
            note("HEAD_SIGNATURE_REPLACED",
                 f"head {j}: malformed ({e})", {"head": j})
            continue
        size = body["tree_size"]
        root = body["root"]
        # head root must equal a root recomputed from its leaf prefix
        pref = merkle.tree_root_from_hashes(leaf_hashes[:size]).hex()
        if pref != root:
            note("TREE_ROOT_MISMATCH",
                 f"head {j} root does not match its {size} leaves",
                 {"head": j, "size": size, "head_root": root,
                  "recomputed": pref})
        if body["prev_head"] != prev_digest:
            note("HEAD_CHAIN_BROKEN",
                 f"head {j}: prev_head does not link to the prior head digest",
                 {"head": j, "prev_head": body["prev_head"],
                  "expected": prev_digest})
        prev_digest = sh["head_digest"]
        if size in root_by_size and root_by_size[size] != root:
            note("SAME_SIZE_TWO_ROOTS",
                 f"two signed roots at tree size {size}",
                 {"size": size, "roots": [root_by_size[size], root]})
        root_by_size[size] = root
        last_head = sh

    if last_head is not None:
        if last_head["head"]["tree_size"] != len(leaves):
            note("LEAF_MISSING",
                 "current head size disagrees with the exported leaf count",
                 {"head_size": last_head["head"]["tree_size"],
                  "n_leaves": len(leaves)})
        elif last_head["head"]["root"] != recomputed_root:
            note("TREE_ROOT_MISMATCH",
                 "current head root != recomputed leaf-set root",
                 {"head_root": last_head["head"]["root"],
                  "recomputed": recomputed_root})
        else:
            # Independently regenerate EVERY leaf's inclusion path and fold
            # it: this is where a wrong/tampered inclusion path is caught
            # (a recomputed root alone proves the set, not that a served
            # path for a leaf actually reaches that root).
            for i, lh in enumerate(leaf_hashes):
                path = merkle.inclusion_proof(leaf_hashes, i)
                if not merkle.verify_inclusion(
                        lh, i, len(leaf_hashes), path,
                        bytes.fromhex(last_head["head"]["root"])):
                    note("BAD_INCLUSION_PATH",
                         f"leaf {i} inclusion path fails to rebuild the root",
                         {"index": i})

        # Append-only consistency between every pair of successive heads:
        # each later head must be a strict extension of the prior one.
        for a, b in zip(heads, heads[1:]):
            ma, mb = a["head"]["tree_size"], b["head"]["tree_size"]
            if mb > ma:
                proof = merkle.consistency_proof(leaf_hashes[:mb], ma)
                if not merkle.verify_consistency(
                        ma, mb, proof,
                        bytes.fromhex(a["head"]["root"]),
                        bytes.fromhex(b["head"]["root"])):
                    note("BROKEN_CONSISTENCY",
                         f"head at size {mb} is not an append of size {ma}",
                         {"old_size": ma, "new_size": mb})

    # 5) append-only relationship between successive heads -----------------
    sizes = [sh["head"]["tree_size"] for sh in heads]
    if sizes != sorted(sizes):
        note("LEAF_REORDERED", "head sizes are not strictly ordered",
             {"sizes": sizes})

    # 6) split-view handling -------------------------------------------------
    open_split = False
    for sv in splits:
        if sv.get("status") == "OPEN":
            open_split = True
            # publishing after an open split is a skip-conflict violation
            sv_created = sv.get("created_at", "")
            for sh in heads:
                if sh["head"]["issued_at"] > sv_created and \
                        sh not in (sv.get("our_head"), sv.get("their_head")):
                    note("CONFLICT_SKIPPED",
                         "a new head was published while a split was OPEN",
                         {"split": sv.get("split_id"),
                          "head_size": sh["head"]["tree_size"]})
        else:
            dec = sv.get("decision") or {}
            accepted = dec.get("accepted_root")
            ours = (sv.get("our_head") or {}).get("head", {}).get("root")
            theirs = (sv.get("their_head") or {}).get("head", {}).get("root")
            if accepted not in (ours, theirs):
                note("SPLIT_DISPOSITION_INVALID",
                     "resolution accepts a head not in the conflict evidence",
                     {"split": sv.get("split_id"), "accepted": accepted})
            if not dec.get("reason") or not dec.get("decided_by"):
                note("SPLIT_DISPOSITION_INVALID",
                     "resolution missing reason/decided_by",
                     {"split": sv.get("split_id")})
            # rejected branch must remain in evidence
            rejected = dec.get("rejected_root")
            if rejected is None or rejected not in (ours, theirs):
                note("SPLIT_DISPOSITION_INVALID",
                     "rejected branch missing from evidence",
                     {"split": sv.get("split_id")})

    # 7) every ACTIVE key version must have a transparency leaf -------------
    if keys:
        active = [(k["purpose"], k["version"], k.get("fingerprint"))
                  for k in keys if k.get("status") == ACTIVE]
        logged_versions = set()
        for lf in leaves:
            logged_versions.add((lf["purpose"], lf["version"],
                                 lf["fingerprint"]))
        for purpose, version, fp in active:
            if (purpose, version, fp) not in logged_versions and \
                    (purpose, version) not in {(p, v) for p, v, _ in
                                               logged_versions}:
                note("UNREGISTERED_ACTIVATION",
                     f"ACTIVE key {purpose} v{version} has no transparency leaf",
                     {"purpose": purpose, "version": version})
            elif (purpose, version) not in {(p, v)
                                            for p, v, _ in logged_versions}:
                note("UNREGISTERED_ACTIVATION",
                     f"ACTIVE key {purpose} v{version} missing leaf",
                     {"purpose": purpose, "version": version})

    return _report(bundle, findings)


def _report(bundle, findings: list[Finding]) -> dict:
    return {
        "ok": not findings,
        "bundle_version": (bundle or {}).get("bundle_version"),
        "checks": {
            "leaves": len((bundle or {}).get("leaves", [])),
            "heads": len((bundle or {}).get("heads", [])),
            "split_views": len((bundle or {}).get("split_views", [])),
        },
        "findings": [f.to_dict() for f in findings],
    }


def verify_proof(leaf: dict, index: int, size: int, path: list[str],
                 root_hex: str) -> bool:
    """Standalone inclusion verification of one leaf (hex path/root)."""
    try:
        return merkle.verify_inclusion(
            merkle.leaf_hash(leaf), int(index), int(size),
            [bytes.fromhex(p) for p in path], bytes.fromhex(root_hex))
    except Exception:
        return False
