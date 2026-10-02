"""Caller-facing transparency log for the key version directory.

Every key lifecycle change (creation/staging, activation/handover entry,
retirement and erasure) emits a *canonical leaf* into an append-only Merkle
tree. The leaf binds purpose, version, public fingerprint, previous and next
status, ceremony id and the matching audit-entry digest - and nothing else.
Leaves contain only public material: never shares, signing seeds or sealing
material.

The log is independently verifiable:

  * a signed tree head (STH) carries tree size, Merkle root, previous head
  * digest and issue time, signed by the service identity;
  * clients fetch a leaf, its inclusion path and the STH, or a consistency
    proof from an old head they pinned;
  * a gossip observer lets browsers/monitors submit heads they have seen; a
    second root at the same size (an equivocation) or a head that is not a
    strict extension of a smaller one records a split-view and freezes
    transparency publishing and new key activation.

Crash safety / multi-process
----------------------------
Sequencing a leaf, writing it, updating tree nodes and publishing the head
happen in ONE store-lock transaction on ONE atomic state file. A process
exiting between those steps leaves either the complete old head or the
complete new head on disk; a reopened store can never observe a head that
references a leaf that is not durable. Two publishers racing for the same
next size serialize on the flock: exactly one wins; the loser reads the
winner's leaf/head. Re-delivery of the same audit event returns the original
leaf index (idempotent de-duplication by business event).
"""

from __future__ import annotations

import json
import os
import time

from . import crypto
from . import ed25519
from . import merkle
from .errors import CeremonyError
from .storage import GENESIS, utcnow

DIRNAME = "transparency"
STATE_NAME = "state.json"

HEAD_DOMAIN = "kc-transparency-tree-head-v1"
LEAF_SCHEMA = "kc-tlog-leaf-v1"
BUNDLE_VERSION = "kc-tlog-bundle-v1"

# Lifecycle events a leaf may record. These deliberately name only PUBLIC
# transitions; secrets never enter the log.
EVENT_CREATED = "CREATED"          # version registered (STAGED or first ACTIVE)
EVENT_ACTIVATED = "ACTIVATED"      # entered the ACTIVE role / handover entry
EVENT_RETIRED = "RETIRED"          # ACTIVE -> RETIRING (handover opened)
EVENT_DESTROYED = "DESTROYED"      # private material erased; public kept
EVENT_ABORTED = "ABORTED"          # a staged version was aborted


class TransparencyError(CeremonyError):
    pass


class TransparencyFrozen(TransparencyError):
    """A split-view is open: no new heads or key activations are allowed."""

    code = "TRANSPARENCY_FROZEN"
    http_status = 409


class ContradictoryState(TransparencyError):
    """The same (purpose, version) shows two incompatible state changes."""

    code = "CONTRADICTORY_STATE"
    http_status = 409


class HeadNotAppend(TransparencyError):
    code = "HEAD_NOT_APPEND"
    http_status = 409


class BadHead(TransparencyError):
    code = "BAD_HEAD"
    http_status = 422


class SplitUnresolved(TransparencyError):
    code = "SPLIT_UNRESOLVED"
    http_status = 409


def _new_state() -> dict:
    return {
        "schema": LEAF_SCHEMA,
        "service_pub": None,
        "leaves": [],          # canonical leaf objects, append-only
        "leaf_hashes": [],     # hex leaf hashes, same order
        # dedup: business event key -> leaf index
        "event_index": {},
        # dedup: (purpose, version, next_state) -> index (state contradiction)
        "state_index": {},
        "heads": [],           # signed tree heads, oldest first
        "frozen": False,
        "last_trusted_head": None,
        "split_views": [],
        "gossip": [],          # observed heads retained as evidence
        "sequence": 0,
    }


def business_event_key(purpose: str, version: int, event: str,
                       audit_seq: int) -> str:
    """Identity of a business change: a given lifecycle transition for a
    version is recorded at most once. Keyed on purpose/version/event and the
    audit entry it reflects, so a re-delivered audit event cannot create a
    second leaf."""
    return crypto.digest_hex(
        {"purpose": purpose, "version": version, "event": event,
         "audit_seq": audit_seq})


def make_leaf(*, purpose: str, version: int, fingerprint: str,
              prev_state: str | None, next_state: str, event: str,
              ceremony_id: str, audit_seq: int, audit_digest: str) -> dict:
    """Construct the canonical public leaf body."""
    leaf = {
        "purpose": purpose,
        "version": int(version),
        "fingerprint": fingerprint,
        "prev_state": prev_state,
        "next_state": next_state,
        "ceremony_id": ceremony_id,
        "event": event,
        "audit_seq": int(audit_seq),
        "audit_digest": audit_digest,
    }
    leaf["leaf_hash"] = merkle.leaf_hash(leaf).hex()
    return leaf


def head_body(tree_size: int, root: str, issued_at: str,
              prev_head: str) -> dict:
    return {"domain": HEAD_DOMAIN, "tree_size": int(tree_size),
            "root": root, "issued_at": issued_at,
            "prev_head": prev_head}


def head_digest(body: dict) -> str:
    return crypto.digest_hex({
        "domain": HEAD_DOMAIN, "tree_size": body["tree_size"],
        "root": body["root"], "issued_at": body["issued_at"],
        "prev_head": body["prev_head"]})


def sign_head(body: dict, service_seed: bytes) -> dict:
    h = head_body(body["tree_size"], body["root"], body["issued_at"],
                  body["prev_head"])
    d = head_digest(h)
    return {"head": h, "head_digest": d,
            "svc_sig": crypto.b64e(ed25519.sign(service_seed, d.encode()))}


def verify_head(signed: dict, service_pub: bytes) -> bool:
    try:
        body, d = signed["head"], signed["head_digest"]
        if head_digest(body) != d:
            return False
        return ed25519.verify(service_pub, d.encode(),
                             crypto.b64d(signed["svc_sig"]))
    except Exception:
        return False


class TransparencyLog:
    """Append-only Merkle transparency log bound to a data directory.

    All mutating operations must run inside the shared store lock; this class
    serializes itself on the SAME flock as the rest of the system (it shares
    ``store.root``) and writes a single atomic state file, so leaf+nodes+head
    form one commit boundary."""

    def __init__(self, store):
        self.store = store
        self.dir = os.path.join(store.root, DIRNAME)
        os.makedirs(self.dir, exist_ok=True)
        self.path = os.path.join(self.dir, STATE_NAME)
        self.seed = store.service_seed()
        self.pub = ed25519.public_from_secret(self.seed)
        self.state = self._load()

    # ---- persistence -----------------------------------------------------
    def _load(self) -> dict:
        if not os.path.exists(self.path):
            st = _new_state()
            st["service_pub"] = crypto.b64e(self.pub)
            self._save(st)
            return st
        with open(self.path, encoding="utf-8") as f:
            st = json.load(f)
        for k, v in _new_state().items():
            st.setdefault(k, v)
        return st

    def _save(self, st: dict):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(st, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def save(self):
        self._save(self.state)

    # ---- views -----------------------------------------------------------
    @property
    def tree_size(self) -> int:
        return len(self.state["leaves"])

    def _hashes(self) -> list[bytes]:
        return [bytes.fromhex(h) for h in self.state["leaf_hashes"]]

    def root(self) -> bytes:
        return merkle.tree_root_from_hashes(self._hashes())

    def current_head(self) -> dict | None:
        return self.state["heads"][-1] if self.state["heads"] else None

    def is_frozen(self) -> bool:
        return bool(self.state["frozen"])

    def _require_unfrozen(self):
        if self.state["frozen"]:
            raise TransparencyFrozen(
                "transparency publishing is frozen by a split-view; no new "
                "heads or key activations until an operator resolves it")

    # ---- leaf append + head publish (single commit boundary) -------------
    def append_lifecycle(self, *, purpose: str, version: int,
                         fingerprint: str, prev_state: str | None,
                         next_state: str, event: str, ceremony_id: str,
                         audit_entry: dict,
                         sign: bool = True,
                         _persist: bool = True) -> dict:
        """Append one lifecycle leaf and (atomically) publish a new head.

        Idempotent: the same business event key returns the original leaf
        index and existing head. A contradictory next_state for the same
        (purpose, version) freezes the log and raises rather than picking a
        side. Returns {"leaf", "index", "head", "duplicate"}.
        """
        st = self.state
        audit_seq = audit_entry["seq"]
        audit_digest = audit_entry["hash"]
        ekey = business_event_key(purpose, version, event, audit_seq)
        existing = st["event_index"].get(ekey)
        if existing is not None:
            # Idempotent de-duplication is valid even while frozen: re-opening
            # a frozen store must not raise while healing already-logged
            # events, and a re-delivered event returns its original index.
            idx = int(existing)
            return {"leaf": st["leaves"][idx], "index": idx,
                    "head": st["heads"][-1] if st["heads"] else None,
                    "duplicate": True}

        self._require_unfrozen()

        # Contradiction guard: same (purpose, version) may never carry two
        # different next_state leaves (e.g. two ACTIVE fingerprints).
        skey = f"{purpose}|{version}|{next_state}"
        # A version is identified by purpose+version; if a leaf already
        # exists for this version with a different fingerprint, that is a key
        # replacement - reject outright.
        for lf in st["leaves"]:
            if lf["purpose"] == purpose and lf["version"] == version:
                if lf["fingerprint"] != fingerprint:
                    self._freeze(
                        reason="fingerprint mismatch for same purpose/version",
                        offending=None)
                    raise ContradictoryState(
                        f"{purpose} v{version} already logged with a different "
                        "fingerprint; transparency frozen")
        # Forged state jump: next_state must follow the recorded last state.
        last = self._last_version_state(purpose, version)
        if last is not None and not _valid_transition(last, next_state, event):
            self._freeze(reason=f"illegal state jump {last}->{next_state}",
                         offending=None)
            raise ContradictoryState(
                f"{purpose} v{version}: forbidden transition "
                f"{last} -> {next_state}")

        leaf = make_leaf(
            purpose=purpose, version=version, fingerprint=fingerprint,
            prev_state=last, next_state=next_state, event=event,
            ceremony_id=ceremony_id, audit_seq=audit_seq,
            audit_digest=audit_digest)
        idx = len(st["leaves"])
        st["leaves"].append(leaf)
        st["leaf_hashes"].append(leaf["leaf_hash"])
        st["event_index"][ekey] = idx
        head = None
        if sign:
            head = self._publish_head_locked()
        if _persist:
            self._save(st)
        return {"leaf": leaf, "index": idx, "head": head, "duplicate": False}

    def _last_version_state(self, purpose: str, version: int) -> str | None:
        last = None
        for lf in self.state["leaves"]:
            if lf["purpose"] == purpose and lf["version"] == version:
                last = lf["next_state"]
        return last

    def publish_head(self) -> dict:
        """Publish a head for the current tree size (forces a new STH)."""
        st = self.state
        self._require_unfrozen()
        head = self._publish_head_locked()
        self._save(st)
        return head

    def _publish_head_locked(self) -> dict:
        st = self.state
        size = len(st["leaves"])
        root = merkle.tree_root_from_hashes(self._hashes()).hex()
        prev = st["heads"][-1]["head_digest"] if st["heads"] else GENESIS
        # Two heads at the same size must never coexist (CAS on size).
        if st["heads"] and st["heads"][-1]["head"]["tree_size"] == size:
            return st["heads"][-1]
        body = head_body(size, root, utcnow(), prev)
        signed = sign_head(body, self.seed)
        st["heads"].append(signed)
        return signed

    # ---- proofs ----------------------------------------------------------
    def leaf_by_index(self, index: int) -> dict | None:
        if 0 <= index < len(self.state["leaves"]):
            return self.state["leaves"][index]
        return None

    def find_leaves(self, *, purpose: str | None = None,
                    version: int | None = None,
                    audit_seq: int | None = None) -> list[dict]:
        out = []
        for i, lf in enumerate(self.state["leaves"]):
            if purpose is not None and lf["purpose"] != purpose:
                continue
            if version is not None and lf["version"] != version:
                continue
            if audit_seq is not None and lf["audit_seq"] != audit_seq:
                continue
            out.append({"index": i, "leaf": lf})
        return out

    def inclusion_for_index(self, index: int) -> dict:
        hashes = self._hashes()
        leaf = self.state["leaves"][index]
        path = [h.hex() for h in
                merkle.inclusion_proof(hashes, index)]
        return {"index": index, "tree_size": len(hashes),
                "leaf": leaf,
                "leaf_hash": hashes[index].hex(),
                "inclusion_path": path,
                "head": self.current_head()}

    def consistency(self, old_size: int) -> dict:
        hashes = self._hashes()
        n = len(hashes)
        if not 0 <= old_size <= n:
            raise HeadNotAppend(f"old size {old_size} not within 0..{n}")
        if old_size == n:
            proof = {}
        else:
            proof = merkle.encode_consistency(
                merkle.consistency_proof(hashes, old_size))
        return {"old_size": old_size, "new_size": n,
                "proof": proof, "head": self.current_head()}

    # ---- gossip / split-view --------------------------------------------
    def observe_head(self, signed_head: dict, observer: str = "external") \
            -> dict:
        """Record a head a browser/monitor claims to have seen.

        Detects equivocation: a different root at a size we already have, or
        a head that is not a strict append of a smaller trusted head. On
        detection a split-view is recorded and publishing is frozen. The
        observed head is retained as evidence either way.
        """
        st = self.state
        if not verify_head(signed_head, self.pub):
            raise BadHead("submitted head signature is invalid")
        body = signed_head["head"]
        size, root = body["tree_size"], body["root"]
        rec = {"observer": observer, "observed_at": utcnow(),
               "signed_head": signed_head, "tree_size": size, "root": root}
        st["gossip"].append(rec)

        our = self._head_at_size(size)
        split = None
        if our is not None and our["head"]["root"] != root:
            split = self._record_split(
                kind="SAME_SIZE_DIFFERENT_ROOT", our=our,
                theirs=signed_head, observer=observer)
        elif our is None and size > self.tree_size:
            # A future head not derivable from anything we trust: attempt to
            # verify it strictly appends our current or last trusted head.
            base = st.get("last_trusted_head") or self.current_head()
            if base is not None and not self._extends(base, signed_head):
                split = self._record_split(
                    kind="NOT_A_STRICT_APPEND", our=base,
                    theirs=signed_head, observer=observer)
        self._save(st)
        return {"recorded": True, "split_view": split,
                "frozen": st["frozen"]}

    def _head_at_size(self, size: int) -> dict | None:
        for h in self.state["heads"]:
            if h["head"]["tree_size"] == size:
                return h
        return None

    def _extends(self, base: dict, candidate: dict) -> bool:
        """True if candidate's root strictly appends base's root. We can only
        verify this for heads whose leaves we hold; otherwise require the
        candidate's own prev_head chain to reach base."""
        bm = base["head"]["tree_size"]
        cm, cr = candidate["head"]["tree_size"], candidate["head"]["root"]
        if cm < bm:
            return False
        if cm == bm:
            return cr == base["head"]["root"]
        if cm <= self.tree_size:
            hashes = self._hashes()[:cm]
            proof = merkle.consistency_proof(hashes, bm)
            return merkle.verify_consistency(
                bm, cm, proof,
                bytes.fromhex(base["head"]["root"]),
                bytes.fromhex(cr))
        # candidate beyond our leaves: only the hash chain can be checked,
        # which is necessary but weaker; treat as a split for safety unless
        # its prev link chains to our head.
        return candidate["head"]["prev_head"] == base["head_digest"]

    def _record_split(self, *, kind: str, our: dict, theirs: dict,
                      observer: str) -> dict:
        st = self.state
        st["sequence"] += 1
        sid = f"sv-{st['sequence']}"
        rec = {
            "split_id": sid, "kind": kind, "status": "OPEN",
            "created_at": utcnow(), "observer": observer,
            "our_head": our, "their_head": theirs,
            "decision": None,
        }
        st["split_views"].append(rec)
        st["frozen"] = True
        if st.get("last_trusted_head") is None:
            st["last_trusted_head"] = self.current_head()
        return rec

    def list_split_views(self) -> list[dict]:
        return list(self.state["split_views"])

    def resolve_split(self, split_id: str, accepted_root: str,
                      reason: str, decided_by: str) -> dict:
        """Operator chooses a branch. The accepted branch MUST be verifiably
        derived (strict append) from the last trusted head; the rejected head
        stays as evidence. Publishing resumes from a continuous chain rooted
        at the last trusted head."""
        st = self.state
        if not reason or not reason.strip():
            raise BadHead("a reason is required to resolve a split-view")
        if not decided_by or not decided_by.strip():
            raise BadHead("decided_by is required")
        sv = next((s for s in st["split_views"]
                   if s["split_id"] == split_id), None)
        if sv is None:
            raise BadHead(f"unknown split-view {split_id}")
        if sv["status"] == "RESOLVED":
            return sv
        base = st.get("last_trusted_head") or self.current_head()
        accepted = sv["our_head"] if accepted_root == sv["our_head"]["head"]["root"] \
            else sv["their_head"] if accepted_root == sv["their_head"]["head"]["root"] \
            else None
        if accepted is None:
            raise BadHead("accepted root is not one of the conflicting heads")
        if base is not None and not self._extends(base, accepted):
            raise SplitUnresolved(
                "accepted branch cannot be proven to extend the last trusted "
                "head; refusing to resume")
        sv["status"] = "RESOLVED"
        sv["decision"] = {
            "accepted_root": accepted_root,
            "rejected_root": (sv["their_head"]["head"]["root"]
                              if accepted is sv["our_head"]
                              else sv["our_head"]["head"]["root"]),
            "reason": reason, "decided_by": decided_by,
            "decided_at": utcnow(),
            "base_head_digest": base["head_digest"] if base else GENESIS,
        }
        # Resume only if no other open split remains.
        if not any(s["status"] == "OPEN" for s in st["split_views"]):
            st["frozen"] = False
        self._save(st)
        return sv

    # ---- internal freeze (contradiction) ---------------------------------
    def _freeze(self, *, reason: str, offending):
        st = self.state
        st["frozen"] = True
        st["sequence"] += 1
        st["split_views"].append({
            "split_id": f"sv-{st['sequence']}",
            "kind": "INTERNAL_CONTRADICTION",
            "status": "OPEN",
            "created_at": utcnow(),
            "observer": "service",
            "reason": reason,
            "our_head": self.current_head(),
            "their_head": offending,
            "decision": None,
        })
        if st.get("last_trusted_head") is None:
            st["last_trusted_head"] = self.current_head()

    # ---- status / export -------------------------------------------------
    def status(self) -> dict:
        st = self.state
        latest_versions = self.latest_versions()
        return {
            "tree_size": len(st["leaves"]),
            "root": self.root().hex(),
            "frozen": st["frozen"],
            "current_head": self.current_head(),
            "last_trusted_head": st.get("last_trusted_head"),
            "latest_versions": latest_versions,
            "pending_events": self._pending_events(),
            "split_views": st["split_views"],
            "n_leaves": len(st["leaves"]),
            "n_heads": len(st["heads"]),
        }

    def latest_versions(self) -> dict:
        latest = {}
        for i, lf in enumerate(self.state["leaves"]):
            latest[lf["purpose"]] = {
                "version": lf["version"], "state": lf["next_state"],
                "fingerprint": lf["fingerprint"], "leaf_index": i,
                "event": lf["event"],
            }
        return latest

    def _pending_events(self) -> list:
        # Lifecycle leaves whose audit event exists but which are not yet
        # covered by the newest head (all appended leaves publish together, so
        # this is non-empty only between append-without-sign and publish).
        head_size = self.state["heads"][-1]["head"]["tree_size"] \
            if self.state["heads"] else 0
        return [{"index": i, "leaf": lf}
                for i, lf in enumerate(self.state["leaves"][head_size:],
                                       start=head_size)]

    def export_bundle(self) -> dict:
        st = self.state
        return {
            "bundle_version": BUNDLE_VERSION,
            "exported_at": utcnow(),
            "service_pub": st["service_pub"],
            "leaves": list(st["leaves"]),
            "heads": list(st["heads"]),
            "event_index": dict(st["event_index"]),
            "frozen": st["frozen"],
            "last_trusted_head": st.get("last_trusted_head"),
            "split_views": list(st["split_views"]),
            "gossip": list(st["gossip"]),
        }


# ---------------------------------------------------------------------------
# lifecycle transition table
# ---------------------------------------------------------------------------

_TRANSITIONS = {
    None: {EVENT_CREATED},
    "STAGED": {EVENT_ACTIVATED, EVENT_ABORTED},
    "ACTIVE": {EVENT_RETIRED},
    "RETIRING": {EVENT_DESTROYED},
    "DESTROYED": set(),
    "ABORTED": set(),
}


def _valid_transition(prev: str | None, next_state: str, event: str) -> bool:
    allowed = _TRANSITIONS.get(prev, set())
    # The event and resulting state must agree.
    expects = {
        EVENT_CREATED: ("STAGED", "ACTIVE"),
        EVENT_ACTIVATED: ("ACTIVE",),
        EVENT_RETIRED: ("RETIRING",),
        EVENT_DESTROYED: ("DESTROYED",),
        EVENT_ABORTED: ("ABORTED",),
    }.get(event)
    if expects is None or next_state not in expects:
        return False
    return event in allowed
