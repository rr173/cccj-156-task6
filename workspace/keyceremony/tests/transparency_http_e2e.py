"""HTTP end-to-end for the caller-facing transparency log.

Drives a GENERATE then a four-eyes ROTATE publish through the normal console
API, then verifies via the PUBLIC transparency endpoints that:
  * leaves and signed heads are produced for every lifecycle change,
  * inclusion and consistency proofs verify (using the same pure math the
    browser uses),
  * a gossiped same-size different-root head triggers a split-view, freezes
    publishing and blocks a new key activation while historical verification
    still works,
  * an operator resolves the split choosing the genuinely extending branch;
    the rejected head remains evidence and publishing resumes.

Run:  python3 tests/transparency_http_e2e.py [port]
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kc import merkle

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8421
ROOT = f"/tmp/kc-tlog-http-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

subprocess.run([sys.executable, "-m", "kc.bootstrap", "--root", ROOT],
               capture_output=True, check=True)
proc = subprocess.Popen(
    [sys.executable, "-m", "kc.server", "--root", ROOT, "--port", str(PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    BASE = f"http://127.0.0.1:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)

    TOK = {}

    def call(path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        hdr = {"Content-Type": "application/json"}
        if token:
            hdr["Authorization"] = "Bearer " + token
        req = urllib.request.Request(
            BASE + path, data=data, method="POST" if body is not None else "GET",
            headers=hdr)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def pub(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            BASE + path, data=data,
            method="POST" if body is not None else "GET",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def login(pid):
        call("/api/session/login-challenge", {"device_id": "dev_" + pid})
        s, j = call("/api/session/login", {"device_id": "dev_" + pid})
        assert s == 200, (s, j)
        TOK[pid] = j["token"]

    def steps(cid, pids):
        for pid in pids:
            assert call(f"/api/ceremonies/{cid}/attest",
                        {"device_id": "dev_" + pid}, token=TOK[pid])[0] == 200
        for pid in pids:
            assert call(f"/api/ceremonies/{cid}/receive",
                        {"device_id": "dev_" + pid}, token=TOK[pid])[0] == 200
        for pid in ("alice", "bruno", "carla"):
            assert call(f"/api/ceremonies/{cid}/confirm",
                        {"device_id": "dev_" + pid}, token=TOK[pid])[0] == 200

    for pid in ("alice", "bruno", "carla", "diego"):
        login(pid)

    def verify_inclusion_browser(index, size, leaf, path, roothex):
        return merkle.verify_inclusion(
            merkle.leaf_hash(leaf), index, size,
            [bytes.fromhex(p) for p in path], bytes.fromhex(roothex))

    # --- 1. public status is readable without a token --------------------
    s, st0 = pub("/api/tlog/status")
    assert s == 200 and st0["tree_size"] == 0, (s, st0)

    # --- 2. GENERATE ------------------------------------------------------
    s, c = call("/api/ceremonies/open",
                {"kind": "GENERATE", "policy_id": "pol-root-v1",
                 "purpose": "root-signing"}, token=TOK["alice"])
    assert s == 200, (s, c)
    cid1 = c["id"]
    steps(cid1, list(TOK))
    assert call(f"/api/ceremonies/{cid1}/commit", {}, token=TOK["alice"])[0] == 200

    s, st1 = pub("/api/tlog/status")
    assert st1["tree_size"] >= 1, st1
    old_head = st1["current_head"]
    print("GENERATE leaves:", st1["tree_size"], "root:",
          old_head["head"]["root"][:16])

    # every leaf verifies inclusion
    s, m = pub("/api/tlog/leaves?purpose=root-signing")
    assert s == 200
    for hit in m["matches"]:
        s, inc = pub(f"/api/tlog/inclusion?index={hit['index']}")
        assert s == 200
        assert verify_inclusion_browser(
            inc["index"], inc["tree_size"], inc["leaf"],
            inc["inclusion_path"], inc["head"]["head"]["root"]), hit["index"]

    # --- 3. ROTATE through a four-eyes ticket ----------------------------
    s, rc = call("/api/ceremonies/open",
                 {"kind": "ROTATE", "policy_id": "pol-root-v1",
                  "purpose": "root-signing"}, token=TOK["diego"])
    assert s == 200, (s, rc)
    cid2 = rc["id"]
    steps(cid2, list(TOK))
    assert call(f"/api/ceremonies/{cid2}/commit", {}, token=TOK["diego"])[0] == 200

    old_active = st1["latest_versions"]["root-signing"]
    # direct publish is protected
    s, j = call(f"/api/ceremonies/{cid2}/publish",
                {"expected_active": "x"}, token=TOK["diego"])
    assert s == 422 and j["error"] == "PROTECTED_OPERATION", (s, j)

    # diego creates the ticket, alice (complementary) approves -> executes
    s, keysv = call("/api/keys", token=TOK["diego"])
    expected = [k["id"] for k in keysv["keys"]
                if k["purpose"] == "root-signing" and k["status"] == "ACTIVE"][0]
    s, tk = call("/api/tickets",
                 {"operation": "PUBLISH_GENERATION",
                  "payload": {"ceremony_id": cid2,
                              "expected_active": expected}},
                 token=TOK["diego"])
    assert s == 200, (s, tk)
    tid = tk["ticket"]["id"]
    s, appr = call("/api/tickets/approve", {"ticket_id": tid},
                   token=TOK["alice"])
    assert s == 200, (s, appr)

    s, st2 = pub("/api/tlog/status")
    assert st2["tree_size"] > st1["tree_size"], (st1["tree_size"],
                                                 st2["tree_size"])
    print("ROTATE leaves:", st2["tree_size"], "frozen:", st2["frozen"])

    # --- 4. consistency old head -> new head ------------------------------
    m = old_head["head"]["tree_size"]
    s, cons = pub(f"/api/tlog/consistency?old_size={m}")
    assert s == 200
    ok = merkle.verify_consistency(
        m, cons["new_size"], cons["proof"],
        bytes.fromhex(old_head["head"]["root"]),
        bytes.fromhex(cons["head"]["head"]["root"]))
    assert ok, "consistency failed"
    print("consistency size", m, "->", cons["new_size"], "verified")

    # a bogus old root must fail
    assert not merkle.verify_consistency(
        m, cons["new_size"], cons["proof"], b"\x00" * 32,
        bytes.fromhex(cons["head"]["head"]["root"]))

    # --- 5. gossip an equivocating same-size head -> split-view ----------
    from kc.transparency import sign_head, head_body
    # forge using the SERVICE seed is not available externally; instead take
    # a valid current head shape and re-sign a different root at the same size
    # by reading service seed (this simulates a signing-key compromise / an
    # alternate valid signer producing an equivocation, which gossip exists to
    # catch). We construct it server-trusted by signing with the same key.
    seed = open(os.path.join(ROOT, "service.identity"), "rb").read()
    cur = st2["current_head"]["head"]
    evil = sign_head(head_body(cur["tree_size"], "e" * 64,
                               cur["issued_at"], cur["prev_head"]), seed)
    s, obs = pub("/api/tlog/observe",
                 {"observer": "browser-monitor", "signed_head": evil})
    assert s == 200 and obs["split_view"], (s, obs)
    assert obs["frozen"], obs
    print("split-view detected:", obs["split_view"]["split_id"])

    # historical inclusion still works while frozen
    s, inc = pub("/api/tlog/inclusion?index=0")
    assert verify_inclusion_browser(
        inc["index"], inc["tree_size"], inc["leaf"],
        inc["inclusion_path"], inc["head"]["head"]["root"])

    # new activation blocked: opening/committing another rotation must fail
    s, blocked = call("/api/ceremonies/open",
                      {"kind": "ROTATE", "policy_id": "pol-root-v1",
                       "purpose": "root-signing"}, token=TOK["diego"])
    # open may succeed, but publish/commit must be blocked by the freeze.
    if s == 200:
        cid3 = blocked["id"]
        steps(cid3, list(TOK))
        call(f"/api/ceremonies/{cid3}/commit", {}, token=TOK["diego"])
        s, tk2 = call("/api/tickets",
                      {"operation": "PUBLISH_GENERATION",
                       "payload": {"ceremony_id": cid3,
                                   "expected_active": expected}},
                      token=TOK["diego"])
        if s == 200:
            s, j = call("/api/tickets/approve",
                        {"ticket_id": tk2["ticket"]["id"]},
                        token=TOK["alice"])
            assert j.get("error") in (
                "TRANSPARENCY_FROZEN", "TARGET_STATE_CHANGED",
                "CONFLICT_STATE"), (s, j)
    print("new activation blocked while frozen")

    # --- 6. resolve with reason: choose the extending branch --------------
    s, splits = pub("/api/tlog/splits")
    sv = splits["split_views"][0]
    good_root = sv["our_head"]["head"]["root"]
    s, res = call("/api/tlog/resolve",
                  {"split_id": sv["split_id"], "accepted_root": good_root,
                   "reason": "out-of-band verification confirms our log",
                   "decided_by": "alice"}, token=TOK["alice"])
    assert s == 200 and res["status"] == "RESOLVED", (s, res)
    s, st3 = pub("/api/tlog/status")
    assert not st3["frozen"], st3
    # rejected head still evidence
    s, splits2 = pub("/api/tlog/splits")
    dec = splits2["split_views"][0]["decision"]
    assert dec["rejected_root"] == "e" * 64
    print("split resolved; rejected head retained as evidence")

    # --- 7. transparency bundle independently checks ----------------------
    s, bundle = pub("/api/tlog/bundle")
    assert s == 200
    from kc import transparency_verify as tv
    rep = tv.verify_bundle(bundle)
    assert rep["ok"], [f["code"] for f in rep["findings"]]
    print("independent checker: PASS")

    print("TRANSPARENCY HTTP E2E OK")
finally:
    proc.terminate()
    proc.wait(timeout=5)
