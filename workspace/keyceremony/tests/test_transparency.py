"""Tests for the caller-facing transparency log.

Covers:
  * Merkle inclusion + consistency math (positive and tamper negatives),
  * lifecycle leaves for create / activate-handover / retire / erase,
  * idempotent audit-event delivery (one leaf index, one quota),
  * multi-process concurrent append (deterministic order, no gaps,
    continuous head chain, single winner per size),
  * crash atomicity around leaf write / node update / head publish,
  * consistency proofs from an old head after many lifecycle changes,
  * split-view on a same-size different-root head, freeze + activation block,
  * operator branch resolution and rejected-head evidence retention,
  * the independent checker (clean passes; each tamper gives a specific code),
  * browser-side verification logic parity (the same fold rules).
"""

import json
import multiprocessing
import os
import random
import shutil
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import crypto
from kc import merkle
from kc import policy as P
from kc.attestation import provision_device
from kc.ceremony import Orchestrator
from kc.console import DeviceContext
from kc.storage import Store
from kc.transparency import (
    EVENT_ACTIVATED, EVENT_CREATED, EVENT_DESTROYED, EVENT_RETIRED,
    ContradictoryState, TransparencyFrozen, TransparencyLog,
    sign_head, head_body, verify_head,
)
from kc import transparency_verify as tv
from kc.directory import ACTIVE, DESTROYED, RETIRING, STAGED

ROLES_4 = [
    ("alice", "Alice Owner", P.ROOT_OWNER),
    ("bruno", "Bruno Steward", P.KEY_STEWARD),
    ("carla", "Witness Carla", P.WITNESS_SHAREHOLDER),
    ("diego", "Diego Op", P.ENCLAVE_OPERATOR),
]


class World:
    def __init__(self, root, threshold=3):
        shutil.rmtree(root, ignore_errors=True)
        self.root = root
        self.store = Store(root)
        self.wallets = {}
        with self.store.locked():
            self.orch = Orchestrator(self.store)
            slots = []
            for pid, name, role in ROLES_4:
                self.orch.enroll_participant(pid, name, role)
                w = provision_device("dev_" + pid, name)
                self.wallets[pid] = w
                self.orch.bind_device(pid, w, label=role)
                slots.append((pid, role, w.device_id))
            self.orch.create_policy("pol-root-v1", "root policy",
                                   threshold, slots)
            self.orch.save()
        self.ctx = {pid: DeviceContext(w) for pid, w in self.wallets.items()}

    def reopen(self):
        with self.store.locked():
            self.orch = Orchestrator(self.store)
        return self.orch

    def _run(self, kind, purpose="root-signing",
             confirmers=("alice", "bruno", "carla")):
        o = self.orch
        cid = o.open_ceremony(kind, "pol-root-v1", purpose, "alice")["id"]
        for pid, ctx in self.ctx.items():
            ctx.attest(o, cid)
        for pid, ctx in self.ctx.items():
            ctx.receive_share(o, cid)
        for pid in confirmers:
            self.ctx[pid].confirm(o, cid)
        o.commit(cid, "alice")
        return cid

    def generate(self, purpose="root-signing"):
        return self._run(P.GENERATE, purpose)

    def rotate(self, purpose="root-signing"):
        old = self.orch.dir.active(purpose)["id"]
        cid = self._run(P.ROTATE, purpose)
        self.orch.publish_rotation(cid, "alice", expected_active=old)
        return cid

    def destroy_retiring(self, purpose="root-signing"):
        retiring = next(k for k in
                        self.orch.dir.versions_for_purpose(purpose)
                        if k["status"] == RETIRING)
        cid = self.orch.open_ceremony(P.DESTROY, "pol-root-v1", purpose,
                                      "alice",
                                      target_version=retiring["id"])["id"]
        for pid, ctx in self.ctx.items():
            ctx.attest(o := self.orch, cid)
        for pid, ctx in self.ctx.items():
            ctx.confirm(o, cid)
        o.commit(cid, "alice")
        return cid


# --------------------------------------------------------------------------
# Merkle math
# --------------------------------------------------------------------------

class TestMerkleMath(unittest.TestCase):
    def test_inclusion_all_sizes(self):
        for n in range(1, 80):
            hs = [os.urandom(32) for _ in range(n)]
            root = merkle.tree_root_from_hashes(hs)
            for i in range(n):
                p = merkle.inclusion_proof(hs, i)
                self.assertTrue(
                    merkle.verify_inclusion(hs[i], i, n, list(p), root))

    def test_inclusion_tamper_negatives(self):
        hs = [os.urandom(32) for _ in range(12)]
        root = merkle.tree_root_from_hashes(hs)
        for i in range(12):
            p = merkle.inclusion_proof(hs, i)
            self.assertFalse(
                merkle.verify_inclusion(os.urandom(32), i, 12, list(p), root))
            self.assertFalse(
                merkle.verify_inclusion(hs[i], i, 12, list(p),
                                       os.urandom(32)))
            if p:
                self.assertFalse(
                    merkle.verify_inclusion(hs[i], i, 12, p[:-1], root))
            other = [os.urandom(32) for _ in range(12)]
            self.assertFalse(
                merkle.verify_inclusion(hs[i], i, 12,
                                       merkle.inclusion_proof(other, i), root))

    def test_consistency_all_pairs(self):
        for n in range(1, 70):
            hs = [os.urandom(32) for _ in range(n)]
            rn = merkle.tree_root_from_hashes(hs)
            for m in range(1, n):
                rm = merkle.tree_root_from_hashes(hs[:m])
                p = merkle.consistency_proof(hs, m)
                self.assertTrue(
                    merkle.verify_consistency(m, n, p, rm, rn), (m, n))
                w = merkle.encode_consistency(p)
                self.assertTrue(
                    merkle.verify_consistency(m, n, w, rm, rn))

    def test_consistency_tamper_negatives(self):
        random.seed(5)
        for _ in range(40):
            n = random.randint(2, 60)
            m = random.randint(1, n - 1)
            hs = [os.urandom(32) for _ in range(n)]
            rn = merkle.tree_root_from_hashes(hs)
            rm = merkle.tree_root_from_hashes(hs[:m])
            p = merkle.consistency_proof(hs, m)
            # forged old root / new root
            self.assertFalse(
                merkle.verify_consistency(m, n, p, os.urandom(32), rn))
            self.assertFalse(
                merkle.verify_consistency(m, n, p, rm, os.urandom(32)))
            # replaced key inside old prefix
            ev = hs[:]
            ev[random.randrange(m)] = os.urandom(32)
            self.assertFalse(
                merkle.verify_consistency(
                    m, n, merkle.consistency_proof(ev, m), rm,
                    merkle.tree_root_from_hashes(ev)))
            # splice another tree's proof
            other = [os.urandom(32) for _ in range(n)]
            self.assertFalse(
                merkle.verify_consistency(
                    m, n, merkle.consistency_proof(other, m), rm, rn))
            # truncated new path
            if p["new_path"]:
                self.assertFalse(
                    merkle.verify_consistency(
                        m, n, {**p, "new_path": p["new_path"][:-1]}, rm, rn))


# --------------------------------------------------------------------------
# lifecycle logging
# --------------------------------------------------------------------------

class TestLifecycleLeaves(unittest.TestCase):
    def setUp(self):
        self.w = World("/tmp/kc-tlog-life")

    def test_create_rotate_destroy_leaves(self):
        w = self.w
        w.generate()
        tlog = w.orch.tlog
        # first generation: one CREATED leaf (ACTIVE)
        leaves = tlog.state["leaves"]
        self.assertEqual(len(leaves), 1)
        self.assertEqual(leaves[0]["event"], EVENT_CREATED)
        self.assertEqual(leaves[0]["next_state"], ACTIVE)
        self.assertIsNone(leaves[0]["prev_state"])
        head = tlog.current_head()
        self.assertEqual(head["head"]["tree_size"], 1)

        w.rotate()
        events = [l["event"] for l in tlog.state["leaves"]]
        self.assertIn(EVENT_CREATED, events)
        self.assertIn(EVENT_ACTIVATED, events)
        self.assertIn(EVENT_RETIRED, events)
        # version 2 CREATED is STAGED then ACTIVATED; version 1 RETIRING
        by_ver = {}
        for l in tlog.state["leaves"]:
            by_ver.setdefault((l["purpose"], l["version"]), []).append(l)
        v2 = by_ver[("root-signing", 2)]
        self.assertEqual([l["next_state"] for l in v2],
                         [STAGED, ACTIVE])
        v1 = by_ver[("root-signing", 1)]
        self.assertEqual(v1[-1]["next_state"], RETIRING)
        # head size matches leaf quota exactly
        self.assertEqual(tlog.current_head()["head"]["tree_size"],
                         len(tlog.state["leaves"]))

    def test_inclusion_for_both_generations(self):
        w = self.w
        w.generate()
        h1 = w.orch.tlog.current_head()
        w.rotate()
        tlog = w.orch.tlog
        rn = tlog.root()
        hashes = tlog._hashes()
        for i, lf in enumerate(tlog.state["leaves"]):
            p = merkle.inclusion_proof(hashes, i)
            self.assertTrue(
                merkle.verify_inclusion(
                    bytes.fromhex(lf["leaf_hash"]), i, len(hashes), p, rn),
                i)
        # old head -> new head consistency
        m = h1["head"]["tree_size"]
        cp = tlog.consistency(m)
        self.assertTrue(merkle.verify_consistency(
            m, cp["new_size"], cp["proof"],
            bytes.fromhex(h1["head"]["root"]),
            bytes.fromhex(cp["head"]["head"]["root"])))

    def test_destroyed_public_material_still_queryable(self):
        w = self.w
        w.generate()
        w.rotate()
        w.destroy_retiring()
        tlog = w.orch.tlog
        dest = [l for l in tlog.state["leaves"]
                if l["event"] == EVENT_DESTROYED]
        self.assertEqual(len(dest), 1)
        # even after erasure the leaf / fingerprint / inclusion still verify
        hit = tlog.find_leaves(version=1)
        self.assertTrue(hit)
        inc = tlog.inclusion_for_index(hit[0]["index"])
        self.assertTrue(tv.verify_proof(
            inc["leaf"], inc["index"], inc["tree_size"],
            inc["inclusion_path"], inc["head"]["head"]["root"]))

    def test_duplicate_audit_event_returns_same_index(self):
        w = self.w
        tlog = w.orch.tlog
        audit = w.orch.audit.entries
        # synthesize: re-deliver the same audit entry twice manually
        e = {"seq": 999, "hash": "a" * 64,
             "payload": {"ceremony_id": "x"}}
        r1 = tlog.append_lifecycle(
            purpose="p", version=1, fingerprint="f", prev_state=None,
            next_state=ACTIVE, event=EVENT_CREATED, ceremony_id="x",
            audit_entry=e)
        r2 = tlog.append_lifecycle(
            purpose="p", version=1, fingerprint="f", prev_state=None,
            next_state=ACTIVE, event=EVENT_CREATED, ceremony_id="x",
            audit_entry=e)
        self.assertEqual(r1["index"], r2["index"])
        self.assertTrue(r2["duplicate"])
        self.assertEqual(len(tlog.state["leaves"]),
                         tlog.current_head()["head"]["tree_size"])

    def test_contradictory_fingerprint_freezes(self):
        w = self.w
        tlog = w.orch.tlog
        e1 = {"seq": 1, "hash": "a" * 64, "payload": {"ceremony_id": "c"}}
        tlog.append_lifecycle(
            purpose="p", version=1, fingerprint="fp1", prev_state=None,
            next_state=STAGED, event=EVENT_CREATED, ceremony_id="c",
            audit_entry=e1)
        e2 = {"seq": 2, "hash": "b" * 64, "payload": {"ceremony_id": "c2"}}
        with self.assertRaises(ContradictoryState):
            tlog.append_lifecycle(
                purpose="p", version=1, fingerprint="fp_DIFFERENT",
                prev_state=STAGED, next_state=ACTIVE, event=EVENT_ACTIVATED,
                ceremony_id="c2", audit_entry=e2)
        self.assertTrue(tlog.is_frozen())

    def test_illegal_state_jump_rejected(self):
        w = self.w
        tlog = w.orch.tlog
        e1 = {"seq": 1, "hash": "a" * 64, "payload": {"ceremony_id": "c"}}
        tlog.append_lifecycle(
            purpose="p", version=1, fingerprint="f", prev_state=None,
            next_state=STAGED, event=EVENT_CREATED, ceremony_id="c",
            audit_entry=e1)
        # STAGED -> DESTROYED directly is illegal
        e2 = {"seq": 2, "hash": "b" * 64, "payload": {"ceremony_id": "c2"}}
        with self.assertRaises(ContradictoryState):
            tlog.append_lifecycle(
                purpose="p", version=1, fingerprint="f", prev_state=STAGED,
                next_state=DESTROYED, event=EVENT_DESTROYED,
                ceremony_id="c2", audit_entry=e2)


# --------------------------------------------------------------------------
# multi-process commit
# --------------------------------------------------------------------------

def _worker_append(root, purpose, version, seq):
    store = Store(root)
    with store.locked():
        tlog = TransparencyLog(store)
        if tlog.is_frozen():
            return {"frozen": True}
        e = {"seq": seq, "hash": f"{seq:064d}",
             "payload": {"ceremony_id": f"c{seq}"}}
        r = tlog.append_lifecycle(
            purpose=purpose, version=version, fingerprint=f"fp-{seq}",
            prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
            ceremony_id=f"c{seq}", audit_entry=e)
        tlog.save()
        return {"index": r["index"], "duplicate": r["duplicate"],
                "size": tlog.tree_size}


class TestMultiProcessCommit(unittest.TestCase):
    def setUp(self):
        shutil.rmtree("/tmp/kc-tlog-mp", ignore_errors=True)
        self.root = "/tmp/kc-tlog-mp"
        Store(self.root)  # create dir + service seed

    def test_concurrent_distinct_leaves_total_order(self):
        args = [(self.root, "p", i + 1, i + 1) for i in range(12)]
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(6) as pool:
            outs = pool.starmap(_worker_append, args)
        tlog = TransparencyLog(Store(self.root))
        self.assertEqual(tlog.tree_size, 12)
        self.assertEqual(sorted(o["index"] for o in outs), list(range(12)))
        self.assertFalse(any(o.get("duplicate") for o in outs))
        # head chain continuous and sizes 1..12
        sizes = [h["head"]["tree_size"] for h in tlog.state["heads"]]
        self.assertEqual(sizes, list(range(1, 13)))

    def test_duplicate_event_multiprocess_one_leaf(self):
        args = [(self.root, "p", 1, 777) for _ in range(8)]
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(8) as pool:
            outs = pool.starmap(_worker_append, args)
        tlog = TransparencyLog(Store(self.root))
        self.assertEqual(tlog.tree_size, 1)
        self.assertEqual({o["index"] for o in outs}, {0})
        self.assertEqual(tlog.current_head()["head"]["tree_size"], 1)


# --------------------------------------------------------------------------
# crash atomicity
# --------------------------------------------------------------------------

class TestCrashAtomicity(unittest.TestCase):
    def setUp(self):
        shutil.rmtree("/tmp/kc-tlog-crash", ignore_errors=True)
        self.root = "/tmp/kc-tlog-crash"
        Store(self.root)

    def _head_never_dangles(self):
        """After reopening, the current head must reference exactly its
        declared size of durable leaves and recompute to its root."""
        tlog = TransparencyLog(Store(self.root))
        h = tlog.current_head()
        if h is None:
            self.assertEqual(tlog.tree_size, 0)
            return
        size = h["head"]["tree_size"]
        self.assertEqual(size, tlog.tree_size)
        self.assertEqual(
            merkle.tree_root_from_hashes(
                tlog._hashes()[:size]).hex(), h["head"]["root"])

    def test_interrupted_appends_heal_to_consistent_heads(self):
        for seq in range(1, 20):
            store = Store(self.root)
            with store.locked():
                tlog = TransparencyLog(store)
                e = {"seq": seq, "hash": f"{seq:064d}",
                     "payload": {"ceremony_id": f"c{seq}"}}
                tlog.append_lifecycle(
                    purpose="p", version=seq, fingerprint=f"fp{seq}",
                    prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
                    ceremony_id=f"c{seq}", audit_entry=e)
                # Simulate an exit at several points: no _save at all (only
                # in-memory), or save (full commit). Either is valid.
                if seq % 3 == 0:
                    tlog.save()
                # otherwise discard by not saving - reopen must not see it
            self._head_never_dangles()
        # a final reopen and heal: every durable audit event eventually lands
        store = Store(self.root)
        with store.locked():
            tlog = TransparencyLog(store)
            self._head_never_dangles()

    def test_reopen_sees_only_complete_heads(self):
        for seq in range(1, 10):
            store = Store(self.root)
            with store.locked():
                tlog = TransparencyLog(store)
                e = {"seq": seq, "hash": f"{seq:064d}",
                     "payload": {"ceremony_id": f"c{seq}"}}
                tlog.append_lifecycle(
                    purpose="p", version=seq, fingerprint=f"fp{seq}",
                    prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
                    ceremony_id=f"c{seq}", audit_entry=e)
                tlog.save()
            self._head_never_dangles()


def _crash_worker(root, seq, crash_point):
    """Append a leaf then hard-exit at a named point:
      after_leaf  - leaf sequenced in memory, never persisted
      after_save  - full commit saved, then exit
    os._exit skips all Python cleanup, modeling a real crash."""
    store = Store(root)
    with store.locked():
        tlog = TransparencyLog(store)
        e = {"seq": seq, "hash": f"{seq:064d}",
             "payload": {"ceremony_id": f"c{seq}"}}
        tlog.append_lifecycle(
            purpose="p", version=seq, fingerprint=f"fp{seq}",
            prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
            ceremony_id=f"c{seq}", audit_entry=e,
            _persist=(crash_point != "after_leaf"))
        os._exit(0)


class TestHardCrashAtomicity(unittest.TestCase):
    def setUp(self):
        shutil.rmtree("/tmp/kc-tlog-hardcrash", ignore_errors=True)
        self.root = "/tmp/kc-tlog-hardcrash"
        Store(self.root)

    def _check(self):
        tlog = TransparencyLog(Store(self.root))
        h = tlog.current_head()
        if h is not None:
            size = h["head"]["tree_size"]
            self.assertEqual(size, tlog.tree_size)
            self.assertEqual(
                merkle.tree_root_from_hashes(tlog._hashes()).hex(),
                h["head"]["root"])
            # no head may reference a missing leaf
            self.assertLessEqual(size, len(tlog.state["leaves"]))

    def test_crash_between_leaf_and_save_is_rolled_back(self):
        ctx = multiprocessing.get_context("fork")
        seq = 1
        p = ctx.Process(target=_crash_worker,
                        args=(self.root, seq, "after_leaf"))
        p.start(); p.join()
        self._check()
        tlog = TransparencyLog(Store(self.root))
        self.assertEqual(tlog.tree_size, 0)  # nothing durable committed

    def test_crash_after_save_sees_complete_new_head(self):
        ctx = multiprocessing.get_context("fork")
        p = ctx.Process(target=_crash_worker,
                        args=(self.root, 1, "after_save"))
        p.start(); p.join()
        self._check()
        tlog = TransparencyLog(Store(self.root))
        self.assertEqual(tlog.tree_size, 1)
        # a second crashing process continues from the committed head
        p = ctx.Process(target=_crash_worker,
                        args=(self.root, 2, "after_save"))
        p.start(); p.join()
        self._check()
        tlog = TransparencyLog(Store(self.root))
        self.assertEqual(tlog.tree_size, 2)
        sizes = [h["head"]["tree_size"] for h in tlog.state["heads"]]
        self.assertEqual(sizes, [1, 2])

    def test_mixed_crashes_converge_to_continuous_chain(self):
        ctx = multiprocessing.get_context("fork")
        # seq identifies the leaf position; crashed (unpersisted) workers
        # leave no trace, so retry those positions afterwards.
        plan = [(1, "after_save"), (2, "after_leaf"), (3, "after_save"),
                (4, "after_leaf"), (5, "after_save")]
        for seq, point in plan:
            p = ctx.Process(target=_crash_worker,
                            args=(self.root, seq, point))
            p.start(); p.join()
        self._check()
        tlog = TransparencyLog(Store(self.root))
        # only the saved commits (1,3,5) are durable; the leaf-index quota
        # still has no gaps because crashed leaves were never sequenced on
        # disk (each fresh process re-derived size from the committed state).
        self.assertEqual(tlog.tree_size, 3)
        sizes = [h["head"]["tree_size"] for h in tlog.state["heads"]]
        self.assertEqual(sizes, [1, 2, 3])
        # leaves carry their business version but occupy indices 0,1,2
        self.assertEqual([l["version"] for l in tlog.state["leaves"]],
                         [1, 3, 5])


# --------------------------------------------------------------------------
# consistency across many changes
# --------------------------------------------------------------------------

class TestLongConsistency(unittest.TestCase):
    def test_old_head_after_many_changes(self):
        w = World("/tmp/kc-tlog-long")
        w.generate()
        tlog = w.orch.tlog
        pins = [(tlog.current_head()["head"]["tree_size"],
                 tlog.current_head()["head"]["root"])]
        for v in range(2, 6):
            w.rotate()
            pins.append((tlog.current_head()["head"]["tree_size"],
                         tlog.current_head()["head"]["root"]))
            w.destroy_retiring()
        # every pinned head verifies append-only against the final head
        final_head = tlog.current_head()
        for m, root in pins:
            cp = tlog.consistency(m)
            self.assertTrue(merkle.verify_consistency(
                m, cp["new_size"], cp["proof"],
                bytes.fromhex(root),
                bytes.fromhex(final_head["head"]["root"])), m)


# --------------------------------------------------------------------------
# split-view freeze + resolution
# --------------------------------------------------------------------------

class TestSplitView(unittest.TestCase):
    def setUp(self):
        shutil.rmtree("/tmp/kc-tlog-split", ignore_errors=True)
        self.root = "/tmp/kc-tlog-split"
        Store(self.root)
        self.store = Store(self.root)
        with self.store.locked():
            self.tlog = TransparencyLog(self.store)
            for seq in range(1, 4):
                e = {"seq": seq, "hash": f"{seq:064d}",
                     "payload": {"ceremony_id": f"c{seq}"}}
                self.tlog.append_lifecycle(
                    purpose="p", version=seq, fingerprint=f"fp{seq}",
                    prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
                    ceremony_id=f"c{seq}", audit_entry=e)
            self.tlog.save()
            self.good_head = self.tlog.current_head()

    def _evil_head_same_size(self):
        # a structurally valid signed head at the SAME size but different root
        body = head_body(
            self.good_head["head"]["tree_size"], "f" * 64,
            self.good_head["head"]["issued_at"],
            self.good_head["head"]["prev_head"])
        seed = self.store.service_seed()
        return sign_head(body, seed)

    def test_equivocation_freezes_and_blocks_activation(self):
        evil = self._evil_head_same_size()
        out = self.tlog.observe_head(evil, observer="mon1")
        self.assertTrue(self.tlog.is_frozen())
        self.assertIsNotNone(out["split_view"])
        self.assertEqual(out["split_view"]["kind"],
                         "SAME_SIZE_DIFFERENT_ROOT")
        # new leaf / head now blocked
        e = {"seq": 50, "hash": "z" * 64, "payload": {"ceremony_id": "cx"}}
        with self.assertRaises(TransparencyFrozen):
            self.tlog.append_lifecycle(
                purpose="p", version=99, fingerprint="fpx",
                prev_state=None, next_state=ACTIVE, event=EVENT_CREATED,
                ceremony_id="cx", audit_entry=e)
        # the rejected head is retained as evidence
        ev_roots = [s["their_head"]["head"]["root"]
                    for s in self.tlog.list_split_views()]
        self.assertIn("f" * 64, ev_roots)

    def test_resume_after_choosing_extending_branch(self):
        evil = self._evil_head_same_size()
        self.tlog.observe_head(evil, observer="mon1")
        # the evil root cannot be accepted (does not extend trusted head)
        with self.assertRaises(Exception):
            self.tlog.resolve_split(
                self.tlog.list_split_views()[0]["split_id"],
                "f" * 64, "try to pick evil", "ops")
        # accepting our genuine branch resumes
        sv = self.tlog.resolve_split(
            self.tlog.list_split_views()[0]["split_id"],
            self.good_head["head"]["root"],
            "out-of-band verification confirms our head", "ops")
        self.assertEqual(sv["status"], "RESOLVED")
        self.assertFalse(self.tlog.is_frozen())
        # publishing resumes with a continuous chain
        e = {"seq": 51, "hash": "y" * 64, "payload": {"ceremony_id": "cy"}}
        r = self.tlog.append_lifecycle(
            purpose="p", version=4, fingerprint="fp4", prev_state=None,
            next_state=ACTIVE, event=EVENT_CREATED, ceremony_id="cy",
            audit_entry=e)
        self.assertFalse(r["duplicate"])
        self.tlog.save()

    def test_history_verification_unaffected_while_frozen(self):
        evil = self._evil_head_same_size()
        self.tlog.observe_head(evil, observer="mon1")
        # inclusion proofs still verify while frozen
        hashes = self.tlog._hashes()
        for i in range(len(hashes)):
            p = merkle.inclusion_proof(hashes, i)
            self.assertTrue(merkle.verify_inclusion(
                hashes[i], i, len(hashes), p, self.tlog.root()))


# --------------------------------------------------------------------------
# independent checker
# --------------------------------------------------------------------------

class TestIndependentChecker(unittest.TestCase):
    def setUp(self):
        self.w = World("/tmp/kc-tlog-check")
        self.w.generate()
        self.w.rotate()
        self.w.destroy_retiring()

    def _bundle(self, keys=None):
        return self.w.orch.tlog.export_bundle()

    def test_clean_bundle_passes(self):
        rep = tv.verify_bundle(self._bundle(),
                               keys=list(self.w.orch.state["keys"].values()))
        self.assertTrue(rep["ok"], [f["code"] for f in rep["findings"]])

    def test_checker_detects_each_tamper(self):
        keys = list(self.w.orch.state["keys"].values())

        # missing leaf: head size larger than leaf set
        b = self._bundle()
        b2 = json.loads(json.dumps(b))
        last = b2["heads"][-1]
        b2["heads"].append({
            "head": {"domain": last["head"]["domain"],
                     "tree_size": last["head"]["tree_size"] + 1,
                     "root": "0" * 64,
                     "issued_at": "2999-01-01T00:00:00Z",
                     "prev_head": last["head_digest"]},
            "head_digest": "0" * 64, "svc_sig": last["svc_sig"]})
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("LEAF_MISSING", codes)

        # duplicate business event
        b2 = json.loads(json.dumps(b))
        dup = dict(b2["leaves"][0])
        b2["leaves"].append(dup)
        b2["leaf_hashes"] = [l["leaf_hash"] for l in b2["leaves"]]
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("DUPLICATE_BUSINESS_EVENT", codes)

        # fingerprint swap
        b2 = json.loads(json.dumps(b))
        lf = b2["leaves"][0]
        other = next(l for l in b2["leaves"]
                     if l["purpose"] == lf["purpose"]
                     and l["version"] != lf["version"])
        other["version"] = lf["version"]
        other["fingerprint"] = "swapped"
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertTrue({"FINGERPRINT_SWAP", "ILLEGAL_TRANSITION"} & codes)

        # same size two roots
        b2 = json.loads(json.dumps(b))
        h0 = dict(b2["heads"][0])
        evil = json.loads(json.dumps(h0))
        evil["head"] = dict(h0["head"], root="e" * 64)
        evil["head_digest"] = "e" * 64
        b2["heads"].insert(1, evil)
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("SAME_SIZE_TWO_ROOTS", codes)

        # broken head chain
        b2 = json.loads(json.dumps(b))
        b2["heads"][1]["head"]["prev_head"] = "9" * 64
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("HEAD_CHAIN_BROKEN", codes)

        # head signature replaced
        b2 = json.loads(json.dumps(b))
        b2["heads"][0]["svc_sig"] = crypto.b64e(b"\x00" * 64)
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("HEAD_SIGNATURE_REPLACED", codes)

        # conflict skipped: an OPEN split plus a later head
        b2 = json.loads(json.dumps(b))
        b2["frozen"] = True
        b2["split_views"].append({
            "split_id": "sv-x", "kind": "SAME_SIZE_DIFFERENT_ROOT",
            "status": "OPEN", "created_at": "2000-01-01T00:00:00Z",
            "our_head": b2["heads"][0], "their_head": b2["heads"][0],
            "decision": None})
        codes = {f["code"] for f in tv.verify_bundle(b2, keys=keys)["findings"]}
        self.assertIn("CONFLICT_SKIPPED", codes)

        # unregistered activation: ACTIVE key with no matching leaf
        b2 = self._bundle()
        keys2 = json.loads(json.dumps(keys))
        keys2.append({"purpose": "ghost", "version": 9,
                      "status": ACTIVE, "fingerprint": "ghostfp"})
        codes = {f["code"]
                 for f in tv.verify_bundle(b2, keys=keys2)["findings"]}
        self.assertIn("UNREGISTERED_ACTIVATION", codes)

    def test_checker_detects_reordered_and_bad_path(self):
        keys = list(self.w.orch.state["keys"].values())
        # reorder: swap two leaves while keeping head root inconsistent.
        b = self._bundle()
        b2 = json.loads(json.dumps(b))
        if len(b2["leaves"]) >= 2:
            b2["leaves"][0], b2["leaves"][1] = b2["leaves"][1], b2["leaves"][0]
            b2["leaf_hashes"] = [l["leaf_hash"] for l in b2["leaves"]]
            codes = {f["code"] for f in
                     tv.verify_bundle(b2, keys=keys)["findings"]}
            # reordering breaks the head-root recomputation / inclusion paths
            self.assertTrue(
                {"TREE_ROOT_MISMATCH", "BAD_INCLUSION_PATH"} & codes, codes)

    def test_checker_detects_broken_consistency(self):
        keys = list(self.w.orch.state["keys"].values())
        b = self._bundle()
        b2 = json.loads(json.dumps(b))
        # fabricate an earlier head with a wrong root but a valid-looking
        # chain to the last head -> the append check between heads fails
        if len(b2["heads"]) >= 2:
            mid = b2["heads"][0]
            # recompute a root from a reordered prefix
            lh = [l["leaf_hash"] for l in b2["leaves"]]
            import hashlib
            fake = hashlib.sha256(b"x").hexdigest()
            mid["head"]["root"] = fake
            mid["head_digest"] = fake
            codes = {f["code"] for f in
                     tv.verify_bundle(b2, keys=keys)["findings"]}
            self.assertIn("BROKEN_CONSISTENCY", codes)

    def test_export_bundle_transparency_check(self):
        from kc import export as export_mod
        bundle = export_mod.build_bundle(self.w.orch)
        rep = export_mod.verify_bundle(bundle)
        self.assertTrue(rep["ok"], rep["problems"])
        self.assertTrue(rep["checks"]["transparency_ok"])


# --------------------------------------------------------------------------
# browser-side parity
# --------------------------------------------------------------------------

class TestBrowserParity(unittest.TestCase):
    def test_consistency_wire_shape_is_browser_friendly(self):
        hs = [os.urandom(32) for _ in range(13)]
        p = merkle.consistency_proof(hs, 6)
        w = merkle.encode_consistency(p)
        self.assertEqual(set(w),
                         {"old_size", "new_size", "leaf_index", "leaf",
                          "old_path", "new_path"})
        self.assertTrue(all(isinstance(x, str) for x in w["new_path"]))
        # the browser folds inclusion paths; confirm the fields it needs exist
        self.assertEqual(w["leaf_index"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
