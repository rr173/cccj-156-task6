"""Merkle tree math for the caller-facing transparency log.

Pure functions only - no storage, no service state - so the browser, the
independent checker and any external monitor run exactly the same algorithms.
Hashing follows the RFC 6962 domain separation:

  leaf_hash  = SHA256(0x00 || canonical(leaf))
  inner_hash = SHA256(0x01 || left || right)

Leaf ordering is total and fixed the moment a leaf is sequenced, so
truncation, reordering or splicing a path from a different tree all fail
verification.

  * inclusion proofs rebuild one leaf's root from its sibling path;
  * consistency proofs bind the last leaf of the old prefix (a *public*
    leaf) into BOTH roots with its old-tree and new-tree inclusion paths.
    The old path's left siblings are the balanced roots of every leaf in
    [0, m), so rebuilding the old root binds the whole old prefix; the new
    path binds every appended leaf. A client needs only its two trusted
    (size, root) pairs.

The empty tree root is 64 ASCII zeroes (same GENESIS convention as the
hash-chained audit log).
"""

from __future__ import annotations

from . import crypto

LEAF_DOMAIN = b"\x00"
NODE_DOMAIN = b"\x01"
EMPTY_ROOT = "0" * 64

# Leaf content is fully public: purpose, version, public fingerprint,
# previous/next status, ceremony id and audit reference only. No shares,
# signing seeds or wrapping material are ever placed inside a leaf.
LEAF_FIELDS = ("purpose", "version", "fingerprint", "prev_state",
               "next_state", "ceremony_id", "event", "audit_seq",
               "audit_digest")


def leaf_content(leaf: dict) -> dict:
    return {k: leaf[k] for k in LEAF_FIELDS}


def hash_leaf_bytes(data: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(LEAF_DOMAIN + data).digest()


def leaf_hash(leaf: dict) -> bytes:
    return hash_leaf_bytes(crypto.dumps(leaf_content(leaf)).encode("utf-8"))


def hash_children(left: bytes, right: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(NODE_DOMAIN + left + right).digest()


def _promote(cur: list[bytes]) -> list[bytes]:
    nxt = []
    for i in range(0, len(cur) - 1, 2):
        nxt.append(hash_children(cur[i], cur[i + 1]))
    if len(cur) % 2:
        nxt.append(cur[-1])  # odd trailing node promoted unchanged
    return nxt


def build_levels(hashes: list[bytes]) -> list[list[bytes]]:
    levels = [list(hashes)]
    while levels[-1] and len(levels[-1]) > 1:
        levels.append(_promote(levels[-1]))
    return levels


def tree_root_from_hashes(hashes: list[bytes]) -> bytes:
    if not hashes:
        return bytes.fromhex(EMPTY_ROOT)
    cur = list(hashes)
    while len(cur) > 1:
        cur = _promote(cur)
    return cur[0]


def tree_root(leaves: list) -> bytes:
    return tree_root_from_hashes([leaf_hash(l) for l in leaves])


# ---------------------------------------------------------------------------
# inclusion proof
# ---------------------------------------------------------------------------

def inclusion_proof(hashes: list[bytes], index: int) -> list[bytes]:
    """Sibling digests, bottom-up, combining leaf ``index`` into the root."""
    n = len(hashes)
    if not 0 <= index < n:
        raise IndexError("leaf index out of range")
    proof: list[bytes] = []
    cur = list(hashes)
    idx = index
    while len(cur) > 1:
        if idx % 2:
            proof.append(cur[idx - 1])
        elif idx + 1 < len(cur):
            proof.append(cur[idx + 1])
        # odd trailing node is promoted without a sibling
        cur = _promote(cur)
        idx //= 2
    return proof


def verify_inclusion(leaf_value: bytes, index: int, size: int,
                     proof: list[bytes], root: bytes) -> bool:
    """Fold a leaf hash with its sibling path and compare to the root.

    ``leaf_value`` is the already domain-separated leaf hash. Every proof
    node must be consumed (a truncated or over-long path fails).
    """
    if size <= 0 or not 0 <= index < size:
        return False
    idx, n = index, size
    acc = leaf_value
    nodes = list(proof)
    while n > 1:
        if not (n % 2 == 1 and idx == n - 1):  # not an odd promoted node
            if not nodes:
                return False
            sib = nodes.pop(0)
            acc = hash_children(sib, acc) if idx % 2 \
                else hash_children(acc, sib)
        n = (n + 1) // 2
        idx //= 2
    return n == 1 and not nodes and acc == root


# ---------------------------------------------------------------------------
# consistency proof (public boundary leaf, two inclusion paths)
# ---------------------------------------------------------------------------

def consistency_proof(hashes: list[bytes], first: int) -> dict:
    """Prove the n-tree strictly appends to the tree of hashes[:first].

    The proof binds the *last leaf of the old prefix* (index m-1, itself a
    public transparency leaf hash) into BOTH roots independently:

      * ``leaf``     - the leaf hash at index m-1,
      * ``old_path`` - its inclusion path in the m-leaf tree,
      * ``new_path`` - its inclusion path in the n-leaf tree.

    The old path's left siblings are the balanced roots of every leaf in
    [0, m-1), so rebuilding the old root binds the entire old prefix; the new
    path binds every appended leaf. Truncation, reordering, key replacement
    and a spliced foreign path all fail one of the two folds.
    """
    n = len(hashes)
    if not 0 < first < n:
        return {}
    m = first
    return {
        "old_size": m,
        "new_size": n,
        "leaf_index": m - 1,
        "leaf": hashes[m - 1],
        "old_path": inclusion_proof(hashes[:m], m - 1),
        "new_path": inclusion_proof(hashes, m - 1),
    }


def encode_consistency(proof: dict) -> dict:
    """JSON/hex wire form."""
    return {
        "old_size": proof["old_size"],
        "new_size": proof["new_size"],
        "leaf_index": proof["leaf_index"],
        "leaf": proof["leaf"].hex(),
        "old_path": [p.hex() for p in proof["old_path"]],
        "new_path": [p.hex() for p in proof["new_path"]],
    }


def decode_consistency(wire: dict) -> dict:
    return {
        "old_size": int(wire["old_size"]),
        "new_size": int(wire["new_size"]),
        "leaf_index": int(wire["leaf_index"]),
        "leaf": bytes.fromhex(wire["leaf"]),
        "old_path": [bytes.fromhex(p) for p in wire["old_path"]],
        "new_path": [bytes.fromhex(p) for p in wire["new_path"]],
    }


def verify_consistency(old_size: int, new_size: int,
                       proof: dict, old_root: bytes,
                       new_root: bytes) -> bool:
    """Verify a consistency proof by folding the old and new inclusion paths
    of the public boundary leaf against the two independently trusted roots.
    Accepts the binary form or the hex wire form."""
    if not isinstance(proof, dict):
        return False
    if isinstance(proof.get("leaf"), str):
        try:
            proof = decode_consistency(proof)
        except Exception:
            return False
    m, n = old_size, new_size
    if m < 0 or n < m:
        return False
    if m == 0:
        return True
    if m == n:
        return old_root == new_root
    try:
        if proof.get("old_size") != m or proof.get("new_size") != n:
            return False
        if proof.get("leaf_index") != m - 1:
            return False
        leaf = proof["leaf"]
        old_path = proof["old_path"]
        new_path = proof["new_path"]
    except (KeyError, TypeError):
        return False
    if not (isinstance(leaf, bytes)
            and all(isinstance(x, bytes) for x in old_path + new_path)):
        return False
    if not verify_inclusion(leaf, m - 1, m, list(old_path), old_root):
        return False
    if not verify_inclusion(leaf, m - 1, n, list(new_path), new_root):
        return False
    return True
