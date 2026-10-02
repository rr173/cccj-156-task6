"""Command-line interface for the caller-facing transparency log.

    python3 -m kc.transparency_cli status    --root ./kc-data
    python3 -m kc.transparency_cli leaves    --root ./kc-data [--purpose p]
    python3 -m kc.transparency_cli inclusion --root ./kc-data --index N
    python3 -m kc.transparency_cli consistency --root ./kc-data --old-size M
    python3 -m kc.transparency_cli observe   --root ./kc-data --head head.json
    python3 -m kc.transparency_cli splits    --root ./kc-data
    python3 -m kc.transparency_cli resolve   --root ./kc-data --split sv-1 \\
                                   --accept <root> --reason "..." --by alice
    python3 -m kc.transparency_cli export    --root ./kc-data --out bundle.json
    python3 -m kc.transparency_cli verify    bundle.json [--keys keys.json]

`verify` is fully offline: it recomputes every root and checks lifecycle
legality from only the exported artifacts (plus optionally the exported
keys list, to catch an unregistered ACTIVE key).
"""

from __future__ import annotations

import argparse
import json
import sys

from . import transparency_verify as tv
from .errors import CeremonyError
from .storage import Store
from .transparency import TransparencyLog


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kc.transparency_cli")
    ap.add_argument("command",
                    choices=["status", "leaves", "inclusion", "consistency",
                             "observe", "splits", "resolve", "export",
                             "verify"])
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--purpose")
    ap.add_argument("--version", type=int)
    ap.add_argument("--audit-seq", type=int)
    ap.add_argument("--index", type=int)
    ap.add_argument("--old-size", type=int)
    ap.add_argument("--head")
    ap.add_argument("--observer", default="cli")
    ap.add_argument("--split")
    ap.add_argument("--accept")
    ap.add_argument("--reason")
    ap.add_argument("--by")
    ap.add_argument("--out")
    ap.add_argument("--keys")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_intermixed_args(argv)

    if a.command == "verify":
        path = a.paths[0] if a.paths else None
        if not path:
            ap.error("verify needs a bundle path")
        with open(path, encoding="utf-8") as f:
            bundle = json.load(f)
        keys = None
        if a.keys:
            with open(a.keys, encoding="utf-8") as f:
                keys = json.load(f)
        report = tv.verify_bundle(bundle, keys=keys, strict=False)
        print(json.dumps(report, indent=2, sort_keys=True))
        if report["ok"]:
            print(f"[PASS] transparency bundle verified: {report['checks']}")
            return 0
        print(f"[FAIL] {len(report['findings'])} finding(s):",
              file=sys.stderr)
        for fnd in report["findings"]:
            print(f"  - {fnd['code']}: {fnd['message']}", file=sys.stderr)
        return 1

    arc = TransparencyLog(Store(a.root))
    if a.command == "status":
        print(json.dumps(arc.status(), indent=2, sort_keys=True))
    elif a.command == "leaves":
        print(json.dumps({"matches": arc.find_leaves(
            purpose=a.purpose, version=a.version,
            audit_seq=a.audit_seq)}, indent=2, sort_keys=True))
    elif a.command == "inclusion":
        print(json.dumps(arc.inclusion_for_index(a.index), indent=2,
                         sort_keys=True))
    elif a.command == "consistency":
        print(json.dumps(arc.consistency(a.old_size), indent=2,
                         sort_keys=True))
    elif a.command == "splits":
        print(json.dumps({"split_views": arc.list_split_views()},
                         indent=2, sort_keys=True))
    elif a.command == "observe":
        with open(a.head, encoding="utf-8") as f:
            signed = json.load(f)
        print(json.dumps(arc.observe_head(signed, observer=a.observer),
                         indent=2, sort_keys=True))
    elif a.command == "resolve":
        out = arc.resolve_split(a.split, a.accept, a.reason, a.by)
        print(json.dumps(out, indent=2, sort_keys=True))
    elif a.command == "export":
        bundle = arc.export_bundle()
        text = json.dumps(bundle, indent=2, sort_keys=True)
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"exported transparency bundle -> {a.out}")
        else:
            print(text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CeremonyError as e:
        print(json.dumps({"error": str(e), "code": e.code}), file=sys.stderr)
        sys.exit(2)
