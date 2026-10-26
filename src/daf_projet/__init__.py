"""DAF-Projet: DDoS detection and generalisation to unseen attacks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _smoke(args: argparse.Namespace) -> int:
    import numpy as np
    import pandas as pd
    import sklearn

    from .data import DropConstantFeatures, dedupe, load_dataset, split

    X, y_family, y_binary, meta = load_dataset(args.data_dir)
    X_deduped, y_deduped = dedupe(X, y_family)
    X_train, X_test, y_train, y_test = split(X_deduped, y_deduped, seed=args.seed)

    dropper = DropConstantFeatures().fit(X_train)
    print(f"sklearn        {sklearn.__version__}")
    print(f"pandas         {pd.__version__}")
    print(f"numpy          {np.__version__}")
    print(f"raw rows       {len(X):,}  features {X.shape[1]}")
    print(f"deduped rows   {len(X_deduped):,}  removed {len(X) - len(X_deduped):,}")
    print(f"dedupe stats   {X_deduped.attrs.get('dedupe')}")
    print(f"train / test   {len(X_train):,} / {len(X_test):,}")
    print(f"constant cols  {len(dropper.constant_features_)}")
    print(f"  {dropper.constant_features_}")
    print(f"families       {y_family.nunique()}")
    print(f"src_file in meta: {'src_file' in meta.columns}")
    print("\nfamily counts (deduped):")
    print(y_deduped.value_counts().to_string())
    binary_deduped = (y_deduped != "Benign").astype(int)
    print("\nbinary counts (deduped):")
    print(binary_deduped.map({0: "Benign", 1: "DDoS"}).value_counts().to_string())
    print("\ntest class counts:")
    print(y_test.value_counts().to_string())
    return 0


def _run_experiment(module_name: str, args: argparse.Namespace) -> int:
    from importlib import import_module

    module = import_module(f".experiments.{module_name}", package=__name__)
    return int(module.main(args))


def _baseline(args: argparse.Namespace) -> int:
    return _run_experiment("baseline", args)


def _exp1(args: argparse.Namespace) -> int:
    return _run_experiment("exp1_binary_vs_multi", args)


def _exp2(args: argparse.Namespace) -> int:
    return _run_experiment("exp2_loado", args)


def _exp3(args: argparse.Namespace) -> int:
    return _run_experiment("exp3_features", args)


def _sibling(args: argparse.Namespace) -> int:
    return _run_experiment("exp2_sibling_check", args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="daf-projet", description="DDoS detection experiments"
    )
    subparsers = parser.add_subparsers(dest="command")

    smoke = subparsers.add_parser("smoke", help="load data and print audit summary")
    smoke.add_argument("--data-dir", type=Path, default=None)
    smoke.add_argument("--seed", type=int, default=42)
    smoke.set_defaults(func=_smoke)

    baseline = subparsers.add_parser("baseline", help="run Phase 2 baselines")
    baseline.add_argument("--data-dir", type=Path, default=None)
    baseline.add_argument("--seed", type=int, default=42)
    baseline.add_argument("--cap", type=int, default=None)
    baseline.set_defaults(func=_baseline)

    exp1 = subparsers.add_parser("exp1", help="binary vs multiclass")
    exp1.add_argument("--data-dir", type=Path, default=None)
    exp1.add_argument("--seed", type=int, default=42)
    exp1.add_argument("--cap", type=int, default=None)
    exp1.set_defaults(func=_exp1)

    exp2 = subparsers.add_parser("exp2", help="leave-one-attack-out")
    exp2.add_argument("--data-dir", type=Path, default=None)
    exp2.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    exp2.add_argument("--models", nargs="+", default=None)
    exp2.add_argument("--min-rows", type=int, default=1_000)
    exp2.add_argument("--cap", type=int, default=None)
    exp2.set_defaults(func=_exp2)

    exp3 = subparsers.add_parser("exp3", help="feature reduction")
    exp3.add_argument("--data-dir", type=Path, default=None)
    exp3.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    exp3.add_argument("--cap", type=int, default=20_000)
    exp3.set_defaults(func=_exp3)

    sibling = subparsers.add_parser(
        "sibling", help="E2 sensitivity: purge sibling labels too"
    )
    sibling.add_argument("--data-dir", type=Path, default=None)
    sibling.add_argument("--seed", type=int, default=42)
    sibling.add_argument("--cap", type=int, default=20_000)
    sibling.set_defaults(func=_sibling)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
