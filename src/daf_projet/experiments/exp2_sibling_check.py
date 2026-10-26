"""Sensitivity check for Experiment 2: purge sibling families too.

In the fine-grained label set, ``LDAP`` and ``DrDoS_LDAP`` are different
labels but the same attack mechanism.  The headline LOADO run purges only the
held-out label.  This supplementary check purges both labels of a pair, which
is the stricter definition of "unseen mechanism".  It is not part of the 99-fit
grid; it tests whether the headline binary scores survive when the sibling is
removed.
"""

from __future__ import annotations

import argparse

import pandas as pd

from ..data import BENIGN, split, subsample
from .common import RESULTS_DIR, ensure_dirs, fit_and_score, load_deduped, make_models, metrics_row
from .exp2_loado import _balanced_test


def main(args: argparse.Namespace) -> int:
    ensure_dirs()
    X, y_family, _, _ = load_deduped(args.data_dir)
    pairs = [
        ("LDAP", ["LDAP", "DrDoS_LDAP"]),
        ("DrDoS_LDAP", ["DrDoS_LDAP", "LDAP"]),
        ("MSSQL", ["MSSQL", "DrDoS_MSSQL"]),
        ("DrDoS_MSSQL", ["DrDoS_MSSQL", "MSSQL"]),
        ("UDP", ["UDP", "DrDoS_UDP"]),
        ("DrDoS_UDP", ["DrDoS_UDP", "UDP"]),
    ]

    rows = []
    for target, purge_labels in pairs:
        held = y_family == target
        if not held.any():
            continue
        keep = ~y_family.isin(purge_labels)
        X_pool = X.loc[keep].reset_index(drop=True)
        y_pool = y_family.loc[keep].reset_index(drop=True)
        held_X = X.loc[held].reset_index(drop=True)
        held_y = y_family.loc[held].reset_index(drop=True)

        X_train, X_test, y_train, y_test = split(X_pool, y_pool, seed=args.seed)
        X_train, y_train = subsample(X_train, y_train, cap=args.cap, seed=args.seed)
        y_binary_train = (y_train != BENIGN).astype("int8")
        X_eval, y_eval, _, _ = _balanced_test(
            held_X, held_y, X_test, y_test, args.seed
        )
        pipeline = make_models(seed=args.seed, names=["random_forest"])["random_forest"]
        result = fit_and_score(pipeline, X_train, y_binary_train, X_eval, y_eval)
        metrics = result["metrics"]
        rows.append(
            metrics_row(
                metrics,
                target_family=target,
                purged_labels=", ".join(purge_labels),
                seed=args.seed,
                n_test_heldout=int(y_eval.sum()),
                n_test_benign=int((y_eval == 0).sum()),
                recall_target=float(metrics["per_class"].loc[1, "recall"]),
                fpr=float(metrics["fpr"]),
            )
        )
        print(
            f"{target:14s} purge={purge_labels!s:35s} "
            f"macro-F1={metrics['macro_f1']:.4f} recall={rows[-1]['recall_target']:.4f}"
        )

    out = pd.DataFrame(rows)
    out.to_csv(RESULTS_DIR / "exp2_sibling_check.csv", index=False)
    print(f"wrote {RESULTS_DIR / 'exp2_sibling_check.csv'}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cap", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=42)
    raise SystemExit(main(parser.parse_args()))
