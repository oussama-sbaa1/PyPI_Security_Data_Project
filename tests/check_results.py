"""Check Spark's results by a different route. Run after the pipeline:  python tests/check_results.py

Each check recomputes a number with plain pandas and scipy on the gold tables, without Spark:
  1. direct dependents and transitive reach, by an independent breadth-first search;
  2. 'open' flaws: the latest version really is on the flaw's affected list;
  3. locked dependents: the version-range logic, on the links Spark called locked;
  4. the streaming totals against the batch truth.
The verdict for each check is printed and saved to results/verification.csv.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy.sparse import csr_matrix  # noqa: E402
from scipy.sparse.csgraph import breadth_first_order  # noqa: E402

from config import GOLD, RESULTS, SILVER  # noqa: E402
from depparse import allowed_versions  # noqa: E402

rows = []


def verdict(check, compared, failures, note=""):
    rows.append({"check": check, "compared": compared, "failures": failures, "note": note})
    print(f"{'PASS' if failures == 0 else 'FAIL'}  {check}: {compared:,} compared, {failures:,} wrong. {note}", flush=True)


def check_reach():
    edges = pd.read_parquet(GOLD / "edges", columns=["src", "dst"])
    rank = pd.read_parquet(GOLD / "ranking.parquet", columns=["id", "reach", "direct_dependents"])
    names = pd.Index(pd.unique(edges[["src", "dst"]].values.ravel()))
    code = pd.Series(np.arange(len(names)), index=names)
    src, dst = code[edges.src].to_numpy(), code[edges.dst].to_numpy()
    # Edges reversed: walking from a package along them visits everything that depends on it.
    reverse = csr_matrix((np.ones(len(src), dtype=bool), (dst, src)), shape=(len(names), len(names)))

    linked = rank[rank.id.isin(names)]
    direct = pd.Series(edges.groupby("dst").size()).reindex(linked.id).fillna(0).astype(int).to_numpy()
    verdict("direct dependents vs edge count", len(linked), int((direct != linked.direct_dependents.to_numpy()).sum()))

    # The 100 widest packages plus 200 chosen at random across the rest.
    top = linked.nlargest(100, "reach")
    rest = linked.drop(top.index)
    sample = pd.concat([top, rest.sample(min(200, len(rest)), random_state=42)])
    wrong = 0
    for row in sample.itertuples():
        order = breadth_first_order(reverse, code[row.id], directed=True, return_predecessors=False)
        if len(order) - 1 != row.reach:
            wrong += 1
            print("   reach differs:", row.id, "spark", row.reach, "bfs", len(order) - 1, flush=True)
    verdict("transitive reach vs independent BFS", len(sample), wrong, "top 100 by reach and 200 random")


def check_open():
    status = pd.read_parquet(GOLD / "flaw_status", columns=["package", "latest_version", "affected_versions", "is_open"])
    wrong = 0
    for row in status.itertuples():
        listed = row.affected_versions is not None and row.latest_version in set(row.affected_versions)
        wrong += int(listed != bool(row.is_open))
    verdict("open flag vs affected list", len(status), wrong)


def check_locked():
    locked = pd.read_parquet(GOLD / "locked_edges", columns=["src", "dst", "cluster_id"])
    if locked.empty:
        return
    picked = locked.sample(min(2000, len(locked)), random_state=42)
    edges = pd.read_parquet(GOLD / "edges", columns=["src", "dst", "spec"])
    flaws = pd.read_parquet(SILVER / "flaw_package", columns=["cluster_id", "package", "affected_versions"]).rename(columns={"package": "dst"})
    versions = pd.read_parquet(SILVER / "projects", columns=["package", "all_versions"]).rename(columns={"package": "dst"})
    joined = picked.merge(edges, on=["src", "dst"]).merge(flaws, on=["cluster_id", "dst"]).merge(versions, on="dst")
    wrong = 0
    for row in joined.itertuples():
        allowed = allowed_versions(row.spec, list(row.all_versions))
        if not allowed or not set(allowed) <= set(row.affected_versions):
            wrong += 1
    verdict("locked links vs version-range logic", len(joined), wrong, "2,000 random locked links")


def check_stream():
    path = RESULTS / "part2" / "completeness.csv"
    if not path.exists():
        return
    t = pd.read_csv(path)
    verdict("stream windows above the batch count", int(t.window_rows.sum()), int(t.window_rows_above_truth.sum()),
            "a stream can lose late events, but it must never count more than batch")
    replay = t[t.run.str.startswith("replay")]
    if len(replay):
        r = replay.iloc[0]
        print(f"      replay completeness: {r.pct_complete}% ({int(r.lost_events):,} of {int(r.truth_events):,} events lost)", flush=True)


def main():
    random.seed(42)
    check_reach()
    check_open()
    check_locked()
    check_stream()
    pd.DataFrame(rows).to_csv(RESULTS / "verification.csv", index=False, lineterminator="\n")
    if any(r["failures"] for r in rows):
        sys.exit("Some checks failed, see above.")
    print("all result checks passed")


if __name__ == "__main__":
    main()
