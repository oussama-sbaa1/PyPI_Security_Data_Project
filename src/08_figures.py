"""Draw the report's figures from the CSV files in results/. No Spark needed."""
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

from config import FIGURES, RESULTS  # noqa: E402

SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
BLUE = "#2a78d6"
BAR_PT = 7.5     # bar thickness in points, about 20 px at this resolution
DPI = 200


def compact(x, _=None):
    x = float(x)
    if abs(x) >= 1e6:
        return f"{x / 1e6:g}M"
    if abs(x) >= 1e4:
        return f"{x / 1e3:g}K"
    return f"{x:,.0f}" if x >= 1 or x == 0 else f"{x:g}"


def figure(width, height, title, subtitle=None):
    fig, ax = plt.subplots(figsize=(width, height), dpi=DPI, facecolor=SURFACE)
    style(ax)
    fig.text(0.012, 0.975, title, fontsize=11.5, fontweight="bold", color=INK, va="top")
    if subtitle:
        fig.text(0.012, 0.975 - 0.34 / height, subtitle, fontsize=8.5, color=INK2, va="top")
    return fig, ax


def style(ax):
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(AXIS)
        ax.spines[side].set_linewidth(0.6)
    ax.tick_params(which="both", colors=MUTED, labelsize=8, length=0)
    ax.set_axisbelow(True)


def finish(fig, name, top=0.82, bottom=0.12, left=0.1, right=0.97):
    fig.subplots_adjust(top=top, bottom=bottom, left=left, right=right)
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURES / name, facecolor=SURFACE)
    plt.close(fig)
    print("wrote", name, flush=True)


def hbars(ax, labels, values, tips):
    """Thin horizontal bars from one baseline, rounded only at the data end, value at the tip."""
    y = list(range(len(labels)))[::-1]
    top = max(values)
    ax.hlines(y, 0, values, color=BLUE, linewidth=BAR_PT, capstyle="round")
    ax.set_xlim(0, top * 1.22)
    ax.set_ylim(-0.7, len(labels) - 0.3)
    ax.set_yticks(y, labels, color=INK2, fontsize=8.5)
    ax.spines["bottom"].set_visible(False)
    ax.set_xticks([])
    for yi, value, tip in zip(y, values, tips):
        ax.annotate(tip, (value, yi), xytext=(7, 0), textcoords="offset points", va="center", fontsize=8, color=INK2)


def left_for(labels):
    """Left margin that fits the longest bar label at this font size and figure width."""
    return min(0.45, 0.03 + 0.0098 * max(len(str(x)) for x in labels))


def read(path):
    p = RESULTS / path
    return pd.read_csv(p) if p.exists() else None


def fig_scale():
    d = read("part1/events_by_year.csv")
    d = d[d.year < 2027]
    fig, ax = figure(7.2, 3, "PyPI releases per year", "'new release' events in the changelog. 2026 stops at 6 November.")
    ax.vlines(d.year, 0, d.new_release, color=BLUE, linewidth=BAR_PT, capstyle="round")
    ax.set_ylim(0, d.new_release.max() * 1.15)
    ax.yaxis.set_major_formatter(FuncFormatter(compact))
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_xticks(d.year[::2], [str(y) for y in d.year[::2]])
    last = d.iloc[-1]
    ax.annotate(compact(last.new_release), (last.year, last.new_release), xytext=(0, 7), textcoords="offset points",
                ha="center", fontsize=8, color=INK2)
    finish(fig, "scale_releases_per_year.png", left=0.08)


def fig_malicious_hist():
    d = read("part1/malicious_lifetime_hist.csv")
    d["label"] = d.bin.str.split(" ", n=1).str[1]
    total = d["count"].sum()
    fig, ax = figure(7.2, 3.2, "How long malicious packages stay online",
                     f"From upload to the first quarantine or removal, {total:,} packages with both events in the log.")
    hbars(ax, d.label.tolist(), d["count"].tolist(), [f"{c:,}  ({100 * c / total:.0f}%)" for c in d["count"]])
    finish(fig, "malicious_lifetime.png", bottom=0.04, left=left_for(d.label))


def fig_malicious_year():
    d = read("part1/malicious_lifetime_by_year.csv")
    d = d[d.packages >= 20]
    fig, ax = figure(7.2, 3, "Median time online, by year of takedown",
                     "Years with at least 20 measured malicious packages. Log scale.")
    ax.plot(d.takedown_year, d.median_hours_online, color=BLUE, linewidth=1.6, marker="o", markersize=5,
            markeredgecolor=SURFACE, markeredgewidth=1.2, solid_capstyle="round")
    ax.set_yscale("log")
    ax.set_ylabel("hours", color=MUTED, fontsize=8)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x:g}"))
    ax.set_xticks(d.takedown_year, [str(y) for y in d.takedown_year])
    ax.margins(x=0.06, y=0.2)
    for _, row in pd.concat([d.iloc[[0, -1]], d.loc[[d.median_hours_online.idxmax()]]]).drop_duplicates("takedown_year").iterrows():
        ax.annotate(f"{row.median_hours_online:g} h", (row.takedown_year, row.median_hours_online), xytext=(0, 8),
                    textcoords="offset points", ha="center", fontsize=8, color=INK2)
    finish(fig, "malicious_by_year.png")


def fig_fix():
    d = read("part1/fix_status.csv")
    order = ["record over a year after the fix", "fix before disclosure", "fix within a week of disclosure", "fix 1-4 weeks after",
             "fix over 30 days after", "fix listed, version not on PyPI", "no fix listed"]
    d = d.set_index("fix_status").reindex(order).dropna().reset_index()
    d["count"] = d["count"].astype(int)
    total = d["count"].sum()
    fig, ax = figure(7.2, 3.1, "When the fix ships, relative to public disclosure",
                     f"{total:,} flaw-and-package pairs. Disclosure is the earliest date in any aliased advisory or NVD.")
    hbars(ax, d.fix_status.tolist(), d["count"].tolist(), [f"{c:,}  ({100 * c / total:.0f}%)" for c in d["count"]])
    finish(fig, "fix_timing.png", bottom=0.04, left=left_for(d.fix_status))


def fig_open():
    d = read("part1/open_by_severity.csv")
    d["label"] = d.band.str.split(" ", n=1).str[1]
    fig, ax = figure(7.2, 2.5, "Flaws still present in the version pip installs today",
                     "Share of each severity band on packages that are still on PyPI.")
    hbars(ax, d.label.tolist(), d.pct_open.tolist(), [f"{p:.0f}%  ({o:,} of {n:,})" for p, o, n in zip(d.pct_open, d.open_in_latest, d.flaws_on_live_packages)])
    finish(fig, "open_by_severity.png", top=0.78, bottom=0.04, left=left_for(d.label))


def fig_top_risk():
    d = read("part3/top_open_risk.csv").head(15)
    fig, ax = figure(7.2, 4.6, "Open flaws with the widest reach",
                     "Score = highest open severity x log reach. At the tip: transitive dependents, then CVSS.")
    hbars(ax, d.id.tolist(), d.risk_open.tolist(), [f"{r:,.0f} dependents, CVSS {s:g}" for r, s in zip(d.reach, d.max_open_severity)])
    ax.set_xlim(0, d.risk_open.max() * 1.45)
    finish(fig, "top_open_risk.png", top=0.87, bottom=0.03, left=left_for(d.id))


def fig_degree():
    d = read("part3/indegree_distribution.csv").sort_values("direct_dependents")
    d = d[d.direct_dependents > 0]
    total = d["count"].sum()
    ccdf = d["count"][::-1].cumsum()[::-1] / total
    fig, ax = figure(7.2, 3.1, "A few packages carry the dependency graph",
                     "Share of packages with at least N direct dependents, among packages that have any. Log-log.")
    ax.plot(d.direct_dependents, ccdf, color=BLUE, linewidth=1.6, solid_capstyle="round")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(color=GRID, linewidth=0.6)
    ax.xaxis.set_major_formatter(FuncFormatter(compact))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{100 * v:g}%"))
    ax.set_xlabel("direct dependents, N", color=MUTED, fontsize=8)
    finish(fig, "degree_distribution.png", bottom=0.16, left=0.1)


def fig_validation():
    d = read("part3/ranking_all.csv").dropna(subset=["dependentCount"])
    d = d[(d.reach > 0) & (d.dependentCount > 0)]
    v = read("part3/depsdev_validation.csv").iloc[0]
    fig, ax = figure(5.4, 4.2, "Our reach against deps.dev",
                     f"{len(d):,} packages with a flaw. Spearman {v.spearman_reach_vs_depsdev_all:.2f} over all {int(v.packages_compared):,} compared.")
    ax.scatter(d.dependentCount, d.reach, s=11, color=BLUE, alpha=0.45, linewidths=0)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(color=GRID, linewidth=0.6)
    ax.xaxis.set_major_formatter(FuncFormatter(compact))
    ax.yaxis.set_major_formatter(FuncFormatter(compact))
    ax.set_xlabel("deps.dev dependents of the default version", color=MUTED, fontsize=8)
    ax.set_ylabel("our transitive dependents", color=MUTED, fontsize=8)
    finish(fig, "reach_vs_depsdev.png", top=0.86, bottom=0.12, left=0.14)


def fig_watermark():
    d = read("part2/completeness.csv")
    d = d[d.run.str.startswith("watermark ")].copy()
    if d.empty:
        return
    d["label"] = d.run.str.replace("watermark ", "", regex=False)
    minutes = {"minutes": 1, "hour": 60, "hours": 60}
    d["m"] = d.label.str.extract(r"(\d+)")[0].astype(int) * d.label.str.extract(r"([a-z]+)")[0].map(minutes)
    d = d.sort_values("m")
    d["lost_pct"] = 100 - d.pct_complete
    fig, ax = figure(7.2, 2.8, "Events lost to the watermark",
                     "The same 10 days of hourly micro-batches with each watermark, against the batch count of the same hours.")
    hbars(ax, d.label.tolist(), d.lost_pct.tolist(), [f"{p:.3f}%  ({int(n):,} events)" for p, n in zip(d.lost_pct, d.lost_events)])
    ax.set_xlim(0, max(d.lost_pct.max() * 1.35, 0.01))
    finish(fig, "watermark_completeness.png", bottom=0.04, left=left_for(d.label))


def fig_state():
    names = [("activity", "Q1 hourly counts"), ("short_lived", "Q2 create + takedown"), ("new_maintainer", "Q3 maintainer + release")]
    frames = [(label, read(f"part2/progress_sink_replay_{q}.csv")) for q, label in names]
    if any(f is None or f.empty for _, f in frames):
        return
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.6), dpi=DPI, facecolor=SURFACE)
    fig.text(0.012, 0.975, "Watermarks keep streaming state bounded", fontsize=11.5, fontweight="bold", color=INK, va="top")
    fig.text(0.012, 0.87, "Rows held in the state store after each micro-batch of the replay.", fontsize=8.5, color=INK2, va="top")
    for ax, (label, f) in zip(axes, frames):
        style(ax)
        ax.plot(f.batch, f.state_rows, color=BLUE, linewidth=1.2)
        ax.set_title(label, fontsize=8.5, color=INK2, loc="left")
        ax.grid(axis="y", color=GRID, linewidth=0.6)
        ax.yaxis.set_major_formatter(FuncFormatter(compact))
        ax.set_ylim(0, None)
        ax.set_xlabel("micro-batch", color=MUTED, fontsize=8)
    fig.subplots_adjust(wspace=0.32)
    finish(fig, "stream_state.png", top=0.7, bottom=0.17, left=0.08)


def main():
    for draw in (fig_scale, fig_malicious_hist, fig_malicious_year, fig_fix, fig_open, fig_top_risk,
                 fig_degree, fig_validation, fig_watermark, fig_state):
        draw()


if __name__ == "__main__":
    main()
