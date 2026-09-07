import argparse
import csv
import math
import statistics
from pathlib import Path

import matplotlib.pyplot as plt

COMMAND_NAMES = {
    0x00000131: "CreatePrimary",
    0x00000147: "ActivateCredential",
    0x00000151: "PolicySecret",
    0x00000158: "Quote",
    0x00000168: "MakeCredential",
    0x00000176: "StartAuthSession",
    0x0000017B: "GetRandom",
    0x0000017E: "PCR_Read",
}

PAPER_OPERATIONS = [
    ("EK_CREATE", "EK Create"),
    ("AK_CREATE", "AK Create"),
    ("MAKE_CREDENTIAL", "MakeCredential"),
    ("ACTIVATE_CREDENTIAL", "ActivateCredential"),
    ("QUOTE", "Quote"),
]

BREAKDOWN_OPERATIONS = [
    ("AK_CREATE", "AK Create"),
    ("ACTIVATE_CREDENTIAL", "ActivateCredential"),
    ("QUOTE", "Quote"),
]

PAYLOAD_FIELDS = [
    ("ek_public_bytes", "EK Public"),
    ("ak_public_bytes", "AK Public"),
    ("credential_secret_bytes", "Credential Secret"),
    ("quote_signature_bytes", "Quote Signature"),
    ("attestation_response_bytes", "Attestation Response"),
]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def as_int(value: str) -> int:
    return int(value, 0)


def percentile(values: list[float], q: float) -> float:
    values = sorted(values)

    if not values:
        return math.nan

    if len(values) == 1:
        return values[0]

    pos = (len(values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return values[lo]

    weight = pos - lo

    return values[lo] * (1.0 - weight) + values[hi] * weight


def describe_ns(values: list[int]) -> dict[str, float | int]:
    us = [v / 1000.0 for v in values]
    return {
        "n": len(us),
        "mean_us": statistics.fmean(us),
        "median_us": statistics.median(us),
        "sd_us": statistics.pstdev(us),
        "p95_us": percentile(us, 0.95),
    }


def delta_pct(rsa: float, pq: float) -> float:
    return ((pq - rsa) / rsa) * 100.0 if rsa else math.nan


def alignment_key(row: dict[str, str]) -> tuple[int, int, int, int]:
    return (
        as_int(row["command_code"]),
        int(row["request_bytes"]),
        int(row["response_bytes"]),
        as_int(row["response_code"]),
    )


def align_client_server(client: list[dict[str, str]], server: list[dict[str, str]]) -> list[dict]:
    """Match measured client commands to fwTPM commands.

    fwTPM also records setup, warm-up and cleanup commands. Matching backwards
    by command code + request/response sizes + response code selects the final
    measured client runs while preserving command order.
    """
    server_index = len(server) - 1
    pairs: list[tuple[dict[str, str], dict[str, str]]] = []

    for c in reversed(client):
        wanted = alignment_key(c)
        while server_index >= 0 and alignment_key(server[server_index]) != wanted:
            server_index -= 1
        if server_index < 0:
            raise RuntimeError(
                f"Could not align run={c.get('run')} phase={c.get('phase')} " f"command={c.get('command_code')}"
            )
        pairs.append((c, server[server_index]))
        server_index -= 1

    pairs.reverse()
    merged: list[dict] = []

    for c, s in pairs:
        client_ns = int(c["rtt_ns"])
        internal_ns = int(s["internal_ns"])
        outside_ns = client_ns - internal_ns
        if outside_ns < 0:
            raise RuntimeError(
                "Internal fwTPM time exceeded the containing client RTT; "
                "client/server traces are probably mismatched."
            )
        code = as_int(c["command_code"])
        merged.append(
            {
                "run": int(c["run"]),
                "phase": c["phase"],
                "command_code": code,
                "command_name": COMMAND_NAMES.get(code, f"0x{code:08x}"),
                "client_ns": client_ns,
                "internal_ns": internal_ns,
                "outside_ns": outside_ns,
            }
        )
    return merged


def summarize_profile(profile: str, rows: list[dict]) -> list[dict]:
    output: list[dict] = []

    for phase, label in PAPER_OPERATIONS:
        selected = [r for r in rows if r["phase"] == phase]
        if not selected:
            raise RuntimeError(f"No rows for {profile}:{phase}")
        client = describe_ns([r["client_ns"] for r in selected])
        internal = describe_ns([r["internal_ns"] for r in selected])
        outside = describe_ns([r["outside_ns"] for r in selected])
        output.append(
            {
                "profile": profile,
                "phase": phase,
                "operation": label,
                "command": selected[0]["command_name"],
                "n": client["n"],
                "client_mean_us": client["mean_us"],
                "client_median_us": client["median_us"],
                "client_sd_us": client["sd_us"],
                "client_p95_us": client["p95_us"],
                "internal_mean_us": internal["mean_us"],
                "internal_median_us": internal["median_us"],
                "internal_p95_us": internal["p95_us"],
                "outside_mean_us": outside["mean_us"],
                "internal_share_pct": internal["mean_us"] / client["mean_us"] * 100.0,
            }
        )
    return output


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: float, digits: int = 1) -> str:
    return f"{value:.{digits}f}"


def analyze_application(raw_root: Path) -> list[dict]:
    rows_by_profile = {p: read_csv(raw_root / p / "client_runs.csv") for p in ("rsa", "pq")}
    result: list[dict] = []

    for metric, field in (("Verifier", "verifier_ns"), ("Gesamtflow", "full_flow_ns")):
        stats = {}
        for profile in ("rsa", "pq"):
            values = [int(r[field]) for r in rows_by_profile[profile]]
            stats[profile] = describe_ns(values)
        result.append(
            {
                "metric": metric,
                "rsa_mean_us": stats["rsa"]["mean_us"],
                "rsa_median_us": stats["rsa"]["median_us"],
                "pq_mean_us": stats["pq"]["mean_us"],
                "pq_median_us": stats["pq"]["median_us"],
                "delta_pct": delta_pct(stats["rsa"]["mean_us"], stats["pq"]["mean_us"]),
            }
        )

    return result


def analyze_payloads(raw_root: Path) -> list[dict]:
    metadata = {p: read_csv(raw_root / p / "client_metadata.csv")[0] for p in ("rsa", "pq")}
    result = []

    for field, label in PAYLOAD_FIELDS:
        rsa = int(metadata["rsa"][field])
        pq = int(metadata["pq"][field])
        result.append(
            {
                "object": label,
                "rsa_bytes": rsa,
                "pq_bytes": pq,
                "pq_over_rsa": pq / rsa,
            }
        )

    return result


def make_comparison(performance: list[dict]) -> list[dict]:
    by_key = {(r["profile"], r["phase"]): r for r in performance}
    rows = []

    for phase, label in PAPER_OPERATIONS:
        rsa = by_key[("rsa", phase)]
        pq = by_key[("pq", phase)]
        rows.append(
            {
                "operation": label,
                "rsa_client_mean_us": rsa["client_mean_us"],
                "pq_client_mean_us": pq["client_mean_us"],
                "client_delta_pct": delta_pct(rsa["client_mean_us"], pq["client_mean_us"]),
                "rsa_internal_mean_us": rsa["internal_mean_us"],
                "pq_internal_mean_us": pq["internal_mean_us"],
                "internal_delta_pct": delta_pct(rsa["internal_mean_us"], pq["internal_mean_us"]),
                "rsa_outside_mean_us": rsa["outside_mean_us"],
                "pq_outside_mean_us": pq["outside_mean_us"],
            }
        )

    return rows


def plot_breakdown(path: Path, comparison: list[dict]) -> None:
    lookup = {r["operation"]: r for r in comparison}
    labels = []
    internal = []
    outside = []

    for _, label in BREAKDOWN_OPERATIONS:
        row = lookup[label]
        for profile in ("RSA", "PQ"):
            prefix = profile.lower()
            labels.append(f"{label} ({profile})")
            internal.append(row[f"{prefix}_internal_mean_us"])
            outside.append(row[f"{prefix}_outside_mean_us"])

    positions = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(6.8, 3.7))
    ax.barh(positions, internal, label="fwTPM intern")
    ax.barh(positions, outside, left=internal, label="außerhalb fwTPM")
    ax.set_xlabel("Mittlere Laufzeit [µs]")
    ax.set_yticks(positions, labels)
    ax.invert_yaxis()
    ax.legend(frameon=False)
    ax.grid(axis="x", alpha=0.25)
    fig.tight_layout()
    fig.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
    fig.savefig(path.with_suffix(".png"), dpi=220, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze RSA/PQ wolfTPM benchmark CSV files")
    parser.add_argument("--results", type=Path, default=Path("results"))
    args = parser.parse_args()
    results = args.results.resolve()
    raw = results / "raw"
    out = results / "analysis"
    out.mkdir(parents=True, exist_ok=True)
    merged = {}
    performance: list[dict] = []

    for profile in ("rsa", "pq"):
        client = read_csv(raw / profile / "client_transport.csv")
        server = read_csv(raw / profile / "fwtpm_internal.csv")
        merged[profile] = align_client_server(client, server)
        performance.extend(summarize_profile(profile, merged[profile]))

    comparison = make_comparison(performance)
    application = analyze_application(raw)
    payloads = analyze_payloads(raw)

    write_csv(out / "performance.csv", performance)
    write_csv(out / "comparison.csv", comparison)
    write_csv(out / "application.csv", application)
    write_csv(out / "payload_sizes.csv", payloads)

    plot_breakdown(out / "latency_breakdown", comparison)

    print(f"analysis: {out}")
    print("  performance.csv")
    print("  comparison.csv")
    print("  application.csv")
    print("  payload_sizes.csv")
    print("  latency_breakdown.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
