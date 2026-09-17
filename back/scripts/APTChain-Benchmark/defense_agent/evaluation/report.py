"""Report generation — per-scenario JSON + Markdown, global CSV/JSON."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def write_scenario_report(out_dir: Path, scenario: str, result: dict[str, Any],
                          log_metrics_dict: dict, pr_curve: list, storyline_dict: dict,
                          candidate_pr_dict: dict | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "detections.jsonl").open("w", encoding="utf-8") as fh:
        for d in result["detections"]:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    with (out_dir / "log_level_metrics.json").open("w", encoding="utf-8") as fh:
        json.dump(log_metrics_dict, fh, ensure_ascii=False, indent=2)
    with (out_dir / "pr_curve.json").open("w", encoding="utf-8") as fh:
        json.dump(pr_curve, fh, ensure_ascii=False, indent=2)
    with (out_dir / "storyline_level_metrics.json").open("w", encoding="utf-8") as fh:
        json.dump(storyline_dict, fh, ensure_ascii=False, indent=2)
    if candidate_pr_dict is not None:
        with (out_dir / "storyline_candidate_pr.json").open("w", encoding="utf-8") as fh:
            json.dump(candidate_pr_dict, fh, ensure_ascii=False, indent=2)
    with (out_dir / "cross_summary.json").open("w", encoding="utf-8") as fh:
        json.dump(result["cross_summary"], fh, ensure_ascii=False, indent=2)

    # Markdown summary
    md = build_md_summary(scenario, result, log_metrics_dict, pr_curve, storyline_dict, candidate_pr_dict)
    with (out_dir / "summary.md").open("w", encoding="utf-8") as fh:
        fh.write(md)


def build_md_summary(scenario: str, result: dict, log_dict: dict, pr_curve: list, storyline_dict: dict,
                     candidate_pr_dict: dict | None = None) -> str:
    lines = [f"# Detection Report: {scenario}", ""]
    stats = result["stats"]
    lines += [
        "## Detection Stats",
        "",
        f"- Total canonical events: **{stats['total']}**",
        f"- Malicious: **{stats['malicious']}** ({stats['malicious']/max(1,stats['total'])*100:.2f}%)",
        f"- Suspicious: **{stats['suspicious']}** ({stats['suspicious']/max(1,stats['total'])*100:.2f}%)",
        f"- Benign: **{stats['benign']}** ({stats['benign']/max(1,stats['total'])*100:.2f}%)",
        "",
        "### By source",
        "",
    ]
    for src, n in sorted(stats["by_source"].items(), key=lambda x: -x[1]):
        lines.append(f"- {src}: {n}")
    lines.append("")

    lines += ["## Task A — Log-level Precision / Recall / F1", ""]
    lines += [
        f"Default threshold = 0.2 (suspicious+malicious both count).",
        "",
        f"- TP = **{log_dict['tp']}**, FP = **{log_dict['fp']}**, FN = **{log_dict['fn']}**",
        f"- TN sample (benign, for FPR estimate) = {log_dict['tn_sample']}",
        f"- Precision = **{log_dict['precision']:.4f}**",
        f"- Recall    = **{log_dict['recall']:.4f}**",
        f"- F1        = **{log_dict['f1']:.4f}**",
        f"- FPR estimate = {log_dict['fpr_estimate']:.4f}",
        "",
        "### By GT kind (recall)",
        "",
        "| GT kind | TP | FN |",
        "|---------|----|----|",
    ]
    for k, v in sorted(log_dict["per_gt_kind"].items()):
        lines.append(f"| {k} | {v['tp']} | {v['fn']} |")
    lines.append("")
    lines += ["### By detection event type (precision)",
              "",
              "| Det event_type | TP | FP |",
              "|----------------|----|----|"]
    for k, v in sorted(log_dict["per_det_type"].items()):
        lines.append(f"| {k} | {v['tp']} | {v['fp']} |")
    lines.append("")

    lines += ["### PR Curve", "",
              "| Threshold | Precision | Recall | F1 | TP | FP | FN |",
              "|-----------|-----------|--------|----|----|----|----|"]
    for row in pr_curve:
        lines.append(f"| {row['threshold']:.1f} | {row['precision']:.4f} | {row['recall']:.4f} | {row['f1']:.4f} | {row['tp']} | {row['fp']} | {row['fn']} |")
    lines.append("")

    lines += ["## Task B — Storyline-level", ""]
    lines += [
        f"- Storylines (observable): **{storyline_dict['storyline_total']}**",
        f"- Detected: **{storyline_dict['storyline_detected']}** ({storyline_dict['storyline_detection_rate']*100:.1f}%)",
        f"- Avg step coverage: **{storyline_dict['avg_step_coverage']:.4f}**",
        f"- Order preservation (LCS): **{storyline_dict['order_score']:.4f}**",
        f"- Storyline P/R/F1 (GT-side only): P={storyline_dict['storyline_prf']['precision']:.4f}, R={storyline_dict['storyline_prf']['recall']:.4f}, F1={storyline_dict['storyline_prf']['f1']:.4f}",
        "",
    ]
    if candidate_pr_dict is not None:
        lines += [
            "### Task B — Candidate-side PR (multi-step correlation)",
            "",
            f"- Candidates emitted by detector: **{candidate_pr_dict['candidates']}**",
            f"- Matched a GT storyline: **{candidate_pr_dict['matched']}**",
            f"- Unmatched (FP — no GT storylines overlap): **{candidate_pr_dict['unmatched']}**",
            f"- GT observable storylines: **{candidate_pr_dict['gt_total']}**",
            f"- GT matched (recall numerator): **{candidate_pr_dict['gt_matched']}**",
            f"- **Precision = {candidate_pr_dict['precision']:.4f}**, Recall = {candidate_pr_dict['recall']:.4f}, F1 = {candidate_pr_dict['f1']:.4f}",
            "",
            "Sample unmatched candidates (likely false positives):",
            "",
        ]
        for c in candidate_pr_dict.get("unmatched_candidates_sample", [])[:5]:
            lines.append(f"- {c['candidate_id']} ({c['source']}) host={c['host']} events={c['n_events']} first={c['first']}")
        lines.append("")

    lines += ["### Per-storyline (GT-side)",
              "",
              "| Storyline ID | Detected | Coverage | Observable | Matched |",
              "|--------------|----------|----------|------------|---------|"]
    for sid in sorted(storyline_dict["per_storyline"].keys()):
        v = storyline_dict["per_storyline"][sid]
        lines.append(f"| {sid} | {'Y' if v['detected'] else 'N'} | {v['coverage']:.2f} | {v['observable_events']} | {v['matched_events']} |")
    lines.append("")

    cs = result["cross_summary"]
    lines += ["## Cross-event signals", "",
              f"- Beacons detected: {len(cs['beacons'])}",
              f"- Lateral movement candidates: {len(cs['lateral_movement'])}",
              f"- Credential dumping chains: {len(cs['credential_dumping'])}",
              ""]
    if cs["beacons"]:
        lines.append("### Top beacons")
        for b in cs["beacons"][:5]:
            lines.append(f"- {b['src_ip']} → {b['dst_ip']}:{b['dst_port']} ({b['attempts']} attempts, mean {b['mean_interval']}s, jitter {b['jitter_cv']})")
    if cs["lateral_movement"]:
        lines.append("### Lateral movement candidates")
        for l in cs["lateral_movement"][:5]:
            lines.append(f"- user={l['user']} hosts={l['hosts']} first={l['first']}")
    if cs["credential_dumping"]:
        lines.append("### Credential dumping chains")
        for c in cs["credential_dumping"][:5]:
            lines.append(f"- host={c['host']} user={c['user']} lsass@{c['lsass_at']} → explicit_cred@{c['explicit_credential_at']}")

    return "\n".join(lines) + "\n"


def write_global_report(global_dir: Path, per_scenario: list[dict]) -> None:
    """per_scenario: list of {scenario, log_dict, pr_curve, storyline_dict, candidate_pr_dict}."""
    global_dir.mkdir(parents=True, exist_ok=True)

    # CSV
    csv_path = global_dir / "all_scenarios.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "scenario",
            "log_tp", "log_fp", "log_fn",
            "log_precision", "log_recall", "log_f1",
            "storyline_total", "storyline_detected", "storyline_detection_rate",
            "avg_step_coverage", "order_score",
            "cand_emitted", "cand_matched", "cand_unmatched",
            "cand_precision", "cand_recall", "cand_f1",
            "cross_beacons", "cross_lateral", "cross_cred_dumping",
        ])
        for row in per_scenario:
            cpr = row.get("candidate_pr_dict", {}) or {}
            w.writerow([
                row["scenario"],
                row["log_dict"]["tp"], row["log_dict"]["fp"], row["log_dict"]["fn"],
                row["log_dict"]["precision"], row["log_dict"]["recall"], row["log_dict"]["f1"],
                row["storyline_dict"]["storyline_total"], row["storyline_dict"]["storyline_detected"], row["storyline_dict"]["storyline_detection_rate"],
                row["storyline_dict"]["avg_step_coverage"], row["storyline_dict"]["order_score"],
                cpr.get("candidates", 0), cpr.get("matched", 0), cpr.get("unmatched", 0),
                cpr.get("precision", 0), cpr.get("recall", 0), cpr.get("f1", 0),
                row["cross_counts"]["beacons"], row["cross_counts"]["lateral"], row["cross_counts"]["cred_dumping"],
            ])

    # JSON
    with (global_dir / "all_scenarios.json").open("w", encoding="utf-8") as fh:
        json.dump(per_scenario, fh, ensure_ascii=False, indent=2)

    # Markdown
    md_lines = ["# Global Detection Report", ""]
    md_lines += [
        "Aggregated metrics across all scenarios.",
        "",
        "## Task A — log-level (single-log detection)",
        "",
        "| Scenario | TP | FP | FN | Precision | Recall | F1 |",
        "|----------|----|----|----|-----------|--------|----|",
    ]
    for row in per_scenario:
        ld = row["log_dict"]
        md_lines.append(
            f"| {row['scenario']} | {ld['tp']} | {ld['fp']} | {ld['fn']} | "
            f"{ld['precision']:.3f} | {ld['recall']:.3f} | {ld['f1']:.3f} |"
        )
    md_lines += [
        "",
        "## Task B — storyline-level (multi-step correlation)",
        "",
        "Two complementary views:",
        "- **GT-side**: among observable GT storylines, how many had ≥1 event detected (no FP possible, recall only).",
        "- **Cand-side**: among candidates the detector emitted (beacons + lateral + cred-dump + rule clusters), how many line up with a GT storyline (precision + recall).",
        "",
        "### GT-side",
        "",
        "| Scenario | Detected | Coverage | Order |",
        "|----------|----------|----------|-------|",
    ]
    for row in per_scenario:
        sd = row["storyline_dict"]
        md_lines.append(
            f"| {row['scenario']} | {sd['storyline_detected']}/{sd['storyline_total']} | "
            f"{sd['avg_step_coverage']:.2f} | {sd['order_score']:.2f} |"
        )
    md_lines += [
        "",
        "### Candidate-side (real PR)",
        "",
        "| Scenario | Candidates | Matched | Unmatched (FP) | GT Total | GT Matched | Precision | Recall | F1 |",
        "|----------|------------|---------|----------------|----------|------------|-----------|--------|-----|",
    ]
    for row in per_scenario:
        cpr = row.get("candidate_pr_dict", {}) or {}
        md_lines.append(
            f"| {row['scenario']} | {cpr.get('candidates', 0)} | {cpr.get('matched', 0)} | "
            f"{cpr.get('unmatched', 0)} | {cpr.get('gt_total', 0)} | {cpr.get('gt_matched', 0)} | "
            f"{cpr.get('precision', 0):.3f} | {cpr.get('recall', 0):.3f} | {cpr.get('f1', 0):.3f} |"
        )

    with (global_dir / "report.md").open("w", encoding="utf-8") as fh:
        fh.write("\n".join(md_lines) + "\n")