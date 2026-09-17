"""Task A — log-level precision / recall / F1.

For each GT event, check whether any aligned detection was marked
malicious (>=threshold score). If yes → TP. If no → FN.

For each detection not aligned to any GT event that is marked
malicious/suspicious → FP.

True-Negatives (benign detections not aligned to GT) are estimated via sampling.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .align import align_all, observable_events


@dataclass
class LogLevelMetrics:
    scenario: str
    tp: int
    fp: int
    fn: int
    tn_sample: int
    precision: float
    recall: float
    f1: float
    fpr: float
    per_gt_kind: dict[str, dict[str, int]]  # TP/FN broken down by GT kind
    per_det_type: dict[str, dict[str, int]]  # TP/FP broken down by detection event_type
    observable_total: int
    matched_records: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn_sample": self.tn_sample,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr_estimate": round(self.fpr, 4),
            "per_gt_kind": self.per_gt_kind,
            "per_det_type": self.per_det_type,
            "observable_total": self.observable_total,
            "matched_records": self.matched_records,
        }


def _safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def compute_pr_curve(scenario: str, detections: list[dict], gt: dict,
                     thresholds: list[float] | None = None) -> list[dict[str, float]]:
    """Compute precision/recall/F1 across multiple score thresholds."""
    if thresholds is None:
        thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    out = []
    for t in thresholds:
        m = compute_log_level(scenario, detections, gt, malicious_threshold=t)
        out.append({
            "threshold": t,
            "tp": m.tp,
            "fp": m.fp,
            "fn": m.fn,
            "precision": round(m.precision, 4),
            "recall": round(m.recall, 4),
            "f1": round(m.f1, 4),
        })
    return out


def compute_log_level(scenario: str, detections: list[dict], gt: dict, malicious_threshold: float = 0.2,
                      tn_sample_size: int = 5000) -> LogLevelMetrics:
    aligned = align_all(detections, gt)
    obs = observable_events(gt)

    gt_events = gt.get("events", [])
    gt_systems = {g.get("system") for g in gt_events if g.get("system")}
    gt_storyline_systems = {g.get("storyline_id"): g.get("system") for g in gt_events if g.get("storyline_id")}

    per_gt_tp: Counter = Counter()
    per_gt_fn: Counter = Counter()
    per_det_tp: Counter = Counter()
    per_det_fp: Counter = Counter()
    tp = 0
    fn = 0
    matched_records = 0

    # TP / FN
    for g in gt_events:
        rid = g["record_id"]
        gt_kind = g.get("kind", "unknown")
        if rid not in obs:
            continue
        matches = aligned.get(rid, [])
        hit = any(d.get("score", 0) >= malicious_threshold for d in matches) if matches else False
        if hit:
            tp += 1
            per_gt_tp[gt_kind] += 1
            matched_records += 1
            for d in matches:
                if d.get("score", 0) >= malicious_threshold:
                    per_det_tp[d.get("event_type", "unknown")] += 1
        else:
            fn += 1
            per_gt_fn[gt_kind] += 1

    # Build set of detection dicts that are TP (used to skip them in FP calc)
    tp_det_set: set[int] = set()
    for rid, matches in aligned.items():
        for d in matches:
            if d.get("score", 0) >= malicious_threshold:
                tp_det_set.add(id(d))

    # FP: detections marked malicious/suspicious on in-scope systems not aligned to any GT event
    fp = 0
    for d in detections:
        if d.get("score", 0) < malicious_threshold:
            continue
        if id(d) in tp_det_set:
            continue
        # Restrict to in-scope systems (those present in GT)
        host = d.get("host", "")
        in_scope = any(_host_matches(host, sysname) for sysname in gt_systems if sysname)
        if not in_scope:
            continue
        fp += 1
        per_det_fp[d.get("event_type", "unknown")] += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    # TN estimate via sampling benign detections
    benign = [d for d in detections if d.get("verdict") == "benign"]
    tn_sample = min(tn_sample_size, len(benign))
    sample = benign[:tn_sample]

    fpr = _safe_div(fp, fp + tn_sample) if tn_sample else 0.0

    per_gt_kind = {}
    for k in set(per_gt_tp) | set(per_gt_fn):
        per_gt_kind[k] = {"tp": per_gt_tp.get(k, 0), "fn": per_gt_fn.get(k, 0)}
    per_det_type = {}
    for k in set(per_det_tp) | set(per_det_fp):
        per_det_type[k] = {"tp": per_det_tp.get(k, 0), "fp": per_det_fp.get(k, 0)}

    return LogLevelMetrics(
        scenario=scenario,
        tp=tp,
        fp=fp,
        fn=fn,
        tn_sample=tn_sample,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        per_gt_kind=per_gt_kind,
        per_det_type=per_det_type,
        observable_total=len(obs),
        matched_records=matched_records,
    )


def _host_matches(host: str, system: str) -> bool:
    if not host or not system:
        return False
    if host == system:
        return True
    if system.endswith(host) or host.endswith(system):
        return True
    return False