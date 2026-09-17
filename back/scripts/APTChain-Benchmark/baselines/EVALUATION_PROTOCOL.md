# Frozen Evaluation Protocol

This protocol prevents detector inputs from seeing EvidenceForge ground truth and
makes very different provenance detectors comparable.

## Data split

Each scenario is split independently in timestamp order.

1. Find the timestamp of the first malicious eCAR edge using `labels.jsonl`.
2. Treat every edge before that timestamp as the clean prefix.
3. Use the first 80% of the clean-prefix edges for self-supervised training.
4. Use the final 20% of the clean-prefix edges for threshold calibration.
5. Test from the first malicious edge through the end of the capture.

Labels are opened only after the graph and anomaly scores have been produced. The
split boundary is the one unavoidable use of offline truth; no label, storyline,
logical-event ID, or detectability field becomes a model feature.

## Log/event view

One neutral graph edge corresponds to one source eCAR record. A detector score is
therefore joined back to an eCAR log by edge UUID. Report:

- precision, recall, F1, accuracy, balanced accuracy, MCC;
- AUROC and average precision (AUPRC) when scores are available;
- false positives per million benign test edges;
- TP, FP, TN, and FN counts.

Accuracy is retained for compatibility with published papers but is not a primary
metric because malicious edges are extremely rare.

## Action/storyline view

A ground-truth action is one storyline ID represented by at least one malicious
edge in the detector-visible eCAR graph. Predicted edge alerts are collapsed into
alert components by host, shared endpoint, and a five-minute transitive gap.
Components and actions are greedily matched one-to-one when the component contains
an edge labeled with that storyline ID. This yields action TP/FP/FN and coherent
precision, recall, and F1. A component spanning several actions can match only one,
which intentionally penalizes overly coarse alerting.

Time-to-detect is measured from the first detector-visible malicious edge of the
matched storyline to its first alerted malicious edge. Invisible scenario steps are
reported separately and are not counted as detector false negatives.

## Repetition and reporting

All seven completed clean-prefix adapters run with five seeds. The seed list and training
parameters are recorded by each adapter and result manifest. Aggregate tables
distinguish micro counts from mean per-scenario metrics and never compare numbers
produced under different split or matching policies as if they were equal.

## Supervised task methods

TAPAS is not a clean-prefix anomaly detector: its official source trains a
two-class GraphSAGE using benign/attack task labels and evaluates a random 20% of
the same dataset. For EvidenceForge it uses seven leave-one-scenario-out folds:
six complete scenarios supply training labels and the seventh scenario remains
untouched until evaluation. The fold repeats for five seeds.

The native unit is a connected process-parent task. A predicted malicious task is
projected to its incident eCAR edges for the log/event view, after which the same
attack-onward event and action matching rules apply. Full-capture event metrics
and native task metrics are also retained. TAPAS is displayed in a separate table
and never ranked as though its supervised protocol were the clean-prefix protocol.
