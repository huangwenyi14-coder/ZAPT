# Provenance Detection Baselines

This directory is the isolated reproduction lab for published provenance-based
intrusion detectors. It consumes the detector-safe graph files under
`provenance_graph/graphs/`; it never adds ML dependencies to EvidenceForge's
generation environment.

## Layout

| Path | Purpose |
|---|---|
| `source_lock.json` | Reviewed upstream URLs, exact commits, and licenses |
| `adapter_environments.json` | Portable Python, source, patch, probe, and artifact contract for all eight adapters |
| `third_party/<method>/` | Ignored local checkouts of published code |
| `envs/<adapter>/` | Ignored, isolated uv environment used by the common benchmark adapters |
| `envs/native/<method>/` | Ignored empty/source-native smoke environment, never used by the common benchmark |
| `native_methods.json` | Upstream entry point and native environment contract per method |
| `native_smoke.py` | Unmodified-source integrity, syntax, dependency, and entry-point probes |
| `compat_smoke.py` | Separate host-compatible entry-point probes with exact patch/diff evidence |
| `METHOD_AUDIT.md` | Source availability, venue corrections, feasibility, and reproduction order |
| `EVALUATION_PROTOCOL.md` | Frozen log/event and action/storyline metrics |
| `velox_adapter.py` | First adapted source reproduction using PIDSMaker's VELOX specification |
| `nodlink_adapter.py` | NODLINK official VAE with a neutral process-behavior input adapter |
| `magic_adapter.py` | MAGIC official GMAE/KNN model with a neutral DGL input adapter |
| `threatrace_adapter.py` | Modern PyG port of ThreaTrace's GraphSAGE objective |
| `shadewatcher_adapter.py` | Modern PyTorch port of ShadeWatcher's TransR/GraphSAGE objectives |
| `kairos_adapter.py` | KAIROS official TGN with a neutral temporal-graph input adapter |
| `orthrus_adapter.py` | ORTHRUS official model stack with a neutral temporal-graph input adapter |
| `tapas_adapter.py` | TAPAS official LSTM/GraphSAGE with a cross-scenario task adapter |
| `compare_results.py` | Rebuild the common seven-method result table |
| `results/<method>/` | Checked-in aggregate metrics; raw alert rows remain ignored |

The user-suggested `baselin` name is normalized to the conventional plural
`baselines`.

## Portable one-command reset

On a fresh Linux server, install `git` and
[`uv`](https://docs.astral.sh/uv/getting-started/installation/), clone this repository, and run:

```bash
./baselines/reset_baselines.sh --without-tapas
```

This fetches every required official checkout at the commit in `source_lock.json`, applies the
reviewed MAGIC compatibility patch, clears only the seven selected adapter environments, installs
the pinned CPU stack, checks dependency consistency, and imports the model classes used by each
adapter. A machine-specific audit report is written to the ignored path
`baselines/work/environment-reset/report.json`.

TAPAS needs only two extracted files totaling less than 100 KiB, although its official archive is
24.3 GB. Prefer copying the extracted directory from an existing machine and rebuilding all eight
methods in one command:

```bash
rsync -a OLD_SERVER:/path/to/EvidenceForge/baselines/artifacts/tapas-inspection/ \
  /tmp/tapas-inspection/
./baselines/reset_baselines.sh --tapas-from /tmp/tapas-inspection
```

If no existing extraction is available, explicitly opt into the large download and provide
RARLab `unrar`:

```bash
./baselines/reset_baselines.sh --include-large-tapas --unrar /usr/bin/unrar
```

The reset defaults to `--torch-backend cpu`, matching the frozen adapter runs. Pass a supported uv
backend such as `--torch-backend auto` only when intentionally validating a different hardware
stack. Rebuild one method with repeatable `--method`, or verify an existing installation without
changing it:

```bash
./baselines/reset_baselines.sh --method magic
uv run python -m baselines.reset_baselines --check --without-tapas
```

This reconstructs the eight **EvidenceForge-compatible adapters** used by the common protocol. It
does not claim to construct the papers' byte-identical DARPA environments. KAIROS, ORTHRUS, and
PIDSMaker native DARPA workflows still require their upstream Docker/CUDA/PostgreSQL setup;
ThreaTrace and ShadeWatcher native workflows require legacy Python 3.6-era containers.

## Fetch pinned sources

```bash
uv run python -m baselines.fetch_sources
```

This fetches ThreaTrace, ShadeWatcher, MAGIC, NODLINK, KAIROS, PIDSMaker,
ORTHRUS, and the currently public ProvFusion tree. TAPAS is not downloaded by default because its
official Zenodo artifact is 24,330,707,000 bytes:

```bash
uv run python -m baselines.fetch_sources --source tapas --include-large
uv run python -m baselines.prepare_tapas --unrar /path/to/rarlab/unrar
```

The preparation step extracts only `darpa.py` and `stackedlstm_tc.pt`. RARLab's
official `unrar` is required because the tested 7-Zip build does not support the
archive's compression method.

## Test every upstream source independently

The following command creates one empty source-native probe environment per repository under
`envs/native/` and runs the
locked-revision, Python syntax, unmodified requirements-resolution, and native
entry-point checks. Exact stderr and exit codes are retained, so an incompatible
CUDA/Linux dependency is not confused with a model-quality result.

```bash
uv run python -m baselines.native_smoke
```

Use `--method magic` (repeatable) to test only selected repositories. Results are
written to `results/source_native/`. Passing these smoke tests does not constitute
a seven-dataset reproduction; each method must additionally receive its own input
adapter, train on a leakage-free benign split, and emit alerts for the common
evaluation harness.

The native smoke command intentionally resolves dependencies with `--dry-run`; it does not install
the paper environments. Its separate `envs/native/` path prevents it from clearing a working
adapter environment.

After installing the documented files under `compat_requirements/`, run the
separate compatibility probes without overwriting the unmodified-source report:

```bash
uv run python -m baselines.compat_smoke
```

## VELOX environment

The first baseline uses an isolated Python 3.11 environment. All installation is
performed with `uv`, never `pip`:

```bash
uv venv --python 3.11 baselines/envs/velox
uv pip install --python baselines/envs/velox/bin/python \
  -r baselines/requirements-velox.txt
```

Run the five-seed benchmark over all seven converted scenarios:

```bash
PYTHONPATH=. baselines/envs/velox/bin/python -m baselines.velox_adapter \
  --epochs 12 --seeds 0,1,2,3,4
```

The adapter preserves the locked PIDSMaker VELOX configuration's core behavior:
128-dimensional Word2Vec node features trained on the clean split, a linear node
encoder, a two-layer edge MLP, self-supervised edge-type prediction, Adam with
the published learning rate and weight decay, 12 epochs, and a threshold equal
to the maximum clean-validation loss. It replaces PostgreSQL/DARPA ingestion and
PyG batching with the neutral JSONL graph only. Unary events become self-edges
for the model, matching the existing SPADE export convention.

## Completed adapted-source benchmark

Seven methods have now run independently over all seven datasets and five seeds.
The table reports the mean of per-seed, seven-scenario micro metrics:

| Method | Source execution scope | Event P / R / F1 | Action P / R / F1 |
|---|---|---:|---:|
| VELOX | PIDSMaker specification port | 0.0126 / 0.0479 / 0.0196 | 0.0099 / 0.0640 / 0.0169 |
| NODLINK | Official VAE + input adapter | 0.0001 / 0.0124 / 0.0003 | 0.0001 / 0.0020 / 0.0002 |
| MAGIC | Official GMAE/KNN + compatibility patches + input adapter | 0.0015 / 0.0107 / 0.0027 | 0.0017 / 0.0100 / 0.0028 |
| ThreaTrace | GraphSAGE objective port to modern PyG | 0.0061 / 0.1521 / 0.0117 | 0.0056 / 0.1500 / 0.0107 |
| ShadeWatcher | TransR/GraphSAGE objective port to modern PyTorch | 0.0016 / 0.0050 / 0.0024 | 0.0016 / 0.0120 / 0.0028 |
| KAIROS | Official TGN + input adapter | 0.0037 / 0.0380 / 0.0066 | 0.0030 / 0.0460 / 0.0055 |
| ORTHRUS | Official model stack + input adapter | 0.0109 / 0.0537 / 0.0176 | 0.0119 / 0.0680 / 0.0202 |

These low values are a useful finding, not failed scripts. Each scenario places
its first visible malicious edge only about 15–20 minutes into the capture,
leaving merely 184–942 clean training edges per scenario. Published PIDS
benchmarks normally provide entire clean training days. High raw accuracy is
therefore misleading under the extreme class imbalance and is not a headline
metric here. See `results/COMPARISON.md` and `results/comparison.json` for the
per-scenario table and machine-readable aggregation.

## Run each detector separately

Every detector has its own executable adapter and isolated environment. The
commands below do not route all papers through VELOX:

```bash
PYTHONPATH=. baselines/envs/velox/bin/python -m baselines.velox_adapter
PYTHONPATH=. baselines/envs/nodlink/bin/python -m baselines.nodlink_adapter
PYTHONPATH=. baselines/envs/magic_adapter/bin/python -m baselines.magic_adapter
PYTHONPATH=. baselines/envs/threatrace_adapter/bin/python -m baselines.threatrace_adapter
PYTHONPATH=. baselines/envs/shadewatcher_adapter/bin/python -m baselines.shadewatcher_adapter
PYTHONPATH=. baselines/envs/kairos_adapter/bin/python -m baselines.kairos_adapter
PYTHONPATH=. baselines/envs/orthrus_adapter/bin/python -m baselines.orthrus_adapter
uv run python -m baselines.compare_results
```

Every result row records whether it executed official model classes directly or
an API port. None is described as byte-identical paper reproduction because the
papers' DARPA/OpTC parsers and clean-day training sets are replaced by the seven
EvidenceForge graphs.

ShadeWatcher's official checkout is retained and independently probed, but its
documented Ubuntu 16.04, Python 3.6.5, TensorFlow-GPU 1.14 environment cannot be
created by current `uv` on this arm64 host. Its scored adapter therefore ports
the locked TransR, knowledge-attention, two-layer GraphSAGE, interaction-ranking,
and knowledge-ranking objectives to modern PyTorch. Upstream's bundled evaluator
contains benign samples only, so it cannot produce attack precision/recall/F1
without an evaluation adapter. The benchmark uses 40 epochs instead of the
upstream default of 1000 and replaces its fixed 1.5 cutoff with the shared
maximum-clean-validation threshold; both changes are recorded in every run.

## NODLINK adapted-source benchmark

The NODLINK adapter imports the VAE class directly from the locked upstream
checkout. It replaces the ETW/Sysdig parser with process-behavior documents built
from the neutral graph, trains FastText only on the clean prefix, calibrates the
published 90th-percentile reconstruction threshold on clean validation processes,
and projects each process score back to its events:

```bash
PYTHONPATH=. baselines/envs/nodlink/bin/python -m baselines.nodlink_adapter
```

This is an adapted-source run, not a byte-identical reproduction of the paper's
Windows ETW experiment. That distinction is recorded in every result row.

ProvFusion is source-tested but not scored: the public repository says the full
release is planned for August–October 2026, omits its processed dataset, and its
current main path calls a missing `compute_top_k_dissimilar_mean` function.
RapSheet, PROGRAPHER, and Slot have no located author implementation, so assigning
them numbers would be an independent reimplementation rather than a source test.

## TAPAS supervised cross-scenario benchmark

TAPAS is supplied as a single 24.33 GB official Zenodo RAR. Its official
`darpa.py`, `stackedlstm_tc.pt` checkpoint, `LSTM`, and `GraphSAGE` are executed
directly through a neutral process-task adapter:

```bash
PYTHONPATH=. baselines/envs/tapas_adapter/bin/python -m baselines.tapas_adapter
```

The original artifact randomly shuffles labeled tasks from one DARPA dataset into
an 80/20 train/test split. That protocol would leak scenario-specific attack
labels on these seven generated datasets, so the adapter instead trains on six
complete scenarios and tests the untouched seventh, repeating all seven held-out
folds over five seeds. It reports separately from the seven clean-prefix anomaly
detectors:

| View | Accuracy / P / R / F1 |
|---|---:|
| Native process task | 0.9709 / 0.2000 / 0.2571 / 0.2190 |
| Full-capture log/event | 0.9957 / 0.1781 / 0.1858 / 0.1733 |
| Attack-onward log/event | 0.9955 / 0.1791 / 0.1858 / 0.1743 |
| Attack-onward action | — / 0.1301 / 0.0750 / 0.0700 |

The high accuracy is not evidence of reliable attack detection: four held-out
scenarios have zero attack recall under every seed. See
`results/tapas/SUMMARY.md` for all 35 runs.
