# Published Method Audit (2026-07-21)

| Method | Correct venue/year | Public implementation | Local status | Fit to EvidenceForge |
|---|---|---|---|---|
| ThreaTrace | IEEE TIFS 2022 | [Official GitHub](https://github.com/threaTrace-detector/threaTrace), MIT | Pinned; modern PyG objective port completed for 7×5 runs | High at entity/node level |
| ShadeWatcher | NDSS 2022 | [Official GitHub](https://github.com/jun-zeng/ShadeWatcher), GPL-3.0 | Pinned; native Python 3.6/TensorFlow 1.14 probe retained; modern PyTorch objective port completed for 7×5 runs | High for CDM-style relation and entity graphs, but the bundled evaluator has benign records only |
| RapSheet | IEEE S&P 2020, published as [*Tactical Provenance Analysis for Endpoint Detection and Response Systems*](https://dartlab.org/assets/pdf/rapsheet.pdf) | No author source located | Paper-only | Medium for alert correlation; it consumes upstream EDR alerts rather than detecting directly from raw provenance |
| PROGRAPHER | [USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/yang-fan) | No author source located | Paper-only | Medium; graph-snapshot embedding loses some fine-grained action labels |
| NODLINK | [NDSS 2024](https://www.ndss-symposium.org/wp-content/uploads/2024-204-paper.pdf) | [Official GitHub](https://github.com/PKU-ASAL/Simulated-Data), research-only MIT | Official VAE + neutral process adapter completed for 7×5 runs | High for process/entity detection and investigation |
| MAGIC | [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/jia-zian) | [Official GitHub](https://github.com/FDUDSDE/MAGIC), MIT | Official GMAE/KNN + two compatibility fixes completed for 7×5 runs | High; supports entity and batched-log views |
| KAIROS | IEEE S&P 2024 | [Official GitHub](https://github.com/ubc-provenance/kairos); no license file | Official TGN + neutral TemporalData adapter completed for 7×5 runs | High at edge and investigation level |
| Slot | [ACM CCS 2025](https://doi.org/10.1145/3719027.3744788) | No author source located | Paper-only | High in principle; cannot claim a source reproduction |
| TAPAS | [USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas) | [Official Zenodo artifact](https://doi.org/10.5281/zenodo.15610687) | Official LSTM checkpoint + GraphSAGE source completed with 7-fold LOSO × 5 seeds | High for online process-task segmentation; supervised result is separate from clean-prefix anomaly methods |
| ORTHRUS | USENIX Security 2025 | [Official GitHub](https://github.com/ubc-provenance/orthrus), Apache-2.0 | Official factory/model/neighbor/inference stack + input adapter completed for 7×5 runs | Very high for conservative edge alerts and attribution |
| Sometimes Simpler / VELOX | [USENIX Security 2025](https://www.usenix.org/system/files/usenixsecurity25-bilot.pdf) | [PIDSMaker](https://github.com/ubc-provenance/PIDSMaker), Apache-2.0 | Specification port completed for 7×5 runs | Very high; simple edge anomaly detector and strongest common harness |
| ProvFusion | IEEE S&P 2026 | [GitHub](https://github.com/Joney-Yf/ProvFusion) currently contains an early code tree but its README still promises the full release for Aug–Oct 2026; no license file | Pinned as experimental/incomplete | Very high after release stabilization; directly fuses node/edge views |

## Execution status and remaining order

VELOX, NODLINK, MAGIC, ThreaTrace, ShadeWatcher, KAIROS, and ORTHRUS now have
independent five-seed results under the frozen clean-prefix protocol. TAPAS has a separate
35-run supervised leave-one-scenario-out result because its native objective
requires attack task labels. ProvFusion should be re-audited after its
declared August–October 2026 complete release: the current tree omits processed
input, calls a missing function from its main path, and does not contain a stable
environment manifest.

ShadeWatcher's source-native environment is obsolete on this host: current `uv`
does not create Python versions below 3.7, while upstream requires Python 3.6.5
and TensorFlow-GPU 1.14. The scored path is consequently an algorithm/objective
port, not direct execution of its TensorFlow classes. It uses 40 epochs rather
than the source default of 1000 and the frozen clean-validation threshold rather
than the source's fixed 1.5 cutoff.

RapSheet is better evaluated as a second-stage investigation method supplied with
the same detector alerts, not placed in a raw-log detection F1 table. PROGRAPHER,
Slot, and any other paper without author code must be labeled independent
reimplementations if pursued; they cannot be presented as source reproductions.
