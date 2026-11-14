# Submission validation and publication status — 14 November 2026

**Local candidate validated for build/host reproduction. GitHub publication and new privileged kernel/network execution remain pending.** No remote-main update is claimed.

Candidate: `submission/reproducibility-20261114`, isolated from both existing worktrees. Base is cached `origin/main` `7dbee55`; runtime source provenance is `711b909261e352cfb87ce3c34d598f5615e04661`. Final local commits are recorded in the audit response and Git log; this document is versioned with them. A clean checkout check is recorded separately below.

## Executed checks (E)

Ubuntu 22.04.5, WSL2 `6.6.87.2-microsoft-standard-WSL2`, x86-64, Python 3.10.12, clang-12. Build artifacts and new full output logs are ignored under `.output` / `artifacts/submission`. Selected machine-readable summaries are included under `docs/evidence`.

| Check | Outcome |
| --- | --- |
| Root `make`, `make -C src`, `make -C tc demo-models` | PASS; vendored dependencies, original XDP, both TC objects and all four controllers built |
| `validation/run.py --output artifacts/submission/original-numerical` | PASS: 34 tests run, 32 passed, 2 documented skips (optional old smoke bytes, missing original FP32) |
| `quantization/run_host.py --output artifacts/submission/layer-numerical` | PASS: 19,004 fixtures, 114,024 tensors, 2,584,544 integers, 121 boundary checks, zero mismatches, UBSan PASS |
| `evaluation/offline.py --output artifacts/submission/original-three-way` | PASS: 13,844 rows, zero XDP/TC Q16 tensor differences, zero layer-specific prediction changes |
| Core unit modules listed below | PASS: 117 run, 113 passed, 4 sandbox socket skips |
| Ordinary-user socket/HTTP classes outside sandbox | PASS: 5 tests, no skips; actual half-close/response, inherited socket, port conflict, read-only API/security |
| TC prepare/host regressions, Q16 and layer-specific | PASS: 37 tests per mode, zero errors/failures, read-only ELF inspection |
| Fresh-model tests | PASS: 20 tests |
| CIC CSV + threshold tests | PASS: 30 tests, including validation-only threshold selection guards |
| Original XDP completion-witness tests | PASS: 12 tests, after generating required frozen fixtures |
| Frozen fresh checkpoint: quantize/compare into NEW output | PASS: 2,826 same test vectors, 8,478 successful integer outputs, 50,868 tensors / 1,153,008 integers; zero prediction changes or XDP/TC Q16 differences |
| Fresh and XDP kernel-bundle preparation; integrated demo preparation | PASS; compilation/ELF/host fixtures only, NOT verifier or kernel execution |
| Fresh model identity in both modes | PASS; header/scaler/packed expected bytes; live kernel readback NOT RUN during this audit |

The core command was:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest -v quantization.test_reference quantization.test_benchmark evaluation.test_audit evaluation.test_metrics evaluation.test_kernel_latency evaluation.test_latency evaluation.cic.test_capture evaluation.cic.test_labels evaluation.cic.test_metrics evaluation.cic.test_pipeline demo.test_demo demo.test_final_server deployment.tests.test_dashboard
```

Actual audit Python: `/tmp/ebpf-submission-20261114-venv/bin/python`; `.venv` is the documented equivalent for a new clone. The skipped socket classes were then actually run as UID 1000 outside the sandbox:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest -v demo.test_demo.SocketProtocol demo.test_final_server.OwnedListeners deployment.tests.test_dashboard.HTTP
.venv/bin/python -B experiments/fresh_model_20261108/test_experiment.py
.venv/bin/python -B -m unittest -v research.cic_csv_mlp.test_study research.cic_threshold_sensitivity.test_sensitivity
python3 experiments/xdp_final_20261108/test_harness.py
python3 scripts/check_submission.py
```

These are host/synthetic protocol tests unless expressly labeled real sockets. They do not count as actual BPF execution. No training, test-split modification, production parameter write, physical attachment or network reconfiguration occurred. Existing source-model tests continue to characterize original defects rather than concealing them.

## Failures investigated and resolved

- Initial TC test preparation refused the submission branch name. Removed only obsolete `feature/` restriction, then both 37-test mode preparations passed.
- Directly importing `tc.tests.test_tc` is unsupported because its compiled context/import paths are supplied by `tc/demo.py`; use `run-tc-smoke.sh --prepare`. No assertions were removed.
- Initial optional CIC metric tests lacked sklearn in system Python. Installed pinned dependencies in a temporary venv; the complete core suite passed there. No system packages changed.
- Original-XDP host tests initially lacked generated `kernel-ready/fixtures.jsonl.gz`. Generated the documented fresh bundle, then all 12 tests passed. Compiled bundles are deliberately not committed.
- Candidate-only preservation guard caught an edited entry README. Rebased the disclosed candidate documentation guard, preserving original historical manifests. No inference or checkpoint mismatch was waived.

## Pending / unverified checks

| Check | Status and reason |
| --- | --- |
| New verifier acceptance / kernel test-run / concurrency | PENDING USER EXECUTION; `sudo -n true` returned `sudo: a password is required` |
| New isolated TC attachment and real namespace packet processing | PENDING USER EXECUTION; same sudo restriction |
| New physical Ubuntu VM / Windows two-laptop run | NOT RUN; external hardware, operator-only attachment |
| New training or full CIC raw-data research rerun | NOT RUN; frozen artifacts used; no retraining requested, external CIC source not part of clean clone |
| Authenticated latest-remote check and push/PR/merge | BLOCKED; HTTPS fetch could not obtain GitHub username/authentication |
| Actual GitHub default branch / protection / root README visibility after merge | NOT VERIFIED; cached origin/HEAD is main, not live API evidence |

Historical operator kernel/runtime results are included as explicitly historical summaries, not substituted for these pending checks. Current inference source and weights are unchanged from the validated demo source; only the test's branch-name guard changes executable test behavior.

For a fresh privileged check, run [the isolated TC commands](GETTING_STARTED.md) or [fresh model pilot then network gates](TWO_LAPTOP.md), review actual PASS/cleanup records and retain them. Never run any physical-interface command merely to validate the submission.

## Publication steps still required

Do not submit the GitHub main link assuming these local commits are published. After configuring HTTPS authentication **locally** (never paste a token into chat), from this submission worktree:

```bash
git fetch origin
git log --oneline --left-right origin/main...HEAD
git diff --stat origin/main...HEAD
```

If remote main changed since `7dbee55`, inspect those commits and merge `origin/main` into the candidate with a normal merge, resolve/retest without resets or rewriting existing history. Do not merge the old unrelated implementation branch. After reviewing the staged source/secret scan and privileged checks appropriate to the target environment:

```bash
git push -u origin submission/reproducibility-20261114
```

Open a GitHub pull request **from `submission/reproducibility-20261114` into `main`**, review the inventory and validation caveats and use a normal merge. If branch protection/permissions require a maintainer, let that maintainer merge. No force push or default-branch change is needed based solely on cached refs. `gh` was not installed/authenticated here; no unsupported CLI execution is claimed.

After the remote PR is merged:

```bash
git fetch origin
git merge-base --is-ancestor submission/reproducibility-20261114 origin/main
git show origin/main:README.md
```

The ancestry check assumes a normal merge; for a squash merge inspect the resulting tree/diff instead. Confirm GitHub's default branch is main in repository settings and open the repository root in the browser. Only then report main/README as published. Original developer branches/worktrees remain available for raw evidence and rollback; none has been reset or deleted.

## Clean-checkout evidence

See [machine-readable audit](evidence/submission-checks.json) for the exact completed checks, and [clean-checkout results](evidence/clean-checkout.json) for validation after committing the selected files. Missing external raw archives and licensing ambiguity are disclosed in the entry guides. The candidate is not represented as a new physical or privileged end-to-end verification.
