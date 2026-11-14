# Repository audit and integration plan — 14 November 2026

## Gate 1: established before integration

Cached `main` and `origin/main`: `7dbee55` (only README). Implementation branch `feature/final-demo-evaluation`: `711b909261e352cfb87ce3c34d598f5615e04661`, also cached origin tip. These have **unrelated histories** (`git merge-base` returned no ancestor). A blind merge would introduce historical `dataset-instance` attack tooling and generated logs into main's ancestry.

`git fetch origin` was attempted with repository-write/network permission and failed: `could not read Username for 'https://github.com': No such device or address`. Remote freshness, branch protection and actual GitHub default branch cannot currently be confirmed. Cached `origin/HEAD` points at main. No push or merge is claimed.

| Branch / worktree | Location / scope |
| --- | --- |
| `feature/final-demo-evaluation`, `711b909` | Original development worktree; final committed demo/runtime/model selection |
| `feature/bidirectional-mlp`, `711b909` | Existing isolated sparse worktree; uncommitted CSV and threshold research |
| `feature/cic-external-evaluation`, `73868b1` | Committed original-model evaluation/harness; newer fresh/benchmark files remained uncommitted in development tree |
| `feature/native-deployment-dashboard`, `0ba2b2b` | Ownership-aware deployment and dashboard |
| `feature/tc-egress-bidirectional`, `791e259` | Verified canonical two-hook TC baseline |
| `feature/tc-concurrency-bidirectional`, `d502d57` | Earlier concurrency evidence |
| `feature/tc-ingress-prototype`, `f06718f` | Initial TC implementation |
| `baseline-validation`, `2073fe7` | Original numerical/kernel framework |
| `baseline-reproduction`, local `18f855b`, cached remote `65c49c7` | Earlier baseline setup |
| cached `origin/test-env`, `53a8e12` | Temporary dashboard branch; excluded |
| `submission/reproducibility-20261114` | New isolated candidate based on cached origin/main; original worktrees preserved |

## Selection

Copy the final runtime/source snapshot from `711b909`, preserving core code bytes, source attribution and origin commit. Import explicitly selected uncommitted training/benchmark/PCAP research source, portable numeric checkpoints/splits and small evidence summaries. Keep offline CIC experiments under `research/`, outside production model defaults. [Imported file hashes](IMPORTED_FILES.json) identify uncommitted sources and destinations.

Retain original XDP/TC source, both runtime models, tests, vendored dependencies, and two small numeric reproduction arrays. Include the frozen fresh checkpoint, scaler, exact split IDs, labels, and compact stored-vector host predictions needed to audit and rebuild the benchmark without retraining. No production model was replaced or recalibrated.

Excluded: all `dataset-instance` tooling/payloads (not opened or executed), bulk execution logs, stale runtime states, generated binaries/libraries, `.output`, local credentials/configuration, temporary environments, PCAPs and CIC ZIP. They remain safely in original branches/worktrees. Historical raw evidence is not pretended to be included; summaries record its origin. Existing remote feature history may still contain unsafe historical payloads; this candidate does not rewrite it or claim to clean the whole GitHub repository's history.

The original tracked deletion at `dataset-instance/intrusion/metasploit/myshell` was not restored, executed or staged in the original checkout. No reset, worktree deletion, branch deletion, force-push or indiscriminate staging was used.

## Necessary reproducibility correction

`tc/demo.py` rejected any branch not starting `feature/`, so isolated preparation actually failed on the submission branch. The candidate removes only that obsolete branch-name restriction; it still records branch/commit, preserves immutable inputs, refuses resource conflicts and gates privileged execution. No BPF instruction, packet feature, inference condition or parameter changed.

Historical preservation manifests referenced omitted build products/logs and older demo/controller revisions. Submission-local manifests bind included current sources and selected artifacts; generated products are excluded. [Scope and rebased paths](evidence/submission-preservation-scope.json) disclose the difference. Historical manifests/results in original worktrees were not changed. New preparation creates new hashes and cannot reuse old privileged approval/evidence automatically.

## Publication gate

This is a selective snapshot commit, not a merge of unsafe/incompatible histories. Publication requires successful candidate checks, authenticated fetch, reconciliation with actual remote main and a reviewed pull request. Authentication is unavailable in this session; local completion does not equal GitHub main integration. See [validation and remaining commands](SUBMISSION_VALIDATION.md).
