# Isolated bidirectional-MLP feasibility study

Read [BIDIRECTIONAL_MLP_EXPERIMENT.md](../../BIDIRECTIONAL_MLP_EXPERIMENT.md)
for findings, gate decisions, source hashes and exact rerun commands.

This package contains a predictions-blind CSV/PCAP audit and offline feature
reference. It is **not** a trained classifier, experimental kernel program or
replacement for the verified two-laptop demo. Dataset Gate 3 failed; training,
quantization and kernel integration were deliberately not attempted.

Run commands from this worktree's root. Every audit output directory must be
new. The original source archive, capture and previous reconstruction evidence
are external inputs; `DEPENDENCIES.json` identifies copied untracked helpers.
No download, network connection, privileged execution or model loading occurs.

`POLICY.json` defines fixed formulas, packet inclusion, candidate termination,
label-window validation and the campaign-group split requirement. `features.py`
implements only the offline reference. `audit.py` provides `inventory`, `pilot`
and `groups` subcommands. Tests intentionally distinguish host C helper checks
from Linux-kernel BPF execution.

No final training/test cohort has been frozen. Do not repurpose the preparation
pilot as a held-out test set. Do not use existing reproduction weights/scalers
with the changed input representation, or report CSV-only metrics as live TC
effectiveness.
