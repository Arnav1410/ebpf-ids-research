# Attribution, licensing and research responsibility

This project reproduces and extends **Real-Time Intrusion Detection and Prevention with Neural Network in Kernel using eBPF**, Junyu Zhang, Pengfei Chen, Zilong He, Hongyang Chen and Xiaoyun Li, DSN 2024, DOI 10.1109/DSN58291.2024.00048.

- [Paper](https://dsn2024uq.github.io/Proceedings/pdfs/DSN2024-6rvE3SSpzFYmysif75Dkid/410500a416/410500a416.pdf)
- [Authors' repository](https://github.com/IntelligentDDS/NN-eBPF)
- [CIC-IDS-2017, Canadian Institute for Cybersecurity / UNB](https://www.unb.ca/cic/datasets/ids-2017.html)

Upstream supplies the XDP pipeline, bias-free MLP architecture, original training/quantization scripts, original quantized parameter header and numeric reproduction arrays. The IIT Kharagpur team adapted the runtime to TC ingress, added egress monitoring/canonical flow statistics and concurrency protections, developed guarded deployment/telemetry/dashboard/client tools, added offline fixed-point scaling, trained a separate reproduction model and developed numerical, benchmark and offline CIC experiments. Original program behavior is not silently attributed to the extensions.

No project-wide LICENSE file was found in the local source tree or the upstream root inspected on 14 November 2026. Absence is **not** a permissive license. This submission adds no blanket license or ownership claim over upstream code/data. Clarify upstream permission before redistribution beyond the authorized academic submission; comply with dataset terms. License ambiguity remains a submission caveat, not evidence of an invented permission.

Vendored components retain their own notices: [libbpf](../libbpf/LICENSE), [libbpf BSD](../libbpf/LICENSE.BSD-2-Clause), [libbpf LGPL](../libbpf/LICENSE.LGPL-2.1), [bpftool](../bpftool/LICENSE), [bpftool GPL](../bpftool/LICENSE.GPL-2.0), [bpftool BSD](../bpftool/LICENSE.BSD-2-Clause), and bpftool's nested libbpf notices. These are tracked vendored directories, not Git submodules requiring initialization. `.gitmodules` is historical upstream metadata; ordinary clone is sufficient.

AI assistance (including Codex) was used for implementation, test development, analysis and documentation. Students selected the research scope, performed privileged/operator-controlled runs and physical demonstration, and reviewed results. The repository distinguishes saved operator evidence from new local checks; it does not imply that AI-generated code or paper figures independently establish correctness.

No malware, attack program or captured payload must be executed to reproduce the documented tests. The demonstration emits bounded ordinary TCP traffic. Offline CSV metrics, host numerical checks, actual kernel execution and live attack-detection effectiveness are separate claims.
