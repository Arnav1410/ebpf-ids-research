# Source acquisition — resolved locally

**PASS, 8 November 2026:** the operator supplied the Tuesday capture, its MD5
sidecar and original-style `GeneratedLabelledFlows.zip` at:

```text
/mnt/c/Study Materials/Semester 7/USAP/Term Project/Tuesday-WorkingHours.pcap
/mnt/c/Study Materials/Semester 7/USAP/Term Project/Tuesday-WorkingHours.md5
/mnt/c/Study Materials/Semester 7/USAP/Term Project/GeneratedLabelledFlows.zip
```

The capture is PCAPNG despite its extension: 11,048,283,608 bytes,
11,551,954 packets, one Ethernet interface and microsecond timestamps. Its
complete MD5 matches the supplied sidecar. The ZIP is 283,876,488 bytes;
only `TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv` was streamed,
without extracting other days. The CSV member is 174,696,560 bytes and retains
endpoint and timestamp identity. It contains 445,909 source records.

[Source binding and all SHA256 values](../../verification-logs/cic-external-20261108/source-binding.json)
were saved before CIC predictions. The actual download transaction was not
observed, so checksum correspondence is not independent official authentication.
No dataset bytes were downloaded by the agent and no captures were modified,
replayed, or executed. Tuesday-only acquisition approval up to 15 GiB remains
the scope; no additional day was acquired.

All selected packet references and model inputs can be regenerated using
[README.md](README.md). The original registration-form 403 is no longer a
blocker because the operator provided local inputs. A complete scan took
324.156 seconds for reconstruction, with peak process RSS 426,628 KiB.
The 2,500-flow resource validation took 39.101 seconds; final 15,026-flow
validation took 67.755 seconds on the recorded WSL2 environment.

The strict packet/label matching policy leaves only 26 eligible intrusion
records. The target balanced 30,000-flow experiment was not achieved.
Additional capture days or a broader validated treatment of CIC FIN appendices
requires a separately documented selection protocol and renewed validation;
large downloads still require operator approval. Current scores are restricted
to the audited smaller subset described in the root report.
