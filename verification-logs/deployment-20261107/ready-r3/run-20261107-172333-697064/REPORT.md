# Isolated deployment validation

```json
{
  "status": "PASS",
  "native_linux": "NOT RUN",
  "two_laptop": "NOT RUN",
  "reused_verified_regressions": {
    "static_q16": "/home/arnav/research/ebpf-ids-research/verification-logs/deployment-20261107/ready/regression-static_q16/run-20261107-171750-708464/results.json",
    "layer_specific": "/home/arnav/research/ebpf-ids-research/verification-logs/deployment-20261107/ready/regression-layer_specific/run-20261107-171755-579088/results.json"
  },
  "static_q16_regression": "PASS",
  "layer_specific_regression": "PASS",
  "static_q16_deployment": {
    "status": "PASS",
    "flows": 11,
    "predictions": 11,
    "logits_reference": "PASS",
    "tensors_reference": {
      "records": 11,
      "stage_tensors": 66,
      "integers": 1496
    },
    "dashboard": "PASS actual LIVE HTTP API; unprivileged process",
    "foreign_filter_preserved": "PASS",
    "cleanup": "PASS"
  },
  "layer_specific_deployment": {
    "status": "PASS",
    "flows": 11,
    "predictions": 11,
    "logits_reference": "PASS",
    "tensors_reference": {
      "records": 11,
      "stage_tensors": 66,
      "integers": 1496
    },
    "dashboard": "PASS actual LIVE HTTP API; unprivileged process",
    "foreign_filter_preserved": "PASS",
    "cleanup": "PASS"
  },
  "address_and_route_preservation": "PASS",
  "unprivileged_http_endpoint_tests": "PASS",
  "namespace_cleanup": "PASS"
}
```
