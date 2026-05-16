# evidentia-collectors

Evidence collection agents for [Evidentia](https://github.com/polycentric-labs/evidentia). **Phase 2 — under construction.**

Pulls compliance evidence from cloud providers and SaaS systems and maps it to specific framework controls.

## Planned collectors

| Collector | Source system | Phase |
|---|---|---|
| `aws` | AWS Config, IAM, CloudTrail, Security Hub | 2 (primary) |
| `github` | GitHub repository configuration, branch protection, secrets | 2 (primary) |
| `okta` | Okta user/group/policy data | 2 (primary) |
| `azure` | Azure Policy, Entra ID, Defender | 2 (secondary) |
| `gcp` | Google Cloud Asset Inventory, IAM, Security Command Center | 2 (secondary) |

## Install

```bash
pip install evidentia-collectors            # core only
pip install evidentia-collectors[aws]       # with AWS support
pip install evidentia-collectors[all]       # all collectors
```

License: Apache 2.0
