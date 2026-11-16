# phantom-rig-core

Private control repository for **rigctl** 1.0.0. Everything here is generated.

| Path | Purpose |
| --- | --- |
| `.github/workflows/rig.yml` | Ephemeral Windows workstation (RDP over Tailscale) |
| `.github/workflows/vps.yml` | Ephemeral Ubuntu VPS (SSH over Tailscale) |
| `.rig/rig_agent.py` | Node agent: status API, encrypted snapshots, keep-alive |

Releases tagged `rig-state-*` hold AES-256-GCM encrypted workspace snapshots;
they can only be read with the `RIG_STATE_KEY` kept by rigctl.

Drive it from your machine:

```
rigctl up --os windows   # or: --os ubuntu
rigctl status
rigctl connect | rigctl ssh | rigctl web
rigctl migrate | rigctl kill
```
