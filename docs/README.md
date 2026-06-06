# Goodix GM168 — Documentation index

Project documentation. Read in this order:

| File | What's in it |
|------|---|
| [SUMMARY.md](SUMMARY.md) | High-level overview of what shipped this session, before/after table of changes, completed-tasks list |
| [DRIVER.md](DRIVER.md) | Linux driver internals: decoder, state machines, runtime safety, build/test instructions — the file to read before touching `goodix_gm168.c` |
| [PSK.md](PSK.md) | PSK lifecycle (provisioning + runtime), the DPAPI/MCU sealing scheme, evidence from Frida capture, and the cross-host sharing strategy |
| [PIPELINE.md](PIPELINE.md) | End-to-end extraction pipeline: Frida capture → DPAPI unseal → Linux driver. Concrete commands, failure modes, portability table. |
| [DEV_STACK.md](DEV_STACK.md) | How dev is wired: PC + laptop, SSH ports 22 (Windows) and 2200 (WSL), repo layout, deploy/fetch scripts |
| [NEXT_STEPS.md](NEXT_STEPS.md) | Roadmap with priorities and effort estimates — what to do in the next session, where to start |

For protocol and reverse-engineering details, the canonical reference lives
in `../RESEARCH.md` at the repo root. Its TL;DR section has the verified
decode algorithm in C; the rest documents the wire format, commands,
calibration blob layout, and Frida instrumentation.

## Quick navigation

- Driver source: [`../goodix_gm168/goodix_gm168.c`](../goodix_gm168/goodix_gm168.c)
- Frida hook: [`../frida_work/gx_hook.js`](../frida_work/gx_hook.js)
- Analysis scripts: [`../scripts/`](../scripts/)
- Captured ground truth: `../frida_work/dumps/`
- Calibration blob: [`../calib_windows.dat`](../calib_windows.dat)
