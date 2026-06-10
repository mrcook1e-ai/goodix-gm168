# goodix-gm168 — Documentation

Project documentation, in reading order:

| File | What's in it |
|------|---|
| [DRIVER.md](DRIVER.md) | Driver internals: decoder, state machines, build/test |
| [PIPELINE.md](PIPELINE.md) | End-to-end image pipeline: USB → TLS → decode → NBIS |
| [PSK.md](PSK.md) | PSK lifecycle, DPAPI/MCU sealing scheme, sharing strategy |

For install / usage docs see the repo-root [README.md](../README.md) and
[INSTALL.md](../INSTALL.md).

For the reverse-engineering history — pcaps, Wbdi.dll extraction
scripts, WhiteBox AES key derivation, RE methodology — see the
[`archive/reverse-engineering`](https://github.com/mrcook1e-ai/goodix-gm168/tree/archive/reverse-engineering)
branch.
