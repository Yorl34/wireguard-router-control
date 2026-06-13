# Router WG Panel

Local panel for managing WireGuard-backed routers.

## Run

```powershell
python .\server.py
```

Open:

```text
http://127.0.0.1:8787
```

## Generated outputs

- OpenWrt paste script for `wg0` and firewall zone `wg`
- VPS peer block for the router WireGuard config
- WireGuard keys for newly added routers and clients

## Data

`data/routers.json` is runtime state. Do not commit real private keys or production values.
