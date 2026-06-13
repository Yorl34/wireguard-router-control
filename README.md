# WireGuard Router Control

Web panel for managing OpenWrt routers over WireGuard.

## What it does

- Stores router and client inventory.
- Generates WireGuard configs and OpenWrt paste scripts.
- Keeps VPS peers in sync with the panel state.

## Stack

- Python HTTP panel
- Docker Compose
- WireGuard
- Caddy reverse proxy

## Public-safe notes

This repository is sanitized for GitHub:
- all real secrets are replaced with placeholders
- live keys and production credentials are removed
- example values are used instead of private infrastructure details

## Quick start

1. Copy `.env.example` to `.env` and change the secrets.
2. Review `docker-compose.yml` and `Caddyfile` for your domain.
3. Start the stack with Docker Compose.

## License

MIT
