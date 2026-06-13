# WireGuard Router Control

[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![Stack](https://img.shields.io/badge/stack-Python%20%7C%20Docker%20%7C%20WireGuard-2ea44f)](./README.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Docker-blue)](./README.md)

Web panel for managing OpenWrt routers over WireGuard.

## Overview

This project helps keep a small WireGuard router fleet organized from one VPS-backed panel.

It is designed to:

- store router and client inventory
- generate WireGuard configs and OpenWrt paste scripts
- keep VPS peers synchronized with panel state
- expose a clean web UI for day-to-day administration

## Stack

- Python HTTP panel
- Docker Compose
- WireGuard
- Caddy reverse proxy

## Repository layout

- `router-panel` - web panel, API, and static UI
- `router-wireguard` - WireGuard server templates and config
- `docker-compose.yml` - local stack definition
- `Caddyfile` - reverse proxy routing

## Public-safe notes

This repository is sanitized for GitHub.

- real secrets are replaced with placeholders
- production credentials are removed
- example values are used instead of private infrastructure details

## Quick start

1. Copy `.env.example` to `.env` and set your own secrets.
2. Review `docker-compose.yml` and `Caddyfile` for your domain and ports.
3. Start the stack with Docker Compose.

## License

MIT
