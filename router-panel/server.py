from __future__ import annotations

import base64
import hmac
import json
import mimetypes
import os
import secrets
import hashlib
import socket
import time
from datetime import datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import qrcode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
DATA_DIR = ROOT / "data"
DATA_FILE = DATA_DIR / "routers.json"
WG_CONF = Path(os.environ.get("ROUTER_WG_CONF", "/app/router-wg/wg0.conf"))
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
WG_CONTAINER = os.environ.get("WG_CONTAINER", "wr-control-wireguard")
WG_PEERS_CACHE: dict[str, object] = {"ts": 0.0, "peers": {}}


DEFAULT_STATE = {
    "settings": {
        "serverName": "wg-hub",
        "serverEndpoint": "wg.example.com",
        "serverPort": 51820,
        "serverPublicKey": "CHANGE_ME_PUBLIC_KEY",
        "wgCidr": "10.10.10.0/24",
        "dns": "1.1.1.1",
    },
    "routers": [
        {
            "id": "router-001",
            "name": "Example Router",
            "site": "Primary",
            "wgIp": "10.10.10.2",
            "lanIp": "10.0.0.1",
            "lanCidr": "10.0.0.0/24",
            "model": "OpenWrt Router",
            "status": "installed",
            "allowLan": True,
            "notes": "Example router entry.",
            "publicKey": "CHANGE_ME_PUBLIC_KEY",
            "privateKey": "",
            "presharedKey": "CHANGE_ME_PRESHARED_KEY",
            "createdAt": "2026-06-09T00:00:00",
            "updatedAt": "2026-06-09T00:00:00",
        }
    ],
    "clients": [],
}


def ensure_data() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(json.dumps(DEFAULT_STATE, ensure_ascii=False, indent=2), encoding="utf-8")


def load_state() -> dict:
    ensure_data()
    state = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    state.setdefault("clients", [])
    return state


def save_state(state: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DATA_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def now_iso() -> str:
    return datetime.now().replace(microsecond=0).isoformat()


def auth_secret() -> bytes:
    raw = os.environ.get("PANEL_SESSION_SECRET", "")
    if raw:
        return raw.encode("utf-8")
    return hashlib.sha256(os.environ.get("PANEL_PASSWORD", "change-me").encode("utf-8")).digest()


def build_session(username: str) -> str:
    issued = str(int(datetime.now().timestamp()))
    nonce = secrets.token_hex(8)
    payload = f"{username}:{issued}:{nonce}"
    sig = hmac.new(auth_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session(token: str, username: str) -> bool:
    parts = token.split(":")
    if len(parts) != 4:
        return False
    token_user, issued, nonce, sig = parts
    if token_user != username:
        return False
    payload = f"{token_user}:{issued}:{nonce}"
    expected = hmac.new(auth_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def generate_keypair() -> tuple[str, str]:
    private = x25519.X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64(private_raw), b64(public_raw)


def generate_psk() -> str:
    return b64(os.urandom(32))


def next_router_id(routers: list[dict]) -> str:
    used = {router.get("id") for router in routers}
    i = 1
    while True:
        candidate = f"router-{i:03d}"
        if candidate not in used:
            return candidate
        i += 1


def next_client_id(clients: list[dict]) -> str:
    used = {client.get("id") for client in clients}
    i = 1
    while True:
        candidate = f"client-{i:03d}"
        if candidate not in used:
            return candidate
        i += 1


def next_wg_ip(routers: list[dict]) -> str:
    used = {router.get("wgIp") for router in routers}
    for last in range(2, 255):
        ip = f"10.66.66.{last}"
        if ip not in used:
            return ip
    return "10.66.66.250"


def next_client_ip(state: dict) -> str:
    used = {router.get("wgIp") for router in state.get("routers", [])}
    used.update(client.get("wgIp") for client in state.get("clients", []))
    for last in range(100, 255):
        ip = f"10.66.66.{last}"
        if ip not in used:
            return ip
    return "10.66.66.254"


def router_by_id(state: dict, router_id: str) -> dict | None:
    return next((router for router in state["routers"] if router.get("id") == router_id), None)


def client_by_id(state: dict, client_id: str) -> dict | None:
    return next((client for client in state.get("clients", []) if client.get("id") == client_id), None)


def lan_routes(state: dict) -> list[str]:
    routes = []
    seen = set()
    for router in state.get("routers", []):
        if not router.get("allowLan", True):
            continue
        route = str(router.get("lanCidr") or "").strip()
        if not route or route in seen:
            continue
        seen.add(route)
        routes.append(route)
    return routes


def openwrt_script(settings: dict, router: dict) -> str:
    lan_enabled = router.get("allowLan", True)
    lan_forward = ""
    if lan_enabled:
        lan_forward = """

# 6. Allow traffic from WireGuard to the LAN zone.
uci -q delete firewall.wg_lan
uci set firewall.wg_lan='forwarding'
uci set firewall.wg_lan.src='wg'
uci set firewall.wg_lan.dest='lan'
"""
    return f"""# {router['name']} -> {settings['serverName']}
# Paste into OpenWrt SSH as root.

# 1. Update package lists and install WireGuard support.
opkg update
opkg install kmod-wireguard wireguard-tools luci-proto-wireguard

# 2. Remove old wg0 and firewall entries if they exist.
uci -q delete network.wg0
uci -q delete network.wg0_peer
uci -q delete firewall.wg
uci -q delete firewall.wg_lan

# 3. Create the wg0 interface on the router.
uci set network.wg0='interface'
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='{router.get('privateKey', '')}'
uci add_list network.wg0.addresses='{router['wgIp']}/32'

# 4. Add the VPS as the WireGuard peer.
uci set network.wg0_peer='wireguard_wg0'
uci set network.wg0_peer.description='{settings['serverName']}'
uci set network.wg0_peer.public_key='{settings['serverPublicKey']}'
uci set network.wg0_peer.preshared_key='{router.get('presharedKey', '')}'
uci set network.wg0_peer.endpoint_host='{settings['serverEndpoint']}'
uci set network.wg0_peer.endpoint_port='{settings['serverPort']}'
uci set network.wg0_peer.route_allowed_ips='1'
uci add_list network.wg0_peer.allowed_ips='{settings['wgCidr']}'
uci set network.wg0_peer.persistent_keepalive='25'

# 5. Allow traffic through the WireGuard zone.
uci set firewall.wg='zone'
uci set firewall.wg.name='wg'
uci set firewall.wg.input='ACCEPT'
uci set firewall.wg.output='ACCEPT'
uci set firewall.wg.forward='REJECT'
uci add_list firewall.wg.network='wg0'
{lan_forward}
# 7. Save config files and reboot the router.
uci commit network
uci commit firewall
sync
reboot
"""


def vps_peer_block(router: dict) -> str:
    allowed_ips = [f"{router['wgIp']}/32"]
    if router.get("allowLan", True) and router.get("lanCidr"):
        allowed_ips.append(str(router["lanCidr"]))
    return f"""[Peer]
# {router['name']} | {router.get('site', '')} | LAN {router.get('lanIp', '')}
PublicKey = {router.get('publicKey', '')}
PresharedKey = {router.get('presharedKey', '')}
AllowedIPs = {", ".join(allowed_ips)}
"""


def managed_vps_peer_block(router: dict) -> str:
    allowed_ips = [f"{router['wgIp']}/32"]
    if router.get("allowLan", True) and router.get("lanCidr"):
        allowed_ips.append(str(router["lanCidr"]))
    return f"""[Peer]
# router-panel:{router['id']} {router['name']} | {router.get('site', '')} | LAN {router.get('lanIp', '')}
PublicKey = {router.get('publicKey', '')}
PresharedKey = {router.get('presharedKey', '')}
AllowedIPs = {", ".join(allowed_ips)}
"""


def access_client_config(settings: dict, client: dict) -> str:
    lan_routes_comment = ""
    allowed_ips = [settings["wgCidr"]]
    for route in settings.get("lanRoutes", []):
        if route and route not in allowed_ips:
            allowed_ips.append(route)
    if len(allowed_ips) > 1:
        lan_routes_comment = "\n# LAN routes:\n" + "\n".join(f"# {route}" for route in allowed_ips[1:]) + "\n"
    return f"""[Interface]
PrivateKey = {client.get('privateKey', '')}
Address = {client['wgIp']}/32
DNS = {settings.get('dns', '1.1.1.1')}

[Peer]
PublicKey = {settings['serverPublicKey']}
PresharedKey = {client.get('presharedKey', '')}
Endpoint = {settings['serverEndpoint']}:{settings['serverPort']}
AllowedIPs = {", ".join(allowed_ips)}
PersistentKeepalive = 25
{lan_routes_comment}
"""


def client_vps_peer_block(client: dict) -> str:
    return f"""[Peer]
# access-client:{client['id']} {client['name']} | {client.get('deviceType', '')}
PublicKey = {client.get('publicKey', '')}
PresharedKey = {client.get('presharedKey', '')}
AllowedIPs = {client['wgIp']}/32
"""


def apply_router_to_vps(router: dict) -> dict:
    if not router.get("publicKey"):
        raise ValueError("router public key is empty")
    if not router.get("presharedKey"):
        raise ValueError("router preshared key is empty")
    if not router.get("wgIp"):
        raise ValueError("router WireGuard IP is empty")
    if not WG_CONF.exists():
        raise FileNotFoundError(f"{WG_CONF} not found")

    original = WG_CONF.read_text(encoding="utf-8").strip()
    blocks = original.split("\n[Peer]\n")
    interface = blocks[0].rstrip()
    peer_blocks = [("[Peer]\n" + block).strip() for block in blocks[1:]]
    public_key = router.get("publicKey", "")
    allowed_ip = f"AllowedIPs = {router['wgIp']}/32"
    marker = f"router-panel:{router['id']}"

    kept = []
    removed = 0
    for block in peer_blocks:
        if marker in block or f"PublicKey = {public_key}" in block or allowed_ip in block:
            removed += 1
            continue
        kept.append(block)

    kept.append(managed_vps_peer_block(router).strip())
    next_conf = interface + "\n\n" + "\n\n".join(kept) + "\n"
    WG_CONF.write_text(next_conf, encoding="utf-8")
    restart_wireguard_container()
    return {"ok": True, "conf": str(WG_CONF), "removed": removed, "container": WG_CONTAINER}


def apply_client_to_vps(client: dict) -> dict:
    if not client.get("publicKey"):
        raise ValueError("client public key is empty")
    if not client.get("presharedKey"):
        raise ValueError("client preshared key is empty")
    if not client.get("wgIp"):
        raise ValueError("client WireGuard IP is empty")
    if not WG_CONF.exists():
        raise FileNotFoundError(f"{WG_CONF} not found")

    original = WG_CONF.read_text(encoding="utf-8").strip()
    blocks = original.split("\n[Peer]\n")
    interface = blocks[0].rstrip()
    peer_blocks = [("[Peer]\n" + block).strip() for block in blocks[1:]]
    public_key = client.get("publicKey", "")
    allowed_ip = f"AllowedIPs = {client['wgIp']}/32"
    marker = f"access-client:{client['id']}"

    kept = []
    removed = 0
    for block in peer_blocks:
        if marker in block or f"PublicKey = {public_key}" in block or allowed_ip in block:
            removed += 1
            continue
        kept.append(block)

    kept.append(client_vps_peer_block(client).strip())
    next_conf = interface + "\n\n" + "\n\n".join(kept) + "\n"
    WG_CONF.write_text(next_conf, encoding="utf-8")
    restart_wireguard_container()
    return {"ok": True, "conf": str(WG_CONF), "removed": removed, "container": WG_CONTAINER}


def restart_wireguard_container() -> None:
    status_line, _headers, _body = docker_request("POST", f"/containers/{WG_CONTAINER}/restart?t=10", timeout=25)
    if " 204 " not in status_line and " 200 " not in status_line:
        raise RuntimeError(status_line or "docker restart failed")


def docker_request(method: str, path: str, payload: dict | None = None, timeout: float = 1.2) -> tuple[str, dict, bytes]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else b""
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: docker",
        "Connection: close",
        f"Content-Length: {len(body)}",
    ]
    if payload is not None:
        headers.append("Content-Type: application/json")
    raw_request = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(DOCKER_SOCKET)
        sock.sendall(raw_request)
        chunks = []
        header_seen = False
        expected_body_len = None
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            raw_so_far = b"".join(chunks)
            if not header_seen and b"\r\n\r\n" in raw_so_far:
                head_so_far, _, body_so_far = raw_so_far.partition(b"\r\n\r\n")
                header_seen = True
                status_line_so_far = head_so_far.decode("iso-8859-1", "replace").splitlines()[0]
                if " 204 " in status_line_so_far:
                    break
                for line in head_so_far.decode("iso-8859-1", "replace").splitlines()[1:]:
                    key, sep, value = line.partition(":")
                    if sep and key.lower() == "content-length":
                        try:
                            expected_body_len = int(value.strip())
                        except ValueError:
                            expected_body_len = None
                        break
                if expected_body_len is not None and len(body_so_far) >= expected_body_len:
                    break
            elif header_seen and expected_body_len is not None:
                _head, _, body_so_far = raw_so_far.partition(b"\r\n\r\n")
                if len(body_so_far) >= expected_body_len:
                    break
    raw = b"".join(chunks)
    head, _, response_body = raw.partition(b"\r\n\r\n")
    header_lines = head.decode("iso-8859-1", "replace").splitlines()
    status_line = header_lines[0] if header_lines else ""
    response_headers = {}
    for line in header_lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            response_headers[key.lower()] = value.strip()
    return status_line, response_headers, response_body


def docker_exec(cmd: list[str]) -> str:
    create_status, _headers, create_body = docker_request(
        "POST",
        f"/containers/{WG_CONTAINER}/exec",
        {
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": False,
            "Cmd": cmd,
        },
    )
    if " 201 " not in create_status:
        raise RuntimeError(create_status or "docker exec create failed")
    exec_id = json.loads(create_body.decode("utf-8")).get("Id")
    start_status, _headers, start_body = docker_request(
        "POST",
        f"/exec/{exec_id}/start",
        {"Detach": False, "Tty": False},
    )
    if " 200 " not in start_status:
        raise RuntimeError(start_status or "docker exec start failed")
    return demux_docker_output(start_body).decode("utf-8", "replace")


def demux_docker_output(raw: bytes) -> bytes:
    output = bytearray()
    i = 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4 : i + 8], "big")
        if size <= 0 or i + 8 + size > len(raw):
            break
        output.extend(raw[i + 8 : i + 8 + size])
        i += 8 + size
    if output:
        return bytes(output)
    return raw


def wireguard_peers() -> dict:
    now = time.time()
    cached_ts = float(WG_PEERS_CACHE.get("ts", 0.0))
    cached_peers = WG_PEERS_CACHE.get("peers", {})
    if now - cached_ts < 8 and isinstance(cached_peers, dict):
      return cached_peers
    try:
        dump = docker_exec(["wg", "show", "wg0", "dump"])
    except Exception:
        return {}
    now = time.time()
    peers = {}
    for line in dump.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        public_key, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = parts[:8]
        try:
            latest_handshake = int(handshake)
        except ValueError:
            latest_handshake = 0
        peers[public_key] = {
            "endpoint": endpoint,
            "allowedIps": allowed_ips,
            "latestHandshake": latest_handshake,
            "rx": rx,
            "tx": tx,
            "keepalive": keepalive,
        }
    WG_PEERS_CACHE["ts"] = now
    WG_PEERS_CACHE["peers"] = peers
    return peers


def human_age(seconds: int) -> str:
    if seconds < 5:
        return "только что"
    if seconds < 60:
        return f"{seconds} сек назад"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} мин назад"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} ч назад"
    days = hours // 24
    return f"{days} дн назад"


def enrich_state_with_runtime(state: dict) -> dict:
    peers = wireguard_peers()
    now = int(time.time())
    for item in [*state.get("routers", []), *state.get("clients", [])]:
        peer = peers.get(item.get("publicKey", ""))
        latest = int(peer.get("latestHandshake", 0)) if peer else 0
        if not peer or latest == 0:
            runtime_status = "expected"
            runtime_text = "Ожидается"
            handshake_text = "ещё не подключался"
        else:
            age = max(0, now - latest)
            runtime_status = "online" if age <= 180 else "offline"
            runtime_text = "Онлайн" if runtime_status == "online" else "Оффлайн"
            handshake_text = human_age(age)
        item["runtimeStatus"] = runtime_status
        item["runtimeText"] = runtime_text
        item["lastHandshake"] = latest
        item["lastHandshakeText"] = handshake_text
    return state


def admin_client_config(settings: dict, public_key: str, private_key: str, ip: str = "10.66.66.100") -> str:
    allowed_ips = [settings["wgCidr"]]
    for route in settings.get("lanRoutes", []):
        if route and route not in allowed_ips:
            allowed_ips.append(route)
    lan_routes_comment = ""
    if len(allowed_ips) > 1:
        lan_routes_comment = "\n# LAN routes:\n" + "\n".join(f"# {route}" for route in allowed_ips[1:]) + "\n"
    return f"""[Interface]
PrivateKey = {private_key}
Address = {ip}/32
DNS = {settings.get('dns', '192.168.1.1')}

[Peer]
PublicKey = {settings['serverPublicKey']}
Endpoint = {settings['serverEndpoint']}:{settings['serverPort']}
AllowedIPs = {", ".join(allowed_ips)}
PersistentKeepalive = 25
{lan_routes_comment}

# Add this peer to VPS:
# PublicKey = {public_key}
# AllowedIPs = {ip}/32
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "WireGuardRouterControl/1.0"

    def is_authenticated(self) -> bool:
        user = os.environ.get("PANEL_USER", "")
        password = os.environ.get("PANEL_PASSWORD", "")
        if not user or not password:
            return True
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        session = cookie.get("panel_session")
        if session and verify_session(session.value, user):
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        supplied_user, sep, supplied_password = decoded.partition(":")
        return bool(sep) and hmac.compare_digest(supplied_user, user) and hmac.compare_digest(supplied_password, password)

    def require_auth(self, browser: bool = False) -> bool:
        if self.is_authenticated():
            return True
        if browser:
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        body = b'{"error":"unauthorized"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            if self.is_authenticated():
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self.static_response("/login.html")
        if parsed.path == "/logout":
            self.send_response(HTTPStatus.SEE_OTHER)
            cookie = "panel_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            if os.environ.get("COOKIE_SECURE", "1") != "0":
                cookie += "; Secure"
            self.send_header("Set-Cookie", cookie)
            self.send_header("Location", "/login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/styles.css":
            return self.static_response(parsed.path)
        if parsed.path in {"/app-icon.png", "/apple-touch-icon.png", "/favicon.ico"}:
            if parsed.path == "/favicon.ico":
                return self.static_response("/app-icon.png")
            return self.static_response("/app-icon.png") if parsed.path == "/apple-touch-icon.png" else self.static_response(parsed.path)
        if parsed.path.startswith("/api/"):
            if not self.require_auth(browser=False):
                return
        else:
            if not self.require_auth(browser=True):
                return
        if parsed.path == "/api/state":
            state = load_state()
            state["settings"]["lanRoutes"] = lan_routes(state)
            return self.json_response(enrich_state_with_runtime(state))
        if parsed.path == "/api/export/vps-peers":
            state = load_state()
            body = "\n".join(vps_peer_block(router) for router in state["routers"])
            return self.text_response(body, "text/plain; charset=utf-8")
        if parsed.path == "/api/export/admin-client":
            state = load_state()
            private_key, public_key = generate_keypair()
            state["settings"]["lanRoutes"] = lan_routes(state)
            return self.text_response(admin_client_config(state["settings"], public_key, private_key), "text/plain; charset=utf-8")
        if parsed.path == "/api/qr":
            query = parse_qs(parsed.query)
            text = query.get("text", [""])[0]
            return self.qr_response(text)
        self.static_response(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            return self.handle_login()
        if parsed.path == "/logout":
            self.send_response(HTTPStatus.SEE_OTHER)
            cookie = "panel_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
            if os.environ.get("COOKIE_SECURE", "1") != "0":
                cookie += "; Secure"
            self.send_header("Set-Cookie", cookie)
            self.send_header("Location", "/login")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path.startswith("/api/"):
            if not self.require_auth(browser=False):
                return
        else:
            if not self.require_auth(browser=True):
                return
        if parsed.path == "/api/routers":
            state = load_state()
            payload = self.read_json()
            private_key, public_key = generate_keypair()
            router = {
                "id": next_router_id(state["routers"]),
                "name": payload.get("name") or "Новый роутер",
                "site": payload.get("site") or "",
                "wgIp": payload.get("wgIp") or next_wg_ip(state["routers"]),
                "lanIp": payload.get("lanIp") or "192.168.1.1",
                "lanCidr": payload.get("lanCidr") or "192.168.1.0/24",
                "model": payload.get("model") or "",
                "status": payload.get("status") or "planned",
                "allowLan": bool(payload.get("allowLan", True)),
                "notes": payload.get("notes") or "",
                "privateKey": private_key,
                "publicKey": public_key,
                "presharedKey": generate_psk(),
                "createdAt": now_iso(),
                "updatedAt": now_iso(),
            }
            state["routers"].append(router)
            save_state(state)
            return self.json_response(router, HTTPStatus.CREATED)
        if parsed.path == "/api/clients":
            state = load_state()
            payload = self.read_json()
            private_key, public_key = generate_keypair()
            client = {
                "id": next_client_id(state["clients"]),
                "name": payload.get("name") or "Новое устройство",
                "deviceType": payload.get("deviceType") or "phone",
                "wgIp": payload.get("wgIp") or next_client_ip(state),
                "allowLan": bool(payload.get("allowLan", True)),
                "notes": payload.get("notes") or "",
                "privateKey": private_key,
                "publicKey": public_key,
                "presharedKey": generate_psk(),
                "createdAt": now_iso(),
                "updatedAt": now_iso(),
            }
            state["clients"].append(client)
            save_state(state)
            return self.json_response(client, HTTPStatus.CREATED)
        if parsed.path == "/api/settings":
            state = load_state()
            state["settings"].update(self.read_json())
            save_state(state)
            return self.json_response(state["settings"])
        if parsed.path.startswith("/api/routers/") and parsed.path.endswith("/apply-vps"):
            router_id = parsed.path.split("/")[-2]
            state = load_state()
            router = router_by_id(state, router_id)
            if not router:
                return self.not_found()
            try:
                result = apply_router_to_vps(router)
            except Exception as exc:
                return self.json_response({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return self.json_response(result)
        if parsed.path.startswith("/api/clients/") and parsed.path.endswith("/apply-vps"):
            client_id = parsed.path.split("/")[-2]
            state = load_state()
            client = client_by_id(state, client_id)
            if not client:
                return self.not_found()
            try:
                result = apply_client_to_vps(client)
            except Exception as exc:
                return self.json_response({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return self.json_response(result)
        self.not_found()

    def do_PUT(self) -> None:
        if not self.require_auth(browser=False):
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/routers/"):
            router_id = parsed.path.rsplit("/", 1)[-1]
            state = load_state()
            router = router_by_id(state, router_id)
            if not router:
                return self.not_found()
            payload = self.read_json()
            for key in ("name", "site", "wgIp", "lanIp", "lanCidr", "model", "status", "notes"):
                if key in payload:
                    router[key] = payload[key]
            if "allowLan" in payload:
                router["allowLan"] = bool(payload["allowLan"])
            router["updatedAt"] = now_iso()
            save_state(state)
            return self.json_response(router)
        if parsed.path.startswith("/api/clients/"):
            client_id = parsed.path.rsplit("/", 1)[-1]
            state = load_state()
            client = client_by_id(state, client_id)
            if not client:
                return self.not_found()
            payload = self.read_json()
            for key in ("name", "deviceType", "wgIp", "notes"):
                if key in payload:
                    client[key] = payload[key]
            if "allowLan" in payload:
                client["allowLan"] = bool(payload["allowLan"])
            client["updatedAt"] = now_iso()
            save_state(state)
            return self.json_response(client)
        self.not_found()

    def do_DELETE(self) -> None:
        if not self.require_auth(browser=False):
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/routers/"):
            router_id = parsed.path.rsplit("/", 1)[-1]
            state = load_state()
            state["routers"] = [router for router in state["routers"] if router.get("id") != router_id]
            save_state(state)
            return self.json_response({"ok": True})
        if parsed.path.startswith("/api/clients/"):
            client_id = parsed.path.rsplit("/", 1)[-1]
            state = load_state()
            state["clients"] = [client for client in state.get("clients", []) if client.get("id") != client_id]
            save_state(state)
            return self.json_response({"ok": True})
        self.not_found()

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in parse_qs(body).items()}

    def handle_login(self) -> None:
        payload = self.read_form()
        user = os.environ.get("PANEL_USER", "")
        password = os.environ.get("PANEL_PASSWORD", "")
        if payload.get("username") == user and payload.get("password") == password:
            token = build_session(user)
            cookie = f"panel_session={token}; Path=/; HttpOnly; SameSite=Lax"
            if os.environ.get("COOKIE_SECURE", "1") != "0":
                cookie += "; Secure"
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Set-Cookie", cookie)
            self.send_header("Location", "/")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/login?error=1")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def json_response(self, data: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def text_response(self, text: str, content_type: str) -> None:
        body = text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def qr_response(self, text: str) -> None:
        import io

        buffer = io.BytesIO()
        qrcode.make(text).save(buffer, format="PNG")
        body = buffer.getvalue()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "image/png")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def static_response(self, path: str) -> None:
        if path == "/":
            path = "/index.html"
        target = (PUBLIC / path.lstrip("/")).resolve()
        if not str(target).startswith(str(PUBLIC.resolve())) or not target.exists() or target.is_dir():
            return self.not_found()
        body = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def not_found(self) -> None:
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def main() -> None:
    ensure_data()
    port = int(os.environ.get("PORT", "8787"))
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Router admin panel: http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
