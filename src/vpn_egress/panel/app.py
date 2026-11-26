"""vpn-egress panel: the web UI (the unprivileged half).

OIDC sign-in (group-gated), a status view of what
the router reports, and the DNS blocklist editor. The panel writes
state.json; the router (vpn-egress-router) validates and applies it.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import api, backup
from .state import (
    LABEL_RE,
    allocate_addresses,
    dns_config,
    dns_from_form,
    exit_from_form,
    expiry_info,
    gen_keypair,
    gen_obfuscation,
    list_from_form,
    next_id,
    parse_expiry,
    parse_size,
    parse_wg_conf,
    public_key,
    read_json,
    render_client_config,
    save_section,
    size_text,
    traffic_allowance,
)

APPLY_WAIT = 5.0  # seconds a save waits for the router to apply it
EXIT_SETTLE = 30  # seconds after a change that a down exit still counts as connecting


def state_applied(state_dir: Path) -> bool:
    """Has the router applied the current state.json? True when it can't
    tell (no state yet, or a router that doesn't report it)."""
    status = read_json(state_dir / "status.json") or {}
    if "state_mtime" not in status:
        return True
    try:
        mtime = (state_dir / "state.json").stat().st_mtime_ns
    except FileNotFoundError:
        return True
    if status["state_mtime"] != mtime:
        return False
    # Exits that are new or got a new config take a few seconds to connect:
    # shortly after a change, count them as part of applying it.
    settling = time.time() - mtime / 1e9 < EXIT_SETTLE
    return not (settling and any(e.get("enabled") and not e.get("up") for e in status.get("exits") or []))


def _applying(request: Request) -> dict:
    # Only on GET pages: the script reloads the page, which must not re-send a form.
    settings = getattr(request.app.state, "settings", None)
    return {"applying": request.method == "GET" and settings is not None and not state_applied(settings.state_dir)}


TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"), context_processors=[_applying])
ICON_SVG = (Path(__file__).parent / "static" / "icon.svg").read_bytes()
SESSION_HOURS = 8


@dataclass(frozen=True)
class Settings:
    issuer: str
    client_id: str
    client_secret: str
    public_url: str
    session_secret: str
    allowed_groups: frozenset[str] = field(default_factory=frozenset)
    state_dir: Path = Path("/state")

    @classmethod
    def from_env(cls) -> Settings:
        def need(name: str) -> str:
            value = os.environ.get(name, "").strip()
            if not value:
                raise RuntimeError(f"{name} is not set")
            return value

        groups = frozenset(g.strip() for g in need("OIDC_ALLOWED_GROUPS").split(",") if g.strip())
        if not groups:
            raise RuntimeError("OIDC_ALLOWED_GROUPS has no groups")
        return cls(
            issuer=need("OIDC_ISSUER").rstrip("/"),
            client_id=need("OIDC_CLIENT_ID"),
            client_secret=need("OIDC_CLIENT_SECRET"),
            public_url=need("PUBLIC_URL").rstrip("/"),
            session_secret=need("SESSION_SECRET"),
            allowed_groups=groups,
            state_dir=Path(os.environ.get("STATE_DIR", "/state")),
        )


def is_allowed(claims: dict, allowed: frozenset[str]) -> bool:
    groups = claims.get("groups") or []
    if isinstance(groups, str):
        groups = [groups]
    return bool(allowed & set(groups))


def public_state(state: dict | None) -> dict:
    """The parts of state.json that are safe to show (no keys)."""
    state = state or {}
    exits = [
        {
            "id": e.get("id"),
            "name": e.get("name"),
            "enabled": e.get("enabled", True),
            "endpoint": (e.get("wireguard") or {}).get("endpoint"),
        }
        for e in state.get("exits", [])
        if isinstance(e, dict)
    ]
    lists = [
        {
            "id": l.get("id"),
            "name": l.get("name"),
            "exit": l.get("exit"),
            "when_down": l.get("when_down", "block"),
            "entries": len(l.get("cidrs", [])),
        }
        for l in state.get("lists", [])
        if isinstance(l, dict)
    ]
    return {"exits": exits, "lists": lists}


def human_bytes(n: int | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f}\u00a0{unit}" if unit == "B" else f"{n:.1f}\u00a0{unit}"
        n /= 1024
    return ""


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = secrets.token_urlsafe(32)
    return token


def csrf_ok(request: Request, form) -> bool:
    expected = request.session.get("csrf")
    return bool(expected) and secrets.compare_digest(expected, str(form.get("csrf", "")))


def human_age(seconds: int | None) -> str:
    if seconds is None:
        return "never"
    if seconds < 120:
        return f"{seconds}\u00a0s\u00a0ago"
    if seconds < 7200:
        return f"{seconds // 60}\u00a0min\u00a0ago"
    return f"{seconds // 3600}\u00a0h\u00a0ago"


def human_size(n: int | None) -> str:
    """Decimal units, as providers bill transfer (10 TB = 10^13 bytes)."""
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            digits = 0 if unit in ("B", "KB") or n >= 100 else 1
            return f"{n:.{digits}f}\u00a0{unit}"
        n /= 1000
    return ""


def today() -> datetime.date:
    return datetime.datetime.now(datetime.UTC).date()


def warnings(state: dict, traffic: dict | None) -> list[dict]:
    """Things to act on soon: exit configs expiring, the transfer allowance."""
    out = []
    for e in state.get("exits", []):
        if not isinstance(e, dict) or not e.get("enabled", True):
            continue
        info = expiry_info(e.get("expires"), today())
        if info and info["level"] != "ok":
            when = f"expired {-info['days']} days ago" if info["days"] < 0 else f"expires in {info['days']} days"
            out.append(
                {
                    "kind": "exit_expiry",
                    "level": info["level"],
                    "text": f"Exit {e.get('name')}: config {when} ({info['date']}). "
                    "Get a new one from the provider and replace it on Exits.",
                }
            )
    if traffic and traffic.get("allowance"):
        allowance, tx, proj = traffic["allowance"], traffic.get("tx", 0), traffic.get("projected_tx")
        if tx >= allowance:
            out.append(
                {
                    "kind": "traffic",
                    "level": "bad",
                    "text": f"Transfer this month is over the allowance: {human_size(tx)}.",
                }
            )
        elif tx >= 0.8 * allowance:
            out.append(
                {
                    "kind": "traffic",
                    "level": "warn",
                    "text": f"Transfer this month is at {tx / allowance:.0%} of the allowance.",
                }
            )
        elif proj and proj > allowance:
            out.append(
                {
                    "kind": "traffic",
                    "level": "warn",
                    "text": f"At this rate, transfer reaches {human_size(proj)} by the end of the month.",
                }
            )
    return out


STATUS_STALE = 300  # seconds without a router status before the API reports it


def router_warnings(status: dict | None, applied: bool) -> list[dict]:
    """For monitoring: the router itself (the Status page shows these inline)."""
    now = time.time()
    if not status or now - status.get("updated", 0) > STATUS_STALE:
        return [{"kind": "router", "level": "bad", "text": "No recent status from the router: is it running?"}]
    out = []
    if status.get("error"):
        out.append({"kind": "router", "level": "bad", "text": f"Router: {status['error']}"})
    if applied:  # right after a change, new exits are still connecting
        for e in status.get("exits") or []:
            if e.get("enabled") and not e.get("up"):
                out.append({"kind": "exit_down", "level": "bad", "text": f"Exit {e.get('name')} is down."})
    return out


TEMPLATES.env.filters["bytes"] = human_bytes
TEMPLATES.env.filters["size"] = human_size
TEMPLATES.env.filters["age"] = human_age
TEMPLATES.env.filters["date"] = lambda ts: time.strftime("%-d %b %H:%M UTC", time.gmtime(ts))


def create_app(settings: Settings, oauth: OAuth | None = None) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    @app.middleware("http")
    async def wait_for_router(request: Request, call_next):
        """After a POST that changed the state, give the router a moment to
        apply it, so the next page shows the result."""
        state_file = settings.state_dir / "state.json"

        def mtime():
            try:
                return state_file.stat().st_mtime_ns
            except FileNotFoundError:
                return None

        before = mtime() if request.method == "POST" else None
        response = await call_next(request)
        if request.method == "POST" and mtime() != before:
            deadline = time.monotonic() + APPLY_WAIT
            while not state_applied(settings.state_dir) and time.monotonic() < deadline:
                await asyncio.sleep(0.25)
        return response

    @app.get("/applied", include_in_schema=False)
    async def applied(request: Request):
        if current_user(request) is None:
            return PlainTextResponse("", status_code=401)
        return {"applied": state_applied(settings.state_dir)}

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        session_cookie="egress_session",
        max_age=SESSION_HOURS * 3600,
        same_site="lax",
        https_only=settings.public_url.startswith("https://"),
    )

    if oauth is None:
        oauth = OAuth()
        oauth.register(
            name="oidc",
            client_id=settings.client_id,
            client_secret=settings.client_secret,
            server_metadata_url=f"{settings.issuer}/.well-known/openid-configuration",
            client_kwargs={"scope": "openid profile email groups", "code_challenge_method": "S256"},
        )
    client = oauth.create_client("oidc")
    redirect_uri = f"{settings.public_url}/auth/callback"

    def current_user(request: Request) -> dict | None:
        user = request.session.get("user")
        if not user or time.time() - user.get("at", 0) > SESSION_HOURS * 3600:
            return None
        return user

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon():
        return Response(ICON_SVG, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    @app.get("/login")
    async def login(request: Request):
        request.session.pop("user", None)
        return await client.authorize_redirect(request, redirect_uri)

    @app.get("/auth/callback")
    async def callback(request: Request):
        try:
            token = await client.authorize_access_token(request)
        except OAuthError as exc:
            return TEMPLATES.TemplateResponse(
                request,
                "message.html",
                {"title": "Sign-in failed", "text": exc.error or "OIDC error", "retry": True},
                status_code=400,
            )
        claims = dict(token.get("userinfo") or {})
        if "groups" not in claims:
            claims.update(await client.userinfo(token=token))
        if not is_allowed(claims, settings.allowed_groups):
            return TEMPLATES.TemplateResponse(
                request,
                "message.html",
                {
                    "title": "Not allowed",
                    "text": f"{claims.get('preferred_username') or claims.get('email') or 'This account'} "
                    "is not in a group that may use the egress panel.",
                    "retry": False,
                },
                status_code=403,
            )
        request.session["user"] = {
            "sub": claims.get("sub"),
            "name": claims.get("name") or claims.get("preferred_username") or claims.get("email"),
            "email": claims.get("email"),
            "groups": sorted(set(claims.get("groups") or [])),
            "at": int(time.time()),
        }
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/", status_code=303)

    def load_traffic(raw_state: dict) -> dict | None:
        traffic = read_json(settings.state_dir / "traffic.json")
        if traffic:
            traffic["allowance"] = traffic_allowance(raw_state, traffic)
        return traffic

    def api_tokens(raw_state: dict) -> list[dict]:
        used = api.usage(settings.state_dir)
        return [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "scope": t.get("scope"),
                "created": t.get("created"),
                "last_used": used.get(str(t.get("id"))),
            }
            for t in api.tokens(raw_state)
        ]

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        user = current_user(request)
        if user is None:
            # A landing page, not an automatic OIDC redirect: with a live
            # identity-provider session that redirect signs straight back in, so
            # signing out would look like it did nothing.
            return TEMPLATES.TemplateResponse(request, "landing.html", {})
        status = read_json(settings.state_dir / "status.json")
        raw_state = read_json(settings.state_dir / "state.json") or {}
        state = public_state(raw_state)
        traffic = load_traffic(raw_state)
        return TEMPLATES.TemplateResponse(
            request,
            "index.html",
            {
                "user": user,
                "page": "status",
                "csrf": csrf_token(request),
                "status": status,
                "state": state,
                "traffic": traffic,
                "snapshot": (lambda snaps: backup.snapshot_time(snaps[-1]) if snaps else None)(
                    backup.snapshots(settings.state_dir)
                ),
                "allowance_text": size_text(traffic.get("allowance")) if traffic else "",
                "tokens": api_tokens(raw_state),
                "warnings": warnings(raw_state, traffic),
                "flash": request.session.pop("flash", None),
                "status_age": int(time.time()) - status["updated"] if status and status.get("updated") else None,
                "build_sha": os.environ.get("BUILD_SHA", "unknown")[:12],
            },
        )

    def dns_page(
        request: Request,
        user: dict,
        config: dict,
        rows: list[dict],
        errors: list[str],
        saved: bool,
        status_code: int = 200,
    ):
        status = read_json(settings.state_dir / "dns-status.json")
        return TEMPLATES.TemplateResponse(
            request,
            "dns.html",
            {
                "user": user,
                "page": "dns",
                "csrf": csrf_token(request),
                "rows": rows,
                "block": "\n".join(config.get("block", [])),
                "allow": "\n".join(config.get("allow", [])),
                "errors": errors,
                "saved": saved,
                "status": status,
                "status_age": int(time.time()) - status["updated"] if status and status.get("updated") else None,
            },
            status_code=status_code,
        )

    @app.get("/dns", response_class=HTMLResponse)
    async def dns_get(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        config, _source = dns_config(settings.state_dir)
        rows = [
            {"name": l.get("name", ""), "url": l.get("url", ""), "enabled": l.get("enabled", True)}
            for l in config.get("lists", [])
            if isinstance(l, dict)
        ]
        return dns_page(request, user, config, rows, [], request.query_params.get("saved") == "1")

    @app.post("/dns", response_class=HTMLResponse)
    async def dns_post(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        form = await request.form()
        if not csrf_ok(request, form):
            return PlainTextResponse("Form expired, reload the page.", status_code=400)
        config, rows, errors = dns_from_form(form)
        if errors:
            return dns_page(request, user, config, rows, errors, False, status_code=400)
        save_section(settings.state_dir, "dns", config)
        return RedirectResponse("/dns?saved=1", status_code=303)

    # --- exits and lists -------------------------------------------------------

    def load_state() -> dict:
        return read_json(settings.state_dir / "state.json") or {}

    def status_by_id(key: str) -> dict:
        status = read_json(settings.state_dir / "status.json") or {}
        return {s.get("id"): s for s in status.get(key, []) if isinstance(s, dict)}

    def flash(request: Request, message: str, bad: bool = False) -> None:
        request.session["flash"] = {"text": message, "bad": bad}

    async def guarded_form(request: Request):
        """(user, form) for a signed-in POST with a valid CSRF token, else a response."""
        user = current_user(request)
        if user is None:
            return None, RedirectResponse("/", status_code=303)
        form = await request.form()
        if not csrf_ok(request, form):
            return None, PlainTextResponse("Form expired, reload the page.", status_code=400)
        return user, form

    def exits_page(request: Request, user: dict, errors=None, values=None, status_code=200):
        state = load_state()
        st = status_by_id("exits")
        used = {l.get("exit") for l in state.get("lists", []) if isinstance(l, dict)}
        exits = []
        for e in state.get("exits", []):
            if not isinstance(e, dict):
                continue
            wg = e.get("wireguard") or {}
            exits.append(
                {
                    "id": e.get("id"),
                    "name": e.get("name"),
                    "enabled": e.get("enabled", True),
                    "endpoint": wg.get("endpoint"),
                    "ipv6": bool(wg.get("address6")),
                    "in_use": e.get("id") in used,
                    "status": st.get(e.get("id")),
                    "expiry": expiry_info(e.get("expires"), today()),
                }
            )
        return TEMPLATES.TemplateResponse(
            request,
            "exits.html",
            {
                "user": user,
                "page": "exits",
                "csrf": csrf_token(request),
                "exits": exits,
                "next_year": (today() + datetime.timedelta(days=365)).isoformat(),
                "flash": request.session.pop("flash", None),
                "errors": errors or [],
                "values": values or {},
            },
            status_code=status_code,
        )

    @app.get("/exits", response_class=HTMLResponse)
    async def exits_get(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        return exits_page(request, user)

    @app.post("/exits/add", response_class=HTMLResponse)
    async def exits_add(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        name = (form.get("name") or "").strip()
        errors = [] if LABEL_RE.match(name) else ["Name must be 1–40 characters"]
        wg, conf_errors = parse_wg_conf(form.get("conf", ""))
        errors += conf_errors
        expires = parse_expiry(form.get("expires", ""), errors)
        state = load_state()
        exits = [e for e in state.get("exits", []) if isinstance(e, dict)]
        if any(e.get("name") == name for e in exits):
            errors.append(f"An exit named {name} already exists")
        new_id = next_id(exits)
        if new_id is None:
            errors.append("No free exit slots")
        if errors:
            return exits_page(request, user, errors, {"name": name, "expires": form.get("expires")}, status_code=400)
        exits.append({"id": new_id, "name": name, "enabled": True, "expires": expires, "wireguard": wg})
        save_section(settings.state_dir, "exits", exits)
        flash(request, f"Added {name}. It connects within a minute.")
        return RedirectResponse("/exits", status_code=303)

    def find(items: list, item_id: int) -> dict | None:
        return next((i for i in items if isinstance(i, dict) and i.get("id") == item_id), None)

    @app.post("/exits/{exit_id}/toggle")
    async def exits_toggle(request: Request, exit_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        exits = load_state().get("exits", [])
        e = find(exits, exit_id)
        if e:
            e["enabled"] = not e.get("enabled", True)
            save_section(settings.state_dir, "exits", exits)
            flash(request, f"{e['name']} {'enabled' if e['enabled'] else 'disabled'}.")
        return RedirectResponse("/exits", status_code=303)

    @app.post("/exits/{exit_id}/replace", response_class=HTMLResponse)
    async def exits_replace(request: Request, exit_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        exits = load_state().get("exits", [])
        e = find(exits, exit_id)
        if e is None:
            return RedirectResponse("/exits", status_code=303)
        wg, errors = parse_wg_conf(form.get("conf", ""))
        expires = parse_expiry(form.get("expires", ""), errors)
        if errors:
            return exits_page(request, user, [f"{e['name']}: {x}" for x in errors], status_code=400)
        e["wireguard"] = wg
        e["expires"] = expires
        save_section(settings.state_dir, "exits", exits)
        flash(request, f"{e['name']}: new config saved; it reconnects within a minute.")
        return RedirectResponse("/exits", status_code=303)

    @app.post("/traffic")
    async def traffic_save(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        errors: list[str] = []
        off = form.get("action") == "off" or not (form.get("allowance") or "").strip()
        allowance = None if off else parse_size(form.get("allowance", ""), errors)
        if errors:
            flash(request, errors[0], bad=True)
        else:
            save_section(settings.state_dir, "traffic", {"allowance": allowance})
            flash(request, f"Allowance set to {human_size(allowance)}." if allowance else "Allowance turned off.")
        return RedirectResponse("/", status_code=303)

    # --- API ------------------------------------------------------------------------

    @app.post("/api/tokens", response_class=HTMLResponse)
    async def api_token_create(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        section, token, errors = api.create(load_state(), form.get("name") or "", form.get("scope") or "")
        if errors:
            flash(request, f"Token not created: {'; '.join(errors)}.", bad=True)
            return RedirectResponse("/#api", status_code=303)
        save_section(settings.state_dir, "api", section)
        return TEMPLATES.TemplateResponse(
            request,
            "api_token.html",
            {
                "user": user,
                "page": "status",
                "csrf": csrf_token(request),
                "token": token,
                "entry": section["tokens"][-1],
                "public_url": settings.public_url,
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/tokens/{token_id}/delete")
    async def api_token_delete(request: Request, token_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        items = api.tokens(load_state())
        gone = [t for t in items if t.get("id") == token_id]
        if gone:
            save_section(settings.state_dir, "api", {"tokens": [t for t in items if t.get("id") != token_id]})
            flash(request, f"Deleted token {gone[0].get('name')}; it stops working now.")
        return RedirectResponse("/#api", status_code=303)

    def api_auth(request: Request, need: str) -> tuple[dict | None, JSONResponse | None]:
        token, error = api.authenticate(load_state(), request.headers.get("authorization"), need)
        if token is None:
            code = 403 if error and "scope" in error else 401
            return None, JSONResponse({"error": error}, status_code=code, headers={"WWW-Authenticate": "Bearer"})
        api.record_use(settings.state_dir, token["id"])
        return token, None

    @app.get("/api/status")
    async def api_status(request: Request):
        _, denied = api_auth(request, "status")
        if denied:
            return denied
        raw_state = load_state()
        status = read_json(settings.state_dir / "status.json")
        traffic = load_traffic(raw_state)
        exits = {e.get("id"): e for e in (status or {}).get("exits", []) if isinstance(e, dict)}
        pipe = (status or {}).get("pipe") or {}
        return JSONResponse(
            {
                "warnings": router_warnings(status, state_applied(settings.state_dir)) + warnings(raw_state, traffic),
                "status_updated": (status or {}).get("updated"),
                "router_error": (status or {}).get("error"),
                "exits": [
                    {
                        "name": e.get("name"),
                        "enabled": e.get("enabled", True),
                        "up": (exits.get(e.get("id")) or {}).get("up"),
                        "handshake_age": (exits.get(e.get("id")) or {}).get("handshake_age"),
                        "expires": e.get("expires"),
                        "days_left": (expiry_info(e.get("expires"), today()) or {}).get("days"),
                    }
                    for e in raw_state.get("exits", [])
                    if isinstance(e, dict)
                ],
                "traffic": {k: traffic.get(k) for k in ("month", "since", "tx", "rx", "allowance", "projected_tx")}
                if traffic
                else None,
                "pipe_peers": [
                    {"handshake_age": p.get("handshake_age"), "rx": p.get("rx"), "tx": p.get("tx")}
                    for p in pipe.get("peers") or []
                ],
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/backup")
    async def api_backup(request: Request):
        _, denied = api_auth(request, "backup")
        if denied:
            return denied
        passphrase = ""
        if await request.body():
            try:
                body = await request.json()
            except ValueError:
                return JSONResponse({"error": 'body must be JSON: {"passphrase": "..."}'}, status_code=400)
            passphrase = body.get("passphrase", "") if isinstance(body, dict) else None
            if not isinstance(passphrase, str):
                return JSONResponse({"error": "passphrase must be a string"}, status_code=400)
        name = f"vpn-egress-backup-{today().isoformat()}.json"
        return Response(
            backup.export(load_state(), passphrase),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
        )

    # --- backup ----------------------------------------------------------------------

    @app.post("/backup/export")
    async def backup_export(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        passphrase = form.get("passphrase") or ""
        if passphrase != (form.get("passphrase2") or ""):
            flash(request, "Backup: the passphrases don't match.", bad=True)
            return RedirectResponse("/#backup", status_code=303)
        data = backup.export(load_state(), passphrase)
        name = f"vpn-egress-backup-{today().isoformat()}.json"
        return Response(
            data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
        )

    def backup_preview(request: Request, user: dict, state: dict, created: str, errors: list[str]):
        return TEMPLATES.TemplateResponse(
            request,
            "backup_preview.html",
            {
                "user": user,
                "page": "status",
                "csrf": csrf_token(request),
                "created": created,
                "errors": errors,
                "current": backup.summary(load_state()),
                "incoming": backup.summary(state),
            },
            status_code=400 if errors else 200,
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/backup/upload", response_class=HTMLResponse)
    async def backup_upload(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        upload = form.get("file")
        raw = await upload.read(backup.MAX_SIZE + 1) if hasattr(upload, "read") else b""
        try:
            if not raw:
                raise backup.BackupError("Choose a backup file")
            state, created = backup.read(raw, form.get("passphrase") or "")
        except backup.BackupError as exc:
            flash(request, f"Backup not read: {exc}.", bad=True)
            return RedirectResponse("/#backup", status_code=303)
        errors = backup.check(state, pipe_status().get("addresses"))
        if errors:
            backup.drop_pending(settings.state_dir)
            return backup_preview(request, user, state, created, errors)
        request.session["restore"] = backup.save_pending(settings.state_dir, state, created)
        return backup_preview(request, user, state, created, [])

    @app.post("/backup/restore")
    async def backup_restore(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        pending = backup.take_pending(settings.state_dir, request.session.pop("restore", ""))
        if pending is None:
            flash(request, "Nothing to restore (the upload expired after 15 minutes); upload it again.", bad=True)
        else:
            backup.restore(settings.state_dir, pending[0])
            flash(request, f"Restored the backup from {pending[1] or 'an unknown date'}.")
        return RedirectResponse("/", status_code=303)

    @app.post("/backup/cancel")
    async def backup_cancel(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        request.session.pop("restore", None)
        backup.drop_pending(settings.state_dir)
        return RedirectResponse("/#backup", status_code=303)

    @app.post("/backup/undo")
    async def backup_undo(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        when = backup.undo(settings.state_dir)
        if when:
            flash(request, f"Put back the settings as they were before the restore ({when}).")
        else:
            flash(request, "There is nothing to undo.", bad=True)
        return RedirectResponse("/", status_code=303)

    @app.post("/exits/{exit_id}/edit", response_class=HTMLResponse)
    async def exits_edit(request: Request, exit_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        exits = load_state().get("exits", [])
        e = find(exits, exit_id)
        if e is None:
            return RedirectResponse("/exits", status_code=303)
        name = (form.get("name") or "").strip()
        errors = [] if LABEL_RE.match(name) else ["Name must be 1–40 characters"]
        if any(x is not e and isinstance(x, dict) and x.get("name") == name for x in exits):
            errors.append(f"An exit named {name} already exists")
        expires = parse_expiry(form.get("expires", ""), errors)
        if errors:
            return exits_page(request, user, [f"{e['name']}: {x}" for x in errors], status_code=400)
        e["name"], e["expires"] = name, expires
        save_section(settings.state_dir, "exits", exits)
        flash(request, f"{name} saved.")
        return RedirectResponse("/exits", status_code=303)

    @app.post("/exits/{exit_id}/delete")
    async def exits_delete(request: Request, exit_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        state = load_state()
        e = find(state.get("exits", []), exit_id)
        if e is None:
            return RedirectResponse("/exits", status_code=303)
        users = [l.get("name") for l in state.get("lists", []) if isinstance(l, dict) and l.get("exit") == exit_id]
        if (state.get("default") or {}).get("exit") == exit_id:
            users.append("Everything else")
        if users:
            flash(request, f"{e['name']} is used by {', '.join(users)}; change those first.", bad=True)
        else:
            save_section(settings.state_dir, "exits", [x for x in state["exits"] if x is not e])
            flash(request, f"Deleted {e['name']}.")
        return RedirectResponse("/exits", status_code=303)

    def lists_page(request: Request, user: dict, edit=None, status_code=200):
        """edit: {"id": list id or "new", "values": form values, "errors": [...]}"""
        state = load_state()
        exits = [
            {
                "id": e.get("id"),
                "name": e.get("name"),
                "has_dns": any("." in d for d in (e.get("wireguard") or {}).get("dns", [])),
            }
            for e in state.get("exits", [])
            if isinstance(e, dict)
        ]
        st = status_by_id("lists")
        lists = []
        for l in state.get("lists", []):
            if not isinstance(l, dict):
                continue
            item = {
                "id": l.get("id"),
                "name": l.get("name"),
                "exit": l.get("exit"),
                "when_down": l.get("when_down", "block"),
                "resolve_via_exit": l.get("resolve_via_exit", False),
                "entries": "\n".join(l.get("entries", l.get("cidrs", []))),
                "status": st.get(l.get("id")),
                "errors": [],
            }
            if edit and edit["id"] == l.get("id"):
                item.update(edit["values"], errors=edit["errors"])
            lists.append(item)
        new = {
            "name": "",
            "exit": exits[0]["id"] if exits else None,
            "when_down": "block",
            "resolve_via_exit": True,
            "entries": "",
            "errors": [],
        }
        if edit and edit["id"] == "new":
            new.update(edit["values"], errors=edit["errors"])
        d = state.get("default") or {}
        default = {"exit": d.get("exit", "direct"), "when_down": d.get("when_down", "block"), "errors": []}
        if edit and edit["id"] == "default":
            default.update(edit["values"], errors=edit["errors"])
        return TEMPLATES.TemplateResponse(
            request,
            "routing.html",
            {
                "user": user,
                "page": "routing",
                "csrf": csrf_token(request),
                "lists": lists,
                "exits": exits,
                "new": new,
                "default": default,
                "now": int(time.time()),
                "flash": request.session.pop("flash", None),
            },
            status_code=status_code,
        )

    def edit_values(form, parsed: dict) -> dict:
        return {
            "name": parsed["name"],
            "exit": parsed["exit"],
            "when_down": parsed["when_down"],
            "resolve_via_exit": parsed["resolve_via_exit"],
            "entries": form.get("entries", ""),
        }

    @app.get("/routing", response_class=HTMLResponse)
    async def lists_get(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        return lists_page(request, user)

    @app.post("/routing/add", response_class=HTMLResponse)
    async def lists_add(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        state = load_state()
        lists = [l for l in state.get("lists", []) if isinstance(l, dict)]
        errors: list[str] = []
        parsed = list_from_form(form, state.get("exits", []), errors)
        if any(l.get("name") == parsed["name"] for l in lists):
            errors.append(f"A list named {parsed['name']} already exists")
        new_id = next_id(lists)
        if new_id is None:
            errors.append("No free list slots")
        if errors:
            return lists_page(request, user, {"id": "new", "values": edit_values(form, parsed), "errors": errors}, 400)
        lists.append({"id": new_id, **parsed})
        save_section(settings.state_dir, "lists", lists)
        flash(request, f"Added {parsed['name']}.")
        return RedirectResponse("/routing", status_code=303)

    @app.post("/routing/{list_id}/save", response_class=HTMLResponse)
    async def lists_save(request: Request, list_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        state = load_state()
        lists = [l for l in state.get("lists", []) if isinstance(l, dict)]
        l = find(lists, list_id)
        if l is None:
            return RedirectResponse("/routing", status_code=303)
        errors: list[str] = []
        parsed = list_from_form(form, state.get("exits", []), errors)
        if any(x.get("name") == parsed["name"] and x is not l for x in lists):
            errors.append(f"A list named {parsed['name']} already exists")
        if errors:
            return lists_page(
                request, user, {"id": list_id, "values": edit_values(form, parsed), "errors": errors}, 400
            )
        l.pop("cidrs", None)
        l.update(parsed)
        save_section(settings.state_dir, "lists", lists)
        flash(request, f"Saved {parsed['name']}.")
        return RedirectResponse(f"/routing#list-{list_id}", status_code=303)

    @app.post("/routing/{list_id}/move")
    async def lists_move(request: Request, list_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        lists = [l for l in load_state().get("lists", []) if isinstance(l, dict)]
        idx = next((i for i, l in enumerate(lists) if l.get("id") == list_id), None)
        step = -1 if form.get("dir") == "up" else 1
        if idx is not None and 0 <= idx + step < len(lists):
            lists[idx], lists[idx + step] = lists[idx + step], lists[idx]
            save_section(settings.state_dir, "lists", lists)
        return RedirectResponse(f"/routing#list-{list_id}", status_code=303)

    @app.post("/routing/{list_id}/delete")
    async def lists_delete(request: Request, list_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        lists = [l for l in load_state().get("lists", []) if isinstance(l, dict)]
        l = find(lists, list_id)
        if l:
            save_section(settings.state_dir, "lists", [x for x in lists if x is not l])
            flash(request, f"Deleted {l['name']}.")
        return RedirectResponse("/routing", status_code=303)

    # --- the pipe --------------------------------------------------------------

    def pipe_status() -> dict:
        return (read_json(settings.state_dir / "status.json") or {}).get("pipe") or {}

    def pipe_page(request: Request, user: dict, errors=None, values=None, status_code=200):
        state = load_state()
        pipe = state.get("pipe")
        ps = pipe_status()
        runtime = {p.get("public_key"): p for p in ps.get("peers", [])}
        peers = []
        for p in (pipe or {}).get("peers", []):
            peers.append({**p, "runtime": runtime.get(p.get("public_key"))})
        return TEMPLATES.TemplateResponse(
            request,
            "pipe.html",
            {
                "user": user,
                "page": "pipe",
                "csrf": csrf_token(request),
                "pipe": pipe,
                "server_key": public_key(pipe["private_key"]) if pipe else ps.get("public_key"),
                "ps": ps,
                "peers": peers,
                "unmanaged_peers": [] if pipe else ps.get("peers", []),
                "errors": errors or [],
                "values": values or {},
                "flash": request.session.pop("flash", None),
            },
            status_code=status_code,
        )

    def config_page(request: Request, user: dict, peer: dict, conf: str, secret: bool):
        import segno

        qr = segno.make(conf, error="l").svg_inline(omitsize=True, dark="#000", light="#fff") if secret else None
        resp = TEMPLATES.TemplateResponse(
            request,
            "pipe_config.html",
            {"user": user, "page": "pipe", "peer": peer, "conf": conf, "qr": qr, "secret": secret},
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/pipe", response_class=HTMLResponse)
    async def pipe_get(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        return pipe_page(request, user)

    @app.post("/pipe/recreate")
    async def pipe_recreate(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        pipe = load_state().get("pipe") or {"peers": []}
        priv, _ = gen_keypair()
        pipe.update(private_key=priv, obfuscation=gen_obfuscation())
        save_section(settings.state_dir, "pipe", pipe)
        flash(request, "New server key and obfuscation saved. Every peer needs a new config.")
        return RedirectResponse("/pipe", status_code=303)

    @app.post("/pipe/peers", response_class=HTMLResponse)
    async def pipe_add_peer(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        import base64
        import ipaddress

        pipe = load_state().get("pipe")
        name = (form.get("name") or "").strip()
        pub = (form.get("public_key") or "").strip()
        raw_nets = (form.get("networks") or "").replace(",", "\n").split()
        errors = [] if LABEL_RE.match(name) else ["Name must be 1–40 characters"]
        if pub:
            try:
                assert len(base64.b64decode(pub, validate=True)) == 32
            except Exception:
                errors.append("Public key must be a WireGuard key (44 characters, base64)")
        nets: list[str] = []
        for n in raw_nets:
            if n.lower() == "any":
                nets += ["0.0.0.0/0", "::/0"]
                continue
            try:
                nets.append(str(ipaddress.ip_network(n, strict=False)))
            except ValueError:
                errors.append(f"“{n}” is not a network")
        if not pipe:
            errors.append("Create the pipe first")
        elif pub and any(p.get("public_key") == pub for p in pipe["peers"]):
            errors.append("A peer with this public key exists")
        a4, a6 = allocate_addresses(pipe, pipe_status().get("addresses", [])) if pipe else (None, None)
        if pipe and not a4:
            errors.append("No free address in the pipe subnet")
        if errors:
            values = {"name": name, "public_key": pub, "networks": form.get("networks", "")}
            return pipe_page(request, user, errors, values, 400)
        priv = None
        if not pub:
            priv, pub = gen_keypair()
        peer = {
            "id": next_id(pipe["peers"]) or len(pipe["peers"]) + 1,
            "name": name,
            "public_key": pub,
            "own_key": priv is None,
            "address": a4,
            "address6": a6,
            "routes": sorted(set(nets), key=nets.index),
            "created": int(time.time()),
        }
        pipe["peers"].append(peer)
        save_section(settings.state_dir, "pipe", pipe)
        if priv is None:
            return RedirectResponse(f"/pipe/peers/{peer['id']}/config", status_code=303)
        return config_page(request, user, peer, render_client_config(pipe, peer, pipe_status(), priv), True)

    @app.get("/pipe/peers/{peer_id}/config", response_class=HTMLResponse)
    async def pipe_peer_config(request: Request, peer_id: int):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/", status_code=303)
        pipe = load_state().get("pipe") or {}
        peer = find(pipe.get("peers", []), peer_id)
        if peer is None or not (peer.get("own_key") or peer.get("kind") == "site"):
            return RedirectResponse("/pipe", status_code=303)
        return config_page(request, user, peer, render_client_config(pipe, peer, pipe_status(), None), False)

    @app.post("/pipe/peers/{peer_id}/regenerate", response_class=HTMLResponse)
    async def pipe_regenerate(request: Request, peer_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        pipe = load_state().get("pipe") or {}
        peer = find(pipe.get("peers", []), peer_id)
        if peer is None:
            return RedirectResponse("/pipe", status_code=303)
        priv, pub = gen_keypair()
        peer.update(public_key=pub, own_key=False)
        peer.pop("kind", None)
        save_section(settings.state_dir, "pipe", pipe)
        return config_page(request, user, peer, render_client_config(pipe, peer, pipe_status(), priv), True)

    @app.post("/pipe/peers/{peer_id}/delete")
    async def pipe_delete(request: Request, peer_id: int):
        user, form = await guarded_form(request)
        if user is None:
            return form
        pipe = load_state().get("pipe") or {}
        peer = find(pipe.get("peers", []), peer_id)
        if peer:
            pipe["peers"] = [p for p in pipe["peers"] if p is not peer]
            save_section(settings.state_dir, "pipe", pipe)
            flash(request, f"Deleted {peer['name']}.")
        return RedirectResponse("/pipe", status_code=303)

    @app.get("/lists", include_in_schema=False)
    async def lists_moved():
        return RedirectResponse("/routing", status_code=308)

    @app.post("/routing/default", response_class=HTMLResponse)
    async def routing_default(request: Request):
        user, form = await guarded_form(request)
        if user is None:
            return form
        state = load_state()
        exit_ref = exit_from_form(form.get("exit", ""), state.get("exits", []))
        if exit_ref is None:
            values = {"exit": form.get("exit"), "when_down": "block"}
            return lists_page(request, user, {"id": "default", "values": values, "errors": ["Pick an exit"]}, 400)
        when_down = "block" if form.get("kill_switch") == "on" else "direct"
        save_section(settings.state_dir, "default", {"exit": exit_ref, "when_down": when_down})
        flash(request, "Saved the default route.")
        return RedirectResponse("/routing#default", status_code=303)

    return app


def app() -> FastAPI:
    """uvicorn factory: `uvicorn vpn_egress.panel.app:app --factory`."""
    return create_app(Settings.from_env())
