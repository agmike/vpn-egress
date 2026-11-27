import json
import os
import time

from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient

from vpn_egress.panel.app import Settings, create_app, is_allowed, public_state


class FakeClient:
    def __init__(self, claims):
        self.claims = claims

    async def authorize_redirect(self, request, redirect_uri):
        return RedirectResponse(f"https://id.example/authorize?redirect_uri={redirect_uri}", status_code=302)

    async def authorize_access_token(self, request):
        return {"access_token": "x", "userinfo": dict(self.claims)}

    async def userinfo(self, token):
        return {"groups": []}


class FakeOAuth:
    def __init__(self, claims):
        self.client = FakeClient(claims)

    def create_client(self, name):
        return self.client


def make_client(tmp_path, claims):
    settings = Settings(
        issuer="https://id.example",
        client_id="cid",
        client_secret="secret",
        public_url="http://testserver",
        session_secret="s" * 32,
        allowed_groups=frozenset({"admins"}),
        state_dir=tmp_path,
    )
    return TestClient(create_app(settings, oauth=FakeOAuth(claims)))


def test_is_allowed():
    assert is_allowed({"groups": ["users", "admins"]}, frozenset({"admins"}))
    assert is_allowed({"groups": "admins"}, frozenset({"admins"}))
    assert not is_allowed({"groups": ["users"]}, frozenset({"admins"}))
    assert not is_allowed({}, frozenset({"admins"}))


def test_public_state_hides_keys():
    state = {
        "exits": [{"id": 1, "name": "nl", "wireguard": {"private_key": "SECRET", "endpoint": "192.0.2.1:51820"}}],
        "lists": [{"id": 1, "name": "x", "exit": 1, "cidrs": ["192.0.2.0/24"]}],
    }
    shown = public_state(state)
    assert "SECRET" not in json.dumps(shown)
    assert shown["exits"][0]["endpoint"] == "192.0.2.1:51820"
    assert shown["lists"][0]["entries"] == 1


def test_signed_out_index_is_a_landing_page(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200 and 'href="/login"' in r.text
    r = client.get("/login", follow_redirects=False)
    assert "redirect_uri=http://testserver/auth/callback" in r.headers["location"]


def test_admin_signs_in_and_sees_status(tmp_path):
    (tmp_path / "status.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "error": None,
                "pipe": {
                    "interface": "awg0",
                    "peers": [
                        {"allowed_ips": "10.0.0.2/32", "endpoint": None, "handshake_age": None, "rx": 0, "tx": 0}
                    ],
                },
                "exits": [
                    {
                        "id": 1,
                        "name": "provider-nl",
                        "enabled": True,
                        "up": True,
                        "handshake_age": 30,
                        "rx": 2048,
                        "tx": 1024,
                    }
                ],
                "lists": [],
            }
        )
    )
    client = make_client(tmp_path, {"sub": "1", "name": "Alex", "groups": ["admins"]})
    r = client.get("/auth/callback", follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/")
    assert r.status_code == 200
    assert "provider-nl" in r.text and "10.0.0.2/32" in r.text and "Alex" in r.text


def test_non_admin_is_refused(tmp_path):
    client = make_client(tmp_path, {"sub": "2", "preferred_username": "guest", "groups": ["users"]})
    r = client.get("/auth/callback", follow_redirects=False)
    assert r.status_code == 403
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200 and "Sign in" in r.text and "Alex" not in r.text


def test_logout_clears_session(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    client.get("/auth/callback", follow_redirects=False)
    assert "Sign out" in client.get("/").text
    r = client.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    r = client.get("/")
    assert r.status_code == 200 and "Sign in" in r.text and "Sign out" not in r.text


def test_favicon_is_public(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    r = client.get("/favicon.svg")
    assert r.status_code == 200 and r.headers["content-type"] == "image/svg+xml"
    assert r.content.startswith(b"<svg")


SEED = {
    "lists": [{"name": "adguard-dns", "url": "https://v.firebog.net/hosts/AdguardDNS.txt", "enabled": True}],
    "block": ["blocked.example.net"],
    "allow": [],
}


def signed_in(tmp_path):
    (tmp_path / "blocklist-defaults.json").write_text(json.dumps(SEED))
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    client.get("/auth/callback", follow_redirects=False)
    return client


def csrf_of(html):
    return html.split('name="csrf" value="', 1)[1].split('"', 1)[0]


def test_dns_page_shows_the_seed(tmp_path):
    client = signed_in(tmp_path)
    r = client.get("/dns")
    assert r.status_code == 200
    assert "adguard-dns" in r.text and "blocked.example.net" in r.text


def test_dns_needs_sign_in(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    assert client.get("/dns", follow_redirects=False).status_code == 303
    assert client.post("/dns", data={}, follow_redirects=False).status_code == 303


def test_dns_save_keeps_other_sections(tmp_path):
    (tmp_path / "state.json").write_text(json.dumps({"exits": [{"id": 1}], "lists": []}))
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/dns").text)
    r = client.post(
        "/dns",
        data={
            "csrf": token,
            "list-count": "2",
            "list-0-name": "adguard-dns",
            "list-0-url": "https://v.firebog.net/hosts/AdguardDNS.txt",
            "list-0-enabled": "on",
            "list-1-name": "hagezi-doh",
            "list-1-url": "https://example.org/doh.txt",
            "block": "Blocked.Example.net.\n\nads.example.com # note",
            "allow": "",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/dns?saved=1"
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["exits"] == [{"id": 1}]
    assert state["dns"]["lists"][1] == {"name": "hagezi-doh", "url": "https://example.org/doh.txt", "enabled": False}
    assert state["dns"]["block"] == ["Blocked.Example.net.", "", "ads.example.com # note"]


def test_dns_remove_row(tmp_path):
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/dns").text)
    client.post(
        "/dns",
        data={
            "csrf": token,
            "list-count": "1",
            "list-0-name": "adguard-dns",
            "list-0-url": "https://v.firebog.net/hosts/AdguardDNS.txt",
            "list-0-remove": "on",
            "block": "",
            "allow": "",
        },
    )
    assert json.loads((tmp_path / "state.json").read_text())["dns"]["lists"] == []


def test_dns_rejects_bad_input_without_saving(tmp_path):
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/dns").text)
    r = client.post(
        "/dns",
        data={
            "csrf": token,
            "list-count": "1",
            "list-0-name": "Bad Name",
            "list-0-url": "http://plain.example/list.txt",
            "block": "not a domain",
            "allow": "",
        },
    )
    assert r.status_code == 400
    assert "Not saved" in r.text and "https://" in r.text and "not a domain" in r.text
    assert not (tmp_path / "state.json").exists()


def test_dns_rejects_missing_csrf(tmp_path):
    client = signed_in(tmp_path)
    r = client.post("/dns", data={"list-count": "0", "block": "", "allow": ""})
    assert r.status_code == 400
    assert not (tmp_path / "state.json").exists()


def test_dns_page_controls(tmp_path):
    client = signed_in(tmp_path)
    html = client.get("/dns").text
    assert 'id="add-list"' in html and "data-remove" in html
    assert 'name="list-count" id="list-count" value="1"' in html
    assert "config from" not in html


def test_dns_empty_remove_flag_keeps_row(tmp_path):
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/dns").text)
    client.post(
        "/dns",
        data={
            "csrf": token,
            "list-count": "1",
            "list-0-name": "adguard-dns",
            "list-0-url": "https://v.firebog.net/hosts/AdguardDNS.txt",
            "list-0-enabled": "on",
            "list-0-remove": "",
            "block": "",
            "allow": "",
        },
    )
    assert len(json.loads((tmp_path / "state.json").read_text())["dns"]["lists"]) == 1


PRIV = "A6ozk18OumNe9b/G1D67XzKO6L9RzmHbNS/d5EVoVkc="
PUB = "5Xl7DvDv34MYvS04zv0TNlmaY8dylsMwvwUVZk5itJo="
CONF = f"""[Interface]
# Key for a test exit
PrivateKey = {PRIV}
Address = 10.64.0.2/32, fd00:64::2/128
DNS = 10.64.0.1, fd00:64::1

[Peer]
# NL test server
PublicKey = {PUB}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 198.51.100.65:51820
# Endpoint = [2001:db8:5::10]:51820
PersistentKeepalive = 25
"""


def state_of(tmp_path):
    return json.loads((tmp_path / "state.json").read_text())


def add_exit(client, name="provider-nl"):
    token = csrf_of(client.get("/exits").text)
    return client.post("/exits/add", data={"csrf": token, "name": name, "conf": CONF}, follow_redirects=False)


def test_add_exit_parses_conf_and_hides_key(tmp_path):
    client = signed_in(tmp_path)
    r = add_exit(client)
    assert r.status_code == 303
    ex = state_of(tmp_path)["exits"][0]
    assert ex["id"] == 1 and ex["enabled"] is True
    assert ex["wireguard"] == {
        "private_key": PRIV,
        "public_key": PUB,
        "endpoint": "198.51.100.65:51820",
        "address": "10.64.0.2/32",
        "address6": "fd00:64::2/128",
        "dns": ["10.64.0.1", "fd00:64::1"],
    }
    page = client.get("/exits").text
    assert "provider-nl" in page and "Added provider-nl" in page and PRIV not in page


def test_add_exit_bad_conf_is_not_echoed(tmp_path):
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/exits").text)
    bad = CONF.replace("Endpoint = 198.51.100.65:51820", "Endpoint = nl.example.com:51820")
    r = client.post("/exits/add", data={"csrf": token, "name": "x", "conf": bad})
    assert r.status_code == 400 and "no host names" in r.text and PRIV not in r.text
    assert not (tmp_path / "state.json").exists() or "exits" not in state_of(tmp_path)


def test_exit_toggle_replace_and_guarded_delete(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    client.post(
        "/routing/add",
        data={
            "csrf": token,
            "name": "ip-check",
            "exit": "1",
            "kill_switch": "on",
            "resolve_via_exit": "on",
            "entries": "ipify.org",
        },
    )
    client.post("/exits/1/toggle", data={"csrf": token})
    assert state_of(tmp_path)["exits"][0]["enabled"] is False
    client.post("/exits/1/replace", data={"csrf": token, "conf": CONF.replace("198.51.100.65", "203.0.113.9")})
    assert state_of(tmp_path)["exits"][0]["wireguard"]["endpoint"] == "203.0.113.9:51820"
    r = client.post("/exits/1/delete", data={"csrf": token})
    assert len(state_of(tmp_path)["exits"]) == 1  # still used by ip-check
    assert "used by ip-check" in r.text
    client.post("/routing/1/delete", data={"csrf": token})
    client.post("/exits/1/delete", data={"csrf": token})
    assert state_of(tmp_path)["exits"] == []


def test_lists_add_save_move(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    for name, entries in (("first", "a.example"), ("second", "203.0.113.0/24\n2001:DB8::/32\n*.B.example.")):
        r = client.post(
            "/routing/add",
            data={"csrf": token, "name": name, "exit": "1", "kill_switch": "", "entries": entries},
            follow_redirects=False,
        )
        assert r.status_code == 303
    lists = state_of(tmp_path)["lists"]
    assert [l["name"] for l in lists] == ["first", "second"]
    assert lists[1]["entries"] == ["203.0.113.0/24", "2001:DB8::/32", "*.B.example."]
    assert lists[1]["resolve_via_exit"] is False and lists[1]["when_down"] == "direct"
    client.post("/routing/2/move", data={"csrf": token, "dir": "up"})
    assert [l["name"] for l in state_of(tmp_path)["lists"]] == ["second", "first"]
    client.post(
        "/routing/1/save",
        data={
            "csrf": token,
            "name": "first",
            "exit": "1",
            "kill_switch": "on",
            "resolve_via_exit": "on",
            "entries": "c.example",
        },
    )
    l1 = next(l for l in state_of(tmp_path)["lists"] if l["id"] == 1)
    assert l1["entries"] == ["c.example"] and l1["when_down"] == "block" and l1["resolve_via_exit"] is True


def test_list_errors_keep_input(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    r = client.post(
        "/routing/add",
        data={"csrf": token, "name": "", "exit": "9", "kill_switch": "on", "entries": "ok.example\nnot valid!"},
    )
    assert r.status_code == 400
    assert "not valid!" in r.text and "Pick an exit" in r.text and "1–40" in r.text
    assert "lists" not in state_of(tmp_path)


def test_exits_and_lists_need_sign_in_and_csrf(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    for path in ("/exits", "/routing"):
        assert client.get(path, follow_redirects=False).status_code == 303
    assert client.post("/exits/add", data={}, follow_redirects=False).status_code == 303
    client = signed_in(tmp_path)
    assert client.post("/exits/add", data={"name": "x", "conf": CONF}).status_code == 400
    assert client.post("/routing/add", data={"name": "x", "exit": "1"}).status_code == 400


def test_list_accepts_wildcards_and_tld(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    client.post(
        "/routing/add",
        data={"csrf": token, "name": "japan", "exit": "1", "kill_switch": "on", "entries": "*.example.co.jp\n*.jp\njp"},
    )
    assert state_of(tmp_path)["lists"][0]["entries"] == ["*.example.co.jp", "*.jp", "jp"]


def test_list_comments_and_rename(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    text = "# streaming\nnetflix.com   # main\n\n\n\nnflxvideo.net\n\n"
    client.post(
        "/routing/add",
        data={"csrf": token, "name": "Streaming (NL)", "exit": "1", "kill_switch": "on", "entries": text},
    )
    l = state_of(tmp_path)["lists"][0]
    assert l["name"] == "Streaming (NL)"
    assert l["entries"] == ["# streaming", "netflix.com   # main", "", "nflxvideo.net"]
    page = client.get("/routing").text
    assert "netflix.com   # main" in page and "List format" in page
    client.post(
        "/routing/1/save", data={"csrf": token, "name": "Video", "exit": "1", "kill_switch": "on", "entries": text}
    )
    assert state_of(tmp_path)["lists"][0]["name"] == "Video"


def test_exit_dns_flag_and_no_groups_footer(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/exits").text)
    no_dns = CONF.replace("DNS = 10.64.0.1, fd00:64::1\n", "")
    client.post("/exits/add", data={"csrf": token, "name": "no-dns", "conf": no_dns})
    page = client.get("/routing").text
    assert 'data-dns="yes"' in page and 'data-dns="no"' in page and "Use exit DNS" in page
    assert "admins" not in client.get("/").text


def test_add_buttons_and_collapsed_lists(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    client.post(
        "/routing/add",
        data={"csrf": token, "name": "ip-check", "exit": "1", "kill_switch": "on", "entries": "ipify.org"},
    )
    page = client.get("/routing").text
    assert 'data-open="#new-list"' in page and 'id="new-list" hidden' in page
    assert 'data-open="#edit-1"' in page and 'id="edit-1" hidden' in page
    assert "→ provider-nl" in page and "kill switch on" in page
    r = client.post("/routing/add", data={"csrf": token, "name": "", "exit": "1", "entries": ""})
    assert 'id="new-list" hidden' not in r.text  # errors keep the form open
    exits = client.get("/exits").text
    assert 'data-open="#new-exit"' in exits and 'id="new-exit" hidden' in exits
    assert "Add blocklist" in client.get("/dns").text


def test_routing_special_exits_sources_and_default(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/routing").text)
    r = client.post(
        "/routing/add",
        data={
            "csrf": token,
            "name": "Not via VPN",
            "exit": "direct",
            "entries": "mail.example.com\nAS2906\nJP  # japan\nNETFLIX\nhttps://lists.example/cdn.json",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    lst = state_of(tmp_path)["lists"][0]
    assert lst["exit"] == "direct" and "AS2906" in lst["entries"]
    r = client.post(
        "/routing/add", data={"csrf": token, "name": "bad", "exit": "block", "entries": "PRIVATE\nhttp://x.example/a"}
    )
    assert r.status_code == 400 and "reserved" in r.text and "not an address" in r.text
    r = client.post("/routing/default", data={"csrf": token, "exit": "1", "kill_switch": "on"}, follow_redirects=False)
    assert r.status_code == 303 and state_of(tmp_path)["default"] == {"exit": 1, "when_down": "block"}
    page = client.get("/routing").text
    assert (
        "Everything else" in page and "→ provider-nl" in page and 'value="direct"' in page and 'value="block"' in page
    )
    r = client.post("/exits/1/delete", data={"csrf": token})
    assert "Everything else" in r.text and len(state_of(tmp_path)["exits"]) == 1
    client.post("/routing/default", data={"csrf": token, "exit": "nope"})
    assert state_of(tmp_path)["default"]["exit"] == 1


def test_lists_url_redirects(tmp_path):
    client = signed_in(tmp_path)
    r = client.get("/lists", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/routing"


# --- pipe ----------------------------------------------------------------------------


def pipe_ready(tmp_path):
    client = signed_in(tmp_path)
    (tmp_path / "status.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "pipe": {
                    "interface": "awg0",
                    "managed": True,
                    "configured": False,
                    "addresses": ["10.66.0.1/24", "fd66::1/64"],
                    "endpoint": "egress.example.com:443",
                    "client_mtu": 1280,
                    "port": 443,
                    "peers": [],
                },
            }
        )
    )
    token = csrf_of(client.get("/pipe").text)
    client.post("/pipe/recreate", data={"csrf": token})
    return client, token


def test_pipe_create_and_device_config(tmp_path):
    from vpn_egress.panel.state import public_key

    client, token = pipe_ready(tmp_path)
    pipe = state_of(tmp_path)["pipe"]
    assert pipe["peers"] == [] and pipe["obfuscation"]["I1"].startswith("<b ")
    r = client.post("/pipe/peers", data={"csrf": token, "name": "Phone"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    assert "<svg" in r.text and "viewBox" in r.text and "Save as file" in r.text and 'id="copy"' in r.text
    conf = r.text.split("<textarea", 1)[1].split(">", 1)[1].split("</textarea>", 1)[0]
    priv = conf.split("PrivateKey = ", 1)[1].split("\n", 1)[0]
    peer = state_of(tmp_path)["pipe"]["peers"][0]
    assert public_key(priv) == peer["public_key"] and "private_key" not in peer and peer["own_key"] is False
    assert peer["address"] == "10.66.0.2/32" and peer["address6"] == "fd66::2/128"
    assert "Endpoint = egress.example.com:443" in conf and "DNS = 10.66.0.1, fd66::1" in conf
    assert f"PublicKey = {public_key(state_of(tmp_path)['pipe']['private_key'])}" in conf
    client.post("/pipe/peers", data={"csrf": token, "name": "Laptop"})
    assert state_of(tmp_path)["pipe"]["peers"][1]["address"] == "10.66.0.3/32"
    old = peer["public_key"]
    client.post("/pipe/peers/1/regenerate", data={"csrf": token})
    assert state_of(tmp_path)["pipe"]["peers"][0]["public_key"] != old
    client.post("/pipe/peers/2/delete", data={"csrf": token})
    assert [p["name"] for p in state_of(tmp_path)["pipe"]["peers"]] == ["Phone"]
    old_server = state_of(tmp_path)["pipe"]["private_key"]
    client.post("/pipe/recreate", data={"csrf": token})
    assert state_of(tmp_path)["pipe"]["private_key"] != old_server and len(state_of(tmp_path)["pipe"]["peers"]) == 1


def test_pipe_peer_with_own_key_and_networks(tmp_path):
    from vpn_egress.panel.state import gen_keypair

    client, token = pipe_ready(tmp_path)
    _, pub = gen_keypair()
    r = client.post("/pipe/peers", data={"csrf": token, "name": "Home", "public_key": "nope", "networks": "x"})
    assert r.status_code == 400 and "WireGuard key" in r.text and "not a network" in r.text
    assert 'id="new-peer" hidden' not in r.text  # the form stays open with the errors
    r = client.post(
        "/pipe/peers",
        data={
            "csrf": token,
            "name": "Home router",
            "public_key": pub,
            "networks": "192.168.10.0/24, 192.168.50.0/24\nany",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/pipe/peers/1/config"
    peer = state_of(tmp_path)["pipe"]["peers"][0]
    assert peer["own_key"] is True and peer["public_key"] == pub
    assert peer["routes"] == ["192.168.10.0/24", "192.168.50.0/24", "0.0.0.0/0", "::/0"]
    page = client.get("/pipe/peers/1/config").text
    assert "own private key" in page and "<svg" not in page and "# Route 192.168.10.0/24, 192.168.50.0/24" in page
    # Regenerate turns it into a peer with panel-made keys, shown once.
    r = client.post("/pipe/peers/1/regenerate", data={"csrf": token})
    assert "<svg" in r.text and state_of(tmp_path)["pipe"]["peers"][0]["own_key"] is False


def test_exit_expiry_default_edit_and_warning(tmp_path):
    import datetime

    client = signed_in(tmp_path)
    today = datetime.datetime.now(datetime.UTC).date()
    next_year = (today + datetime.timedelta(days=365)).isoformat()
    page = client.get("/exits").text
    assert f'value="{next_year}"' in page  # the add form's default
    token = csrf_of(page)
    soon = (today + datetime.timedelta(days=10)).isoformat()
    client.post("/exits/add", data={"csrf": token, "name": "nl", "conf": CONF, "expires": soon})
    assert state_of(tmp_path)["exits"][0]["expires"] == soon
    assert "config expires in 10 days" in client.get("/").text
    r = client.post("/exits/1/edit", data={"csrf": token, "name": "nl 2", "expires": "not a date"})
    assert r.status_code == 400 and "YYYY-MM-DD" in r.text
    client.post("/exits/1/edit", data={"csrf": token, "name": "nl 2", "expires": ""})
    ex = state_of(tmp_path)["exits"][0]
    assert ex["name"] == "nl 2" and ex["expires"] is None
    assert "expires in" not in client.get("/").text
    client.post("/exits/1/replace", data={"csrf": token, "conf": CONF, "expires": next_year})
    assert state_of(tmp_path)["exits"][0]["expires"] == next_year
    past = (today - datetime.timedelta(days=3)).isoformat()
    client.post("/exits/1/edit", data={"csrf": token, "name": "nl 2", "expires": past})
    assert "expired 3 days ago" in client.get("/").text


def test_traffic_meter_on_status(tmp_path):
    now = int(time.time())
    (tmp_path / "traffic.json").write_text(
        json.dumps(
            {
                "updated": now,
                "iface": "eth0",
                "month": "2026-11",
                "since": now - 86400 * 20,
                "month_start": now - 86400 * 20,
                "tx": 8_500_000_000_000,
                "rx": 1_000_000_000,
                "allowance": 10_000_000_000_000,
                "projected_tx": 12_000_000_000_000,
                "today": [1_000_000, 0],
                "days": {},
                "months": {"2026-10": [3_000_000_000_000, 0]},
            }
        )
    )
    client = signed_in(tmp_path)
    page = client.get("/").text
    assert "8.5\u00a0TB" in page and "of 10.0\u00a0TB" in page and "85.0%" in page
    assert "at 85% of the allowance" in page and "2026-10: 3.0\u00a0TB" in page


def test_traffic_allowance_from_panel(tmp_path):
    now = int(time.time())
    (tmp_path / "traffic.json").write_text(
        json.dumps(
            {
                "updated": now,
                "iface": "eth0",
                "since": now,
                "month_start": now,
                "tx": 6_000_000_000_000,
                "rx": 0,
                "allowance": 10_000_000_000_000,
                "projected_tx": None,
                "today": [0, 0],
                "days": {},
                "months": {},
            }
        )
    )
    client = signed_in(tmp_path)
    page = client.get("/").text
    assert 'value="10TB"' in page and "of 10.0\u00a0TB" in page  # the router's default
    token = csrf_of(page)
    page = client.post("/traffic", data={"csrf": token, "allowance": "5 tb"}).text
    assert state_of(tmp_path)["traffic"] == {"allowance": 5_000_000_000_000}
    assert "Allowance set to 5.0\u00a0TB" in page and "over the allowance" in page
    page = client.post("/traffic", data={"csrf": token, "allowance": "lots"}).text
    assert "like 10TB" in page and state_of(tmp_path)["traffic"]["allowance"] == 5 * 10**12
    page = client.post("/traffic", data={"csrf": token, "allowance": "5TB", "action": "off"}).text
    assert state_of(tmp_path)["traffic"] == {"allowance": None}
    assert "Allowance turned off" in page and "no allowance" in page
    assert "over the allowance" not in page and "Turn off" not in page


def test_units_do_not_break():
    from vpn_egress.panel.app import human_age, human_bytes, human_size

    for text in (human_bytes(2048), human_size(5 * 10**12), human_age(38), human_age(800), human_age(50000)):
        assert " " not in text


def test_pages_wait_for_the_router(tmp_path, monkeypatch):
    import vpn_egress.panel.app as panel_app

    monkeypatch.setattr(panel_app, "APPLY_WAIT", 0.3)
    client = signed_in(tmp_path)
    token = csrf_of(client.get("/exits").text)

    def router_status(mtime):
        (tmp_path / "status.json").write_text(json.dumps({"updated": int(time.time()), "state_mtime": mtime}))

    router_status(None)
    started = time.monotonic()
    add_exit(client)  # the router never applies it: the save waits, then gives up
    assert 0.3 <= time.monotonic() - started < 3
    page = client.get("/routing").text
    assert "Applying changes" in page and client.get("/applied").json() == {"applied": False}
    router_status((tmp_path / "state.json").stat().st_mtime_ns)
    assert "Applying changes" not in client.get("/routing").text
    assert client.get("/applied").json() == {"applied": True}
    # Pages rendered for a POST (errors, one-time configs) never get the reloading note.
    router_status(None)
    r = client.post("/exits/add", data={"csrf": token, "name": "x", "conf": "bad"})
    assert r.status_code == 400 and "Applying changes" not in r.text


def test_applied_needs_sign_in(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    assert client.get("/applied").status_code == 401


def test_backup_file_roundtrip_and_errors():
    import pytest

    from vpn_egress.panel import backup

    state = {"exits": [{"id": 1, "name": "nl", "wireguard": {"private_key": PRIV}}], "dns": {"lists": []}}
    plain = backup.export(state)
    assert backup.read(plain)[0] == state and not backup.is_encrypted(plain)
    enc = backup.export(state, "correct horse")
    assert PRIV.encode() not in enc and backup.is_encrypted(enc)
    assert backup.read(enc, "correct horse")[0] == state
    for data, passphrase, message in (
        (enc, "", "enter its passphrase"),
        (enc, "wrong", "Wrong passphrase"),
        (enc.replace(b'"format"', b'"fmt"'), "correct horse", "Not a vpn-egress backup"),
        (b"\x89PNG", "", "not JSON"),
        (plain.replace(b'"version": 1', b'"version": 9'), "", "version 9"),
    ):
        with pytest.raises(backup.BackupError, match=message):
            backup.read(data, passphrase)


def test_backup_download_restore_and_undo(tmp_path):
    client, token = pipe_ready(tmp_path)
    client.post("/pipe/peers", data={"csrf": token, "name": "Phone"})
    add_exit(client, "nl")
    page = client.get("/maintenance").text
    assert "Download a backup" in page and "Undo the restore" not in page
    r = client.post("/backup/export", data={"csrf": token, "passphrase": "pw", "passphrase2": "pw"})
    assert r.headers["content-disposition"].startswith('attachment; filename="vpn-egress-backup-')
    assert r.headers["cache-control"] == "no-store" and PRIV.encode() not in r.content
    saved, file = state_of(tmp_path), r.content
    r = client.post("/backup/export", data={"csrf": token, "passphrase": "pw", "passphrase2": "px"})
    assert "passphrases don&#39;t match" in r.text

    # Change things, then restore: the preview first, nothing replaced yet.
    client.post("/exits/1/delete", data={"csrf": token})
    client.post("/pipe/peers", data={"csrf": token, "name": "Laptop"})
    up = {"file": ("b.json", file, "application/json")}
    r = client.post("/backup/upload", data={"csrf": token, "passphrase": "bad"}, files=up)
    assert "Wrong passphrase" in r.text
    r = client.post("/backup/upload", data={"csrf": token, "passphrase": "pw"}, files=up)
    assert r.status_code == 200 and "Phone, Laptop" in r.text and ">Restore</button>" in r.text
    assert state_of(tmp_path)["exits"] == []
    r = client.post("/backup/restore", data={"csrf": token})
    assert "Restored the backup from" in r.text and "Undo the restore" in r.text
    assert state_of(tmp_path) == saved
    assert not (tmp_path / ".pending-restore.json").exists()
    assert oct((tmp_path / "snapshots").stat().st_mode)[-3:] == "700"
    r = client.post("/backup/restore", data={"csrf": token})  # used up
    assert "Nothing to restore" in r.text
    r = client.post("/backup/undo", data={"csrf": token})
    assert "Put back the settings" in r.text and state_of(tmp_path)["exits"] == []
    assert [p["name"] for p in state_of(tmp_path)["pipe"]["peers"]] == ["Phone", "Laptop"]
    assert "nothing to undo" in client.post("/backup/undo", data={"csrf": token}).text


def test_backup_that_does_not_fit_is_refused(tmp_path):
    from vpn_egress.panel import backup

    client, token = pipe_ready(tmp_path)
    client.post("/pipe/peers", data={"csrf": token, "name": "Phone"})
    state = state_of(tmp_path)
    state["pipe"]["peers"][0]["address"] = "10.99.0.2/32"  # another server's subnet
    up = {"file": ("b.json", backup.export(state), "application/json")}
    r = client.post("/backup/upload", data={"csrf": token}, files=up)
    assert r.status_code == 400 and "fit this server&#39;s pipe subnets" in r.text and ">Restore</button>" not in r.text
    assert "Nothing to restore" in client.post("/backup/restore", data={"csrf": token}).text
    r = client.post("/backup/upload", data={"csrf": token}, files={"file": ("b.json", b"{}", "application/json")})
    assert "Not a vpn-egress backup" in r.text


def test_new_exits_count_as_applying_until_up(tmp_path):
    from vpn_egress.panel.app import state_applied

    client = signed_in(tmp_path)
    add_exit(client)
    mtime = (tmp_path / "state.json").stat().st_mtime_ns

    def status(up):
        exits = [{"id": 1, "enabled": True, "up": up}]
        (tmp_path / "status.json").write_text(json.dumps({"state_mtime": mtime, "exits": exits}))

    status(False)
    assert not state_applied(tmp_path)
    status(True)
    assert state_applied(tmp_path)
    status(False)
    old = time.time() - 60
    os.utime(tmp_path / "state.json", (old, old))
    mtime = (tmp_path / "state.json").stat().st_mtime_ns
    status(False)
    assert state_applied(tmp_path)  # a dead exit doesn't keep the page waiting


def create_token(client, token, name, scope):
    r = client.post("/api/tokens", data={"csrf": token, "name": name, "scope": scope})
    assert r.headers.get("cache-control") == "no-store", r.text
    return r.text.split('id="token" class="mono" value="', 1)[1].split('"', 1)[0]


def test_api_tokens_status_and_backup(tmp_path):
    import datetime

    from vpn_egress.panel import backup

    client = signed_in(tmp_path)
    token = csrf_of(client.get("/maintenance").text)
    soon = (datetime.datetime.now(datetime.UTC).date() + datetime.timedelta(days=5)).isoformat()
    client.post("/exits/add", data={"csrf": token, "name": "nl", "conf": CONF, "expires": soon})
    (tmp_path / "status.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "error": None,
                "exits": [
                    {"id": 1, "name": "nl", "enabled": True, "up": False, "handshake_age": None, "rx": 0, "tx": 0}
                ],
                "pipe": {
                    "interface": "awg0",
                    "peers": [{"handshake_age": 10, "rx": 1, "tx": 2, "public_key": "PEERKEY", "allowed_ips": "x"}],
                },
            }
        )
    )
    reader = create_token(client, token, "monitoring", "status")
    full = create_token(client, token, "backups", "backup")
    assert reader.startswith("vpe_") and reader not in (tmp_path / "state.json").read_text()
    r = client.post("/api/tokens", data={"csrf": token, "name": "backups", "scope": "status"})
    assert "already exists" in r.text

    api = TestClient(client.app)  # no session cookie: the bearer token is the only credential
    assert api.get("/api/status").status_code == 401
    assert api.get("/api/status", headers={"Authorization": "Bearer vpe_wrong"}).status_code == 401
    r = api.get("/api/status", headers={"Authorization": f"Bearer {reader}"})
    assert r.status_code == 200
    data = r.json()
    kinds = {w["kind"] for w in data["warnings"]}
    assert kinds == {"exit_expiry", "exit_down"} and data["exits"][0]["days_left"] == 5
    assert data["pipe_peers"] == [{"handshake_age": 10, "rx": 1, "tx": 2}] and PRIV not in r.text
    assert "PEERKEY" not in r.text

    assert api.post("/api/backup", headers={"Authorization": f"Bearer {reader}"}).status_code == 403
    auth = {"Authorization": f"Bearer {full}"}
    r = api.post("/api/backup", headers=auth, json={"passphrase": "pw"})
    assert r.status_code == 200 and PRIV.encode() not in r.content
    assert backup.read(r.content, "pw")[0]["exits"][0]["wireguard"]["private_key"] == PRIV
    assert PRIV.encode() in api.post("/api/backup", headers=auth).content  # no body: plain
    assert api.post("/api/backup", headers=auth, content=b"nope").status_code == 400
    assert api.post("/api/backup", headers=auth, json={"passphrase": 5}).status_code == 400

    page = client.get("/maintenance").text
    assert "monitoring" in page and "never" not in page.split('id="api"', 1)[1].split("</section>", 1)[0]
    client.post("/api/tokens/1/delete", data={"csrf": token})
    assert api.get("/api/status", headers={"Authorization": f"Bearer {reader}"}).status_code == 401
    assert api.get("/api/status", headers={"Authorization": f"Bearer {full}"}).status_code == 200


def test_api_reports_a_silent_router(tmp_path):
    client = signed_in(tmp_path)
    reader = create_token(client, csrf_of(client.get("/maintenance").text), "m", "status")
    r = TestClient(client.app).get("/api/status", headers={"Authorization": f"Bearer {reader}"})
    assert [w["kind"] for w in r.json()["warnings"]] == ["router"]


def test_notifier_stages_confirmation_and_resolve(tmp_path):
    from vpn_egress.panel.notify import Notifier

    sent = []
    path = tmp_path / "notify-state.json"
    n = Notifier(path, lambda title, body: sent.append(title))

    def w(stage, level="warn"):
        return [{"kind": "exit_expiry", "key": "exit_expiry:1", "stage": stage, "level": level, "text": f"NL {stage}"}]

    assert n.check(w("30")) == []  # first sighting: wait for a second check
    assert [t for t, _ in n.check(w("30"))] == ["⚠️ Egress: NL 30"]
    assert n.check(w("30")) == [] and n.check(w("30")) == []  # same stage: quiet
    n.check(w("7", "bad"))
    n.check(w("7", "bad"))
    assert sent[-1] == "⛔ Egress: NL 7"
    n.check([])  # a one-check blip doesn't resolve it
    n.check(w("7", "bad"))
    assert len(sent) == 2
    n = Notifier(path, lambda title, body: sent.append(title))  # restart: remembers what was sent
    n.check(w("7", "bad"))
    assert len(sent) == 2
    n.check([])
    n.check([])
    assert sent[-1] == "✅ Egress: Resolved: NL 7" and len(sent) == 3
    n.check([])
    assert len(sent) == 3


def test_warnings_have_keys_and_stages():
    from vpn_egress.panel.app import router_warnings, warnings

    traffic = {"allowance": 100, "tx": 85, "projected_tx": None}
    ws = warnings({"exits": [{"id": 3, "name": "nl", "expires": "2000-01-01"}]}, traffic)
    assert [(w["key"], w["stage"]) for w in ws] == [("exit_expiry:3", "expired"), ("traffic", "80")]
    status = {"updated": int(time.time()), "error": None, "exits": [{"id": 3, "name": "nl", "enabled": True}]}
    assert [(w["key"], w["stage"]) for w in router_warnings(status, True)] == [("exit_down:3", "down")]
    assert router_warnings(status, False) == []  # just changed: still connecting
    assert router_warnings(None, True)[0]["stage"] == "silent"


def test_maintenance_page_notify_targets_and_versions(tmp_path):
    (tmp_path / "status.json").write_text(
        json.dumps({"updated": int(time.time()), "versions": {"amneziawg_tools": "3.1.1", "amneziawg_module": None}})
    )
    client = signed_in(tmp_path)
    page = client.get("/maintenance").text
    assert "AmneziaWG tools" in page and "3.1.1" in page and "not loaded" in page
    assert 'href="/maintenance" class="active"' in page and "Download a backup" in page and 'id="api"' in page
    token = csrf_of(page)
    r = client.post("/maintenance/notify/add", data={"csrf": token, "url": "not a url"})
    assert "doesn&#39;t recognise" in r.text and not (tmp_path / "state.json").exists()
    secret = "s3cr3tTOKENvalue"
    url = f"json://user:{secret}@127.0.0.1:9/hook"
    r = client.post("/maintenance/notify/add", data={"csrf": token, "url": url})
    assert state_of(tmp_path)["notify"] == {"urls": [url]}
    assert "Added" in r.text and secret not in r.text and "127.0.0.1" in r.text
    r = client.post("/maintenance/notify/test", data={"csrf": token})  # nothing listens on port 9
    assert "Sent to 0 of 1; failed" in r.text and secret not in r.text
    client.post("/maintenance/notify/0/delete", data={"csrf": token})
    assert state_of(tmp_path)["notify"] == {"urls": []}


def test_live_page_data_and_actions(tmp_path):
    client, token = pipe_ready(tmp_path)
    client.post("/pipe/peers", data={"csrf": token, "name": "Phone"})
    client.post("/pipe/peers", data={"csrf": token, "name": "Home", "public_key": "", "networks": "192.168.10.0/24"})
    add_exit(client, "nl")
    client.post("/routing/add", data={"csrf": token, "name": "video", "exit": "1", "entries": "example.com"})
    (tmp_path / "live.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "dns": [
                    {
                        "t": 1,
                        "client": "10.66.0.2",
                        "type": "A",
                        "name": "www.example.com",
                        "result": "answered",
                        "server": None,
                        "answers": ["198.51.100.7"],
                        "list": 1,
                    },
                    {
                        "t": 2,
                        "client": "192.168.10.20",
                        "type": "A",
                        "name": "ads.example.org",
                        "result": "blocked",
                        "server": None,
                        "answers": [],
                        "list": None,
                    },
                ],
                "conns": [
                    {
                        "t": 3,
                        "proto": "tcp",
                        "client": "10.66.0.2",
                        "dst": "198.51.100.7",
                        "port": 443,
                        "name": "www.example.com",
                        "list": 1,
                        "via": 1,
                    },
                    {
                        "t": 4,
                        "proto": "icmp",
                        "client": "10.66.0.2",
                        "dst": "192.168.10.5",
                        "port": None,
                        "name": None,
                        "list": None,
                        "via": "pipe",
                    },
                ],
            }
        )
    )
    assert 'href="/live" class="active"' in client.get("/live").text
    assert (tmp_path / "live-watch").exists()
    d = client.get("/live/data").json()
    assert [(r["client_name"], r["route"]) for r in d["dns"]] == [
        ("Phone", "video → nl"),
        ("Home", "Everything else → This server"),  # a client on the network behind the Home peer
    ]
    assert [(r["route"], r["via_label"]) for r in d["conns"]] == [("video → nl", "nl"), ("Pipe peer", "Pipe")]
    assert d["lists"] == [{"id": 1, "name": "video"}]

    r = client.post("/live/add", data={"csrf": token, "list": "1", "entry": "example.net"})
    assert r.json() == {"ok": True, "message": "Added example.net to video."}
    assert state_of(tmp_path)["lists"][0]["entries"] == ["example.com", "example.net"]
    assert (
        "already on video" in client.post("/live/add", data={"csrf": token, "list": "1", "entry": "EXAMPLE.net"}).text
    )
    assert client.post("/live/add", data={"csrf": token, "list": "1", "entry": "no such thing!"}).status_code == 400
    assert client.post("/live/add", data={"csrf": token, "list": "9", "entry": "example.org"}).status_code == 400
    assert client.post("/live/add", data={"csrf": "x", "list": "1", "entry": "example.org"}).status_code == 400

    r = client.post("/live/dns", data={"csrf": token, "action": "allow", "name": "ads.example.org"})
    assert r.json()["ok"] and state_of(tmp_path)["dns"]["allow"] == ["ads.example.org"]
    client.post("/live/dns", data={"csrf": token, "action": "block", "name": "tracker.example.net"})
    assert state_of(tmp_path)["dns"]["block"][-1] == "tracker.example.net"  # added to the seed's
    assert client.post("/live/dns", data={"csrf": token, "action": "block", "name": "x;y"}).status_code == 400

    signed_out = TestClient(client.app)
    assert signed_out.get("/live/data").status_code == 401


def test_live_watch_replaces_a_file_it_cannot_touch(tmp_path, monkeypatch):
    from vpn_egress.panel import live

    (tmp_path / "live-watch").write_text("")
    real = os.utime

    def utime(path, *a, **kw):
        if str(path).endswith("live-watch") and not getattr(utime, "done", False):
            utime.done = True
            raise PermissionError(13, "Permission denied")
        return real(path, *a, **kw)

    monkeypatch.setattr(live.os, "utime", utime)
    live.touch_watch(tmp_path)
    assert (tmp_path / "live-watch").exists() and utime.done


def test_live_lookup_labels_the_routers_answer(tmp_path):
    import socket
    import threading

    client, token = pipe_ready(tmp_path)
    add_exit(client, "nl")
    client.post("/routing/add", data={"csrf": token, "name": "japan", "exit": "1", "entries": "JP\nexample.co.jp"})
    assert client.get("/live/lookup?q=192.0.2.1").status_code == 503  # no router socket

    answer = {
        "query": "www.example.co.jp",
        "kind": "domain",
        "claim": 1,
        "error": None,
        "databases": {"country": 1, "asn": 1},
        "addresses": [
            {
                "ip": "203.0.113.9",
                "geoip": {"code": "JP", "prefix": "203.0.113.0/24"},
                "asn": {"number": 64500, "org": "Example KK", "prefix": "203.0.112.0/20"},
                "matches": [{"list": 1, "reasons": [{"kind": "geoip", "name": "JP"}, {"kind": "learned"}]}],
                "route": 1,
            },
            {
                "ip": "192.0.2.1",
                "geoip": {"code": None, "prefix": None},
                "asn": {"number": None},
                "matches": [],
                "route": "default",
            },
        ],
    }
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(tmp_path / "lookup.sock"))
    srv.listen(1)
    got = []

    def serve():
        conn, _ = srv.accept()
        with conn, conn.makefile("rwb") as f:
            got.append(json.loads(f.readline()))
            f.write((json.dumps(answer) + "\n").encode())

    threading.Thread(target=serve, daemon=True).start()
    d = client.get("/live/lookup?q=www.example.co.jp").json()
    srv.close()
    assert got == [{"q": "www.example.co.jp"}]
    assert d["claim_label"] == "japan → nl"
    first, other = d["addresses"]
    assert first["matches"] == [{"list": "japan", "first": True, "why": ["GeoIP JP", "learned from DNS"]}]
    assert first["route_label"] == "japan → nl" and other["route_label"] == "Everything else → This server"
    assert 'id="lookup-q"' in client.get("/live").text


def test_exit_fallback_settings_stats_and_switch(tmp_path):
    import socket
    import threading

    client = signed_in(tmp_path)
    add_exit(client, "nl")
    token = csrf_of(client.get("/exits").text)
    r = client.post("/exits/1/edit", data={"csrf": token, "name": "nl", "expires": "", "fallback": "on"})
    assert r.status_code == 400 and "Pick a country" in r.text
    client.post(
        "/exits/1/edit",
        data={
            "csrf": token,
            "name": "nl",
            "expires": "",
            "fallback": "on",
            "fallback_country": "Netherlands",
            "fallback_ipv6": "on",
        },
    )
    assert state_of(tmp_path)["exits"][0]["fallback"] == {
        "enabled": True,
        "provider": "protonvpn",
        "country": "Netherlands",
        "ipv6": True,
    }

    (tmp_path / "status.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "exits": [{"id": 1, "name": "nl", "enabled": True, "up": True, "handshake_age": 5, "rx": 0, "tx": 0}],
                "pipe": {"interface": "awg0", "peers": []},
                "lists": [],
                "error": None,
            }
        )
    )
    stats = {
        "now": {"rtt4": 23.4, "loss4": 0.0, "rtt6": 25.0, "loss6": 0.0, "rate_rx": 1_250_000, "rate_tx": 125_000},
        "usual": {"rtt4": 20.0, "rtt6": 22.0},
        "peak_24h": {"rx": 12_500_000, "tx": 1_000_000},
        "peak_7d": {"rx": 12_500_000, "tx": 1_000_000},
        "samples": 10,
    }
    (tmp_path / "exit-stats.json").write_text(
        json.dumps(
            {
                "updated": int(time.time()),
                "exits": {
                    "1": {
                        "server": {
                            "name": "NL#412",
                            "city": "Amsterdam",
                            "country": "Netherlands",
                            "endpoint": "198.51.100.2:51820",
                        },
                        "since": time.time() - 60,
                        "reason": "IPv4 packet loss 40%",
                        "degraded": None,
                        "stats": stats,
                    }
                },
            }
        )
    )
    page = client.get("/exits").text
    assert "NL#412" in page and "23&nbsp;ms" in page and "10.0\u00a0Mbit/s" in page and "100\u00a0Mbit/s" in page
    assert "Back to main" in page and "Next server" in page
    status = client.get("/").text
    assert "is on fallback server NL#412 (Amsterdam): IPv4 packet loss 40%" in status

    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(tmp_path / "lookup.sock"))
    srv.listen(2)
    got = []

    def serve():
        for _ in range(2):  # the Exits page asks for countries, then the switch
            conn, _ = srv.accept()
            with conn, conn.makefile("rwb") as f:
                req = json.loads(f.readline())
                got.append(req)
                reply = (
                    {"ok": True, "message": "switching to the main server"}
                    if req.get("cmd") == "switch"
                    else {"countries": [{"country": "Netherlands", "servers": 5, "ipv6": 3}], "updated": 1}
                )
                f.write((json.dumps(reply) + "\n").encode())

    threading.Thread(target=serve, daemon=True).start()
    r = client.post("/exits/1/switch", data={"csrf": token, "to": "main"})
    srv.close()
    assert got[0] == {"cmd": "switch", "exit": 1, "to": "main"}
    assert "Switching to the main server." in r.text and "Netherlands (5, 3 with IPv6)" in r.text


def test_exit_warnings_degraded_without_fallback():
    from vpn_egress.panel.app import exit_warnings

    state = {"exits": [{"id": 1, "name": "nl", "enabled": True}]}
    ws = exit_warnings(state, {"exits": {"1": {"server": None, "degraded": "IPv4 latency 300 ms (usually 20 ms)"}}})
    assert [(w["key"], w["stage"], w["text"]) for w in ws] == [
        ("exit_degraded:1", "IPv4latency", "Exit nl: IPv4 latency 300 ms (usually 20 ms).")
    ]
    assert exit_warnings(state, {"exits": {"1": {"server": None, "degraded": "down: every IPv4 ping lost"}}}) == []


def test_exit_renew_one_and_all(tmp_path):
    import datetime

    client = signed_in(tmp_path)
    add_exit(client, "nl")
    add_exit(client, "jp")
    token = csrf_of(client.get("/exits").text)
    year = (datetime.datetime.now(datetime.UTC).date() + datetime.timedelta(days=365)).isoformat()
    client.post("/exits/1/edit", data={"csrf": token, "name": "nl", "expires": "2026-12-01"})
    client.post("/exits/2/edit", data={"csrf": token, "name": "jp", "expires": "2026-12-02"})
    r = client.post("/exits/1/renew", data={"csrf": token})
    assert f"nl: expiry set to {year}." in r.text
    assert [e["expires"] for e in state_of(tmp_path)["exits"]] == [year, "2026-12-02"]
    r = client.post("/exits/renew", data={"csrf": token})
    assert f"Expiry set to {year} for nl, jp." in r.text
    assert [e["expires"] for e in state_of(tmp_path)["exits"]] == [year, year]
