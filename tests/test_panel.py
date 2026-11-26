import json
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
    assert "8.5 TB" in page and "of 10.0 TB" in page and "85.0%" in page
    assert "at 85% of the allowance" in page and "2026-10: 3.0 TB" in page
