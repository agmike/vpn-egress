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
    token = csrf_of(client.get("/lists").text)
    client.post(
        "/lists/add",
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
    client.post("/lists/1/delete", data={"csrf": token})
    client.post("/exits/1/delete", data={"csrf": token})
    assert state_of(tmp_path)["exits"] == []


def test_lists_add_save_move(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/lists").text)
    for name, entries in (("first", "a.example"), ("second", "203.0.113.0/24\n2001:DB8::/32\n*.B.example.")):
        r = client.post(
            "/lists/add",
            data={"csrf": token, "name": name, "exit": "1", "kill_switch": "", "entries": entries},
            follow_redirects=False,
        )
        assert r.status_code == 303
    lists = state_of(tmp_path)["lists"]
    assert [l["name"] for l in lists] == ["first", "second"]
    assert lists[1]["entries"] == ["203.0.113.0/24", "2001:DB8::/32", "*.B.example."]
    assert lists[1]["resolve_via_exit"] is False and lists[1]["when_down"] == "direct"
    client.post("/lists/2/move", data={"csrf": token, "dir": "up"})
    assert [l["name"] for l in state_of(tmp_path)["lists"]] == ["second", "first"]
    client.post(
        "/lists/1/save",
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
    token = csrf_of(client.get("/lists").text)
    r = client.post(
        "/lists/add",
        data={"csrf": token, "name": "", "exit": "9", "kill_switch": "on", "entries": "ok.example\nnot valid!"},
    )
    assert r.status_code == 400
    assert "not valid!" in r.text and "Pick an exit" in r.text and "1–40" in r.text
    assert "lists" not in state_of(tmp_path)


def test_exits_and_lists_need_sign_in_and_csrf(tmp_path):
    client = make_client(tmp_path, {"sub": "1", "groups": ["admins"]})
    for path in ("/exits", "/lists"):
        assert client.get(path, follow_redirects=False).status_code == 303
    assert client.post("/exits/add", data={}, follow_redirects=False).status_code == 303
    client = signed_in(tmp_path)
    assert client.post("/exits/add", data={"name": "x", "conf": CONF}).status_code == 400
    assert client.post("/lists/add", data={"name": "x", "exit": "1"}).status_code == 400


def test_list_accepts_wildcards_and_tld(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/lists").text)
    client.post(
        "/lists/add",
        data={"csrf": token, "name": "japan", "exit": "1", "kill_switch": "on", "entries": "*.dmm.co.jp\n*.jp\njp"},
    )
    assert state_of(tmp_path)["lists"][0]["entries"] == ["*.dmm.co.jp", "*.jp", "jp"]


def test_list_comments_and_rename(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/lists").text)
    text = "# streaming\nnetflix.com   # main\n\n\n\nnflxvideo.net\n\n"
    client.post(
        "/lists/add", data={"csrf": token, "name": "Streaming (NL)", "exit": "1", "kill_switch": "on", "entries": text}
    )
    l = state_of(tmp_path)["lists"][0]
    assert l["name"] == "Streaming (NL)"
    assert l["entries"] == ["# streaming", "netflix.com   # main", "", "nflxvideo.net"]
    page = client.get("/lists").text
    assert "netflix.com   # main" in page and "List format" in page
    client.post(
        "/lists/1/save", data={"csrf": token, "name": "Video", "exit": "1", "kill_switch": "on", "entries": text}
    )
    assert state_of(tmp_path)["lists"][0]["name"] == "Video"


def test_exit_dns_flag_and_no_groups_footer(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/exits").text)
    no_dns = CONF.replace("DNS = 10.64.0.1, fd00:64::1\n", "")
    client.post("/exits/add", data={"csrf": token, "name": "no-dns", "conf": no_dns})
    page = client.get("/lists").text
    assert 'data-dns="yes"' in page and 'data-dns="no"' in page and "Use exit DNS" in page
    assert "admins" not in client.get("/").text


def test_add_buttons_and_collapsed_lists(tmp_path):
    client = signed_in(tmp_path)
    add_exit(client)
    token = csrf_of(client.get("/lists").text)
    client.post(
        "/lists/add", data={"csrf": token, "name": "ip-check", "exit": "1", "kill_switch": "on", "entries": "ipify.org"}
    )
    page = client.get("/lists").text
    assert 'data-open="#new-list"' in page and 'id="new-list" hidden' in page
    assert 'data-open="#edit-1"' in page and 'id="edit-1" hidden' in page
    assert "→ provider-nl" in page and "kill switch on" in page
    r = client.post("/lists/add", data={"csrf": token, "name": "", "exit": "1", "entries": ""})
    assert 'id="new-list" hidden' not in r.text  # errors keep the form open
    exits = client.get("/exits").text
    assert 'data-open="#new-exit"' in exits and 'id="new-exit" hidden' in exits
    assert "Add blocklist" in client.get("/dns").text
