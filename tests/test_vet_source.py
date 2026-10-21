import pytest

from scanner.vet.source import InvalidSource, Source, parse_source


def public(_host):
    return ["140.82.112.3"]


@pytest.mark.parametrize("text,host,path,branch,clone", [
    ("torvalds/linux", "github.com", "torvalds/linux", None, "https://github.com/torvalds/linux.git"),
    ("my/repo@feature/x", "github.com", "my/repo", "feature/x", "https://github.com/my/repo.git"),
    ("https://github.com/o/r", "github.com", "o/r", None, "https://github.com/o/r.git"),
    ("https://github.com/o/r.git", "github.com", "o/r", None, "https://github.com/o/r.git"),
    ("https://GitHub.com/o/r/", "github.com", "o/r", None, "https://github.com/o/r.git"),
    ("gitlab.com/a/b/c/d", "gitlab.com", "a/b/c/d", None, "https://gitlab.com/a/b/c/d.git"),
    ("https://gitlab.com/g/s/p.git", "gitlab.com", "g/s/p", None, "https://gitlab.com/g/s/p.git"),
    ("https://git.example.org/g/s/p@v1.2", "git.example.org", "g/s/p", "v1.2", "https://git.example.org/g/s/p.git"),
])
def test_valid(text, host, path, branch, clone):
    s = parse_source(text, resolver=public)
    assert isinstance(s, Source)
    assert (s.host, s.path, s.branch, s.clone_url) == (host, path, branch, clone)
    assert "@" not in s.clone_url


@pytest.mark.parametrize("text", [
    "", "   ", "\n",
    "https://github.com@evil.example/x/y",
    "https://user:pw@github.com/o/r",
    "https://github.com:evil@evil.example/o/r",
    "http://github.com/o/r", "file:///etc/passwd", "ssh://git@github.com/o/r",
    "git://github.com/o/r", "ftp://github.com/o/r", "git@github.com:o/r.git",
    "https://localhost/o/r", "https://127.0.0.1/o/r", "https://10.0.0.5/o/r",
    "https://192.168.1.1/o/r", "https://169.254.169.254/o/r", "https://172.16.0.1/o/r",
    "https://[::1]/o/r", "https://[fe80::1]/o/r", "https://[::ffff:127.0.0.1]/o/r",
    "https://2130706433/o/r", "https://0x7f000001/o/r", "https://0177.0.0.1/o/r",
    "https://127.1/o/r", "https://github.com./o/r", "https://intranet/o/r",
    "https://github.com:8443/o/r", "https://github.com:22/o/r",
    "o/../r", "https://github.com/o/../r", "https://github.com/../r", "o/./r",
    "o/r s", "o /r", "https://github.com/o/r\n", "o/r\x00", "o/r\x1b[0m", "o/r\t",
    "o/r@a;b", "o/r@$(id)", "o/r@`id`", "o/r@a b", "o/r@a|b", "o/r@a&b",
    "o/r@-x", "o/r@--upload-pack=x", "o/r@", "o/r@a..b", "o/r@a@b", "o/r@x.lock", "o/r@a/.b", "o/r@a/-b", "o/r@a//b",
    "--upload-pack=touch/x", "-o/r", "o/-r--x", "-c/core.sshCommand=x",
    "o/r?x=1", "o/r#frag", "https://github.com/o/r?x=1", "https://github.com/o/r#f",
    "o\\r", "https://github.com\\@evil.example/o/r", "o/r%2e", "o/r;id", "o/$(id)",
    "o", "https://github.com/o", "https://github.com/", "https://github.com",
    "a/b/c", "https://github.com/a/b/c",  # github has exactly owner/repo
    "https://-evil.com/o/r", "https://evil_.com/o/r", "https://ex ample.com/o/r",
    "https://exämple.com/o/r", "o/rä", "https://github.com//o/r", "o//r",
    "https://" + "a" * 300 + ".com/o/r",
])
def test_rejected(text):
    with pytest.raises(InvalidSource) as e:
        parse_source(text, resolver=public)
    assert str(e.value)


def test_hostname_resolving_to_private_ip_rejected():
    for ip in ["10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.0.9", "::1", "fe80::1",
               "::ffff:10.0.0.1", "fd00::1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "::a00:1", "fec0::1", "2002:a00:1::1", "2001::1", "100.64.0.1", "0.0.0.0"]:
        with pytest.raises(InvalidSource):
            parse_source("https://git.evil.example/g/p", resolver=lambda h, ip=ip: [ip])


def test_any_private_among_many_rejected():
    with pytest.raises(InvalidSource):
        parse_source("https://git.evil.example/g/p", resolver=lambda h: ["8.8.8.8", "10.0.0.1"])


def test_resolution_failure_or_empty_fails_closed():
    def boom(h):
        raise OSError("nxdomain")
    for r in (boom, lambda h: [], lambda h: ["not-an-ip"]):
        with pytest.raises(InvalidSource):
            parse_source("https://git.evil.example/g/p", resolver=r)


def test_vietnamese_message():
    with pytest.raises(InvalidSource) as e:
        parse_source("http://github.com/o/r", resolver=public)
    assert "không" in str(e.value).lower() or "chỉ" in str(e.value).lower()


def test_default_resolver_uses_getaddrinfo(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("10.1.1.1", 0))])
    with pytest.raises(InvalidSource):
        parse_source("https://git.evil.example/g/p")


def test_legit_global_ipv6_accepted():
    s = parse_source("https://git.example.org/g/p", resolver=lambda h: ["2606:4700::1111"])
    assert s.host == "git.example.org"
