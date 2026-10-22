import json

import pytest
from conftest import make_cert

from phpscan import cli, probe
from phpscan.dnsutil import StaticResolver
from phpscan.models import Evidence, PortResult

CERT = make_cert(dns=["web01.example.com"])
RESOLVER = StaticResolver({"web01.example.com": {"192.0.2.10", "2001:db8::10"}})


def fake_scan_port(ip, port, cfg):
    if ip == "192.0.2.99":
        return PortResult(port, "timeout", error="timed out")
    if port == 443 and ip in ("192.0.2.10", "2001:db8::10"):
        return PortResult(port, "open", "https", CERT,
                          evidence=[Evidence("X-Powered-By header", f"https://{ip}:443/", "8.2.35")])
    if port == 80 and ip == "192.0.2.20":
        return PortResult(port, "open", "http", evidence=[Evidence("cookie PHPSESSID", "http://x/", None)])
    return PortResult(port, "closed", error="connection refused")


def fake_scan_vhost(ip, pr, name, cfg):
    return [Evidence("phpinfo() page", f"https://{ip}:443/info.php (Host: {name})", "8.2.35")]


@pytest.fixture
def files(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("192.0.2.10\n2001:0db8::10\n192.0.2.20\n192.0.2.99\nnot-an-ip\n192.0.2.10\n")
    versions = tmp_path / "v.txt"
    versions.write_text("8.5.12\n8.4.27\n8.3.36\n8.2.35\n")
    return hosts, versions, tmp_path


def test_end_to_end(files, monkeypatch, capsys):
    hosts, versions, tmp = files
    monkeypatch.setattr(probe, "scan_port", fake_scan_port)
    monkeypatch.setattr(probe, "scan_vhost", fake_scan_vhost)
    args = cli.build_parser().parse_args(["--hosts", str(hosts), "--versions", str(versions),
                                          "--json", str(tmp / "out.json"), "-o", str(tmp / "r.md")])
    assert cli.run(args, resolver=RESOLVER) == 0
    md = (tmp / "r.md").read_text()
    assert "| web01.example.com | 192.0.2.10<br>2001:db8::10 |" in md
    assert "phpinfo() page (443)" in md
    assert "**unknown**" in md and "**offline**" in md
    assert "| **total** | 3 | 4 |" in md
    assert "not an IP address" in capsys.readouterr().err
    data = json.loads((tmp / "out.json").read_text())
    web = next(g for g in data["groups"] if g["name"] == "web01.example.com")
    assert web["status"] == "patched"
    assert web["members"][0]["ports"]["443"]["vhosts_checked"] == ["web01.example.com"]


def test_read_hosts_cidr(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("192.0.2.0/30\n10.0.0.0/8\n# c\n2001:db8::1 # x\n")
    assert cli.read_hosts(str(f)) == ["192.0.2.1", "192.0.2.2", "2001:db8::1"]


def test_read_hosts_first_only(tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("# header\n\nnot-an-ip\n192.0.2.0/30\n2001:db8::1\n")
    assert cli.read_hosts(str(f), first_only=True) == ["192.0.2.1", "192.0.2.2"]
    f.write_text("2001:db8::1\n192.0.2.1\n")
    assert cli.read_hosts(str(f), first_only=True) == ["2001:db8::1"]
    assert cli.build_parser().parse_args(["--first-only"]).first_only
