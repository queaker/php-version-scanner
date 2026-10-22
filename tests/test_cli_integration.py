"""End-to-end: the real CLI and the real probe against local test servers."""
import json
from collections.abc import Callable

from phpscan import cli
from phpscan.dnsutil import StaticResolver
from testserver import PHPTestServer, PHPWebsite


def test_cli_scans_local_servers_end_to_end(php_server: Callable[..., PHPTestServer], tmp_path) -> None:
    # One IP, three services: patched HTTPS (plus an outdated vhost behind the
    # certificate name), outdated plain HTTP, and a site without PHP.
    https = php_server(PHPWebsite("8.2.35"), vhosts={"localhost": PHPWebsite("8.1.31")}, tls=True)
    http = php_server(PHPWebsite("7.4.33-1+deb11u5"))
    no_php = php_server()

    (tmp_path / "hosts.txt").write_text("127.0.0.1\n")
    (tmp_path / "versions.txt").write_text("8.5.12\n8.4.27\n8.3.36\n8.2.35\n")
    args = cli.build_parser().parse_args([
        "--hosts", str(tmp_path / "hosts.txt"),
        "--versions", str(tmp_path / "versions.txt"),
        "--ports", f"{https.port},{http.port},{no_php.port}",
        "--timeout", "1",
        "-o", str(tmp_path / "report.md"),
        "--json", str(tmp_path / "report.json"),
    ])
    # "localhost" (from the default certificate) resolves to the scanned IP,
    # which makes it a forward-confirmed name for the vhost pass.
    resolver = StaticResolver({"localhost": {"127.0.0.1"}})

    assert cli.run(args, resolver=resolver) == 0

    data = json.loads((tmp_path / "report.json").read_text())
    (group,) = data["groups"]
    (member,) = group["members"]
    assert group["status"] == "unpatched"
    assert member["cert_match"] == "san"
    assert member["confirmed_names"] == ["localhost"]

    ports = member["ports"]
    assert ports[str(https.port)]["scheme"] == "https"
    assert ports[str(https.port)]["vhosts_checked"] == ["localhost"]
    assert ports[str(http.port)]["scheme"] == "http"
    assert ports[str(no_php.port)]["scheme"] == "http"
    assert ports[str(no_php.port)]["evidence"] == []

    versions = {e["version"] for p in ports.values() for e in p["evidence"] if e["version"]}
    assert versions == {"8.2.35", "8.1.31", "7.4.33-1+deb11u5"}

    report = (tmp_path / "report.md").read_text()
    row = next(line for line in report.splitlines() if line.startswith("| localhost |"))
    assert "| 127.0.0.1 | ✅ IP in SAN | localhost |" in row
    assert "7.4.33-1+deb11u5" in row and "8.1.31" in row and "8.2.35" in row
    assert row.endswith("**unpatched** |")
    # Every server saw only the scanner's user agent.
    assert {r.user_agent for s in (https, http, no_php) for r in s.requests} == {
        "php-version-scanner/1.0 (internal patch audit)"}
