# php-version-scanner

Scans IPv4/IPv6 hosts on ports 80, 443, 8080 and 8443. For each host it finds
the PHP version and reports whether that version is in the list of patched
versions. The result is a Markdown table with a status per host. IPv4 and IPv6
addresses of the same host are grouped together when their HTTPS certificate
and DNS records agree.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

## Usage

Run the scanner from a network that can still reach the blocked hosts
(management network or firewall exception).

```sh
.venv/bin/python -m phpscan --hosts hosts.txt --versions php-versions.txt -o report.md --json report.json
```

| Option | Default | Meaning |
|---|---|---|
| `--hosts` | `hosts.txt` | One IPv4/IPv6 address or CIDR per line, `#` comments |
| `--versions` | `php-versions.txt` | Patched PHP versions, one `x.y.z` per line |
| `-o, --output` | stdout | Markdown report |
| `--json` | – | Also write all evidence as JSON |
| `--ports` | `80,443,8080,8443` | Ports to check |
| `--workers` | `32` | Parallel probes |
| `--timeout` / `--dns-timeout` | `5` / `5` | Seconds |
| `--no-phpinfo-probe` | off | Skip `/phpinfo.php`, `/info.php`, … |
| `--no-vhost-pass` | off | Don't re-check with certificate host names (Host header + SNI) |
| `--max-vhosts` | `5` | Host names per IP for the vhost pass |
| `--first-only` | off | Only scan the first valid entry of the hosts file (quick test run) |
| `-v` | off | Log every probe result |

Exit codes: `0` ok, `2` input or usage error, `3` incomplete probe implementation.

## Status values

| Status | Meaning |
|---|---|
| `patched` | Every detected version is in `php-versions.txt` (exact `x.y.z` match; the distro suffix is ignored) |
| `unpatched` | At least one detected version is not in the list |
| `unknown` | Reachable, but no version detected (PHP version hidden, no PHP markers, or no HTTP answer) |
| `offline` | No port reachable |

A group gets the worst status of its reachable members. If the members
disagree, the group is marked `⚠ inconsistent`.

## How it works

1. **Probe** (`probe.py`): checks each port, works out HTTP or HTTPS, saves the
   default certificate, and requests a few paths to collect PHP evidence.
2. **Detect** (`detect.py`): versions from `X-Powered-By`/`Server` headers and
   phpinfo pages. Markers that show PHP without a version (cookies, CMS
   headers, error messages, `.php` links) lead to `unknown`.
3. **Identity** (`grouping.py`, `dnsutil.py`, `certs.py`): PTR lookups, forward
   lookups of the certificate names, and the cert ↔ IP match (`IP in SAN`,
   `via DNS`, `mismatch`).
4. **Vhost pass**: checks each forward-confirmed name again with SNI and the
   `Host` header set to that name.
5. **Grouping**: IPv4 and IPv6 are merged only if they share a certificate
   fingerprint **and** a certificate name (or a PTR name the certificate
   covers) has an A record for the IPv4 and an AAAA record for the IPv6
   address. Cases with only one of these signals are listed as
   "possible same host".
6. **Report** (`status.py`, `report.py`).

## Tests

```sh
.venv/bin/python -m pytest
```

Most tests use a fake `probe` and a `StaticResolver`. Probe integration tests
use only temporary HTTP/HTTPS servers bound to localhost. The reusable
`php_server` fixture accepts a `PHPWebsite` profile, for example:

```python
from phpscan.probe import Config, scan_port
from testserver import PHPWebsite


def test_php_82(php_server):
    server = php_server(PHPWebsite("8.2.35"), tls=True)
    result = scan_port(server.ip, server.port, Config(timeout=1))
    assert result.evidence[0].version == "8.2.35"
```

Pass `vhosts={"old.example.test": PHPWebsite("7.4.33")}` to simulate
different versions selected by the HTTP Host header and TLS SNI.
