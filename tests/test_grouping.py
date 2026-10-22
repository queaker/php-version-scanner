from conftest import make_cert, make_ip

from phpscan.dnsutil import StaticResolver
from phpscan.grouping import annotate_identity, group_hosts

V4, V6 = "192.0.2.10", "2001:db8::10"


def run(results, resolver):
    annotate_identity(results, resolver)
    return group_hosts(results, resolver)


def test_groups_same_cert_and_dns():
    cert = make_cert(dns=["web01.example.com"])
    res = StaticResolver({"web01.example.com": {V4, V6}})
    groups, notes = run([make_ip(V4, cert=cert), make_ip(V6, cert=cert)], res)
    assert len(groups) == 1
    assert groups[0].name == "web01.example.com"
    assert [m.ip for m in groups[0].members] == [V4, V6]
    assert "web01.example.com" in groups[0].reason
    assert notes == []


def test_no_group_without_dns():
    cert = make_cert(dns=["web01.example.com"])
    groups, notes = run([make_ip(V4, cert=cert), make_ip(V6, cert=cert)], StaticResolver())
    assert len(groups) == 2
    assert len(notes) == 1 and "same certificate" in notes[0]


def test_no_group_when_certs_differ():
    res = StaticResolver({"web01.example.com": {V4, V6}})
    a = make_ip(V4, cert=make_cert(dns=["web01.example.com"], serial=1))
    b = make_ip(V6, cert=make_cert(dns=["web01.example.com"], serial=2))
    groups, notes = run([a, b], res)
    assert len(groups) == 2
    assert any("certificates differ" in n for n in notes)


def test_dns_only_to_one_family_not_grouped():
    cert = make_cert(dns=["web01.example.com"])
    res = StaticResolver({"web01.example.com": {V4}})
    groups, _ = run([make_ip(V4, cert=cert), make_ip(V6, cert=cert)], res)
    assert len(groups) == 2


def test_wildcard_cert_grouped_via_ptr():
    cert = make_cert(dns=["*.example.com"])
    res = StaticResolver({"host7.example.com": {V4, V6}},
                         {V4: ["host7.example.com"], V6: ["host7.example.com"]})
    groups, _ = run([make_ip(V4, cert=cert), make_ip(V6, cert=cert)], res)
    assert len(groups) == 1 and groups[0].name == "host7.example.com"


def test_wildcard_without_ptr_not_grouped():
    cert = make_cert(dns=["*.example.com"])
    groups, _ = run([make_ip(V4, cert=cert), make_ip(V6, cert=cert)], StaticResolver())
    assert len(groups) == 2


def test_two_v4_never_grouped():
    cert = make_cert(dns=["lb.example.com"])
    res = StaticResolver({"lb.example.com": {"192.0.2.1", "192.0.2.2"}})
    groups, _ = run([make_ip("192.0.2.1", cert=cert), make_ip("192.0.2.2", cert=cert)], res)
    assert len(groups) == 2


def test_cert_match_values():
    res = StaticResolver({"a.example.com": {"192.0.2.2"}})
    san = make_ip("192.0.2.1", cert=make_cert(ips=["192.0.2.1"]))
    dns = make_ip("192.0.2.2", cert=make_cert(dns=["a.example.com"]))
    no = make_ip("192.0.2.3", cert=make_cert(cn="localhost"))
    plain = make_ip("192.0.2.4", scheme="http")
    annotate_identity([san, dns, no, plain], res)
    assert [r.cert_match for r in (san, dns, no, plain)] == ["san", "dns", "no", "n/a"]
    assert dns.confirmed_names == ["a.example.com"]


def test_single_host_name_falls_back_to_ptr_then_ip():
    res = StaticResolver(reverse={"192.0.2.1": ["ptr.example.com"]})
    groups, _ = run([make_ip("192.0.2.1"), make_ip("192.0.2.2")], res)
    assert sorted(g.name for g in groups) == ["192.0.2.2", "ptr.example.com"]
