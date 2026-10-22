from conftest import make_cert

from phpscan.certs import cert_covers, cert_has_ip, cert_names


def test_parse_cert_fields():
    c = make_cert(cn="web01.example.com", dns=["web01.example.com", "*.example.org"], ips=["192.0.2.10", "2001:db8::10"])
    assert c.san_dns == ["web01.example.com", "*.example.org"]
    assert c.san_ips == ["192.0.2.10", "2001:db8::10"]
    assert c.self_signed
    assert len(c.sha256) == 64


def test_cert_has_ip_normalizes():
    c = make_cert(ips=["2001:db8::10"])
    assert cert_has_ip(c, "2001:0db8:0000::0010")
    assert not cert_has_ip(c, "192.0.2.10")


def test_wildcard_left_label_only():
    c = make_cert(dns=["*.example.com"])
    assert cert_covers(c, "www.example.com")
    assert cert_covers(c, "WWW.Example.com.")
    assert not cert_covers(c, "a.b.example.com")
    assert not cert_covers(c, "example.com")


def test_cn_fallback_without_san():
    assert cert_names(make_cert(cn="legacy.example.com")) == ["legacy.example.com"]
    assert cert_names(make_cert(cn="localhost")) == []
    assert cert_names(make_cert(cn="192.0.2.1")) == []
