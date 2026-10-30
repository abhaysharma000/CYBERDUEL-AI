"""Tests for defensive heuristic rules and indicator identification."""

from cyberduel_threat_intel.heuristics import URLHeuristicAnalyzer
from cyberduel_threat_intel.normalizer import URLNormalizer


def test_whitelist_skips_adversarial_heuristics() -> None:
    analyzer = URLHeuristicAnalyzer()
    # Official trusted domain with a login path
    norm = URLNormalizer.normalize("https://google.com/accounts/login")
    evidence = analyzer.analyze(norm)
    assert len(evidence) == 1
    assert evidence[0].category == "whitelist"


def test_homoglyph_detection_rule() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("https://xn--pypal-4ve.com/account")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "homograph" in categories


def test_credential_spoofing_rule() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("https://bankofamerica.com@malicious-host.net/auth")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "credentials" in categories


def test_ip_host_and_custom_port_rule() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("http://192.168.1.50:9000/login")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "network" in categories
    assert any("port :9000" in e.reason for e in evidence)


def test_brand_impersonation_on_foreign_domain() -> None:
    analyzer = URLHeuristicAnalyzer()
    # Brand token 'paypal' used in subdomain of foreign registrable domain 'attacker-domain.com'
    norm = URLNormalizer.normalize("https://paypal.verification-portal.attacker-domain.com/secure")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "impersonation" in categories
    assert any("paypal" in e.reason for e in evidence)


def test_official_brand_domain_not_flagged_as_impersonation() -> None:
    analyzer = URLHeuristicAnalyzer()
    # Official paypal domain should never flag impersonation of itself
    norm = URLNormalizer.normalize("https://www.paypal.com/signin")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "impersonation" not in categories


def test_phishing_keywords_detection() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("https://unknown-service-site.org/wallet-connect/verify-login")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "lexical" in categories


def test_double_encoding_rule() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("https://example-test.com/path?param=%2525admin")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "obfuscation" in categories


def test_heuristic_analyzer_determinism() -> None:
    analyzer = URLHeuristicAnalyzer()
    norm = URLNormalizer.normalize("https://paypal.com@badsite.xyz:8888/login")
    ev1 = analyzer.analyze(norm)
    ev2 = analyzer.analyze(norm)
    assert len(ev1) == len(ev2)
    assert [e.category for e in ev1] == [e.category for e in ev2]
    assert [e.reason for e in ev1] == [e.reason for e in ev2]


def test_rule_disable_toggle() -> None:
    # Disable IP host rule via override
    overrides = {"HR-IP-HOST-03": {"enabled": False}}
    analyzer = URLHeuristicAnalyzer(rule_overrides=overrides)
    norm = URLNormalizer.normalize("http://192.168.1.1/index.html")
    evidence = analyzer.analyze(norm)
    categories = [e.category for e in evidence]
    assert "network" not in categories
