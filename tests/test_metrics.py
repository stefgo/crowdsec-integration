"""Tests for the Prometheus parser."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "crowdsec"))

from metrics import MetricSet, parse_prometheus  # noqa: E402

SAMPLE = """
# HELP cs_active_decisions Number of active decisions.
# TYPE cs_active_decisions gauge
cs_active_decisions{action="ban",origin="crowdsec",reason="crowdsecurity/ssh-bf"} 12
cs_active_decisions{action="ban",origin="CAPI",reason="lists"} 30
cs_buckets{name="crowdsecurity/ssh-bf"} 2
cs_buckets{name="crowdsecurity/http-probing"} 0
cs_parser_hits_total{datasource="/var/log/auth.log",type="syslog"} 1000
cs_parser_hits_ok_total{parser="child-crowdsecurity/sshd-logs"} 950
cs_parser_hits_ko_total{parser="child-crowdsecurity/sshd-logs"} 50
cs_lapi_route_requests_total{endpoint="/v1/decisions/stream",method="GET"} 400
cs_lapi_route_requests_total{endpoint="/v1/heartbeat",method="GET"} 99
cs_info{version="v1.6.2"} 1
process_start_time_seconds 1.7e+09
"""


def test_parses_labels_and_values():
    metrics = MetricSet(parse_prometheus(SAMPLE))
    assert metrics.total("cs_active_decisions") == 42
    assert metrics.total("cs_buckets") == 2
    assert metrics.single("process_start_time_seconds") == 1.7e9
    assert metrics.label_of("cs_info", "version") == "v1.6.2"


def test_unknown_metric_is_none_not_zero():
    metrics = MetricSet(parse_prometheus(SAMPLE))
    assert metrics.total("cs_does_not_exist") is None


def test_group_sum_by_label():
    metrics = MetricSet(parse_prometheus(SAMPLE))
    assert metrics.group_sum("cs_active_decisions", "reason") == {
        "crowdsecurity/ssh-bf": 12.0,
        "lists": 30.0,
    }


def test_predicate_filters_routes():
    metrics = MetricSet(parse_prometheus(SAMPLE))
    total = metrics.total(
        "cs_lapi_route_requests_total",
        lambda s: s.labels.get("endpoint", "").startswith("/v1/decisions"),
    )
    assert total == 400


def test_quoted_comma_in_label_value():
    parsed = parse_prometheus('cs_x{a="one, value",b="two"} 3')
    assert parsed["cs_x"][0].labels == {"a": "one, value", "b": "two"}
    assert parsed["cs_x"][0].value == 3.0


def test_escaped_quote_in_label_value():
    parsed = parse_prometheus('cs_x{a="he said \\"hi\\"",b="2"} 1')
    assert parsed["cs_x"][0].labels["a"] == 'he said "hi"'
    assert parsed["cs_x"][0].labels["b"] == "2"


def test_comments_and_garbage_are_ignored():
    parsed = parse_prometheus("# HELP x\n\nbroken\ncs_ok 1\n")
    assert "cs_ok" in parsed
    assert "broken" not in parsed


def test_first_total_falls_back():
    metrics = MetricSet(parse_prometheus(SAMPLE))
    assert metrics.first_total(("cs_missing", "cs_parser_hits_total")) == 1000
