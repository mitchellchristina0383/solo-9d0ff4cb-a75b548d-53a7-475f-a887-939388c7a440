"""双线路网段重叠 / 别名映射核查 —— 引擎与 API 测试。

重点覆盖：
* 等长前缀校验、严格 CIDR、同线路原前缀重复退回；
* 去程本线路最长匹配、未映射范围、主机位保留；
* 回程两线全局最长匹配、同长并列歧义、别名冲突（跨线同一原地址算两个来源）；
* 回错线路 / 回错地址；
* 区间运算而非逐地址扫描（直接上 /0 大网段）；
* 需求指定场景：回程被更长前缀接走。
"""

import pytest

from app import app as flask_app
from route_check_engine import (
    MAX_ITEMS_PER_LINE,
    RouteCheckError,
    analyze,
    parse_input,
    parse_rule_lines,
)


# ---------------------------------------------------------------- helpers


def line_input(segments=None, rules=None):
    return {
        "segments": segments or [],
        "rules": [
            {"name": f"R{i}", "original": o, "alias": a}
            for i, (o, a) in enumerate(rules or [], 1)
        ],
    }


def make_raw(a_seg, a_rules, b_seg, b_rules):
    return {
        "A": line_input(a_seg, a_rules),
        "B": line_input(b_seg, b_rules),
    }


def find_ranges(entries):
    return [r["label"] for e in entries for r in e["ranges"]]


@pytest.fixture()
def client():
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


# ---------------------------------------------------------------- 输入校验


def test_strict_cidr_rejects_host_bits_and_garbage():
    with pytest.raises(RouteCheckError) as ei:
        analyze(make_raw(["10.0.0.5/24"], [], [], []))
    msgs = " ".join(e["message"] for e in ei.value.errors)
    assert "10.0.0.0/24" in msgs  # 给出规范写法建议

    with pytest.raises(RouteCheckError):
        analyze(make_raw(["999.0.0.0/24"], [], [], []))

    with pytest.raises(RouteCheckError):
        analyze(make_raw(["10.0.0.0"], [], [], []))  # 缺前缀长度


def test_equal_prefix_length_required():
    raw = make_raw([], [("10.0.0.0/24", "172.16.0.0/25")], [], [])
    with pytest.raises(RouteCheckError) as ei:
        analyze(raw)
    assert any("不等长" in e["message"] for e in ei.value.errors)


def test_duplicate_original_prefix_same_line_rejected():
    raw = make_raw(
        ["10.0.0.0/24"],
        [("10.0.0.0/24", "172.16.0.0/24"),
         ("10.0.0.0/24", "172.16.9.0/24")],
        [], [])
    with pytest.raises(RouteCheckError) as ei:
        analyze(raw)
    assert any("重复" in e["message"] and e["line"] == "A"
               for e in ei.value.errors)


def test_same_original_prefix_on_two_lines_is_allowed_but_conflicts():
    # 同一原前缀出现在两条线路是合法的，回程若别名也相同则产生冲突/歧义
    raw = make_raw(
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.16.0.0/24")],
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.16.0.0/24")],
    )
    res = analyze(raw)
    findings = res["findings"]
    assert res["summary"]["alias_conflict_addresses"] == 256
    assert res["summary"]["return_ambiguity_addresses"] == 256
    assert not findings["wrong_line"] and not findings["wrong_address"]
    # 两个来源都要列出来
    srcs = findings["alias_conflicts"][0]["sources"]
    assert {s["line"] for s in srcs} == {"A", "B"}


def test_parse_rule_lines_formats():
    rules = parse_rule_lines(
        "A1: 10.0.0.0/24 -> 172.16.0.0/24\n"
        "10.1.0.0/24, 172.17.0.0/24\n"
        "# 注释行\n"
        "  10.2.0.0/25 => 172.18.0.0/25 \n"
    )
    assert rules == [
        {"name": "A1", "original": "10.0.0.0/24", "alias": "172.16.0.0/24"},
        {"name": "", "original": "10.1.0.0/24", "alias": "172.17.0.0/24"},
        {"name": "", "original": "10.2.0.0/25", "alias": "172.18.0.0/25"},
    ]


# ---------------------------------------------------------------- 去程


def test_outbound_longest_match_within_own_line_and_host_bits():
    raw = make_raw(
        ["10.0.0.0/24"],
        [("10.0.0.0/24", "172.16.0.0/24"),
         ("10.0.0.128/25", "172.16.9.128/25")],
        [], [])
    res = analyze(raw)
    assert res["summary"]["address_unmapped"] == 0
    # /25 更长，128~255 走第二条；0~127 走 /24 兜底
    entries = {(m["rule"]["index"], m["original_range"]["start"]):
               m["alias_range"]["start"] for m in res["outbound_mapping"]}
    assert entries[(1, "10.0.0.0")] == "172.16.0.0"
    assert entries[(2, "10.0.0.128")] == "172.16.9.128"
    # 主机位保留：10.0.0.200 -> 172.16.9.200
    m255 = next(m for m in res["outbound_mapping"] if m["rule"]["index"] == 2)
    assert m255["original_range"]["end"] == "10.0.0.255"
    assert m255["alias_range"]["end"] == "172.16.9.255"


def test_outbound_unmapped_ranges_reported_per_line():
    raw = make_raw(
        ["10.0.0.0/24"], [("10.0.0.0/25", "172.16.0.0/25")],
        ["10.2.0.0/30"], [],
    )
    res = analyze(raw)
    findings = res["findings"]
    labels = {(e["line"], tuple(e["ranges"][0]["cidrs"]))
              for e in findings["unmapped_outbound"]}
    assert ("A", ("10.0.0.128/25",)) in labels
    assert ("B", ("10.2.0.0/30",)) in labels
    assert res["summary"]["unmapped_outbound_addresses"] == 128 + 4


def test_huge_segment_uses_range_math_not_address_scan():
    # /0 整 42.9 亿地址 + 一条 /24 规则，必须立即完成，且未映射范围正确
    raw = make_raw(["0.0.0.0/0"],
                   [("10.0.0.0/24", "172.16.0.0/24")], [], [])
    res = analyze(raw)
    s = res["summary"]
    assert s["address_total"] == 2 ** 32
    assert s["address_mapped"] == 256
    assert s["address_unmapped"] == 2 ** 32 - 256
    entries = res["findings"]["unmapped_outbound"]
    assert len(entries) == 2  # 缺口左右各一个范围条目
    cidrs = [c for e in entries for r in e["ranges"] for c in r["cidrs"]]
    # 10.0.0.0/24 被挖走后，剩余部分由不包含该 /24 的最小 CIDR 集合覆盖
    assert "10.0.0.0/24" not in cidrs
    from ipaddress import IPv4Network, IPv4Address
    assert sum(IPv4Network(c).num_addresses for c in cidrs) == 2 ** 32 - 256
    all_nets = [IPv4Network(c) for c in cidrs]
    assert any(IPv4Address("0.0.0.0") in n for n in all_nets)
    assert any(IPv4Address("255.255.255.255") in n for n in all_nets)
    assert not any(IPv4Address("10.0.0.100") in n for n in all_nets)


# ---------------------------------------------------------------- 回程


def test_return_longest_match_global_across_lines_hijack_scenario():
    """需求指定场景：回程被更长前缀接走（B 线 /25 截胡 A 线 /24 的后半段）。"""
    raw = make_raw(
        ["10.0.0.0/24"],
        [("10.0.0.0/24", "172.16.0.0/24")],          # A1
        ["10.0.99.128/25"],
        [("10.0.99.128/25", "172.16.0.128/25")],     # B1：别名与 A1 重叠且 /25 更长，
                                                      # 回程截胡后反解到另一个原地址
    )
    res = analyze(raw)
    f = res["findings"]

    # 别名冲突：172.16.0.128/25 同时被 A1 与 B2 两个来源占用
    conflict_cidrs = find_ranges(f["alias_conflicts"])
    assert conflict_cidrs == ["172.16.0.128/25"]
    sources = f["alias_conflicts"][0]["sources"]
    assert {s["line"] for s in sources} == {"A", "B"}

    # 无同长并列 -> 无歧义
    assert f["return_ambiguity"] == []

    # 回错线路：A 来源的后半段回程命中 B1，去了 B 线
    wl = f["wrong_line"]
    assert len(wl) == 1
    assert wl[0]["source_line"] == "A"
    assert wl[0]["actual_line"] == "B"
    assert wl[0]["winner_rule"]["index"] == 1
    assert find_ranges(wl) == ["172.16.0.128/25"]

    # 回错地址：B1 把别名反解到 10.0.99.128/25，而 A 的真实来源是 10.0.0.128/25
    wa = f["wrong_address"]
    assert len(wa) == 1
    assert wa[0]["expected_original_range"]["cidrs"] == ["10.0.0.128/25"]
    assert wa[0]["actual_destination_range"]["cidrs"] == ["10.0.99.128/25"]

    # A 的前半段正常回到 A 线，不产生任何问题
    assert res["summary"]["wrong_line_addresses"] == 128
    assert res["summary"]["wrong_address_addresses"] == 128


def test_return_ambiguity_equal_length_tie():
    raw = make_raw(
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.16.0.0/24")],
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.16.0.0/24")],
    )
    res = analyze(raw)
    amb = res["findings"]["return_ambiguity"]
    assert len(amb) == 1
    tied = {(r["line"], r["index"]) for r in amb[0]["tied_rules"]}
    assert tied == {("A", 1), ("B", 1)}
    # 歧义下不再单列线路/地址错误，避免重复计数
    assert not res["findings"]["wrong_line"]
    assert not res["findings"]["wrong_address"]


def test_wrong_address_within_same_line():
    """同一线路上更长的别名前缀也可能把回包接到别的原地址（回错地址但没回错线）。"""
    raw = make_raw(
        ["10.0.0.0/24", "10.0.99.128/25"],
        [("10.0.0.0/24", "172.16.0.0/24"),
         ("10.0.99.128/25", "172.16.0.128/25")],
        [], [])
    res = analyze(raw)
    f = res["findings"]
    assert not f["wrong_line"]  # 都在 A 线
    wa = f["wrong_address"]
    assert len(wa) == 1
    assert wa[0]["winner_rule"]["line"] == "A"
    assert find_ranges(wa) == ["172.16.0.128/25"]


def test_clean_baseline_has_no_findings():
    raw = make_raw(
        ["10.0.0.0/24", "10.1.0.0/24"],
        [("10.0.0.0/24", "172.16.0.0/24"),
         ("10.1.0.0/24", "172.16.1.0/24")],
        ["10.0.0.0/24"],
        [("10.0.0.0/24", "172.17.0.0/24")],
    )
    res = analyze(raw)
    s = res["summary"]
    assert s["finding_counts"] == {
        "unmapped_outbound": 0, "alias_conflicts": 0,
        "return_ambiguity": 0, "wrong_line": 0, "wrong_address": 0,
    }
    assert s["address_total"] == 256 * 3


def test_overlapping_segments_same_line_are_two_sources():
    # 同线路两个重叠网段经同一规则映射，覆盖区一个别名对应两个来源 -> 冲突
    raw = make_raw(
        ["10.0.0.0/24", "10.0.0.128/25"],
        [("10.0.0.0/24", "172.16.0.0/24")],
        [], [])
    res = analyze(raw)
    assert res["findings"]["alias_conflicts"][0]["ranges"][0]["cidrs"] == [
        "172.16.0.128/25"]
    # 地址总数按并集统计：/24 与重叠的 /25 并集仍是 256，不重复计数
    assert res["lines"]["A"]["address_total"] == 256
    assert res["lines"]["A"]["address_mapped"] == 256
    assert res["summary"]["address_total"] == 256


def test_input_limit_enforced():
    many = ["10.0.0.0/32"] * (MAX_ITEMS_PER_LINE + 1)
    with pytest.raises(RouteCheckError):
        analyze(make_raw(many, [], [], []))


def test_parse_text_input_end_to_end():
    parsed = parse_input({
        "A": {"segments_text": "10.0.0.0/24  # 注释",
              "rules_text": "A1: 10.0.0.0/24 -> 172.16.0.0/24"},
        "B": {"segments_text": "", "rules_text": ""},
    })
    assert len(parsed["A"].segments) == 1
    assert parsed["A"].rules[0].name == "A1"


# ---------------------------------------------------------------- API


def test_api_check_happy_path(client):
    rv = client.post("/api/check", json=make_raw(
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.16.0.0/24")],
        ["10.0.0.0/24"], [("10.0.0.0/24", "172.17.0.0/24")],
    ))
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["ok"] and data["summary"]["address_total"] == 512
    assert data["summary"]["finding_counts"]["alias_conflicts"] == 0


def test_api_check_validation_error_payload(client):
    rv = client.post("/api/check", json=make_raw(
        ["10.0.0.0/24"],
        [("10.0.0.0/24", "172.16.0.0/24"),
         ("10.0.0.0/24", "172.16.9.0/24")],
        [], []))
    assert rv.status_code == 400
    body = rv.get_json()
    assert body["ok"] is False and body["validation_errors"]


def test_index_and_healthz(client):
    assert client.get("/healthz").get_json()["ok"] is True
    html = client.get("/").get_data(as_text=True)
    assert "网段重叠" in html and "映射规则" in html


def test_malformed_structured_rule_does_not_500(client):
    rv = client.post("/api/check", json={
        "A": {"segments": [], "rules": [{"original": "10.0.0.0/24"}]},
        "B": {},
    })
    assert rv.status_code == 400
    assert rv.get_json()["ok"] is False

    # 空字符串规则走文本解析分支，也应返回 400 而非 500
    rv = client.post("/api/check", json={
        "A": {"segments": [], "rules": [""]},
        "B": {},
    })
    assert rv.status_code == 400


def test_non_json_body_rejected(client):
    rv = client.post("/api/check", data="not-json",
                     content_type="text/plain")
    assert rv.status_code == 400
    assert rv.get_json()["ok"] is False
