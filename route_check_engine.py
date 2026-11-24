"""双线路 VPN 接入 · 内网网段重叠 / 别名映射核查引擎。

与 Web 框架无关，Flask 路由只做参数解析和序列化。

业务规则（与需求一一对应）：
* 两条接入线路 A、B，各自填报“待接入网段”（IPv4 CIDR）与“映射规则”；
* 每条规则用**等长** IPv4 CIDR 给出原网段与总部别名网段，
  地址转换按主机位平移（保留主机位）；
* 去程：在**本线路**规则里按原前缀最长匹配；同线路原前缀重复直接退回；
* 回程：在**两线全部规则**里按别名前缀最长匹配，同长并列即歧义；
* 一个别名地址对应多个来源即冲突；两条线路上的同一原地址视为两个来源；
* 核查覆盖待接入网段的全部地址，但实现上只做整数区间（左闭右开）运算，
  绝不逐地址扫描，/0、/8 这种大网段也能瞬时完成。

区间内的所有运算基于 32 位无符号整数：
    lo = 网络地址整数，hi = lo + 地址数，区间一律 [lo, hi)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from ipaddress import (
    AddressValueError,
    IPv4Address,
    IPv4Network,
    NetmaskValueError,
    summarize_address_range,
)
LINES = ("A", "B")
MAX_ITEMS_PER_LINE = 256  # 单线路网段/规则条数上限，防止误输入撑爆页面

_RULE_SPLIT = re.compile(r"\s*(?:->|=>|[,，\s])\s*")


class RouteCheckError(Exception):
    """业务错误。status 为建议的 HTTP 状态码。"""

    def __init__(self, message: str, status: int = 400,
                 errors: list[dict] | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.errors = errors or []


# ---------------------------------------------------------------- 数据模型


@dataclass
class Segment:
    line: str
    index: int  # 1-based，页面定位用
    net: IPv4Network
    lo: int
    hi: int

    def ref(self) -> dict:
        return {"line": self.line, "index": self.index, "cidr": str(self.net)}


@dataclass
class Rule:
    line: str
    index: int  # 1-based
    name: str
    original: IPv4Network
    alias: IPv4Network
    orig_lo: int
    orig_hi: int
    alias_lo: int
    alias_hi: int

    @property
    def ref_id(self) -> str:
        return f"{self.line}#{self.index}"

    def ref(self) -> dict:
        return {
            "line": self.line,
            "index": self.index,
            "name": self.name,
            "original": str(self.original),
            "alias": str(self.alias),
        }


@dataclass
class SourceRange:
    """一段去程已映射地址：某线路某网段经某规则平移成的别名区间。"""

    line: str
    segment: Segment
    rule: Rule
    orig_lo: int
    orig_hi: int
    alias_lo: int
    alias_hi: int


@dataclass
class ParsedLine:
    key: str
    segments: list[Segment] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)


# ---------------------------------------------------------------- 输入解析


def _parse_strict_cidr(text: str, where: str, errors: list[dict],
                       line: str | None = None) -> IPv4Network | None:
    """严格 CIDR：必须带前缀长度且主机位为 0；失败时给出可直接照抄的建议。"""
    raw = str(text).strip()
    if "/" not in raw:
        errors.append({"line": line, "field": where,
                       "message": f"{where} 必须是 IPv4 CIDR（如 10.0.0.0/24），收到：{raw!r}"})
        return None
    try:
        return IPv4Network(raw, strict=True)
    except (NetmaskValueError, AddressValueError, ValueError):
        hint = ""
        try:
            canonical = IPv4Network(raw, strict=False)
            hint = f"；主机位非 0，请改用规范写法 {canonical}"
        except (NetmaskValueError, AddressValueError, ValueError):
            pass
        errors.append({"line": line, "field": where,
                       "message": f"{where} 不是合法 IPv4 CIDR：{raw!r}{hint}"})
        return None


def parse_cidr_lines(text: str) -> list[str]:
    """网段文本框：每行一个 CIDR，# 之后为注释。"""
    items: list[str] = []
    for raw in str(text).splitlines():
        s = raw.split("#", 1)[0].strip()
        if s:
            items.append(s)
    return items


def parse_rule_lines(text: str) -> list[dict]:
    """规则文本框：每行 `[名称:] 原CIDR -> 别名CIDR`，分隔符支持 -> => 逗号 空白。"""
    rules: list[dict] = []
    for lineno, raw in enumerate(str(text).splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        name = ""
        if ":" in line:
            head, _, rest = line.partition(":")
            head = head.strip()
            if head and " " not in head and "/" not in head:
                name, line = head, rest.strip()
        parts = [p for p in _RULE_SPLIT.split(line) if p]
        if len(parts) != 2:
            raise RouteCheckError(
                f"第 {lineno} 行规则无法解析：{raw!r}，应为 `原CIDR -> 别名CIDR`")
        rules.append({"name": name, "original": parts[0], "alias": parts[1]})
    return rules


def _as_list(bucket: dict, list_key: str, text_key: str, parser) -> list:
    items = bucket.get(list_key)
    if isinstance(items, list):
        return items
    text = bucket.get(text_key, "")
    return parser(text) if isinstance(text, str) else []


def _parse_line(key: str, bucket: dict, errors: list[dict]) -> ParsedLine:
    if not isinstance(bucket, dict):
        bucket = {}
    parsed = ParsedLine(key=key)

    seg_items = _as_list(bucket, "segments", "segments_text", parse_cidr_lines)
    if len(seg_items) > MAX_ITEMS_PER_LINE:
        errors.append({"line": key, "field": "segments",
                       "message": f"线路 {key} 网段数 {len(seg_items)} 超过上限 {MAX_ITEMS_PER_LINE}"})
    for i, item in enumerate(seg_items[:MAX_ITEMS_PER_LINE], 1):
        cidr = item if isinstance(item, str) else str(item)
        net = _parse_strict_cidr(cidr, f"网段[{i}]", errors, line=key)
        if net is not None:
            parsed.segments.append(
                Segment(key, i, net, int(net.network_address), _net_hi(net)))

    rule_items = _as_list(bucket, "rules", "rules_text", parse_rule_lines)
    if len(rule_items) > MAX_ITEMS_PER_LINE:
        errors.append({"line": key, "field": "rules",
                       "message": f"线路 {key} 规则数 {len(rule_items)} 超过上限 {MAX_ITEMS_PER_LINE}"})
    seen_orig: dict[tuple[int, int], int] = {}
    for i, item in enumerate(rule_items[:MAX_ITEMS_PER_LINE], 1):
        if isinstance(item, str):
            try:
                parsed_items = parse_rule_lines(item)
            except RouteCheckError as exc:
                errors.append({"line": key, "field": f"规则[{i}]",
                               "message": exc.message})
                continue
            if not parsed_items:
                errors.append({"line": key, "field": f"规则[{i}]",
                               "message": f"规则[{i}] 为空或格式不正确：{item!r}"})
                continue
            item = parsed_items[0]
        if not isinstance(item, dict):
            errors.append({"line": key, "field": f"规则[{i}]",
                           "message": f"规则[{i}] 格式不正确"})
            continue
        name = str(item.get("name", "")).strip()
        where = f"规则[{i}]{('「' + name + '」') if name else ''}"
        orig = _parse_strict_cidr(item.get("original", ""),
                                  f"{where} 原网段", errors, line=key)
        alias = _parse_strict_cidr(item.get("alias", ""),
                                   f"{where} 别名", errors, line=key)
        if orig is None or alias is None:
            continue
        if orig.prefixlen != alias.prefixlen:
            errors.append({
                "line": key, "field": f"规则[{i}]",
                "message": f"{where} 原前缀 /{orig.prefixlen} 与别名前缀 "
                           f"/{alias.prefixlen} 不等长，无法按主机位平移",
            })
            continue
        sig = (int(orig.network_address), orig.prefixlen)
        if sig in seen_orig:
            errors.append({
                "line": key, "field": f"规则[{i}]",
                "message": f"{where} 原前缀 {orig} 与本线路规则 #{seen_orig[sig]} "
                           f"重复，同线路原前缀重复必须退回",
            })
            continue
        seen_orig[sig] = i
        parsed.rules.append(Rule(
            line=key, index=i, name=name or f"{key}-R{i}",
            original=orig, alias=alias,
            orig_lo=int(orig.network_address),
            orig_hi=_net_hi(orig),
            alias_lo=int(alias.network_address),
            alias_hi=_net_hi(alias),
        ))
    return parsed


def _net_hi(net: IPv4Network) -> int:
    """区间右边界（不含）；/0 时为 2**32，刻意保持整数而非 IPv4Address。"""
    return int(net.network_address) + net.num_addresses


def parse_input(raw: dict | None) -> dict[str, ParsedLine]:
    raw = raw or {}
    errors: list[dict] = []
    lines: dict[str, ParsedLine] = {}
    for key in LINES:
        lines[key] = _parse_line(key, raw.get(key) or {}, errors)
    if errors:
        raise RouteCheckError(
            f"输入校验未通过，共 {len(errors)} 处问题，请修正后重试",
            errors=errors)
    return lines


# ---------------------------------------------------------------- 区间工具


def _range_dict(lo: int, hi: int) -> dict:
    """整数区间 -> 可展示的地址范围（附最小 CIDR 划分，仍是范围级结果）。"""
    start, end = IPv4Address(lo), IPv4Address(hi - 1)
    cidrs = [str(n) for n in summarize_address_range(start, end)]
    return {
        "start": str(start),
        "end": str(end),
        "size": hi - lo,
        "cidrs": cidrs,
        "label": cidrs[0] if len(cidrs) == 1 else f"{start} ~ {end}",
    }


def _merge_ranges(pieces: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for lo, hi in sorted(pieces):
        if merged and lo <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(a, b) for a, b in merged]


def _boundaries(intervals: list[tuple[int, int]]) -> list[int]:
    points = {p for lo, hi in intervals for p in (lo, hi)}
    return sorted(points)


# ---------------------------------------------------------------- 去程分析


def _analyze_outbound(line: ParsedLine):
    """返回 (未映射区间列表, 来源区间列表, 去程映射表, 已映射并集)。

    重叠网段中的同一地址属于不同来源，必须分别保留 SourceRange，
    因此来源**不跨网段合并**；地址计数用并集区间另行统计。
    """
    intervals = ([(s.lo, s.hi) for s in line.segments]
                 + [(r.orig_lo, r.orig_hi) for r in line.rules])
    points = _boundaries(intervals)

    unmapped_pieces: list[tuple[int, int]] = []
    sources: list[SourceRange] = []
    mapping: list[dict] = []

    for lo, hi in zip(points, points[1:]):
        seg_hits = [s for s in line.segments if s.lo <= lo < s.hi]
        if not seg_hits:
            continue  # 只核对待接入网段内的地址
        rule_hits = [r for r in line.rules if r.orig_lo <= lo < r.orig_hi]
        if not rule_hits:
            unmapped_pieces.append((lo, hi))
            continue
        # 同线路原前缀重复已在输入校验拦截，这里最长匹配至多一条
        winner = max(rule_hits, key=lambda r: r.original.prefixlen)
        offset = lo - winner.orig_lo
        alo = winner.alias_lo + offset
        ahi = alo + (hi - lo)
        # 每个命中网段各产生一个来源，重叠网段天然形成多来源
        for seg in seg_hits:
            sources.append(SourceRange(
                line=line.key, segment=seg, rule=winner,
                orig_lo=lo, orig_hi=hi, alias_lo=alo, alias_hi=ahi))
        mapping.append({
            "line": line.key,
            "rule": winner.ref(),
            "segments": [s.ref() for s in seg_hits],
            "original_range": _range_dict(lo, hi),
            "alias_range": _range_dict(alo, ahi),
        })

    unmapped = _merge_ranges(unmapped_pieces)
    mapped_union = _merge_ranges([(s.orig_lo, s.orig_hi) for s in sources])
    return unmapped, sources, mapping, mapped_union


# ---------------------------------------------------------------- 回程分析


@dataclass
class _Collector:
    """按分类 key 收集原子区间并合并相邻/重叠区间。"""

    entries: dict[tuple, dict] = field(default_factory=dict)
    order: list[tuple] = field(default_factory=list)

    def add(self, key: tuple, payload: dict, lo: int, hi: int) -> None:
        if key not in self.entries:
            self.entries[key] = {**payload, "_pieces": []}
            self.order.append(key)
        self.entries[key]["_pieces"].append((lo, hi))

    def finish(self) -> list[dict]:
        out = []
        for key in self.order:
            entry = self.entries[key]
            pieces = entry.pop("_pieces")
            entry["ranges"] = [_range_dict(a, b)
                               for a, b in _merge_ranges(pieces)]
            out.append(entry)
        return out


def _analyze_return(lines: dict[str, ParsedLine],
                    sources: list[SourceRange]):
    all_rules = [r for ln in lines.values() for r in ln.rules]
    domain = [(s.alias_lo, s.alias_hi) for s in sources]
    if not domain:
        return {"alias_conflicts": [], "return_ambiguity": [],
                "wrong_line": [], "wrong_address": []}

    intervals = domain + [(r.alias_lo, r.alias_hi) for r in all_rules]
    points = _boundaries(intervals)

    conflicts = _Collector()
    ambiguity = _Collector()
    wrong_line = _Collector()
    wrong_addr = _Collector()

    for lo, hi in zip(points, points[1:]):
        src_hits = [s for s in sources if s.alias_lo <= lo < s.alias_hi]
        if not src_hits:
            continue  # 只核查真正被去程使用到的别名地址
        covering = [r for r in all_rules if r.alias_lo <= lo < r.alias_hi]
        # src_hits 非空时其所属规则必然 covering，covering 不会为空
        max_len = max(r.alias.prefixlen for r in covering)
        winners = [r for r in covering if r.alias.prefixlen == max_len]

        # 1) 别名冲突：同一别名地址对应多个来源
        #    （不同线路的同一原地址、或同线路不同网段映射到同一别名，都算）
        if len(src_hits) >= 2:
            src_refs = tuple(sorted(
                {(s.line, s.rule.index) for s in src_hits}))
            conflicts.add(
                ("conflict", src_refs),
                {"sources": [_source_ref(s) for s in src_hits]},
                lo, hi)

        # 2) 回程歧义：最长匹配同长并列
        if len(winners) >= 2:
            win_refs = tuple(sorted((r.line, r.index) for r in winners))
            ambiguity.add(
                ("amb", win_refs),
                {"tied_rules": [r.ref() for r in winners],
                 "covering_rules": [r.ref() for r in covering],
                 "sources": [_source_ref(s) for s in src_hits]},
                lo, hi)
            continue  # 歧义下无唯一 winner，线路/地址类问题不再重复计

        winner = winners[0]
        # 3) 逐来源判断回错线路 / 回错地址
        for s in src_hits:
            exp_lo = s.orig_lo + (lo - s.alias_lo)
            exp_hi = exp_lo + (hi - lo)
            act_lo = winner.orig_lo + (lo - winner.alias_lo)
            act_hi = act_lo + (hi - lo)

            if winner.line != s.line:
                wrong_line.add(
                    ("line", s.line, s.rule.index, winner.line, winner.index),
                    {"source_line": s.line,
                     "source_rule": s.rule.ref(),
                     "actual_line": winner.line,
                     "winner_rule": winner.ref(),
                     "expected_original_range": _range_dict(exp_lo, exp_hi)},
                    lo, hi)
            if (act_lo, act_hi) != (exp_lo, exp_hi):
                wrong_addr.add(
                    ("addr", s.line, s.rule.index, winner.line, winner.index),
                    {"source_line": s.line,
                     "source_rule": s.rule.ref(),
                     "winner_rule": winner.ref(),
                     "expected_original_range": _range_dict(exp_lo, exp_hi),
                     "actual_destination_range": _range_dict(act_lo, act_hi)},
                    lo, hi)

    return {
        "alias_conflicts": conflicts.finish(),
        "return_ambiguity": ambiguity.finish(),
        "wrong_line": wrong_line.finish(),
        "wrong_address": wrong_addr.finish(),
    }

def _source_ref(s: SourceRange) -> dict:
    return {
        "line": s.line,
        "segment": s.segment.ref(),
        "rule": s.rule.ref(),
        "original_range": _range_dict(s.orig_lo, s.orig_hi),
        "alias_range": _range_dict(s.alias_lo, s.alias_hi),
    }


# ---------------------------------------------------------------- 总入口


def analyze(raw: dict | None) -> dict:
    lines = parse_input(raw)

    all_unmapped: list[dict] = []
    all_sources: list[SourceRange] = []
    all_mapping: list[dict] = []
    line_stats = {}

    for key in LINES:
        ln = lines[key]
        unmapped, sources, mapping, mapped_union = _analyze_outbound(ln)
        all_sources.extend(sources)
        all_mapping.extend(mapping)
        # 网段可能重叠，地址总数/未映射数一律按并集统计，不重复计数
        seg_union = _merge_ranges([(s.lo, s.hi) for s in ln.segments])
        seg_total = sum(b - a for a, b in seg_union)
        mapped_total = sum(b - a for a, b in mapped_union)
        line_stats[key] = {
            "segment_count": len(ln.segments),
            "rule_count": len(ln.rules),
            "address_total": seg_total,
            "address_mapped": mapped_total,
            "address_unmapped": seg_total - mapped_total,
            "segments": [str(s.net) for s in ln.segments],
            "rules": [r.ref() for r in ln.rules],
        }
        for lo, hi in unmapped:
            touched = [s.ref() for s in ln.segments
                       if not (hi <= s.lo or lo >= s.hi)]
            all_unmapped.append({
                "line": key,
                "ranges": [_range_dict(lo, hi)],
                "segments": touched,
            })

    return_findings = _analyze_return(lines, all_sources)

    def _count(entries: list[dict]) -> int:
        return sum(r["size"] for e in entries for r in e["ranges"])

    result = {
        "ok": True,
        "validation_errors": [],
        "lines": line_stats,
        "outbound_mapping": all_mapping,
        "findings": {
            "unmapped_outbound": all_unmapped,
            **return_findings,
        },
        "summary": {
            "address_total": sum(v["address_total"] for v in line_stats.values()),
            "address_mapped": sum(v["address_mapped"] for v in line_stats.values()),
            "address_unmapped": sum(v["address_unmapped"] for v in line_stats.values()),
            "unmapped_outbound_addresses": _count(all_unmapped),
            "alias_conflict_addresses": _count(return_findings["alias_conflicts"]),
            "return_ambiguity_addresses": _count(return_findings["return_ambiguity"]),
            "wrong_line_addresses": _count(return_findings["wrong_line"]),
            "wrong_address_addresses": _count(return_findings["wrong_address"]),
            "finding_counts": {
                "unmapped_outbound": len(all_unmapped),
                "alias_conflicts": len(return_findings["alias_conflicts"]),
                "return_ambiguity": len(return_findings["return_ambiguity"]),
                "wrong_line": len(return_findings["wrong_line"]),
                "wrong_address": len(return_findings["wrong_address"]),
            },
        },
    }
    return result
