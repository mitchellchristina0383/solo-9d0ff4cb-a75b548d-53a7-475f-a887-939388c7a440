# 双线路 VPN 接入 · 网段重叠与回程核查台

两个分支分别接在 VPN 的 **A、B 两条线**上，内网网段存在重叠。接入前需要查清：
总部按别名回包时，会不会走错线路 / 送到错误的原地址。本工具在网页上分别填报
两线的待接入网段与映射规则，给出**地址范围级**的完整核查结果，不逐地址扫描。

## 判定口径

### 输入

* 每条线路填两类内容：
  * **待接入网段**：每行一个严格 IPv4 CIDR（主机位必须为 0，如 `10.0.0.0/24`）；
  * **映射规则**：每行 `[名称:] 原CIDR -> 别名CIDR`，分隔符支持 `->`、`=>`、逗号或空白，
    `#` 之后为注释。
* 每条规则的原 CIDR 与别名 CIDR **必须等长**；地址转换按整数平移完成，
  **主机位逐位保留**（如 `10.0.0.200/24 → 172.16.9.128/25` 类规则下偏移原样保留）。
* 同一线路内原前缀重复直接退回并报错；同一原前缀出现在两条线路是允许的，
  但在别名分析里视为两个来源。

### 去程（分支 → 总部）

* 只在**本线路**的规则里按原前缀做**最长匹配**；同线路原前缀重复在校验阶段拦截。
* 待接入网段内没有任何规则命中的地址，列入 **去程未映射**，注明线路与涉及网段。

### 回程（总部 → 分支）

* 在 **A、B 两线全部规则**里按别名前缀做最长匹配：
  * 唯一最长前缀 → 回该规则所在线路；
  * 同长前缀并列 → **回程歧义**（不猜测、不任选其一）。
* **别名冲突**：一个别名地址对应多个来源。两条线路上的同一原地址、
  或同线路不同网段映射到同一别名，都按多来源计冲突。
* 命中规则所在线路 ≠ 来源线路 → **回错线路**。
* 按命中规则反算出的原地址 ≠ 来源原地址 → **回错地址**（可与回错线路同时出现）。

### 为什么能核查“全部地址”而不扫描

所有网段表示为 32 位整数区间 `[lo, hi)`，取全部网段/规则的边界点把地址轴
切成原子区间，每个原子区间内判定结果恒定，再按判定签名把相邻区间合并输出。
`/0`（42.9 亿地址）这种输入也是毫秒级，输出始终是 CIDR/起止地址范围。

## 运行

### Docker Compose（交付方式）

```bash
docker compose up -d --build
# 浏览器打开 http://localhost:8000
docker compose logs -f
docker compose down
```

健康检查：`GET /healthz`。

### 本地直跑

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py            # http://localhost:8000
pytest                   # 运行测试
```

## HTTP 接口

### `POST /api/check`

请求体：

```json
{
  "A": {
    "segments": ["10.0.0.0/24"],
    "rules": [
      {"name": "A1", "original": "10.0.0.0/24", "alias": "172.16.0.0/24"}
    ]
  },
  "B": {
    "segments_text": "10.0.99.128/25\n",
    "rules_text": "B1: 10.0.99.128/25 -> 172.16.0.128/25\n"
  }
}
```

结构化数组（`segments` / `rules`）与文本框（`segments_text` / `rules_text`）两种形式都支持。
校验失败返回 `400` 与 `validation_errors` 明细；成功返回：

* `lines`：两线网段/规则数量、地址总数与映射覆盖统计；
* `outbound_mapping`：去程最长匹配明细（命中规则、原范围、别名范围）；
* `findings`：五类问题清单
  （`unmapped_outbound` / `alias_conflicts` / `return_ambiguity` /
  `wrong_line` / `wrong_address`），每条注明涉及的**线路与规则**及地址范围；
* `summary`：各类问题影响的地址数量与条目数。

### `POST /api/preview-rules`

把规则文本解析成结构化数组，便于前端做即时格式校验。

## 目录结构

```
app.py                    Flask 入口（/、/healthz、/api/check、/api/preview-rules）
route_check_engine.py     纯标准库核查引擎（CIDR 解析 + 区间切分/合并）
templates/index.html      单页界面
static/app.js, style.css  前端逻辑与样式
tests/test_route_check.py 引擎与 API 测试（含“回程被更长前缀接走”场景）
Dockerfile, compose.yaml  容器化交付
```

## 限制与边界

* 单线路网段/规则各上限 256 条（可在 `route_check_engine.MAX_ITEMS_PER_LINE` 调整）。
* 仅支持 IPv4；IPv6 暂不支持。
* 工具做的是静态配置核查，不感知设备上的路由优先级、策略路由等运行时因素。
