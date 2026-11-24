"""双线路 VPN 网段重叠核查 —— Flask 入口。

纯计算服务、无共享可变状态；部署见 Dockerfile / compose.yaml
（gunicorn 固定 1 个 worker、多线程）。
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from route_check_engine import LINES, RouteCheckError, analyze, parse_rule_lines

app = Flask(__name__)


@app.errorhandler(RouteCheckError)
def handle_route_error(err: RouteCheckError):
    return jsonify({
        "ok": False,
        "error": err.message,
        "validation_errors": err.errors,
    }), err.status


@app.errorhandler(404)
def handle_404(_err):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "接口不存在"}), 404
    return "Not Found", 404


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return render_template("index.html", lines=LINES)


@app.post("/api/check")
def check():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise RouteCheckError("请求体必须是 JSON 对象")
    return jsonify(analyze(data))


@app.post("/api/preview-rules")
def preview_rules():
    """把规则文本框内容解析成结构化结果，供前端即时校验。"""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not isinstance(text, str):
        raise RouteCheckError("text 必须是字符串")
    return jsonify({"ok": True, "rules": parse_rule_lines(text)})


if __name__ == "__main__":
    # 本机直接 `python app.py` 时使用；容器内走 gunicorn。
    app.run(host="0.0.0.0", port=8000, threaded=True)
