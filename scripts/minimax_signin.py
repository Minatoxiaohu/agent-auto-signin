"""MiniMax Code 桌面端每日签到自动领取脚本（每日 400 积分，连签第 4/7 天 1000）。

原理：MiniMax 桌面端的内嵌 webview 把登录 JWT 明文存在 Electron localStorage
（leveldb 文件）里，脚本直接从 leveldb 提取最新有效 JWT，复刻 web 前端的
md5 双重签名协议，直调官方接口：
  GET  https://agent.minimaxi.com/minimax-cloud/api/v1/signin/status  查询签到面板
  POST https://agent.minimaxi.com/minimax-cloud/api/v1/signin/claim   领取今日积分

签名协议（源码逆向自 prod-web-sh 前端，2026-09-09 全链路实测通过）：
  x-timestamp = 秒级时间戳
  x-signature = md5("<秒>I*7Cf%WZ#S&%1RlZJ&C2" + body)   GET 时 body 为空串
  yy          = md5(quote(路径?query) + "_" + body + md5(str(毫秒时间戳)) + "ooui")
  服务端按收到的请求重算签名，query 参数值自拟即可，但集合与顺序需与前端一致；
  缺 timezone_id=Asia/Shanghai 会报 1406010011 invalid timezone_id。

用法：
  python minimax_signin.py auto    # 查状态→今日可领才领（幂等，日常用这个）
  python minimax_signin.py status  # 仅查状态（调试）

输出一行 JSON，人话在 report 字段。任何情况下不打印 token/JWT。
"""

import base64
import glob
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://agent.minimaxi.com"
LEVELDB_GLOB = os.path.join("Library", "Application Support", "MiniMax",
                            "Local Storage", "leveldb")
CONFIG_REL = os.path.join("Library", "Application Support", "MiniMax",
                          "minimax-agent-cn-config.json")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-\.]{80,}")
REQUEST_TIMEOUT = 20


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def find_jwt():
    """从 leveldb（按修改时间新→旧）提取第一个未过期的登录 JWT。

    leveldb 里同时存有多个历史 JWT（token 滚动刷新），必须取 exp 未过期的；
    只认 payload 含 exp+user 字段的（登录 token），避开其它业务的 JWT。
    """
    home = os.path.expanduser("~")
    override = os.environ.get("MINIMAX_LS_LEVELDB")
    files = glob.glob(os.path.join(override, "*")) if override else \
        glob.glob(os.path.join(home, LEVELDB_GLOB, "*"))
    files = [f for f in files if f.endswith((".log", ".ldb"))]
    files.sort(key=os.path.getmtime, reverse=True)
    seen = set()
    now = time.time()
    for f in files:
        try:
            with open(f, "rb") as fh:
                blob = fh.read()
        except Exception:
            continue
        for m in JWT_RE.finditer(blob):
            jwt = m.group().decode("ascii", errors="ignore")
            if jwt in seen:
                continue
            seen.add(jwt)
            try:
                payload = jwt.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                data = json.loads(base64.urlsafe_b64decode(payload))
            except Exception:
                continue
            if isinstance(data, dict) and data.get("exp") and data["exp"] > now \
                    and "user" in data:
                return jwt, None, None
    if seen:
        return None, "NO_SESSION", "本地 JWT 已全部过期，请打开 MiniMax Code 客户端重新登录"
    return None, "NO_AUTH", ("未在 leveldb 中找到登录 token，请先登录 MiniMax Code 桌面端"
                             "（查找目录：%s）" % (files[0] if files else os.path.join(home, LEVELDB_GLOB)))


def real_user_id():
    """从桌面端配置 JSON 取 realUserID；取不到就返回 0（服务端不严格校验该值）。"""
    try:
        with open(os.path.join(os.path.expanduser("~"), CONFIG_REL), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return str(cfg.get("user", {}).get("realUserID") or 0)
    except Exception:
        return "0"


def signed_request(path, jwt, uid, method="GET", body=""):
    """复刻 web 前端签名协议发请求；返回 (http_code, dict)。"""
    ms = int(time.time() * 1000)
    sec = ms // 1000
    params = [
        ("device_platform", "web"), ("biz_id", "3"), ("app_id", "3001"),
        ("version_code", "22201"), ("unix", str(ms)), ("timezone_offset", "480"),
        ("timezone_id", "Asia/Shanghai"), ("sys_language", "zh"), ("lang", "zh"),
        ("uuid", "null"), ("device_id", "48372915"), ("os_name", "macOS"),
        ("browser_name", "Chrome"), ("browser_language", "zh-CN"),
        ("browser_platform", "MacIntel"), ("user_id", uid),
        ("op_ticket", "undefined"), ("screen_width", "1512"), ("screen_height", "982"),
        ("unix", str(ms)), ("token", jwt),
    ]
    full = "%s?%s" % (path, urllib.parse.urlencode(params))
    yy = hashlib.md5(("%s_%s%s%s" % (urllib.parse.quote(full), body,
                                     hashlib.md5(str(ms).encode()).hexdigest(),
                                     "ooui")).encode()).hexdigest()
    xsig = hashlib.md5(("%sI*7Cf%%WZ#S&%%1RlZJ&C2%s" % (sec, body)).encode()).hexdigest()
    headers = {
        "token": jwt, "Content-Type": "application/json",
        "x-timestamp": str(sec), "x-signature": xsig, "yy": yy,
        "Origin": API_BASE, "Referer": API_BASE + "/",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    }
    data = body.encode() if method == "POST" else None
    req = urllib.request.Request(API_BASE + full, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def checkin(claim=False):
    jwt, err_code, err_msg = find_jwt()
    if err_code:
        return 2 if err_code == "NO_AUTH" else 1, {"result": err_code, "report": err_msg}
    uid = real_user_id()

    scode, sbody = signed_request("/minimax-cloud/api/v1/signin/status", jwt, uid)
    if scode == -1:
        return 1, {"result": "NETWORK", "report": "网络不可达，签到跳过（%s）" % (sbody.get("error") or "")}
    base = sbody.get("base_resp") or {} if isinstance(sbody, dict) else {}
    if base.get("status_code") == 1022100011 or scode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效，请打开 MiniMax Code 客户端重新登录"}
    if base.get("status_code") not in (0, None) or not isinstance(sbody.get("data"), dict):
        return 1, {"result": "ERROR", "report": "状态接口异常：%s（HTTP %s）" % (
            base.get("status_msg") or base.get("status_code"), scode)}

    days = sbody["data"].get("days") or []
    today = next((d for d in days if d.get("is_today")), None)
    streak = today.get("day_no") if today else None
    streak_txt = "连签第 %s 天" % streak if streak else "7 天周期"

    if today is None:
        return 0, {"result": "INACTIVE", "report": "签到面板无今日项（可能活动未开启）"}
    if today.get("status") == 3:
        return 0, {"result": "ALREADY", "report": "今日已签过（%s）" % streak_txt,
                   "day_no": streak, "points": today.get("points")}
    if today.get("status") != 2:
        return 0, {"result": "INACTIVE", "report": "今日不可领取（%s）" % streak_txt}

    if not claim:
        return 0, {"result": "PENDING", "report": "今日可领 %s 积分（%s）" % (
            today.get("points"), streak_txt)}

    ccode, cbody = signed_request("/minimax-cloud/api/v1/signin/claim", jwt, uid,
                                  method="POST", body="{}")
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    cdata = (cbody.get("data") or {}) if isinstance(cbody, dict) else {}
    cbase = (cbody.get("base_resp") or {}) if isinstance(cbody, dict) else {}
    if cbase.get("status_code") == 1022100011 or ccode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效，请打开 MiniMax Code 客户端重新登录"}
    # claim_result: 1=已领取, 2=今日已领过（幂等，按 ALREADY 处理）
    if cdata.get("claim_result") in (1, 2):
        result = "CLAIMED" if cdata.get("claim_result") == 1 else "ALREADY"
        verb = "成功领取" if result == "CLAIMED" else "今日已领过"
        return 0, {"result": result,
                   "report": "%s %s 积分（%s）" % (verb, cdata.get("points"), streak_txt),
                   "day_no": cdata.get("day_no"), "points": cdata.get("points")}
    return 1, {"result": "ERROR", "report": "领取失败：%s（HTTP %s）" % (
        cbase.get("status_msg") or json.dumps(cbody, ensure_ascii=False)[:120], ccode)}


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "auto"
    try:
        if action == "auto":
            code, out = checkin(claim=True)
        elif action == "status":
            code, out = checkin(claim=False)
        else:
            code, out = 2, {"result": "ERROR", "report": "未知命令：%s（可用：auto / status）" % action}
    except Exception as e:
        code, out = 2, {"result": "ERROR", "report": "脚本运行异常（%s: %s）" % (type(e).__name__, e)}
    emit(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
