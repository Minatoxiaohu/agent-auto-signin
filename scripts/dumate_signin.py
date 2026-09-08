"""百度搭子（DuMate / 千帆桌面端）每日签到自动领取脚本（每日 500 积分）。

原理：千帆桌面端把登录 Cookie 加密存放在 auth.json（AES-256-GCM，密钥在同目录
.cookie-key），脚本本地解密后携带 Cookie + csrftoken 头直调官方接口：
  GET  https://console.bce.baidu.com/api/dumate/points/loginBonusInfo  查询签到状态
  POST https://console.bce.baidu.com/api/dumate/points/loginBonus      领取今日积分

密文布局（逆向自 app 内 electron/lib/crypto/cookie.ts）：
  blob = base64(auth.json.cookies)；iv = blob[0:12]，tag = blob[12:28]，密文 = blob[28:]
  明文为 Cookie 数组 JSON（name/value/domain/expirationDate 等标准 Electron 结构）。

依赖：pip install cryptography（AES-GCM 无法用 openssl CLI 完成）。
cookie 有效期较长（BDUSS 等至次年 10 月）；失效时重新登录桌面端即可。

用法：
  python dumate_signin.py status  # 仅查状态（调试）
  python dumate_signin.py auto    # 查状态→未领才领（幂等，日常用这个）
  python dumate_signin.py claim   # 仅领取（调试，幂等）

输出一行 JSON，人话在 report 字段。任何情况下不打印 cookie/token。
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

API_BASE = "https://console.bce.baidu.com"
DATA_DIR = os.path.join("Library", "Application Support", "qianfan-desktop-app")
REQUEST_TIMEOUT = 20
CSRF_COOKIE = "bce-user-info"
COOKIE_HOST = "console.bce.baidu.com"


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def find_auth():
    override = os.environ.get("DUMATE_AUTH_DIR")
    base = override or os.path.join(os.path.expanduser("~"), DATA_DIR)
    auth = os.path.join(base, "auth.json")
    key = os.path.join(base, ".cookie-key")
    if _readable(auth) and _readable(key):
        return auth, key, None
    return None, None, ("未找到 DuMate 登录凭据（查找目录：%s）。"
                        "请先登录百度搭子桌面端，或用环境变量 DUMATE_AUTH_DIR 指向数据目录。" % base)


def decrypt_cookies(auth_file, key_file):
    try:
        from cryptography.hazmat.primitives.ciphers import aead
    except ImportError:
        raise RuntimeError("缺少 cryptography 依赖，请先执行: pip install cryptography")
    blob = base64.b64decode(json.load(open(auth_file, "r", encoding="utf-8"))["cookies"])
    key = open(key_file, "rb").read()
    iv, tag, ct = blob[:12], blob[12:28], blob[28:]
    plain = aead.AESGCM(key).decrypt(iv, ct + tag, None)
    cookies = json.loads(plain)
    if not isinstance(cookies, list):
        raise ValueError("cookie payload 必须为数组")
    return cookies


def _domain_match(cookie_domain, hostname):
    dom = cookie_domain.lstrip(".")
    return hostname == dom or hostname.endswith("." + dom)


def build_auth(cookies, hostname=COOKIE_HOST):
    matched = [c for c in cookies
               if c.get("domain") and c.get("value") and _domain_match(c["domain"], hostname)]
    cookie_str = "; ".join("%s=%s" % (c["name"], c["value"]) for c in matched)
    csrf = next((c["value"].strip("\"'") for c in matched
                 if c["name"] == CSRF_COOKIE), None)
    return cookie_str, csrf


def request(path, cookie_str, csrf, method="GET", body=None):
    headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": API_BASE,
        "Referer": API_BASE + "/",
        "Cookie": cookie_str,
    }
    if csrf:
        headers["csrftoken"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API_BASE + "/" + path.lstrip("/"),
                                 data=data, headers=headers, method=method)
    os.environ["no_proxy"] = "*"
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
    auth_file, key_file, err = find_auth()
    if err:
        return 2, {"result": "NO_AUTH", "report": err}
    try:
        cookies = decrypt_cookies(auth_file, key_file)
        cookie_str, csrf = build_auth(cookies)
    except RuntimeError as e:
        return 2, {"result": "NO_AUTH", "report": str(e)}
    except Exception as e:
        return 2, {"result": "NO_AUTH",
                   "report": "解密登录凭据失败（%s: %s），请重新登录百度搭子桌面端" % (type(e).__name__, e)}
    if not cookie_str:
        return 1, {"result": "NO_SESSION", "report": "本地 Cookie 为空或已全部失效，请重新登录百度搭子桌面端"}

    scode, sbody = request("api/dumate/points/loginBonusInfo", cookie_str, csrf)
    if scode == -1:
        return 1, {"result": "NETWORK", "report": "网络不可达，签到跳过（%s）" % (sbody.get("error") or "")}
    if scode in (401, 403) or sbody.get("code") == "Unauthorized":
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录百度搭子桌面端" % scode}
    if scode != 200 or not sbody.get("success"):
        return 1, {"result": "ERROR", "report": "状态接口异常（HTTP %s：%s）" % (
            scode, sbody.get("message") or sbody.get("code") or "")}

    result = sbody.get("result") or {}
    days = result.get("signInDays") or []
    total = result.get("totalPoints")
    tail = "（累计 %s 积分，已签 %s 天）" % (total, len(days)) if total is not None else ""
    if result.get("hasIssued"):
        return 0, {"result": "ALREADY", "report": "今日已签过%s" % tail,
                   "total_points": total, "sign_in_days": days}
    if not claim:
        return 0, {"result": "PENDING", "report": "今日未签到%s" % tail}

    ccode, cbody = request("api/dumate/points/loginBonus", cookie_str, csrf, method="POST")
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    if ccode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录百度搭子桌面端" % ccode}
    if ccode == 200 and cbody.get("success"):
        got = cbody.get("result")
        show = "成功领取 %s 积分" % got if isinstance(got, int) else "签到成功"
        return 0, {"result": "CLAIMED", "report": show + tail, "total_points": total}
    # 已签过的业务幂等：重查一次状态按 ALREADY 处理
    scode2, sbody2 = request("api/dumate/points/loginBonusInfo", cookie_str, csrf)
    if 200 == scode2 and sbody2.get("success") and (sbody2.get("result") or {}).get("hasIssued"):
        result2 = sbody2["result"]
        return 0, {"result": "ALREADY", "report": "今日已签过（累计 %s 积分）" % result2.get("totalPoints"),
                   "total_points": result2.get("totalPoints")}
    return 1, {"result": "ERROR", "report": "领取失败：%s（HTTP %s）" % (
        cbody.get("message") or json.dumps(cbody, ensure_ascii=False)[:120], ccode)}


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "auto"
    try:
        if action == "auto":
            code, out = checkin(claim=True)
        elif action == "status":
            code, out = checkin(claim=False)
        elif action == "claim":
            code, out = checkin(claim=True)
        else:
            code, out = 2, {"result": "ERROR", "report": "未知命令：%s（可用：auto / status / claim）" % action}
    except Exception as e:
        code, out = 2, {"result": "ERROR", "report": "脚本运行异常（%s: %s）" % (type(e).__name__, e)}
    emit(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
