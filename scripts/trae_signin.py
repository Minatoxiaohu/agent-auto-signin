"""Trae SOLO CN 每日签到自动领取脚本（每日 200 积分）。

原理：读取 Trae 桌面端 storage.json 里的加密登录态（iCubeAuthInfo://icube.cloudide），
AES-128-CBC 解密（SHA-512 密钥派生）得到 accessToken，直调官方接口：
  POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/status  查询签到状态
  POST https://api.trae.cn/trae/api/v2/ug/checkin_credits/claim   领取今日积分

解密布局（与 Trae 论坛公开 skill 交叉验证一致）：
  blob = base64(value)；key=blob[6:38] → sha512(key) 与两张硬编码表 XOR 结果拼接
  → 再 sha512 → 前 16B=AES key，16-32B=IV；密文 blob[38:]，明文跳过前 64B 即 JSON。

AES 解密通过 openssl 子进程完成（macOS 自带），避免引入 cryptography 依赖。

用法：
  python trae_signin.py auto    # 查状态→未签才领（幂等，日常用这个）
  python trae_signin.py status  # 仅查状态（调试）
  python trae_signin.py claim   # 仅领取（调试，幂等）

输出一行 JSON，人话在 report 字段。任何情况下不打印 token。
"""

import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# 密钥派生用的两张硬编码表（源自 Trae 客户端实现，公开 skill 已交叉验证）
TABLE_A = bytes([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37])
TABLE_B = bytes([31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
                 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
                 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
                 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125])

STORAGE_REL = os.path.join("TRAE SOLO CN", "User", "globalStorage", "storage.json")
REQUEST_TIMEOUT = 20


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _readable(path):
    """试读代替 exists——WorkBuddy 沙箱会让受保护路径的 exists() 返回 False。"""
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


def find_storage():
    override = os.environ.get("TRAE_STORAGE_FILE")
    candidates = [override] if override else [
        os.path.join(os.path.expanduser("~"), "Library", "Application Support", STORAGE_REL),
        os.path.join(os.environ.get("APPDATA", ""), STORAGE_REL),  # Windows 兜底
    ]
    for c in candidates:
        if c and _readable(c):
            return c, candidates
    return None, candidates


def decrypt_auth(b64_value):
    """解密 iCubeAuthInfo blob，返回 JSON dict；失败抛异常。"""
    blob = base64.b64decode(b64_value)
    sha = hashlib.sha512(blob[6:38]).digest()
    xor = bytes(a ^ b for a, b in zip(TABLE_A, TABLE_B))
    h = hashlib.sha512(sha + xor).digest()
    key_hex, iv_hex = h[:16].hex(), h[16:32].hex()
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc", "-nopad", "-K", key_hex, "-iv", iv_hex],
        input=blob[38:], capture_output=True, timeout=10)
    if proc.returncode != 0:
        raise RuntimeError("openssl 解密失败: %s" % proc.stderr.decode(errors="replace")[:120])
    pt = proc.stdout
    pt = pt[:-pt[-1]]  # 去 PKCS7 padding
    return json.loads(pt[64:].decode("utf-8", errors="replace"))


def request(url, headers, timeout=REQUEST_TIMEOUT):
    req = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def load_auth():
    """返回 (token, region, host, expired_at)；任何一步失败返回 (None, 原因)。"""
    storage, _ = find_storage()
    if not storage:
        return None, "NO_AUTH", "未找到 Trae 的 storage.json，请先登录 Trae 桌面端"
    try:
        with open(storage, "r", encoding="utf-8") as f:
            data = json.load(f)
        enc = data.get("iCubeAuthInfo://icube.cloudide")
        if not enc:
            return None, "NO_AUTH", "storage.json 中无登录态，请先登录 Trae 桌面端"
        auth = decrypt_auth(enc)
    except Exception as e:
        return None, "NO_AUTH", "解密登录态失败（%s: %s），请重新登录 Trae 桌面端" % (type(e).__name__, e)
    token = auth.get("token")
    if not token:
        return None, "NO_SESSION", "登录态中无 token，请重新登录 Trae 桌面端"
    exp = auth.get("expiredAt")
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if exp_dt < datetime.now(timezone.utc):
                return None, "NO_SESSION", "token 已过期（%s），请打开 Trae 客户端刷新登录态" % exp[:10]
        except Exception:
            pass
    region = (auth.get("userRegion") or {}).get("region", "CN") if isinstance(auth.get("userRegion"), dict) else "CN"
    host = (auth.get("host") or "https://api.trae.cn").rstrip("/")
    return (token, region, host, exp), None, None


def checkin(claim=False):
    loaded, err_code, err_msg = load_auth()
    if err_code:
        return 2 if err_code == "NO_AUTH" else 1, {"result": err_code, "report": err_msg}
    token, region, host, exp = loaded
    headers = {
        "Authorization": "Cloud-IDE-JWT %s" % token,
        "X-User-Region": region,
        "Content-Type": "application/json",
    }
    scode, sbody = request(host + "/trae/api/v2/ug/checkin_credits/status", headers)
    if scode == -1:
        return 1, {"result": "NETWORK", "report": "网络不可达，签到跳过（%s）" % (sbody.get("error") or "")}
    if scode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录 Trae 桌面端" % scode}
    if scode != 200 or not isinstance(sbody, dict):
        return 1, {"result": "ERROR", "report": "状态接口异常（HTTP %s）" % scode, "body": sbody}
    if not sbody.get("enable"):
        return 0, {"result": "INACTIVE", "report": "Trae 签到活动未开启"}

    credits_now = sbody.get("credits")
    suffix = "（当前积分 %s）" % credits_now if credits_now is not None else ""
    if sbody.get("checked_in"):
        return 0, {"result": "ALREADY", "report": "今日已签过%s" % suffix, "credits": credits_now}

    if not claim:
        return 0, {"result": "PENDING", "report": "今日未签到%s" % suffix, "credits": credits_now}

    ccode, cbody = request(host + "/trae/api/v2/ug/checkin_credits/claim", headers)
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    if ccode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录 Trae 桌面端" % ccode}
    if isinstance(cbody, dict) and cbody.get("code") == 0:
        got = cbody.get("data", {}).get("credits") if isinstance(cbody.get("data"), dict) else None
        show = "成功领取 %s 积分" % got if got else "签到成功"
        credits_after = got if got is not None else credits_now
        tail = "（当前积分 %s）" % credits_after if credits_after is not None else ""
        return 0, {"result": "CLAIMED", "report": show + tail, "credits": credits_after}
    msg = (cbody.get("message") or json.dumps(cbody, ensure_ascii=False)[:120]) if isinstance(cbody, dict) else str(cbody)
    return 1, {"result": "ERROR", "report": "领取失败：%s（HTTP %s）" % (msg, ccode)}


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
