"""Trae CN 每日签到自动领取脚本（每日 200 积分）。

2026-10-14：客户端由「TRAE SOLO CN」更名为「Trae CN」，数据目录与 appVersion 均已变化，
脚本已兼容新旧两个路径（见 STORAGE_REL_ALT / APP_VERSION）。

2026-10-19：修正 claim 长期失败（9074 / 客户端能点但脚本不能）的根因——
客户端更名后 product.json 的 `packageType` 变成 `TRAE_CN`，而客户端用
`ai(t) = packageType in (SOLO_CN, SOLO_I18N, SOLO_CN_ENTERPRISE)` 决定 `req_source`，
非 SOLO 包发 **1**（旧脚本硬编码 2，是 SOLO 时代的正确值）。同时 `x-app-version`
已升到 3.4.3、`x-device-brand` 应为 `hw.model`（Mac14,5）而非 CPU 架构（arm64）。
现三者均动态读取，与客户端 1:1 一致。详见 detect_req_source() / device_model()。

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
import platform
import ssl
import subprocess
import sys
import time
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
# 2026-10-14：客户端已由「TRAE SOLO CN」更名为「Trae CN」（dataFolderName=.trae-cn），
# 老路径不再产生 storage.json → 脚本曾报 NO_AUTH「未找到 storage.json」。两个都留着。
STORAGE_REL_ALT = os.path.join("Trae CN", "User", "globalStorage", "storage.json")
REQUEST_TIMEOUT = 20

# product.json 位置（用于动态读取 appVersion / packageType，必须与真实客户端一致）
APP_JSON_CANDIDATES = [
    "/Applications/Trae CN.app/Contents/Resources/app/product.json",
    "/Applications/TRAE SOLO CN.app/Contents/Resources/app/product.json",
]
DEFAULT_APP_VERSION = "3.4.3"
# packageType 决定 req_source（见 detect_req_source）
SOLO_PACKAGE_TYPES = {"SOLO_CN", "SOLO_I18N", "SOLO_CN_ENTERPRISE"}


def _load_product_json():
    """直接 try-open（不依赖后面才定义的 _readable，避免模块加载期 NameError）。"""
    for p in APP_JSON_CANDIDATES:
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return {}


_PRODUCT = _load_product_json()

# 客户端版本必须与 product.json 的 appVersion 一致：服务端把 x-app-version 纳入风控，
# 旧版本号会被判为过期/非法客户端（表现为 claim 被 9074 限流）。
# 环境变量 TRAE_APP_VERSION 可覆盖（调试用）。
APP_VERSION = os.environ.get("TRAE_APP_VERSION") or _PRODUCT.get("appVersion") or DEFAULT_APP_VERSION
PACKAGE_TYPE = os.environ.get("TRAE_PACKAGE_TYPE") or _PRODUCT.get("packageType") or ""

# 过去把 9074 判为「纯服务端限流」，理由是 header/body 已与客户端对齐。
# 2026-10-19 复查发现对齐有误（packageType 已变 TRAE_CN → req_source 应为 1，app_version 已 3.4.3），
# 已修正。仍保留适度退避以应对真实限流，但不再拉长到 9 分钟（参数错时快速失败更友好）。
BACKOFF_SECONDS = (0, 5, 20, 45, 90)



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
        os.path.join(os.path.expanduser("~"), "Library", "Application Support", STORAGE_REL_ALT),
        os.path.join(os.path.expanduser("~"), "Library", "Application Support", STORAGE_REL),
        os.path.join(os.environ.get("APPDATA", ""), STORAGE_REL_ALT),  # Windows 兜底
        os.path.join(os.environ.get("APPDATA", ""), STORAGE_REL),
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


def request(url, headers, body=None, timeout=REQUEST_TIMEOUT):
    if body is None:
        body = b"{}"
    elif isinstance(body, (dict, list)):
        body = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
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


def get_device_id(storage_path):
    """Trae 桌面端发 claim 必须带 x-device-id，值来自 @vscode/deviceid 缓存文件
    （guaranteedDeviceId），即 storage.json 里的 telemetry.devDeviceId。"""
    candidates = [
        os.path.join(os.path.expanduser("~"), "Library", "Application Support",
                     "Microsoft", "DeveloperTools", "deviceid"),
    ]
    for c in candidates:
        if _readable(c):
            try:
                v = open(c, "r", encoding="utf-8").read().strip()
                if v:
                    return v
            except Exception:
                pass
    # 回退：storage.json 里的 telemetry.devDeviceId
    if storage_path and _readable(storage_path):
        try:
            with open(storage_path, "r", encoding="utf-8") as f:
                d = json.load(f)
            did = d.get("telemetry.devDeviceId")
            if did:
                return did
        except Exception:
            pass
    return None


_DEVICE_MODEL = None


def device_model():
    """客户端 x-device-brand = commonParams.device_model（systeminformation 的 deviceModel），
    macOS 上即 `sysctl -n hw.model`（如 Mac14,5），不是 platform.machine() 的 CPU 架构。
    旧脚本发 "arm64"，与客户端不一致，是风控可疑点之一。"""
    global _DEVICE_MODEL
    if _DEVICE_MODEL is not None:
        return _DEVICE_MODEL
    val = ""
    try:
        val = subprocess.run(["sysctl", "-n", "hw.model"], capture_output=True,
                             text=True, timeout=3).stdout.strip()
    except Exception:
        val = ""
    _DEVICE_MODEL = val or platform.machine() or "Mac"
    return _DEVICE_MODEL


def os_version():
    """客户端 x-os-version = commonParams.os_version（系统版本号，如 27.0.1）。"""
    try:
        v = subprocess.run(["sw_vers", "-productVersion"], capture_output=True,
                           text=True, timeout=3).stdout.strip()
        if v:
            return v
    except Exception:
        pass
    return platform.mac_ver()[0] or platform.release()


def build_headers(token, region, storage_path):
    """按客户端 `_buildRawHeaders` + `mixAuthorization` + `_applyUgDeviceHeaders` 1:1 还原。

    客户端实测（2026-10-19 逆向 /Applications/Trae CN.app/.../out/main.js @1966800）：
      - Content-Type: application/json
      - Authorization: Cloud-IDE-JWT <token>        （mixAuthorization）
      - x-device-id     = guaranteedDeviceId
      - x-device-brand  = commonParams.device_model   （hw.model，如 Mac14,5）
      - x-device-type   = commonParams.os_name        （macOS）
      - x-os-version    = commonParams.os_version     （如 27.0.1）
      - x-app-version   = product.json 的 appVersion  （如 3.4.3）
    客户端不发 X-User-Region，保留仅为兼容旧逻辑，无副作用。
    """
    headers = {
        "Authorization": "Cloud-IDE-JWT %s" % token,
        "X-User-Region": region,
        "Content-Type": "application/json",
    }
    did = get_device_id(storage_path)
    if did:
        headers["x-device-id"] = did
    headers["x-device-brand"] = device_model()
    headers["x-device-type"] = "macOS"
    headers["x-os-version"] = os_version()
    headers["x-app-version"] = APP_VERSION
    return headers


def detect_req_source():
    """客户端：`const a = ai(this.productService) ? 2 : 1`，
    而 `ai(t) = packageType in (SOLO_CN, SOLO_I18N, SOLO_CN_ENTERPRISE)`。

    ⚠️ 2026-10-19 修正：客户端更名 Trae CN 后 product.json 的 packageType 已变成
    `TRAE_CN`（不再是 SOLO_CN），ai() 返回 false → 真实客户端发的是 **req_source=1**。
    旧脚本一直硬编码 2（SOLO 时代的正确值），与客户端不一致，是 claim 长期 9074 的
    主要可疑根因。此处改为按 product.json 动态判定（环境变量 TRAE_REQ_SOURCE 可覆盖）。
    """
    override = os.environ.get("TRAE_REQ_SOURCE")
    if override:
        try:
            return int(override)
        except Exception:
            pass
    return 2 if PACKAGE_TYPE in SOLO_PACKAGE_TYPES else 1


def claim_body():
    return {"req_source": detect_req_source()}


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
    storage_path, _ = find_storage()
    headers = build_headers(token, region, storage_path)
    body = claim_body()
    scode, sbody = request(host + "/trae/api/v2/ug/checkin_credits/status", headers, body)
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
    diag = {"app_version": APP_VERSION, "package_type": PACKAGE_TYPE,
            "req_source": detect_req_source()}
    if sbody.get("checked_in"):
        return 0, {"result": "ALREADY", "report": "今日已签过%s" % suffix,
                   "credits": credits_now, "diag": diag}

    if not claim:
        return 0, {"result": "PENDING", "report": "今日未签到%s" % suffix,
                   "credits": credits_now, "diag": diag}

    ccode, cbody = request(host + "/trae/api/v2/ug/checkin_credits/claim", headers, body)
    # 9074「当前参与用户太多」是服务端全局限流：请求已与客户端 1:1 对齐仍会命中，
    # 属服务端容量护栏，非脚本问题。用逐步拉长的退避间隔碰运气。
    attempts = 1
    while (ccode == 200 and isinstance(cbody, dict) and cbody.get("code") == 9074
           and attempts < len(BACKOFF_SECONDS)):
        wait = BACKOFF_SECONDS[attempts]
        time.sleep(wait)
        ccode, cbody = request(host + "/trae/api/v2/ug/checkin_credits/claim", headers, body)
        attempts += 1
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    if ccode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录 Trae 桌面端" % ccode}
    if isinstance(cbody, dict) and cbody.get("code") == 0:
        got = cbody.get("data", {}).get("credits") if isinstance(cbody.get("data"), dict) else None
        show = "成功领取 %s 积分" % got if got else "签到成功"
        credits_after = got if got is not None else credits_now
        tail = "（当前积分 %s）" % credits_after if credits_after is not None else ""
        return 0, {"result": "CLAIMED", "report": show + tail, "credits": credits_after,
                   "diag": diag}
    msg = (cbody.get("message") or json.dumps(cbody, ensure_ascii=False)[:120]) if isinstance(cbody, dict) else str(cbody)
    if isinstance(cbody, dict) and cbody.get("code") == 9074:
        return 1, {"result": "ERROR", "report": "领取失败：%s（已重试 %d 次；服务端限流。"
                "若持续出现，先核对 product.json 的 appVersion=%s 与 packageType=%s 是否已变"
                "（本次已发 req_source=%s）" % (msg, attempts, APP_VERSION, PACKAGE_TYPE,
                                               detect_req_source())}
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
