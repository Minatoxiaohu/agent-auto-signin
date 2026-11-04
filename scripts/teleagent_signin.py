"""TeleAgent（星辰超级智能体桌面版）每日签到自动领取脚本（每日 100 积分）。

原理：与其它端一致——读本机客户端已写出的登录凭据，直调官方接口，不开 GUI、不模拟点击，
**客户端不需要保持运行**。

接口（逆向自 app.asar 的 dist/assets/index-*.js 常量表 `pt`）：
  GET  https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/v2/checkDayTask
        查询「积分福利社」每日任务：daily_task.{claimed_today,total_claim_days,total_claimed_points}
  GET  https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/checkTask?type=daily_login
        领取今日积分
  GET  .../companyStore/userCenter   积分余额（可选，仅用于 report 文案）
鉴权：只需 `X-Token`（客户端 request 层 e1() 的必校验头）。其余 X-Timestamp / X-Nonce /
X-App-Version / X-OS-Type / X-SuperAgent-Device-Id / X-Channel-Id / X-Runtime-Env 服务端实测均为可选，
无签名、无 CSRF；脚本仍按客户端全量发送，防止后续加校验。

凭据来源（双路主备，任一可用即成功）：
  1) **safeStorage（权威）**：`<data>/users/<userHash>/app-auth/token.json`
     {"version":1,"encryptedToken":"djEw…","encrypted":true,"scheme":"safe_storage"}
     解密：macOS 从 keychain 条目 "<App> Safe Storage" 取口令 → PBKDF2-HMAC-SHA1(pw,"saltysalt",1003,16B)
     → AES-128-CBC（IV = 16 个空格）；Linux v11 用固定口令 "peanuts"（迭代 1 次）；
     Windows 走 DPAPI（ctypes 调 CryptUnprotectData，无需 pywin32）。AES 由系统 `openssl` 完成。
  2) **leveldb 回退**：`<data>/Partitions/owner%3A<user>/Local Storage/leveldb`
     用 `strings` 抽出 `"token":"…"` 所有历史候选，逐个试探。leveldb 里可能残留过期 token，
     所以必须试探而非直接用；这条路径用于 keychain 被锁（锁屏/休眠）导致主路不可用时兜底。

⚠️ 领取接口**静默幂等**：今日已领时 checkTask 仍返回
`{"code":200,"msg":"success","data":[]}`，不带任何错误码。
所以「领到没」只能靠领取前后重查 checkDayTask 的 claimed_today 判定（与客户端 UI 逻辑一致），
脚本无证据不报成功。

依赖：零第三方依赖（标准库 + 系统自带 openssl；leveldb 回退额外用 strings）。

用法：
  python teleagent_signin.py auto    # 查状态→未领才领→复核（幂等，日常用这个）
  python teleagent_signin.py status  # 仅查状态（调试）
  python teleagent_signin.py claim   # 仅领取并复核（调试，幂等）

环境变量：
  TELEAGENT_DATA_DIR / TELEAGENT_USER_DATA  TeleAgent userData 目录（默认 ~/.local/share/TeleAgent）
  TELEAGENT_TOKEN                           直接指定 token（跳过凭据读取，仅调试）
  TELEAGENT_APP_VERSION                     x-app-version 覆盖值

输出一行 JSON，人话在 report 字段。任何情况下不打印 token。
"""

import base64
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

API_BASE = "https://agent.teleai.com.cn/superCowork/sapi"
PATH_STATUS = "/user/portal/companyStore/v2/checkDayTask"
PATH_CLAIM = "/user/portal/companyStore/checkTask?type=daily_login"
PATH_CENTER = "/user/portal/companyStore/userCenter"
REQUEST_TIMEOUT = 20
DEFAULT_APP_VERSION = "2.7.1"
CLAIM_VERIFY_DELAYS = (0.8, 1.8, 3.0)

# safeStorage 的 keychain 服务名候选（Electron 用 app.getName()，改版后可能变）
KEYCHAIN_SERVICES = [
    "TeleAgent Safe Storage",
    "com.teleai.superagent Safe Storage",
    "TeleAgent 安全存储",
]

OS_TYPE = {"Darwin": "darwin", "Windows": "win32", "Linux": "linux"}.get(
    platform.system(), platform.system().lower())


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _readable(path):
    """沙箱环境下 os.path.exists 会误报 False，用实际试读 1 字节代替。"""
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 目录定位

def user_data_dir():
    override = os.environ.get("TELEAGENT_DATA_DIR") or os.environ.get("TELEAGENT_USER_DATA")
    if override:
        return os.path.expanduser(override)
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return os.path.join(base, "TeleAgent")
    # 实测 macOS 也落在 ~/.local/share（不是 Application Support）
    return os.path.join(home, ".local", "share", "TeleAgent")


def current_owner_id(data):
    try:
        with open(os.path.join(data, "current-owner.json"), "r", encoding="utf-8") as f:
            return json.load(f).get("userId")
    except Exception:
        return None


def candidate_partitions(data):
    """leveldb 回退用的分区目录：当前 owner 优先，其余按 mtime 倒序。"""
    dirs = []
    uid = current_owner_id(data)
    if uid:
        dirs.append(os.path.join(data, "Partitions", "owner%%3Av1_public_%s" % uid))
    part_root = os.path.join(data, "Partitions")
    rest = []
    if os.path.isdir(part_root):
        for d in glob.glob(os.path.join(part_root, "*")):
            if d in dirs:
                continue
            try:
                rest.append((os.path.getmtime(d), d))
            except Exception:
                rest.append((0, d))
    dirs.extend(d for _, d in sorted(rest, reverse=True))
    dirs.append(data)  # 渲染进程默认分区
    return [d for d in dirs if os.path.isdir(d)]


# ---------------------------------------------------------------- 主路：safeStorage

def _keychain_password():
    last = ""
    for svc in KEYCHAIN_SERVICES:
        try:
            proc = subprocess.run(["security", "find-generic-password", "-s", svc, "-w"],
                                  capture_output=True, timeout=10)
        except Exception as e:
            last = "%s: %s" % (type(e).__name__, e)
            continue
        if proc.returncode == 0:
            pw = proc.stdout.decode("utf-8", "replace").strip()
            if pw:
                return pw, None
        last = proc.stderr.decode("utf-8", "replace").strip()[:120]
    return None, last or "keychain 中未找到 safeStorage 条目"


def _aes_cbc_decrypt(key, iv, data):
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc", "-nopad",
         "-K", key.hex(), "-iv", iv.hex()],
        input=data, capture_output=True, timeout=10)
    if proc.returncode != 0:
        raise RuntimeError("openssl 解密失败: %s" % proc.stderr.decode(errors="replace")[:120])
    pt = proc.stdout
    if pt and 0 < pt[-1] <= 16:
        pt = pt[:-pt[-1]]
    return pt


def _dpapi_unprotect(blob):
    """Windows DPAPI 解密（纯 ctypes，不依赖 pywin32）。"""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(blob, len(blob))
    in_blob = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise RuntimeError("DPAPI 解密失败（CryptUnprotectData 返回 0）")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)


def _decrypt_safe_storage(raw):
    blob = base64.b64decode(raw)
    if blob[:3] not in (b"v10", b"v11"):
        raise RuntimeError("未知的 safeStorage 前缀 %r（期望 v10/v11）" % blob[:3])
    system = platform.system()
    if system == "Darwin":
        pw, kerr = _keychain_password()
        if not pw:
            raise RuntimeError("无法读取 keychain 口令（%s）" % kerr)
        key = hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", 1003, 16)
        pt = _aes_cbc_decrypt(key, b" " * 16, blob[3:])
    elif system == "Linux":
        pw = os.environ.get("TELEAGENT_SAFE_STORAGE_PASSWORD", "peanuts")
        iters = 1 if blob[:3] == b"v11" else 1003
        key = hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", iters, 16)
        pt = _aes_cbc_decrypt(key, b" " * 16, blob[3:])
    elif system == "Windows":
        pt = _dpapi_unprotect(blob[3:])
    else:
        raise RuntimeError("不支持的平台：%s" % system)

    text = pt.decode("utf-8", "replace").strip().strip("\x00")
    if text.startswith("{"):
        try:
            text = (json.loads(text) or {}).get("token") or text
        except Exception:
            pass
    if not text:
        raise RuntimeError("解密结果为空")
    return text


def tokens_from_safe_storage(data):
    """返回 [(token, source)]，按 token.json 的 mtime 倒序（多账号取最近活跃的）。"""
    found, notes = [], []
    users = os.path.join(data, "users")
    try:
        names = os.listdir(users)
    except Exception:
        return found, "未找到 %s" % users
    entries = []
    for name in names:
        tf = os.path.join(users, name, "app-auth", "token.json")
        if _readable(tf):
            try:
                entries.append((os.path.getmtime(tf), tf, name))
            except Exception:
                entries.append((0, tf, name))
    if not entries:
        return found, "未找到 users/*/app-auth/token.json"

    for _, tf, name in sorted(entries, reverse=True):
        try:
            raw = json.load(open(tf, "r", encoding="utf-8"))
        except Exception as e:
            notes.append("%s: 读取失败（%s）" % (name, e))
            continue
        enc = raw.get("encryptedToken") or raw.get("token")
        if not enc:
            notes.append("%s: 无 encryptedToken" % name)
            continue
        if raw.get("encrypted") is False and not enc.startswith("djEw"):
            found.append((enc, "safeStorage-plain:%s" % name))
            continue
        try:
            found.append((_decrypt_safe_storage(enc), "safeStorage:%s" % name))
        except Exception as e:
            notes.append("%s: %s" % (name, str(e)[:90]))
    return found, "；".join(notes) if notes else None


# ---------------------------------------------------------------- 备路：leveldb strings

TOKEN_PATTERNS = [
    re.compile(r'"token"\s*:\s*"([^"]{8,})"'),
    re.compile(r'\\+"token\\+"\s*:\s*\\+"([^"\\]{8,})'),
]


def _leveldb_text(path):
    bin_name = shutil.which("strings")
    chunks = []
    files = sorted(glob.glob(os.path.join(path, "*.log"))) + sorted(glob.glob(os.path.join(path, "*.ldb")))
    for f in files:
        try:
            if bin_name:
                out = subprocess.run([bin_name, "-a", f], capture_output=True, text=True,
                                     errors="replace", timeout=30).stdout
            else:
                with open(f, "rb") as fh:
                    out = fh.read().decode("utf-8", "replace")
            chunks.append(out)
        except Exception:
            continue
    return "\n".join(chunks)


def tokens_from_leveldb(data):
    """leveldb 里会残留历史 token（已过期），全部收上来交给调用方逐个试探。"""
    found, seen = [], set()
    for part in candidate_partitions(data):
        ls = os.path.join(part, "Local Storage", "leveldb")
        if not os.path.isdir(ls):
            continue
        text = _leveldb_text(ls)
        for rx in TOKEN_PATTERNS:
            for m in rx.finditer(text):
                tok = m.group(1).replace("\\", "").strip()
                if len(tok) >= 8 and tok not in seen:
                    seen.add(tok)
                    found.append((tok, "leveldb:%s" % os.path.basename(part)[:28]))
    return found


def collect_tokens():
    """(tokens, notes, err)：主路优先，备路兜底。"""
    data = user_data_dir()
    env_tok = os.environ.get("TELEAGENT_TOKEN")
    if env_tok:
        return [(env_tok.strip(), "env")], None, None
    if not os.path.isdir(data):
        return [], [], ("未找到 TeleAgent 数据目录（%s）。请先启动并登录 TeleAgent 桌面端，"
                        "或用环境变量 TELEAGENT_DATA_DIR 指定。" % data)

    tokens, notes = [], []
    ss, ss_note = tokens_from_safe_storage(data)
    tokens.extend(ss)
    if ss_note:
        notes.append("safeStorage 跳过：%s" % ss_note)
    if not ss:
        lv = tokens_from_leveldb(data)
        tokens.extend(lv)
        if lv:
            notes.append("已回退 leveldb 提取（%d 个候选）" % len(lv))

    if not tokens:
        return [], notes, ("未找到 TeleAgent 登录凭据（%s）。请先登录 TeleAgent 桌面端。"
                           % (data + "；" + "；".join(notes) if notes else data))
    return tokens, notes, None


# ---------------------------------------------------------------- HTTP

def app_version():
    v = os.environ.get("TELEAGENT_APP_VERSION")
    if v:
        return v.strip()
    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString",
                 "/Applications/TeleAgent.app/Contents/Info.plist"],
                capture_output=True, timeout=5)
            out = proc.stdout.decode("utf-8", "replace").strip()
            if proc.returncode == 0 and out:
                return out
        except Exception:
            pass
    return DEFAULT_APP_VERSION


def device_id(data):
    try:
        return json.load(open(os.path.join(data, "app-auth", "device-meta.json"),
                              "r", encoding="utf-8")).get("deviceId") or ""
    except Exception:
        return ""


def request(path, token, dev=""):
    ver = app_version()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Token": token,
        "X-Timestamp": str(int(time.time())),
        "X-Nonce": str(uuid.uuid4()),
        "X-App-Version": ver,
        "X-OS-Type": OS_TYPE,
        "X-SuperAgent-Device-Id": dev,
        "X-Channel-Id": "",
        "X-Runtime-Env": "",
        "User-Agent": "TeleAgent/%s" % ver,
    }
    req = urllib.request.Request(API_BASE + path, headers=headers, method="GET")
    # 显式禁用环境代理（客户端可能配了 127.0.0.1:1082 之类），保证直连
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            return resp.status, _loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, _loads(e.read()) or {"error": "HTTP %s" % e.code}
    except Exception as e:
        return -1, {"error": "%s: %s" % (type(e).__name__, e)}


def _loads(raw):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {}


def _daily_task(body):
    return ((body or {}).get("data") or {}).get("daily_task") or {}


def _tail(days, total):
    bits = []
    if days is not None:
        bits.append("本期已领 %s 天" % days)
    if total is not None:
        bits.append("累计 %s 积分" % total)
    return "（%s）" % " · ".join(bits) if bits else ""


def _balance(token, dev):
    code, body = request(PATH_CENTER, token, dev)
    if code != 200:
        return ""
    bal = ((body or {}).get("data") or {}).get("current_points_balance")
    return "，当前余额 %s" % bal if bal is not None else ""


# ---------------------------------------------------------------- 主流程

def checkin(claim=False):
    tokens, notes, err = collect_tokens()
    if err:
        return 2, {"result": "NO_AUTH", "report": err, "notes": notes}

    data = user_data_dir()
    dev = device_id(data)
    used, body, code = None, {}, 0
    for tok, src in tokens:
        code, body = request(PATH_STATUS, tok, dev)
        if code == 200 and body.get("code") in (0, 200):
            used = (tok, src)
            break
        if code == -1:
            return 1, {"result": "NETWORK",
                       "report": "网络不可达，签到跳过（%s）" % body.get("error", "")}
    if used is None:
        if code in (401, 403):
            return 1, {"result": "NO_SESSION",
                       "report": "TeleAgent 登录态已失效（HTTP %s），请重新登录桌面端" % code,
                       "tried": len(tokens), "notes": notes}
        return 1, {"result": "ERROR",
                   "report": "状态接口异常（HTTP %s：%s；已试 %d 个候选凭据）" % (
                       code, body.get("msg") or body.get("message") or body.get("code") or "",
                       len(tokens)),
                   "notes": notes}
    tok, src = used

    task = _daily_task(body)
    if not task or task.get("visible") is False:
        return 0, {"result": "INACTIVE", "report": "今日无「积分福利社」日签任务，跳过", "source": src}

    points = task.get("daily_claimable_points")
    days = task.get("total_claim_days")
    total = task.get("total_claimed_points")
    base = {"daily_points": points, "total_claim_days": days,
            "total_claimed_points": total, "source": src}

    if task.get("claimed_today"):
        return 0, dict(base, result="ALREADY", report="今日已领过每日积分%s" % _tail(days, total))
    if not claim:
        return 0, dict(base, result="PENDING",
                       report="今日可领 %s 积分，尚未领取%s" % (points, _tail(days, total)))

    ccode, cbody = request(PATH_CLAIM, tok, dev)
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    if ccode in (401, 403):
        return 1, {"result": "NO_SESSION",
                   "report": "登录态已失效（HTTP %s），请重新登录 TeleAgent 桌面端" % ccode}
    if ccode != 200 or cbody.get("code") not in (0, 200):
        # 业务幂等：已领过可能报错，再查一次状态按 ALREADY 处理
        vcode, vbody = request(PATH_STATUS, tok, dev)
        vt = _daily_task(vbody)
        if vcode == 200 and vt.get("claimed_today"):
            return 0, dict(base, result="ALREADY", verified=True,
                           report="今日已领过每日积分%s" % _tail(
                               vt.get("total_claim_days"), vt.get("total_claimed_points")),
                           total_claim_days=vt.get("total_claim_days"),
                           total_claimed_points=vt.get("total_claimed_points"))
        return 1, {"result": "ERROR", "report": "领取失败：%s（HTTP %s）" % (
            cbody.get("msg") or cbody.get("message") or
            json.dumps(cbody, ensure_ascii=False)[:120], ccode)}

    # 复核：领取接口静默幂等，必须看到 claimed_today 才算成功
    for wait in CLAIM_VERIFY_DELAYS:
        time.sleep(wait)
        vcode, vbody = request(PATH_STATUS, tok, dev)
        if vcode != 200:
            continue
        vt = _daily_task(vbody)
        if vt.get("claimed_today"):
            vdays, vtotal = vt.get("total_claim_days"), vt.get("total_claimed_points")
            got = None
            if isinstance(vtotal, int) and isinstance(total, int):
                got = vtotal - total
            show = ("成功领取 %s 积分" % got) if isinstance(got, int) and got > 0 \
                else ("成功领取 %s 积分" % points if points else "领取成功")
            return 0, {"result": "CLAIMED", "verified": True, "source": src,
                       "daily_points": points, "total_claim_days": vdays,
                       "total_claimed_points": vtotal,
                       "report": show + _tail(vdays, vtotal) + _balance(tok, dev)}

    return 1, {"result": "ERROR", "verified": False,
               "report": "领取请求已受理，但复核未看到 claimed_today 变化"
                         "（服务端延迟或请求被拦截）；调用前状态：%s。请稍后跑 status 确认。"
                         % (_tail(days, total) or "未知")}


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "auto"
    try:
        if action in ("auto", "claim"):
            code, out = checkin(claim=True)
        elif action == "status":
            code, out = checkin(claim=False)
        else:
            code, out = 2, {"result": "ERROR",
                            "report": "未知命令：%s（可用：auto / status / claim）" % action}
    except Exception as e:
        code, out = 2, {"result": "ERROR",
                        "report": "脚本运行异常（%s: %s）" % (type(e).__name__, e)}
    emit(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
