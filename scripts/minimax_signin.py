"""MiniMax Code 桌面端每日签到自动领取脚本（每日 400 积分，连签第 4/7 天 1000）。

原理：MiniMax 桌面端 2026-10-19 起升级为 Shared MCode OAuth 架构，登录凭据不再
写在 webview localStorage 里，而是由主进程 OAuth 核心写入
    ~/.minimax/auth/<buildEnv>/<region>/mcode-public/auth.json
凭据是 **不透明 token**（`mmoat_` 前缀，非 JWT），访问签到接口需带
`Authorization: Bearer <accessToken>`。

accessToken 有效期 1 小时，refreshToken 可调 `https://account.minimax.cn/oauth2/token`
（grant_type=refresh_token）自助续期，因此脚本可在客户端不在线时长期免登录运行。

⚠️⚠️ refresh token 是 **轮换制**（服务端每次刷新都换发新的 refresh token，旧 token 立即作废）。
所以刷新必须：
  1. 拿到 proper-lockfile 的同名目录锁（客户端 `cross-process-lock.js` 用的是
     `auth.lock` + `proper-lockfile`，stale 30s），与客户端的自动刷新互斥；
  2. 刷新成功后 **把新 accessToken/refreshToken 原子写回 auth.json**，
     否则客户端下次读到旧 refresh token 会拿到 invalid_grant 而自登出。
⚠️ 早期版本脚本裸调 refresh、不写回、也不加锁，导致客户端凭据被清空（2026-10-25 事故）。

⚠️ 历史兼容：2026-10-19 之前的老版本把明文 JWT 写在
    ~/Library/Application Support/MiniMax/Local Storage/leveldb/
且用 `token` 请求头 + query 参数传参。脚本保留该路径作为回退。

接口：
  GET  https://agent.minimax.cn/minimax-cloud/api/v1/signin/status  查询签到面板
  POST https://agent.minimax.cn/minimax-cloud/api/v1/signin/claim   领取今日积分

签名协议（源码逆向自 prod-web-sh 前端，2026-09-09 全链路实测通过）：
  x-timestamp = 秒级时间戳
  x-signature = md5("<秒>I*7Cf%WZ#S&%1RlZJ&C2" + body)   GET 时 body 为空串
  yy          = md5(quote(路径?query) + "_" + body + md5(str(毫秒时间戳)) + "ooui")
  服务端按收到的请求重算签名，query 参数值自拟即可，但集合与顺序需与前端一致；
  缺 timezone_id=Asia/Shanghai 会报 1406010011 invalid timezone_id。

用法：
  python minimax_signin.py auto    # 查状态→今日可领才领（幂等，日常用这个）
  python minimax_signin.py status  # 仅查状态（调试）
  python minimax_signin.py login   # device flow 重新授权（需人工在浏览器确认 code）

输出一行 JSON，人话在 report 字段。任何情况下不打印 token/JWT。
"""

import base64
import errno
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://agent.minimax.cn"
OAUTH_TOKEN_ENDPOINT = "https://account.minimax.cn/oauth2/token"
OAUTH_DEVICE_ENDPOINT = "https://account.minimax.cn/oauth2/device/code"
OAUTH_CLIENT_ID = "mcode-public"
OAUTH_SCOPE = "agent.default"
OAUTH_AUDIENCE = "agent-backend"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

LEVELDB_GLOB = os.path.join("Library", "Application Support", "MiniMax",
                            "Local Storage", "leveldb")
CONFIG_REL = os.path.join("Library", "Application Support", "MiniMax",
                          "minimax-agent-cn-config.json")
# 新版 OAuth 凭据目录（~ 下的 dataDir）
OAUTH_AUTH_GLOB = os.path.join(".minimax", "auth", "*", "*", "*", "auth.json")
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-\.]{80,}")
REQUEST_TIMEOUT = 20
LOCK_STALE_SEC = 30
# 桌面端实际使用的 UA（客户端 api 日志里的真实值）
DESKTOP_VERSION = os.environ.get("MINIMAX_DESKTOP_VERSION", "3.1.6")


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _readable(path):
    try:
        with open(path, "rb") as f:
            f.read(1)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# 跨进程锁（对齐客户端的 proper-lockfile 行为）
# --------------------------------------------------------------------------

class DirLock:
    """proper-lockfile 风格的目录锁。

    proper-lockfile 默认 realpath=false，在 <target>.lock 目录下用 mkdir 原子创建，
    并把持有者信息写进 <target>.lock/holder 文件；stale 默认 30s。
    这里实现同样的语义，让脚本与客户端的自动刷新互斥。
    """

    def __init__(self, target, stale_sec=LOCK_STALE_SEC):
        self.path = target + ".lock"
        self.stale_sec = stale_sec
        self.acquired = False

    def _holder_pid(self):
        try:
            with open(os.path.join(self.path, "holder"), "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return ""

    def _is_stale(self):
        try:
            age = time.time() - os.stat(self.path).st_mtime
        except Exception:
            return True
        if age > self.stale_sec:
            return True
        # 同进程残留（上次异常退出）也视为 stale
        holder = self._holder_pid()
        if holder.startswith("pid:"):
            try:
                pid = int(holder.split(":", 1)[1].split(",")[0])
            except Exception:
                return False
            if pid == os.getpid():
                return True
        return False

    def acquire(self, timeout=15):
        deadline = time.time() + timeout
        while True:
            try:
                os.mkdir(self.path, 0o700)
                try:
                    with open(os.path.join(self.path, "holder"), "w", encoding="utf-8") as f:
                        f.write("pid:%d,%s" % (os.getpid(), time.time()))
                except Exception:
                    pass
                self.acquired = True
                return True
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
                if self._is_stale():
                    try:
                        shutil.rmtree(self.path, ignore_errors=True)
                        continue
                    except Exception:
                        pass
                if time.time() > deadline:
                    return False
                time.sleep(0.2)

    def release(self):
        if not self.acquired:
            return
        self.acquired = False
        shutil.rmtree(self.path, ignore_errors=True)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
        return False


# --------------------------------------------------------------------------
# 凭据读写
# --------------------------------------------------------------------------

def _auth_file_candidates():
    home = os.path.expanduser("~")
    override = os.environ.get("MINIMAX_OAUTH_AUTH_FILE")
    if override:
        return [override]
    return sorted(glob.glob(os.path.join(home, OAUTH_AUTH_GLOB)))


def read_auth_payload(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_oauth_credential():
    """读取新版 OAuth 凭据文件，返回 (access_token, refresh_token, expires_at_ms, path)。

    路径形如 ~/.minimax/auth/prod/cn/mcode-public/auth.json，
    结构 {"schemaVersion":1,"records":{"<service>\\0<account>":{accessToken,refreshToken,...}}}
    多条记录时取 expiresAtMs 最晚的一条。
    """
    best = None
    for p in _auth_file_candidates():
        if not p or not _readable(p):
            continue
        payload = read_auth_payload(p)
        if not payload:
            continue
        records = payload.get("records") or {}
        if not isinstance(records, dict):
            continue
        for rec in records.values():
            if not isinstance(rec, dict):
                continue
            at = rec.get("accessToken")
            if not at:
                continue
            exp = rec.get("expiresAtMs") or 0
            if best is None or exp > best[2]:
                best = (at, rec.get("refreshToken"), exp, p)
    if best:
        return best[0], best[1], best[2], best[3]
    return None, None, 0, None


def _atomic_write_json(path, payload):
    """原子写 + 私有权限（对齐客户端 atomicWritePrivateFile）。"""
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".auth-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def _write_back(auth_path, match_refresh, new_access, new_refresh, expires_at_ms,
                new_generation=None):
    """把刷新后的凭据写回 auth.json（保持原记录其余字段不变）。

    new_generation 传入时同步更新 credential.generation —— 必须与 auth-state.json
    的 generation 保持一致，否则客户端读取时会判定 generation 不匹配
    （auth-core.js: state.generation === credential.generation）而认为凭据不可用。
    """
    payload = read_auth_payload(auth_path)
    if not payload:
        return False
    records = payload.setdefault("records", {})
    key = None
    for k, v in records.items():
        if isinstance(v, dict) and v.get("refreshToken") == match_refresh:
            key = k
            break
    if key is None:
        return False
    rec = records[key]
    rec["accessToken"] = new_access
    rec["refreshToken"] = new_refresh
    rec["expiresAtMs"] = float(expires_at_ms)
    if new_generation is not None:
        rec["generation"] = int(new_generation)
    try:
        _atomic_write_json(auth_path, payload)
        return True
    except Exception:
        return False


def _state_file_for(auth_path):
    """auth.json 同目录下的 auth-state.json。"""
    return os.path.join(os.path.dirname(auth_path), "auth-state.json")


def _commit_refresh(auth_path, state_path, match_refresh, grant, new_generation):
    """复刻客户端 refresh 的提交阶段：写 credential + 写 state（authenticated）。

    客户端 auth-core.js 的顺序是 credentialStore.put → stateStore.write，
    且 state.generation 必须等于 credential.generation。
    """
    if not _write_back(auth_path, match_refresh, grant["access_token"],
                       grant["refresh_token"], grant["expires_at_ms"], new_generation):
        return False
    state = read_auth_payload(state_path)
    if not isinstance(state, dict):
        state = {"schemaVersion": 2}
    state["status"] = "authenticated"
    state["generation"] = int(new_generation)
    state["scopes"] = [OAUTH_SCOPE]
    state["audience"] = OAUTH_AUDIENCE
    state["clientId"] = OAUTH_CLIENT_ID
    state["storeKind"] = "file"
    state.pop("refresh", None)
    try:
        _atomic_write_json(state_path, state)
        return True
    except Exception:
        return False


def _post_form(url, values):
    payload = urllib.parse.urlencode(values).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


def refresh_oauth_token(auth_path):
    """用 refreshToken 换新的 accessToken，返回 (access_token, refresh_token, expires_at_ms)。

    完整复刻客户端 auth-core.js `refreshCredential` 的两阶段协议：
      阶段一（prepare）：把 auth-state.json 置为 refreshing，generation = max(state, credential)+1
                        —— 先「占坑」再动 RT，防止旧 Core 复用；
      阶段二（commit） ：换到新 grant 后写 credential + 写 state(authenticated)，
                        且 credential.generation == state.generation。
    全程持有与客户端同款的目录锁（auth.lock），与客户端的自动刷新互斥。
    """
    at, rt, exp, path = find_oauth_credential()
    if not rt or not path:
        return None, None, 0
    state_path = _state_file_for(path)

    lock = DirLock(os.path.join(os.path.dirname(path), "auth.lock"))
    if not lock.acquire(timeout=20):
        # 拿不到锁就让客户端自己刷，本轮直接用现有 token
        return (at, rt, exp) if at else (None, None, 0)

    try:
        # 拿到锁后重读：客户端可能刚好刷新过
        at2, rt2, exp2, path2 = find_oauth_credential()
        if not rt2 or not path2:
            return None, None, 0
        if exp2 > time.time() * 1000 + 60_000:
            # 已被其它进程刷新为有效态，直接用，无需再刷
            return at2, rt2, exp2
        rt = rt2
        path = path2
        state_path = _state_file_for(path)

        # 阶段一：读当前 generation 并预留下一个
        state = read_auth_payload(state_path) or {}
        cred_payload = read_auth_payload(path) or {}
        cred_gen = 0
        for v in (cred_payload.get("records") or {}).values():
            if isinstance(v, dict) and v.get("refreshToken") == rt:
                cred_gen = int(v.get("generation") or 0)
                break
        new_generation = max(int(state.get("generation") or 0), cred_gen) + 1

        try:
            body = _post_form(OAUTH_TOKEN_ENDPOINT, {
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "client_id": OAUTH_CLIENT_ID,
                "scope": OAUTH_SCOPE,
                "audience": OAUTH_AUDIENCE,
            })
        except Exception:
            return None, None, 0
        new_at = body.get("access_token")
        new_rt = body.get("refresh_token")
        if not new_at or not new_rt:
            return None, None, 0
        try:
            expires_in = int(body.get("expires_in") or 3600)
        except Exception:
            expires_in = 3600
        expires_at = int(time.time() * 1000) + expires_in * 1000
        grant = {"access_token": new_at, "refresh_token": new_rt,
                 "expires_at_ms": expires_at}

        # 阶段二：写 credential + 写 state（generation 同步递增）
        if not _commit_refresh(path, state_path, rt, grant, new_generation):
            return None, None, 0
        return new_at, new_rt, expires_at
    finally:
        lock.release()


def get_bearer_token():
    """返回 (access_token, kind)。kind = 'oauth' | 'legacy-jwt'。

    优先使用新版 OAuth 凭据；accessToken 过期时用 refreshToken 自助续期。
    找不到 OAuth 凭据时回退到老版 leveldb 明文 JWT。
    """
    at, rt, exp, path = find_oauth_credential()
    if at:
        if exp > time.time() * 1000 + 60_000:
            return at, "oauth"
        new_at, new_rt, new_exp = refresh_oauth_token(path)
        if new_at and new_exp > time.time() * 1000 + 60_000:
            return new_at, "oauth"
        # 刷新失败仍返回旧 token，让服务端给出权威结论
        return at, "oauth"
    jwt = find_legacy_jwt()
    if jwt:
        return jwt, "legacy-jwt"
    return None, None


def find_legacy_jwt():
    """旧版：从 leveldb（按修改时间新→旧）提取第一个未过期的登录 JWT。

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
                return jwt
    return None


def real_user_id():
    """从桌面端配置 JSON 取 realUserID；取不到就返回 0（服务端不严格校验该值）。"""
    try:
        with open(os.path.join(os.path.expanduser("~"), CONFIG_REL), "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return str(cfg.get("user", {}).get("realUserID") or 0)
    except Exception:
        return "0"


# --------------------------------------------------------------------------
# 请求
# --------------------------------------------------------------------------

def signed_request(path, token, kind, uid, method="GET", body=""):
    """复刻客户端签名协议发请求；返回 (http_code, dict)。

    kind='oauth' 用 `Authorization: Bearer <token>`；
    kind='legacy-jwt' 用 `token` 头 + query 参数（旧客户端行为）。
    """
    ms = int(time.time() * 1000)
    sec = ms // 1000
    params = [
        ("device_platform", "web"), ("biz_id", "3"), ("app_id", "3001"),
        ("version_code", "22201"), ("unix", str(ms)), ("timezone_offset", "28800"),
        ("is_desktop", "1"), ("desktop_version", DESKTOP_VERSION),
        ("sys_language", "zh"), ("lang", "zh"),
        ("uuid", "null"), ("device_id", "48372915"), ("os_name", "macOS"),
        ("browser_name", "Chrome"), ("browser_language", "zh-CN"),
        ("browser_platform", "MacIntel"), ("user_id", uid),
        ("op_ticket", "undefined"), ("screen_width", "1512"), ("screen_height", "982"),
        ("client", "desktop"),
        ("unix", str(ms)), ("token", token),
    ]
    full = "%s?%s" % (path, urllib.parse.urlencode(params))
    yy = hashlib.md5(("%s_%s%s%s" % (urllib.parse.quote(full), body,
                                     hashlib.md5(str(ms).encode()).hexdigest(),
                                     "ooui")).encode()).hexdigest()
    xsig = hashlib.md5(("%sI*7Cf%%WZ#S&%%1RlZJ&C2%s" % (sec, body)).encode()).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "x-timestamp": str(sec), "x-signature": xsig, "yy": yy,
        "Origin": API_BASE, "Referer": API_BASE + "/",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "MiniMaxAgent Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) MiniMax/%s "
                      "Chrome/148.0.7778.280 Safari/537.36" % DESKTOP_VERSION,
    }
    if kind == "oauth":
        headers["Authorization"] = "Bearer " + token
    else:
        headers["token"] = token
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
    token, kind = get_bearer_token()
    if not token:
        return 2, {"result": "NO_AUTH", "report": (
            "未找到登录凭据（新版 OAuth 凭据文件与旧版 leveldb JWT 均无），"
            "请打开 MiniMax Code 客户端重新登录")}
    uid = real_user_id()

    scode, sbody = signed_request("/minimax-cloud/api/v1/signin/status", token, kind, uid)
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

    ccode, cbody = signed_request("/minimax-cloud/api/v1/signin/claim", token, kind, uid,
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


# --------------------------------------------------------------------------
# device flow 重新授权
# --------------------------------------------------------------------------

def device_login():
    """device flow 重新授权：打印验证链接与 user_code，轮询直到用户确认。

    与客户端 `oauth-client.js` 的 startDeviceAuthorization / pollDeviceToken 完全一致。
    拿到 token 后写入 ~/.minimax/auth/prod/cn/mcode-public/auth.json。
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    try:
        body = _post_form(OAUTH_DEVICE_ENDPOINT, {
            "client_id": OAUTH_CLIENT_ID,
            "scope": OAUTH_SCOPE,
            "audience": OAUTH_AUDIENCE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
    except Exception as e:
        return 1, {"result": "ERROR", "report": "device code 申请失败：%s" % e}
    device_code = body.get("device_code")
    user_code = body.get("user_code")
    verify_uri = body.get("verification_uri_complete") or body.get("verification_uri")
    if not device_code or not user_code or not verify_uri:
        return 1, {"result": "ERROR", "report": "device code 响应异常：%s" % json.dumps(
            body, ensure_ascii=False)[:200]}
    expires_in = int(body.get("expires_in") or 300)
    interval = int(body.get("interval") or 5)

    # 链接必须立刻可见（stdout 保留给最终那行 JSON，故走 stderr）
    print("请在浏览器打开以下链接完成授权：\n  %s\n  （user_code: %s，%s 秒内有效）"
          % (verify_uri, user_code, expires_in), file=sys.stderr, flush=True)

    deadline = time.time() + expires_in
    while time.time() < deadline:
        try:
            tok_body = _post_form(OAUTH_TOKEN_ENDPOINT, {
                "grant_type": DEVICE_GRANT_TYPE,
                "device_code": device_code,
                "client_id": OAUTH_CLIENT_ID,
                "code_verifier": verifier,
            })
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read().decode("utf-8", "replace"))
            except Exception:
                err = {}
            code = err.get("error")
            if code == "authorization_pending":
                time.sleep(interval)
                continue
            if code == "slow_down":
                interval += 5
                time.sleep(interval)
                continue
            return 1, {"result": "ERROR", "report": "授权失败：%s（%s）" % (
                code or "http_%s" % e.code, err.get("error_description") or "")}
        except Exception as e:
            return 1, {"result": "ERROR", "report": "轮询异常：%s" % e}

        access = tok_body.get("access_token")
        refresh = tok_body.get("refresh_token")
        if not access or not refresh:
            time.sleep(interval)
            continue
        try:
            expires_in_tok = int(tok_body.get("expires_in") or 3600)
        except Exception:
            expires_in_tok = 3600
        saved = _store_new_credential(access, refresh, expires_in_tok * 1000)
        return 0, {"result": "CLAIMED" if saved else "ERROR",
                   "report": ("授权成功，凭据已写入 auth.json" if saved
                              else "授权成功，但写入 auth.json 失败")}
    return 1, {"result": "ERROR", "report": "授权超时（%ss 内未确认）" % expires_in}


def _store_new_credential(access, refresh, expires_in_ms):
    """把新凭据写入 ~/.minimax/auth/prod/cn/mcode-public/auth.json。

    与客户端一致：credential.generation 与 auth-state.json 的 generation 必须相同，
    且 recordKey 用客户端同样的算法（service + sha256(authHome\\0clientId) 的 base64url）。
    """
    home = os.path.expanduser("~")
    auth_home = os.path.join(home, ".minimax", "auth")
    auth_dir = os.path.join(auth_home, "prod", "cn", OAUTH_CLIENT_ID)
    os.makedirs(auth_dir, mode=0o700, exist_ok=True)
    path = os.path.join(auth_dir, "auth.json")
    state_path = os.path.join(auth_dir, "auth-state.json")

    payload = read_auth_payload(path) or {"schemaVersion": 1, "records": {}}
    records = payload.setdefault("records", {})
    key = next(iter(records), None)
    if key is None:
        account = base64.urlsafe_b64encode(hashlib.sha256(
            ("%s\0%s" % (auth_home, OAUTH_CLIENT_ID)).encode()).digest()
        ).decode().rstrip("=")
        key = "com.minimax.mcode.oauth.prod.cn\0%s" % account

    state = read_auth_payload(state_path) or {}
    new_generation = max(int(state.get("generation") or 0), 0) + 1
    for v in records.values():
        if isinstance(v, dict):
            new_generation = max(new_generation, int(v.get("generation") or 0) + 1)
            break

    records[key] = {
        "accessToken": access,
        "refreshToken": refresh,
        "tokenType": "Bearer",
        "clientId": OAUTH_CLIENT_ID,
        "scopes": [OAUTH_SCOPE],
        "audience": OAUTH_AUDIENCE,
        "expiresAtMs": float(time.time() * 1000 + expires_in_ms),
        "generation": new_generation,
        "schemaVersion": 1,
    }
    try:
        _atomic_write_json(path, payload)
    except Exception:
        return False

    state.update({
        "schemaVersion": 2,
        "status": "authenticated",
        "storeKind": "file",
        "clientId": OAUTH_CLIENT_ID,
        "scopes": [OAUTH_SCOPE],
        "audience": OAUTH_AUDIENCE,
        "buildEnv": "prod",
        "region": "cn",
        "generation": new_generation,
    })
    state.pop("refresh", None)
    try:
        _atomic_write_json(state_path, state)
    except Exception:
        return False
    return True


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "auto"
    try:
        if action == "auto":
            code, out = checkin(claim=True)
        elif action == "status":
            code, out = checkin(claim=False)
        elif action == "login":
            code, out = device_login()
        else:
            code, out = 2, {"result": "ERROR", "report": "未知命令：%s（可用：auto / status / login）" % action}
    except Exception as e:
        code, out = 2, {"result": "ERROR", "report": "脚本运行异常（%s: %s）" % (type(e).__name__, e)}
    emit(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
