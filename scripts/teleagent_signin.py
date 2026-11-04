"""TeleAgent（电信星辰 Agent 桌面端）每日签到自动领取脚本（每日 100 积分）。

原理：TeleAgent 是 Electron 客户端，登录态写在 userData 分区的 Local Storage
(leveldb) 里，形如 {"state":{"token":"..."}}。脚本读取本机 token，直调官方接口：
  GET  https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/v2/checkDayTask
        查询「积分福利社」每日任务状态（是否今日已领、累计天数/积分）
  GET  https://agent.teleai.com.cn/superCowork/sapi/user/portal/companyStore/checkTask?type=daily_login
        领取今日积分（幂等：已领则返回空 data）

鉴权：只需一个 X-Token 头（逆向自客户端 request 层的 e1()）。
其余 X-* 头（时间戳/设备号/渠道/版本）与 teleagent 头经服务端实测均为可选，
因此脚本不依赖客户端运行、不依赖设备号、不做任何签名。

客户端升级不失效：接口路径与鉴权头取自客户端自身的常量表，脚本不会写死坐标或控件。

依赖：零第三方依赖（只用标准库 + macOS/Linux 自带的 `strings` 读取 leveldb）。

用法：
  python teleagent_signin.py status  # 仅查状态（调试）
  python teleagent_signin.py auto    # 查状态→未领才领（幂等，日常用这个）
  python teleagent_signin.py claim   # 仅领取（调试，幂等）

输出一行 JSON，人话在 report 字段。任何情况下不打印 token。
"""

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://agent.teleai.com.cn/superCowork/sapi"
PATH_STATUS = "/user/portal/companyStore/v2/checkDayTask"
PATH_CLAIM = "/user/portal/companyStore/checkTask?type=daily_login"
REQUEST_TIMEOUT = 20
CLAIM_VERIFY_DELAY = 1.5


def emit(out):
    print(json.dumps(out, ensure_ascii=False, default=str))


def _user_data_dir():
    """Electron userData 目录（macOS/Linux: ~/.local/share/TeleAgent）。"""
    override = os.environ.get("TELEAGENT_USER_DATA")
    if override:
        return override
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        return os.path.join(base, "TeleAgent")
    return os.path.join(home, ".local", "share", "TeleAgent")


def _active_partitions(user_data):
    """候选凭据目录：当前登录 owner 的分区优先，其余按修改时间倒序兜底。"""
    dirs = []
    owner = os.path.join(user_data, "current-owner.json")
    try:
        with open(owner, "r", encoding="utf-8") as f:
            uid = json.load(f).get("userId")
        if uid:
            dirs.append(os.path.join(user_data, "Partitions", "owner%%3Av1_public_%s" % uid))
    except Exception:
        pass
    part_root = os.path.join(user_data, "Partitions")
    if os.path.isdir(part_root):
        for d in glob.glob(os.path.join(part_root, "*")):
            if d not in dirs:
                dirs.append(d)
    # 渲染进程默认分区（web 端登录态）
    dirs.append(user_data)
    return [d for d in dirs if os.path.isdir(d)]


def _leveldb_text(path):
    """把 leveldb 的 .log/.ldb 抽出可打印文本（不改动原文件）。"""
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


def find_tokens():
    """收集所有候选 token（按分区优先级排序），供逐个试探。"""
    tokens = []
    seen = set()
    user_data = _user_data_dir()
    if not os.path.isdir(user_data):
        return tokens, "未找到 TeleAgent 数据目录（查找位置：%s）。请先启动并登录 TeleAgent 桌面端。" % user_data
    for part in _active_partitions(user_data):
        ls = os.path.join(part, "Local Storage", "leveldb")
        if not os.path.isdir(ls):
            continue
        for m in re.finditer(r'"token"\s*:\s*"([^"]{8,})"', _leveldb_text(ls)):
            tok = m.group(1)
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)
    if not tokens:
        return tokens, ("未在 TeleAgent 本地存储中找到登录 token（查找位置：%s）。"
                        "请先启动并登录 TeleAgent 桌面端。" % user_data)
    return tokens, None


def request(path, token, method="GET"):
    headers = {
        "Content-Type": "application/json",
        "X-Token": token,
        "User-Agent": "TeleAgent/2.7.1",
    }
    req = urllib.request.Request(API_BASE + path, headers=headers, method=method)
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


def fetch_status(token):
    """返回 (http_code, body)。body['data']['daily_task'] 是每日任务。"""
    return request(PATH_STATUS, token)


def _daily_task(body):
    return ((body or {}).get("data") or {}).get("daily_task") or {}


def checkin(claim=False):
    tokens, err = find_tokens()
    if err:
        return 2, {"result": "NO_AUTH", "report": err}

    body = {}
    code = 0
    used = None
    for tok in tokens:
        code, body = fetch_status(tok)
        if code == 200 and body.get("code") == 200:
            used = tok
            break
        if code == -1:
            return 1, {"result": "NETWORK", "report": "网络不可达，签到跳过（%s）" % body.get("error", "")}
    if used is None:
        if code in (401, 403):
            return 1, {"result": "NO_SESSION",
                       "report": "TeleAgent 登录态已失效（HTTP %s），请重新登录桌面端" % code}
        return 1, {"result": "ERROR",
                   "report": "状态接口异常（HTTP %s：%s）" % (code, body.get("message") or body.get("code") or "")}

    task = _daily_task(body)
    if not task:
        return 0, {"result": "INACTIVE", "report": "未开启积分福利社每日任务，跳过"}

    points = task.get("daily_claimable_points")
    days = task.get("total_claim_days")
    total = task.get("total_claimed_points")
    tail = ""
    if total is not None or days is not None:
        tail = "（已领 %s 天，累计 %s 积分）" % (days, total)

    if task.get("claimed_today"):
        return 0, {"result": "ALREADY", "report": "今日已领过每日积分%s" % tail,
                   "daily_points": points, "total_claim_days": days, "total_claimed_points": total}
    if not claim:
        return 0, {"result": "PENDING", "report": "今日可领 %s 积分，尚未领取%s" % (points, tail),
                   "daily_points": points}

    ccode, cbody = request(PATH_CLAIM, used)
    if ccode == -1:
        return 1, {"result": "NETWORK", "report": "领取请求未能送达，下次自动重试"}
    if ccode in (401, 403):
        return 1, {"result": "NO_SESSION", "report": "登录态已失效（HTTP %s），请重新登录桌面端" % ccode}
    if ccode != 200 or cbody.get("code") != 200:
        # 业务幂等：已领过时报错也按 ALREADY 处理
        vcode, vbody = fetch_status(used)
        if vcode == 200 and _daily_task(vbody).get("claimed_today"):
            vt = _daily_task(vbody)
            return 0, {"result": "ALREADY",
                       "report": "今日已领过每日积分（已领 %s 天，累计 %s 积分）" % (
                           vt.get("total_claim_days"), vt.get("total_claimed_points")),
                       "daily_points": points, "total_claim_days": vt.get("total_claim_days"),
                       "total_claimed_points": vt.get("total_claimed_points")}
        return 1, {"result": "ERROR", "report": "领取失败：%s（HTTP %s）" % (
            cbody.get("message") or cbody.get("msg") or json.dumps(cbody, ensure_ascii=False)[:120], ccode)}

    # 领取后必须复核：只有服务端确认 claimed_today 才算成功（无证据不报成功）
    time.sleep(CLAIM_VERIFY_DELAY)
    vcode, vbody = fetch_status(used)
    if vcode != 200:
        return 1, {"result": "ERROR", "report": "领取已发起但复核失败（HTTP %s），请稍后重试确认" % vcode}
    vt = _daily_task(vbody)
    if not vt.get("claimed_today"):
        return 1, {"result": "ERROR", "report": "领取接口返回成功但状态未变为「今日已领」，请稍后复核"}
    return 0, {"result": "CLAIMED",
               "report": "成功领取 %s 积分（已领 %s 天，累计 %s 积分）" % (
                   points, vt.get("total_claim_days"), vt.get("total_claimed_points")),
               "daily_points": points, "total_claim_days": vt.get("total_claim_days"),
               "total_claimed_points": vt.get("total_claimed_points")}


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
