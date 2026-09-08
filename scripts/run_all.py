"""agent-auto-signin 统一入口：依次执行三端签到，汇总输出。

用法：
  python run_all.py            # 三端全部执行（auto 模式，幂等）
  python run_all.py workbuddy  # 只跑 WorkBuddy
  python run_all.py trae       # 只跑 Trae
  python run_all.py minimax    # 只跑 MiniMax Code

输出：每个目标一行 JSON（与单脚本输出契约一致），最后多打一行汇总 JSON
（带 "summary": true 标记，方便调用方按行解析时过滤）。

退出码：任一端硬失败（NO_SESSION/NO_AUTH/ERROR/NETWORK/TIMEOUT）返回 1，
ALREADY / CLAIMED / INACTIVE / GROWTH 均视为正常。
"""

import json
import subprocess
import sys

SCRIPTS = {
    "workbuddy": "workbuddy_signin.py",
    "trae": "trae_signin.py",
    "minimax": "minimax_signin.py",
}

# 这些 result 视为"需要人关注"的失败
HARD_FAILURES = {"NO_SESSION", "NO_AUTH", "ERROR", "NETWORK", "TIMEOUT", "UNKNOWN"}
OK_RESULTS = {"CLAIMED", "ALREADY", "INACTIVE", "PENDING", "GROWTH"}


def run_one(name, script, action="auto"):
    try:
        proc = subprocess.run(
            [sys.executable, script, action],
            capture_output=True, timeout=620,
        )
        out = proc.stdout.decode("utf-8", "replace").strip()
        # 单脚本输出是一行 JSON；防御性取最后一行非空内容解析
        line = out.splitlines()[-1] if out else ""
        try:
            data = json.loads(line)
        except Exception:
            data = {"result": "ERROR",
                    "report": "脚本输出无法解析：%s" % (out[:120] or proc.stderr.decode("utf-8", "replace")[:120])}
        return data
    except Exception as e:
        return {"result": "ERROR", "report": "执行异常（%s: %s）" % (type(e).__name__, e)}


def main():
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    targets = sys.argv[1:] or list(SCRIPTS)
    unknown = [t for t in targets if t not in SCRIPTS]
    if unknown:
        print(json.dumps({"result": "ERROR",
                          "report": "未知目标：%s（可用：%s）" % (",".join(unknown), "/".join(SCRIPTS))},
                         ensure_ascii=False))
        return 2

    summary, has_hard_failure = [], False
    for name in targets:
        data = run_one(name, os.path.join(here, SCRIPTS[name]))
        data["agent"] = name
        print(json.dumps(data, ensure_ascii=False, default=str))
        if data.get("result") in HARD_FAILURES:
            has_hard_failure = True
        summary.append({"agent": name, "result": data.get("result"), "report": data.get("report")})

    print(json.dumps({"summary": True,
                      "all_ok": not has_hard_failure,
                      "results": summary}, ensure_ascii=False, default=str))
    return 1 if has_hard_failure else 0


if __name__ == "__main__":
    sys.exit(main())
