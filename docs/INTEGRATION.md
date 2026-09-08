# 集成指南：把 agent-auto-signin 接入你的 Agent 产品

本项目的三个脚本都是**无状态 CLI**：读本机凭据 → 调官方接口 → 输出一行 JSON → 按结果给退出码。这个契约让它可以嵌进任何能跑子进程的宿主：Agent 自动化、Skill 系统、cron、CI 都行。

---

## 通用约定（所有集成方式共守）

1. **逐端独立**：三个脚本互不依赖，一端失败（如登录过期）不影响其余两端。
2. **幂等**：同一端重复执行只返回 `ALREADY`，不会重复计分，调度重叠也无害。
3. **不打印凭据**：任何模式、任何错误路径都不会输出 token/JWT，日志可安全留存。
4. **result → 动作映射**（宿主侧建议的处理策略）：

   | result | 宿主动作 |
   |--------|---------|
   | `CLAIMED` / `ALREADY` / `INACTIVE` / `GROWTH` | 正常汇报结果即可 |
   | `NO_SESSION` / `NO_AUTH` | 提示用户打开对应桌面端重新登录（无需改配置） |
   | `NETWORK` / `TIMEOUT` | 说明"下次自动重试"，可提高调度频率重试 |
   | `ERROR` / `UNKNOWN` | 记录 JSON 里的 `body` 字段提 issue / 排查 |

---

## 方式一：WorkBuddy 自动化任务（推荐给 WorkBuddy 用户）

WorkBuddy 客户端内置「自动化」功能（相当于带 LLM 的定时 cron）。创建一个每日定时任务，prompt 模板：

```
领取 3 个桌面端的每日免费积分，并分别汇报每端结果。
先读 skill：~/.workbuddy/skills/agent-auto-signin/SKILL.md（或直接用绝对路径指向本项目 scripts/）
依次执行：
PY=<你的 python3 路径>
S=<本项目路径>/scripts
"$PY" "$S/workbuddy_signin.py" auto
"$PY" "$S/trae_signin.py" auto
"$PY" "$S/minimax_signin.py" auto
每个脚本输出一行 JSON，人话结果在 report 字段。
汇报要求：分三行逐端汇报，格式「N. 端名：report 内容」；即使某端失败也要单独写清 result 与原因，禁止合并成一句话。
- 接口均幂等，返回 ALREADY 表示今天已领过，正常非失败。
- NO_SESSION/NO_AUTH 表示对应端登录态失效：提醒重新登录该客户端。
- 不要尝试 GUI 模拟点击，三端都只走接口。
```

调度建议：每天 00:01（积分通常 0 点刷新）。在 WorkBuddy 的自动化配置里选「每天」+ 00:01 即可。

---

## 方式二：通用 Agent Skill（Claude Code / CodeBuddy / 自研 Agent）

把本项目包装成 Skill，让 Agent 在对话或定时任务里调用。`examples/agent-skill-SKILL.md` 是现成模板，复制到你的 skill 目录（如 `~/.claude/skills/agent-auto-signin/SKILL.md`），改两处：

- `PY=`：换成宿主可用的 python3；
- `S=`：换成本项目 `scripts/` 的绝对路径。

模板里已包含：调用命令、JSON 输出说明、result 枚举含义、汇报格式约束（逐端分列、失败单独说明）、以及"禁止 GUI 点击"的历史教训。自研 Agent 直接照模板的语义实现即可——核心就是：**subprocess 跑脚本 → 解析最后一行 JSON → 按 result 映射动作**。

---

## 方式三：系统定时任务（不依赖任何 Agent）

### macOS / Linux（crontab）

```bash
crontab -e
# 每天00:01 跑三端，结果追加到日志
1 0 * * * cd /path/to/agent-auto-signin && LANG=en_US.UTF-8 PYTHONUTF8=1 python3 scripts/run_all.py >> signin.log 2>&1
```

`run_all.py` 最后一行是汇总 JSON（`"summary": true, "all_ok": ...`），配 `jq` 可做通知：

```bash
python3 scripts/run_all.py | tail -1 | jq -r '.results[] | "\(.agent): \(.result) \(.report)"'
```

### macOS（launchd）注意

launchd 的 `ExecutionTimeLimit` 默认 10 分钟会强杀进程；WorkBuddy 端脚本内置时间预算（`WORKBUDDY_BUDGET_SECONDS`，默认 420 秒）就是为此设计——预算内必出结果。若调整任务时限，同步调大该环境变量。

### Windows（任务计划程序）

用「每日」触发器指向 `pythonw.exe scripts\run_all.py`，脚本跨平台（凭据路径探测覆盖 Windows/macOS/Linux）。

---

## 凭据路径自定义（可选）

多用户/特殊安装位置时用环境变量覆盖默认探测路径：

| 变量 | 作用 |
|------|------|
| `WORKBUDDY_AUTH_FILE` | 指向 `workbuddy-desktop.info` 会话文件 |
| `TRAE_STORAGE_FILE` | 指向 Trae 的 `storage.json` |
| `MINIMAX_LS_LEVELDB` | 指向 MiniMax 的 `Local Storage/leveldb` 目录 |
| `DUMATE_AUTH_DIR` | 指向 DuMate 数据目录（含 `auth.json` 与 `.cookie-key`） |
| `WORKBUDDY_SIGNIN_LOG` | silent 模式日志路径 |
| `WORKBUDDY_BUDGET_SECONDS` | WorkBuddy 端运行时间预算（默认 420s） |

## 安全须知

> **依赖说明**：百度搭子（DuMate）端需要 `pip install cryptography`（AES-GCM 解密）；WorkBuddy / Trae / MiniMax 三端零第三方依赖（Trae 用系统自带 `openssl`）。

- 脚本只**读取**本机凭据，不写入、不上传、不打印。
- 把日志文件（`signin.log`）加入 `.gitignore`，避免把含积分/账号信息的运行记录提交进仓库。
- 不要在分享屏幕/粘贴日志时带出脚本 `status` 调试模式的原始返回体（其中可能含业务 ID，虽无 token）。
