# agent-auto-signin

> WorkBuddy / Trae / MiniMax Code / 百度搭子（DuMate）四款 AI 桌面端的每日免费积分自动领取脚本。
> 纯官方接口实现、幂等可重复执行，支持一键接入任意 Agent 自动化流程。

## 项目简介

四个 AI 桌面端产品每天都有「签到领积分」活动（WorkBuddy 每日 100 分、Trae 每日 200 分、MiniMax Code 每日 400 分、百度搭子每日 500 分），手动签到容易忘、积分会浪费。本项目读取各桌面端**本机已有的登录凭据**，直接调用官方签到接口完成领取——不开 GUI、不模拟点击、不需要客户端保持运行。

> 💡 **项目缘起**：WorkBuddy 端的积分领取方案（凭据定位 + 接口协议）来自 [88lin/workbuddy-auto-signin](https://github.com/88lin/workbuddy-auto-signin) 的启发，在此致谢；Trae、MiniMax Code 与百度搭子端为本项目独立逆向实现。

**About 建议文案（GitHub 仓库描述）：**

```
WorkBuddy / Trae / MiniMax Code / 百度搭子 四端每日签到自动领取脚本：纯接口实现、幂等安全，支持集成到 WorkBuddy 自动化、任意 Agent Skill 或系统 crontab。
```

Topics 建议：`automation` `checkin` `signin` `agent` `workbuddy` `trae` `minimax` `dumate` `python`

## 支持的平台

| 平台 | 每日奖励 | 凭据来源 | 接口 | 脚本 |
|------|---------|---------|------|------|
| WorkBuddy | 100 积分 | 桌面端写出的明文会话文件 | `{endpoint}/v2/billing/meter/daily-checkin` | `workbuddy_signin.py` |
| Trae CN（原 SOLO CN） | 200 积分 | `storage.json` 加密登录态（AES-128-CBC 本地解密） | `api.trae.cn/.../checkin_credits/{status,claim}` | `trae_signin.py` |
| MiniMax Code | 400 积分（连签第 4/7 天 1000） | 新版（≥2026-10-19）：`~/.minimax/auth/<env>/<region>/mcode-public/auth.json` 的 OAuth token（`mmoat_` 前缀）；旧版回退 webview leveldb JWT | `agent.minimax.cn/.../signin/{status,claim}` | `minimax_signin.py` |
| 百度搭子 DuMate | 500 积分 | `auth.json` 加密 Cookie（AES-256-GCM 本地解密） | `console.bce.baidu.com/api/dumate/points/{loginBonusInfo,loginBonus}` | `dumate_signin.py` |

### 客户端版本相关注意事项

- **Trae 已更名为 Trae CN**（2026-10-14）：App 从 `TRAE SOLO CN.app` 变为 `Trae CN.app`，数据目录同步变为
  `~/Library/Application Support/Trae CN/`，`product.json` 的 `packageType` 变为 `TRAE_CN`
  （客户端据此发 `req_source=1`，旧值 2 会被拒）。脚本自动读取 `product.json` 的 `appVersion` / `packageType`，
  客户端升级无需手改。
- **Trae 的 `x-device-id` 必须是 aha 服务端注册 ID**（纯数字，如 `3340774818975139`），
  持久化在 `~/Library/Application Support/Trae CN/ahanet/tt_net_config.config`。
  用 VS Code 的 `@vscode/deviceid`（UUID 形态）会被服务端判定为非客户端请求，
  `claim` 恒返回 `9074 当前参与用户太多`（而 `status` 不校验该头，所以看起来"状态正常"）。
- **MiniMax Code 于 2026-10-19 起切换为 Shared MCode OAuth**：凭据从 webview leveldb 明文 JWT
  改为 `auth.json` 中的不透明 `mmoat_` token，鉴权头改为 `Authorization: Bearer`，域名改为 `agent.minimax.cn`。
  脚本已适配新版，并支持 `minimax_signin.py login`（device flow + PKCE）重新授权。
  ⚠️ refresh token 是**轮换制**，服务端每次刷新都换发新 token、旧 token 立即作废，
  脚本刷新后必须原子写回 `auth.json`，切勿"只调 refresh 不写回"（会导致客户端自登出）。


## 快速开始

```bash
# 四端全部执行（推荐，幂等可重复跑）
python3 scripts/run_all.py

# 只跑某一端
python3 scripts/workbuddy_signin.py auto
python3 scripts/trae_signin.py auto
python3 scripts/minimax_signin.py auto
python3 scripts/dumate_signin.py auto

# 调试子命令
python3 scripts/workbuddy_signin.py status   # 只查状态
python3 scripts/trae_signin.py status
python3 scripts/minimax_signin.py status
python3 scripts/dumate_signin.py status
```

环境要求：Python 3.8+；Trae 解密用到 `openssl` 命令行（macOS/Linux 自带）；百度搭子解密需要 `pip install cryptography`，其余脚本零依赖。

## 输出契约（供 Agent / 程序解析）

每个脚本输出**一行 JSON**，人话结果在 `report` 字段：

```json
{"result": "CLAIMED", "report": "成功领取 100 积分（连续 3 天，累计 300 积分）", ...}
```

| result | 含义 | 是否失败 |
|--------|------|---------|
| `CLAIMED` | 本次领取成功 | 否 |
| `ALREADY` | 今天已领过（接口幂等） | 否 |
| `INACTIVE` | 签到活动未开启 / 今日不可领 | 否 |
| `PENDING` | 今日可领但未领取（status 模式） | 否 |
| `GROWTH` | WorkBuddy 成长中心执行完毕 | 视情况 |
| `NO_SESSION` | 登录态过期，需重新登录桌面端 | 是 |
| `NO_AUTH` | 本机未找到凭据，需先登录客户端 | 是 |
| `NETWORK` / `TIMEOUT` | 网络不可达 / 时间预算耗尽 | 是 |
| `ERROR` / `UNKNOWN` | 接口或脚本异常 | 是 |

退出码：`0` 正常（含 ALREADY）、`1` 硬失败、`2` 用法/凭据错误。**任何情况下脚本都不会打印 token。**

## 常见问题：MiniMax Code 报 `NO_SESSION` / `NO_AUTH`

MiniMax 桌面端自 2026-10-19 起改为 **Shared MCode OAuth** 架构，凭据不再存放在 webview
localStorage 里，而是由主进程写入：

```
~/.minimax/auth/<buildEnv>/<region>/mcode-public/auth.json
```

里面是**不透明 token**（`mmoat_` 前缀，非 JWT），访问签到接口需要
`Authorization: Bearer <token>`，接口域名也从 `agent.minimaxi.com` 迁到了 `agent.minimax.cn`。
本项目的脚本已适配新架构（同时保留旧版 leveldb JWT 作为回退路径）。

如果你的客户端升级较新、脚本仍读不到凭据，可以走 **device flow 重新授权**：

```bash
python3 scripts/minimax_signin.py login
# 打印形如 https://account.minimax.cn/oauth-authorize?user_code=XXXX-XXXX 的链接
# 浏览器打开确认后，凭据自动写入 auth.json，之后 auto 即可正常领取
```

accessToken 有效期仅 1 小时，脚本会用 `refresh_token` 自动续期（**续期时会带跨进程锁并把新
token 写回文件**，与服务端的 refresh token 轮换机制兼容，因此客户端不在线也能长期运行）。

## 如何集成到你的 Agent 产品

详见 **[docs/INTEGRATION.md](docs/INTEGRATION.md)**，三种方式：

1. **WorkBuddy 自动化任务**——配置每日定时 prompt，让 Agent 读脚本输出逐端汇报（开箱即用示例）；
2. **通用 Agent Skill**——把本项目包装成 Claude Code / CodeBuddy / 自研 Agent 的技能，`examples/agent-skill-SKILL.md` 是可直接套用的模板（含调度建议、汇报格式约束、异常处理约定）；
3. **系统级定时任务**——crontab / launchd / Windows Task Scheduler，配合 `run_all.py` 的汇总行做日志或通知。

关键集成约定：各端脚本相互独立、一端失败不影响其余；所有 result 均幂等，重复执行无害；`NO_SESSION`/`NO_AUTH` 时提示用户重新登录对应客户端即可恢复。

## 设计要点

- **只走接口，不模拟 GUI**：GUI 自动化在 macOS 上会触发权限问题和窗口状态异常（踩过的坑已记录在脚本注释里）。
- **凭据零拷贝**：直接读本机桌面端已写出的凭据文件，不要求用户手工导出任何 secret。
- **时间预算机制**（WorkBuddy 端）：受计划任务 ExecutionTimeLimit 启发，自设运行预算确保总能写出结果，不会无声死掉。
- **沙箱友好**：用「试读 1 字节」代替 `os.path.exists()`，绕开部分 Agent 执行沙箱对受保护路径的假阴性。

## 免责声明

本项目仅供学习交流与个人效率自动化使用，请遵守各产品服务条款；接口协议可能随客户端版本变化，失效请提 issue。凭据仅在本地读取，任何情况下不会上传或打印。

## 致谢

- **[88lin/workbuddy-auto-signin](https://github.com/88lin/workbuddy-auto-signin)**：本项目灵感与 WorkBuddy 端方案的直接来源（凭据文件定位、签到/成长中心接口协议均参考该实现，并在此基础上做了沙箱兼容、时间预算、退出码分级等加固）。
- Trae 登录态解密方案与 Trae 论坛社区公开实现交叉验证。
- 百度搭子端协议（Cookie 加密布局、csrftoken 鉴权）为本项目独立逆向自 DuMate 客户端。

## License

[MIT](LICENSE)
