---
name: agent-auto-signin
description: 每日自动领取 WorkBuddy（100 分）/ Trae SOLO CN（200 分）/ MiniMax Code（400 分）/ 百度搭子 DuMate（500 分）四端免费积分。纯接口实现、幂等安全、不模拟 GUI。当用户要求「领免费积分」「自动签到」「检查签到结果」或配置每日定时领取任务时使用。
---

# Agent Auto Signin — 四端每日积分领取

## 执行命令

把 `PY` 和 `S` 换成你的环境实际值：

```bash
PY=python3
S=<本项目路径>/scripts

"$PY" "$S/workbuddy_signin.py" auto   # WorkBuddy：签到 + 成长中心（派Buddy/盲盒/任务奖）
"$PY" "$S/trae_signin.py" auto        # Trae SOLO CN：每日 200 积分
"$PY" "$S/minimax_signin.py" auto     # MiniMax Code：每日 400 积分（连签第 4/7 天 1000）
"$PY" "$S/dumate_signin.py" auto      # 百度搭子 DuMate：每日 500 积分
```

调试子命令：`status`（只查状态，不领取）。

## 输出与处理约定

- 每个脚本输出**一行 JSON**，人话结果在 `report` 字段。
- result 枚举：
  - `CLAIMED` 领取成功 / `ALREADY` 今日已领过（幂等，非失败）/ `INACTIVE` 活动未开启 / `GROWTH` 成长中心完成 → 正常汇报即可。
  - `NO_SESSION` / `NO_AUTH` → 对应端登录态失效：**提醒用户重新登录该桌面端**，无需改任何配置。
  - `NETWORK` / `TIMEOUT` → 下次自动重试，可稍后重跑。
  - `ERROR` / `UNKNOWN` → 带上 JSON 里的 body 字段排查。
- 退出码：0 正常（含 ALREADY）、1 硬失败、2 用法错误。

## 汇报格式（多端时必须遵守)

逐端分列汇报，格式「N. 端名：report 内容」；某端失败也要单独写清 result 与原因，**禁止合并成一句话或只报其中一端**。

## 红线

- **禁止 GUI 模拟点击**（历史上会关掉客户端窗口），只走接口。
- 四端相互独立，一端失败不影响其余端继续执行。
- 任何情况下不要打印脚本返回内容中的 token/JWT 字段。
