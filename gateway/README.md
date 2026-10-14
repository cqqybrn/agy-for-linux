# gateway（可选）

无 WebUI 时的 HTTP/SSE 网关。破甲规则**不在这里**，与 WebUI 共用仓库根目录 [`rules/global/AGENTS.md`](../rules/global/AGENTS.md)。

```bash
# 在仓库根目录
npm install          # 已含破甲安装
npm run gateway
```

日常用浏览器界面请用根目录 `start.sh`（Linux / macOS）或 `start.cmd`（Windows），不必启动本目录。

> 网关是独立实现，自带账号 / 登录 / 额度逻辑，不依赖 `backend/`。凭据在 Windows / macOS / Linux 上分别走系统凭据存储，Linux 为 `secret-tool` 加文件兜底；无头 Linux 的授权码登录只在 WebUI（`backend/`）里提供。
