# 常见问题

## Q1: `./start.sh` 或 `start.cmd` 提示端口被占用

默认端口 `8790`。可换端口：

**Linux / macOS**:
```bash
PORT=9000 ./start.sh
```

**Windows**:
```cmd
set PORT=9000
start.cmd
```

## Q2: 未检测到 agy CLI

1. 确认已安装 [Antigravity CLI](https://antigravity.google/docs) 且终端能运行 `agy --version`。
2. 未在 PATH 时可显式指定 `AGY_BIN`：

**Linux / macOS**:
```bash
AGY_BIN=/usr/local/bin/agy ./start.sh
# macOS App 内置路径示例：
# AGY_BIN="/Applications/Antigravity.app/Contents/Resources/app/bin/agy" ./start.sh
```

**Windows**:
```cmd
set AGY_BIN=D:\path\to\agy.exe
start.cmd
```

## Q3: 额度不可用 / 超时

- 检查网络与 Google 认证域名；代理见 Q5。
- 账号过期时在界面重新登录。

## Q4: contracts / 模块找不到

在**仓库根目录**执行 `npm install`（npm workspaces monorepo）。

## Q5: 登录连不上 Google / 转圈

`agy` 只认 `HTTPS_PROXY` / `HTTP_PROXY`，不读浏览器系统代理。

- 启动日志出现 `Using the macOS/Linux/Windows system proxy` 表示已自动沿用系统 HTTP 代理（macOS 通过 `scutil --proxy` 探测，Linux 通过 `gsettings` 探测，Windows 通过注册表探测）。
- PAC / 纯 SOCKS 或命令行终端环境需手动导出 HTTP 代理后启动：
  ```bash
  export HTTPS_PROXY=http://127.0.0.1:7890
  export HTTP_PROXY=http://127.0.0.1:7890
  ./start.sh
  ```
- 强制直连：`AGY_STUDIO_PROXY=off ./start.sh`（Windows: `set AGY_STUDIO_PROXY=off`）
- 跳过预检：`AGY_STUDIO_SKIP_NET_CHECK=1 ./start.sh`
- agy 日志：`~/.gemini/antigravity-cli/log/`（Windows: `%USERPROFILE%\.gemini\antigravity-cli\log\`）

## Q6: User location is not supported for the API use

出口 IP 地区不在 Gemini API 支持范围；换节点后重启 WebUI。

## Q7: npm install 报 node-gyp / 编译错误

确认根目录 `.npmrc` 存在（`ignore-scripts=true`），或 `npm install --ignore-scripts`。`./start.sh` 启动时会自动检测并为当前系统（Linux / macOS）校验或重建 `better-sqlite3`。

## Q8: 编辑重问很慢或失败

依赖隐藏 agy 交互执行 `/rewind`，通常 20–60 秒。失败时界面不删记录，可重试或新开会话。
