# 参与贡献

欢迎提 Issue 与 Pull Request。

## 开发环境

- Python 3.8+、Java 17（需要 `keytool` 与 `java`）
- 启动：`cd backend && python3 server.py`

## 提交前检查

- `python3 -m py_compile backend/server.py backend/axml.py`
- 若改动了根目录 `index.html`，请同步更新 `backend/static/index.html`
- 不要提交 `*.keystore`、`.keystore_pass`、`.env`、APK 样本或真实签名证书
- 新增第三方依赖请同步更新 `NOTICE`，并确认其许可证与 Apache-2.0 兼容

## 规范

- 后端保持仅依赖 Python 标准库；前端保持单文件、无构建步骤
- 提交信息用简短英文祈使句，如 `fix: ...` / `feat: ...`
- PR 请说明改动动机、影响范围与验证方式

## 行为准则

本项目仅用于合法授权的应用，不接受任何用于绕过授权、重打包他人应用或其他恶意用途的改动。
