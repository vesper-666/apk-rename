# 在线 APK 包名修改器（APK Package Renamer）

上传一个 APK，自动识别原包名，改成你指定的新包名，随后自动重新打包、对齐、签名并提供下载。

- 前端是**单个 HTML 文件**；后端只用 **Python 标准库**，无框架、无数据库
- 直接改写二进制 `AndroidManifest.xml` 的字符串池，不需要 apktool / aapt
- 16 MB 分片上传、上传暂存复用、进度与预计时间、取消与过期自动重传
- 修改历史只存在你自己的浏览器（localStorage），不上传服务器

> ⚠️ **使用限制与免责声明**
> 本工具仅用于**你自己拥有合法授权**的 Android 应用（自有应用、内部测试包等）。
> 请勿用于重打包、篡改或分发他人应用，或绕过授权校验、植入恶意代码。
> 修改包名后 APK 会**使用新证书重新签名**，与原应用签名不同，无法覆盖安装。
> 本项目**不提供公开在线服务**，请自行部署；作者不对滥用行为及其后果负责。

## 目录结构

```
index.html                    前端（可直接静态托管）
backend/
  server.py                  HTTP 服务：/api/health /chunk /analyze /build
  axml.py                    二进制 AXML 解析与包名改写
  Dockerfile                 容器构建
  static/index.html          后端同源部署时的前端副本（与根目录 index.html 一致）
  tools/uber-apk-signer.jar  签名工具（Apache-2.0，见 NOTICE）
LICENSE / NOTICE / .env.example / SECURITY.md / CONTRIBUTING.md
```

## 快速开始

### Docker（推荐）

```bash
git clone https://github.com/Vesper123/apk-rename.git
cd apk-rename
docker build -f backend/Dockerfile -t apk-rename backend
docker run --rm -p 7860:7860 \
  -e APK_CORS_ORIGIN=https://你的前端域名 \
  apk-rename
```

浏览器打开 `http://localhost:7860` 即可（后端会同源托管前端页面）。
首次启动会用 `keytool` 生成签名证书，**证书和密码不会进入镜像或仓库**。

### 本地运行

需要 Python 3.8+、Java 17（提供 `keytool` 与 `java`）。签名 jar 已随仓库提供。

```bash
cd backend
python3 server.py          # 默认监听 8788 端口
```

## 前端部署

把根目录 `index.html` 传到 Netlify / GitHub Pages / 任意静态托管，然后编辑文件顶部的配置：

```js
window.APK_CONFIG = {
  apiBase: 'https://你的后端地址',   // 不含结尾斜杠
  author: 'Vesper',
  email: '',
  feedbackUrl: 'https://github.com/Vesper123/apk-rename/issues'
};
```

`apiBase` 留空时前端会尝试同源 `/api`，检测不到会给出明确提示。若前后端同源，直接用后端自带的 `backend/static/index.html` 即可，无需配置。

> 部署前请把上面示例中的仓库地址、联系信息替换成你自己的。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `8788`（Docker 中 `7860`） | 监听端口 |
| `MAX_BODY_MB` | `400` | 单个 APK 大小上限（MB） |
| `MAX_CONCURRENT` | `2` | 同时打包的任务数 |
| `UPLOAD_TTL` | `900` | 上传暂存有效期（秒） |
| `CMD_TIMEOUT` | `600` | 对齐/签名命令超时（秒） |
| `APK_TOOLS_DIR` | `backend/tools` | 工具目录 |
| `APK_UBER_SIGNER` | `tools/uber-apk-signer.jar` | 签名 jar 路径 |
| `APK_KEYSTORE` | `tools/release.keystore` | 运行时生成的证书路径，**勿提交** |
| `APK_KEYSTORE_PASS` | 空 | 证书密码；留空则随机生成并持久化 |
| `APK_KEYSTORE_PASS_FILE` | `tools/.keystore_pass` | 随机密码的保存位置 |
| `APK_KEYSTORE_ALIAS` | `apkrename` | 证书别名 |
| `APK_CORS_ORIGIN` | `*` | 允许的跨域来源；公网部署务必收紧 |

完整示例见 [.env.example](.env.example)。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查，返回 `{"ok":true}` |
| POST | `/api/chunk?sid=&idx=` | 上传 16 MB 分片 |
| POST | `/api/analyze?sid=&name=` | 拼接分片、解析 manifest，返回包信息与 `uploadId` |
| POST | `/api/build?package=&name=&upload_id=` | 返回重新签名后的 APK 二进制 |

失败时返回 JSON `{"ok":false,"error":"...","code":"expired"}`；`code=expired` 表示暂存过期，前端会自动重传。

## 已知限制

- 不支持 XAPK / APKS 等分包格式
- 只改写 manifest 中的 `package` 及关联字段，不处理 `resources.arsc` 中的包名引用、代码内硬编码包名、`google-services.json`、App Links 校验等；复杂应用改包名后可能功能异常
- 应用名若来自资源引用则无法内联读出
- 改包名后与原应用是两个应用，可共存但数据不互通；因签名不同，覆盖安装同名旧版本会失败

## 安全说明

后端**没有鉴权，也没有速率限制**，请勿直接暴露到公网。建议置于反向代理之后，自行加认证、限流与体积限制，并通过 `APK_CORS_ORIGIN` 只允许自己的前端域名。签名证书与密码在首次启动时自动生成，且已被 `.gitignore` 排除；如需固定证书，请通过环境变量或挂载卷提供，**不要提交进仓库**。

## 开源协议

本项目采用 [Apache License 2.0](LICENSE)。第三方组件及其许可见 [NOTICE](NOTICE)。

致谢：[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) 提供 zipalign 与 v1/v2/v3 签名。项目最初托管于 ModelScope 创空间。
