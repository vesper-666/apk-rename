# 在线 APK 包名修改器（APK Package Renamer）

上传一个 APK，自动识别原包名，改成你指定的新包名，还可自定义**应用名称**和**应用图标**，随后自动重新打包、对齐、签名并提供下载。

- 前端是**单个 HTML 文件**，无框架、无构建；后端只用 **Python 标准库**（图标重绘可选依赖 Pillow），无数据库
- 直接改写二进制 `AndroidManifest.xml` 的字符串池，不需要 apktool / aapt
- **8 MB 分片 · 4 路并行上传**，带断点续传、单片重试、实时速度与预计时间、取消与过期自动重传
- 多后端探活与故障转移、请求自动重试，降低服务波动带来的失败率
- **液态玻璃 UI**：实时背景采样 + 模糊/提亮 + 边缘折射 + 高光色散；6 套主题色、自定义背景图、玻璃参数可调，全部保存在本机浏览器
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
  server.py                  HTTP 服务：health / chunk / chunk/status / analyze / build
  axml.py                    二进制 AXML 解析、包名与应用名改写
  assets.py                  图标资源定位与按原尺寸重绘
  Dockerfile                 容器构建（JDK 17 + python3-pil）
  static/index.html          后端同源部署时的前端副本（与根目录 index.html 一致）
  tools/uber-apk-signer.jar  签名工具（Apache-2.0，见 NOTICE）
LICENSE / NOTICE / .env.example / SECURITY.md / CONTRIBUTING.md
```

## 快速开始

### Docker（推荐）

```bash
git clone https://github.com/vesper-666/apk-rename.git
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
自定义图标的重绘需要 Pillow（`pip3 install Pillow`）；未安装时会自动降级为「原图直接写回」，功能仍可用，只是各分辨率下清晰度一致。

```bash
cd backend
python3 server.py          # 默认监听 8788 端口
```

## 前端部署

把根目录 `index.html` 传到 Netlify / GitHub Pages / 任意静态托管，然后编辑文件顶部的配置：

```js
window.APK_CONFIG = {
  // 可填字符串，也可填数组：按顺序探活，失败自动切换到下一个后端
  apiBase: ['https://主后端地址', 'https://备用后端地址'],
  author: 'Vesper',
  email: '',
  feedbackUrl: 'https://github.com/vesper-666/apk-rename/issues'
};
```

`apiBase` 留空（或 `[]`）时前端只尝试同源 `/api`，检测不到会给出明确提示。若前后端同源，直接用后端自带的 `backend/static/index.html` 即可，无需配置。

> 部署时请把 `apiBase` 换成你的后端地址，并按需要调整联系邮箱与反馈链接。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` | `8788`（Docker 中 `7860`） | 监听端口 |
| `MAX_BODY_MB` | `400` | 单个 APK 大小上限（MB） |
| `CHUNK_MAX_MB` | `16` | 单个分片上限（MB），前端默认切 8 MB |
| `MAX_CONCURRENT` | `2` | 同时打包的任务数 |
| `MAX_REQUESTS` | `32` | 同时处理的请求上限，超出直接返回 503，防止线程堆积 |
| `READ_TIMEOUT` | `300` | 读请求体的 socket 超时（秒） |
| `CLEAN_INTERVAL` | `60` | 后台清理过期分片/暂存的间隔（秒） |
| `UPLOAD_TTL` | `900` | 上传暂存有效期（秒） |
| `CMD_TIMEOUT` | `600` | 对齐/签名命令超时（秒） |
| `APK_TOOLS_DIR` | `backend/tools` | 工具目录 |
| `APK_UBER_SIGNER` | `tools/uber-apk-signer.jar` | 签名 jar 路径 |
| `APK_KEYSTORE` | `tools/release.keystore` | 运行时生成的证书路径，**勿提交** |
| `APK_KEYSTORE_PASS` | 空 | 证书密码；留空则随机生成并持久化 |
| `APK_KEYSTORE_PASS_FILE` | `tools/.keystore_pass` | 随机密码的保存位置 |
| `APK_KEYSTORE_ALIAS` | `apkrename` | 证书别名 |
| `APK_CORS_ORIGIN` | `*` | 允许的跨域来源；公网部署务必收紧 |

前端的 `CHUNK_SIZE`（默认 8 MB）与 `PARALLEL`（默认 4）在 `index.html` 脚本顶部的常量，可按网关限制调整。

完整示例见 [.env.example](.env.example)。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查。返回版本、运行时长、活跃请求/打包数、缓存数、工具是否就绪与各项限额 |
| GET | `/api/chunk/status?sid=` | 返回已落盘的分片索引与总数，供前端断点续传跳过已传分片 |
| POST | `/api/chunk?sid=&idx=&total=&kind=` | 上传一个分片。`kind=apk` 或 `icon`；`total` 用于完整性校验 |
| POST | `/api/analyze?sid=&name=` | 拼接分片、解析 manifest，返回包信息、`iconCount` 与 `uploadId` |
| POST | `/api/build?package=&name=&upload_id=&label=&icon_sid=` | 返回重新签名后的 APK 二进制 |

`label` 为可选的应用名称（≤60 字符）；`icon_sid` 为可选的图标分片会话 ID。
`/api/build` 额外返回响应头 `X-Icon-Replaced`（实际替换的图标资源数）与 `X-Label-Applied`，前端据此提示结果。

失败时返回 JSON `{"ok":false,"error":"...","code":"expired"}`；`code=expired` 表示暂存过期，前端会自动重传 APK 与图标。分片缺失返回 `code=incomplete`。

## 实现说明

- **改包名**：在 AXML 字符串池末尾追加新包名，改写 `package` 及关联的 authorities / 权限 / sharedUserId，不动既有字符串索引。
- **改应用名**：多数 APK 的 `android:label` 是 `@string/...` 资源引用。这里把该属性的 `typedValue` 从 `TYPE_REFERENCE` 改成 `TYPE_STRING` 并指向新字符串池条目，无需改写 `resources.arsc`。`application`、`activity`、`activity-alias` 上的 label 会一起更新。
- **换图标**：按条目名定位 `res/mipmap-*`、`res/drawable-*` 下的 `ic_launcher*` / `app_icon` 等位图，用 Pillow 按**各条目原尺寸**等比重绘后写回；manifest 中的 icon 引用保持不变，无需解析 `resources.arsc`。自适应图标的前景会缩到 66% 居中以留出安全区。
- **稳定性**：请求并发上限、后台定时清理、启动时清理残留临时文件、SIGTERM 优雅退出；前端多后端探活 + 自动故障转移 + 指数退避重试。

## 已知限制

- 不支持 XAPK / APKS 等分包格式
- 图标替换只覆盖常见命名的**位图**图标；使用 VectorDrawable（XML 矢量图标）、WebP 动图的 APK 可能不生效。自适应图标的 `ic_launcher_background` 底色不改，以免破坏原始配色。解析时若 `iconCount` 为 0，前端会给出提示
- 改应用名会把 application 与各 activity 的 label 统一成同一个名称；原本各页面标题不同的应用会失去区分
- 只改写 manifest 中的 `package` 及关联字段，不处理 `resources.arsc` 中的包名引用、代码内硬编码包名、`google-services.json`、App Links 校验等；复杂应用改包名后可能功能异常
- 改包名后与原应用是两个应用，可共存但数据不互通；因签名不同，覆盖安装同名旧版本会失败

## 安全说明

后端**没有鉴权，也没有速率限制**，请勿直接暴露到公网。建议置于反向代理之后，自行加认证、限流与体积限制，并通过 `APK_CORS_ORIGIN` 只允许自己的前端域名。签名证书与密码在首次启动时自动生成，且已被 `.gitignore` 排除；如需固定证书，请通过环境变量或挂载卷提供，**不要提交进仓库**。

## 开源协议

本项目采用 [Apache License 2.0](LICENSE)。第三方组件及其许可见 [NOTICE](NOTICE)。

致谢：[uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) 提供 zipalign 与 v1/v2/v3 签名。液态玻璃 UI 的设计参考了 Android Compose `backdrop` 的四层光学模型（背景采样 / 模糊 / 边缘折射 / 表面高光），以 Web 技术重新实现。项目最初托管于 ModelScope 创空间。
