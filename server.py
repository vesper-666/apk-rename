#!/usr/bin/env python3
"""在线修改 APK 包名服务。

流程：上传 APK -> 解析 AndroidManifest.xml（自动识别原包名）
    -> 用户自定义包名 -> 重写 manifest -> 重打包 -> zipalign -> 签名 -> 提供下载。
"""

import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

import axml

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, 'static')

TOOLS_DIR = os.environ.get('APK_TOOLS_DIR', os.path.join(ROOT, 'tools'))
UBER_SIGNER = os.environ.get('APK_UBER_SIGNER', os.path.join(TOOLS_DIR, 'uber-apk-signer.jar'))
KEYSTORE = os.environ.get('APK_KEYSTORE', os.path.join(TOOLS_DIR, 'release.keystore'))
KS_PASS = os.environ.get('APK_KEYSTORE_PASS', 'REDACTED')
KS_ALIAS = os.environ.get('APK_KEYSTORE_ALIAS', 'vesper')

PORT = int(os.environ.get('PORT', '8788'))
MAX_BODY = int(os.environ.get('MAX_BODY_MB', '400')) * 1024 * 1024
CMD_TIMEOUT = int(os.environ.get('CMD_TIMEOUT', '600'))

PKG_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')
SIG_SUFFIXES = ('.SF', '.RSA', '.DSA', '.EC')

_build_gate = threading.Semaphore(int(os.environ.get('MAX_CONCURRENT', '2')))

# 上传缓存：解析后把文件暂存 15 分钟，打包时凭 uploadId 复用，
# 免得 30+MB 的 APK 在「解析」和「打包」两步里各传一遍。
UPLOAD_TTL = int(os.environ.get('UPLOAD_TTL', '900'))
_upload_store = {}
_upload_lock = threading.Lock()

# 分片上传目录：网关（如魔搭 32MB 限制）不允许一次性传大文件时，
# 前端把 APK 切成 ≤16MB 的分片依次上传，服务端按序拼回完整文件。
CHUNK_DIR = os.path.join(tempfile.gettempdir(), 'apkchunks')


def _valid_sid(sid):
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{8,64}', sid or ''))


def _purge_chunks(now):
    """清理超过 TTL 的分片目录。"""
    if not os.path.isdir(CHUNK_DIR):
        return
    for name in os.listdir(CHUNK_DIR):
        d = os.path.join(CHUNK_DIR, name)
        try:
            if now - os.path.getmtime(d) > UPLOAD_TTL:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def _assemble_chunks(sid):
    """把分片按序拼成完整 APK 临时文件，成功后删除分片目录。"""
    d = os.path.join(CHUNK_DIR, sid)
    if not os.path.isdir(d):
        raise ApiError('上传分片已失效（超时或服务重启），请重新选择文件',
                       410, code='expired')
    parts = sorted(f for f in os.listdir(d) if f.endswith('.part'))
    if not parts:
        shutil.rmtree(d, ignore_errors=True)
        raise ApiError('上传分片为空，请重新选择文件')
    fd, dst = tempfile.mkstemp(suffix='.apk', prefix='apkupload-')
    total = 0
    try:
        with os.fdopen(fd, 'wb') as out:
            for name in parts:
                with open(os.path.join(d, name), 'rb') as fh:
                    while True:
                        block = fh.read(1 << 20)
                        if not block:
                            break
                        out.write(block)
                        total += len(block)
                if total > MAX_BODY:
                    raise ApiError('APK 过大，最大支持 %d MB' % (MAX_BODY // 1024 // 1024), 413)
    except Exception:
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return dst


def _purge_uploads_locked(now):
    for key in [k for k, v in _upload_store.items() if now - v[1] > UPLOAD_TTL]:
        _, path = _upload_store.pop(key)
        try:
            os.unlink(path)
        except OSError:
            pass


def _put_upload(path):
    with _upload_lock:
        _purge_uploads_locked(time.time())
        uid = secrets.token_urlsafe(16)
        _upload_store[uid] = (path, time.time())
    return uid


def _get_upload(uid):
    with _upload_lock:
        ent = _upload_store.get(uid)
        if ent and os.path.exists(ent[0]):
            _upload_store[uid] = (ent[0], time.time())  # 刷新存活时间
            return ent[0]
        if ent:
            _upload_store.pop(uid, None)
        return None


def _pop_upload(uid):
    with _upload_lock:
        ent = _upload_store.pop(uid, None)
    if ent:
        try:
            os.unlink(ent[0])
        except OSError:
            pass


class ApiError(Exception):
    def __init__(self, message, status=400, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


def _is_signature_entry(name):
    if not name.startswith('META-INF/'):
        return False
    upper = name.upper()
    return upper.endswith(SIG_SUFFIXES) or upper.endswith('MANIFEST.MF')


def _has_v2_signature(path):
    """检测 APK Signing Block（v2/v3 签名没有 META-INF 条目）。"""
    size = os.path.getsize(path)
    try:
        with open(path, 'rb') as f:
            window = min(size, 22 + 65535)  # EOCD = 22 + 最多 65535 字节注释
            f.seek(size - window)
            tail = f.read()
            i = tail.rfind(b'PK\x05\x06')
            if i < 0 or i + 20 > len(tail):
                return False
            cd_off = struct.unpack_from('<I', tail, i + 16)[0]
            if cd_off == 0xFFFFFFFF or cd_off < 16:
                return b'APK Sig Block 42' in tail
            f.seek(cd_off - 16)
            return f.read(16) == b'APK Sig Block 42'
    except OSError:
        return False


def rewrite_zip(src, dst, manifest_bytes):
    """按原顺序重写 APK，替换 manifest 并剔除旧签名条目。"""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, 'w') as zout:
        for zi in zin.infolist():
            if _is_signature_entry(zi.filename):
                continue
            data = manifest_bytes if zi.filename == 'AndroidManifest.xml' else zin.read(zi)
            ni = zipfile.ZipInfo(zi.filename, date_time=zi.date_time)
            ni.compress_type = zi.compress_type
            ni.external_attr = zi.external_attr
            ni.internal_attr = zi.internal_attr
            ni.create_system = zi.create_system
            zout.writestr(ni, data)


def _run(cmd):
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=CMD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise ApiError('处理超时，请换一个更小的 APK', 504)
    except FileNotFoundError:
        raise ApiError('服务端缺少 %s，请联系开发者' % os.path.basename(cmd[0]), 500)
    return proc


def analyze(path):
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if 'AndroidManifest.xml' not in names:
                raise ApiError('这不像一个 APK：缺少 AndroidManifest.xml')
            raw = z.read('AndroidManifest.xml')
    except zipfile.BadZipFile:
        raise ApiError('文件不是有效的 ZIP/APK，请确认上传的是 .apk 文件')

    try:
        info = axml.read_info(raw)
    except axml.AxmlError as exc:
        raise ApiError('无法解析 AndroidManifest.xml：%s' % exc)

    if not info['package']:
        raise ApiError('未能从 manifest 中识别出包名')

    signed = _has_v2_signature(path) or any(_is_signature_entry(n) for n in names)
    return {
        'package': info['package'],
        'versionName': info['versionName'],
        'versionCode': info['versionCode'],
        'label': info['label'],
        'minSdk': info['minSdk'],
        'targetSdk': info['targetSdk'],
        'signed': signed,
        'entries': len(names),
        'size': os.path.getsize(path),
    }


def build(src, new_pkg, workdir):
    if not PKG_RE.match(new_pkg):
        raise ApiError('包名格式不正确：需形如 com.example.app（字母开头，至少两段）')

    with zipfile.ZipFile(src) as z:
        try:
            raw = z.read('AndroidManifest.xml')
        except KeyError:
            raise ApiError('APK 中没有 AndroidManifest.xml')

    try:
        patched = axml.set_package(raw, new_pkg)
    except axml.AxmlError as exc:
        raise ApiError('改写包名失败：%s' % exc)

    packed = os.path.join(workdir, 'repacked.apk')
    signed = os.path.join(workdir, 'signed.apk')
    rewrite_zip(src, packed, patched)

    # uber-apk-signer：zipalign(4 字节) + v1/v2/v3 签名 + 签名校验，一步完成
    proc = _run([
        'java', '-jar', UBER_SIGNER,
        '--apks', packed,
        '--ks', KEYSTORE, '--ksAlias', KS_ALIAS,
        '--ksPass', KS_PASS, '--ksKeyPass', KS_PASS,
        '--out', workdir,
    ])
    produced = [os.path.join(workdir, n) for n in os.listdir(workdir)
                if n != 'repacked.apk' and n.endswith('.apk') and 'igned' in n]
    if proc.returncode != 0 or not produced:
        raise ApiError('对齐/签名失败：%s' % proc.stdout.decode('utf-8', 'replace')[-500:], 500)
    os.replace(produced[0], signed)

    return signed


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = CMD_TIMEOUT
    server_version = 'APKRepack/1.0'

    def log_message(self, fmt, *args):
        sys.stderr.write('[%s] %s\n' % (self.log_date_time_string(), fmt % args))

    # ---------- helpers ----------
    def _cors(self):
        """允许静态托管域名跨域调用 API（页面与后端不同源时）。"""
        self.send_header('Access-Control-Allow-Origin', '*')

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self._cors()
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype, download_name=None):
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(size))
        self._cors()
        if download_name:
            self.send_header(
                'Content-Disposition',
                "attachment; filename*=UTF-8''" + self._url_quote(download_name),
            )
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        with open(path, 'rb') as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)

    @staticmethod
    def _url_quote(name):
        return ''.join(
            '%%%02X' % b for b in name.encode('utf-8')
        )

    def _read_body_to_file(self, suffix):
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            raise ApiError('请求体为空，请先上传 APK')
        if length > MAX_BODY:
            raise ApiError('APK 过大，最大支持 %d MB' % (MAX_BODY // 1024 // 1024), 413)

        fd, path = tempfile.mkstemp(suffix=suffix, prefix='apkupload-')
        remaining = length
        with os.fdopen(fd, 'wb') as out:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
        if remaining > 0:
            os.unlink(path)
            raise ApiError('上传中断，请重试', 400)
        return path

    def _fail(self, exc):
        if isinstance(exc, ApiError):
            body = {'ok': False, 'error': str(exc)}
            if exc.code:
                body['code'] = exc.code
            self._send_json(body, exc.status)
        else:
            self.log_message('unhandled error: %r', exc)
            self._send_json({'ok': False, 'error': '服务器内部错误'}, 500)

    # ---------- routes ----------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ('/', '/index.html'):
            self._send_file(os.path.join(STATIC, 'index.html'), 'text/html; charset=utf-8')
            return
        if path == '/api/health':
            self._send_json({'ok': True})
            return
        if path.startswith('/favicon.ico'):
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._send_json({'ok': False, 'error': 'not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        upload = None       # 本次请求自己落盘的临时文件（finally 负责删）
        cached = None       # 复用的暂存文件（失败时保留，供重试）
        workdir = None
        try:
            if path == '/api/chunk':
                qs = parse_qs(urlparse(self.path).query)
                sid = (qs.get('sid') or [''])[0]
                idx = (qs.get('idx') or [''])[0]
                if not _valid_sid(sid) or not idx.isdigit():
                    raise ApiError('分片参数错误')
                with _upload_lock:
                    _purge_chunks(time.time())
                os.makedirs(os.path.join(CHUNK_DIR, sid), exist_ok=True)
                part = self._read_body_to_file('.part')
                dst = os.path.join(CHUNK_DIR, sid, '%010d.part' % int(idx))
                os.replace(part, dst)
                self._send_json({'ok': True})
                return

            if path == '/api/analyze':
                qs = parse_qs(urlparse(self.path).query)
                sid = (qs.get('sid') or [''])[0]
                if sid:
                    if not _valid_sid(sid):
                        raise ApiError('分片参数错误')
                    upload = _assemble_chunks(sid)
                else:
                    upload = self._read_body_to_file('.apk')
                info = analyze(upload)
                # 解析成功后暂存文件，打包时凭 uploadId 复用，免二次上传
                info['uploadId'] = _put_upload(upload)
                upload = None  # 已入库，交给 TTL 清理，finally 不再删
                info['ok'] = True
                self._send_json(info)
                return

            if path == '/api/build':
                qs = parse_qs(urlparse(self.path).query)
                pkg = (qs.get('package') or [''])[0]
                name = (qs.get('name') or [''])[0]
                uid = unquote((qs.get('upload_id') or [''])[0])
                pkg = unquote(pkg).strip()
                if not pkg:
                    raise ApiError('缺少 package 参数')

                cached = _get_upload(uid) if uid else None
                if cached:
                    upload = cached
                elif uid:
                    # 带了 uploadId 但已过期/被清理：让前端带文件重传
                    raise ApiError('上传的文件已过期（超过 %d 分钟），请重新选择文件' % (UPLOAD_TTL // 60),
                                   410, code='expired')
                else:
                    upload = self._read_body_to_file('.apk')

                workdir = tempfile.mkdtemp(prefix='apkbuild-')
                if not _build_gate.acquire(timeout=120):
                    raise ApiError('当前排队任务较多，请稍后重试', 503)
                try:
                    signed = build(upload, pkg, workdir)
                finally:
                    _build_gate.release()
                if cached:
                    _pop_upload(uid)  # 打包成功才消费暂存
                    upload = None
                stem = os.path.splitext(os.path.basename(name))[0] or 'app'
                self._send_file(
                    signed,
                    'application/vnd.android.package-archive',
                    '%s-%s.apk' % (re.sub(r'[^A-Za-z0-9._-]', '_', stem)[:40], pkg),
                )
                return

            self._send_json({'ok': False, 'error': 'not found'}, 404)
        except ApiError as exc:
            self._fail(exc)
        except BrokenPipeError:
            pass
        except Exception as exc:  # noqa: BLE001
            self._fail(exc)
        finally:
            # 只删自己落盘的临时文件；暂存文件保留，打包失败后还能重试
            if upload and upload != cached and os.path.exists(upload):
                try:
                    os.unlink(upload)
                except OSError:
                    pass
            if workdir:
                shutil.rmtree(workdir, ignore_errors=True)


UBER_SIGNER_URL = ('https://github.com/patrickfav/uber-apk-signer/releases/'
                   'download/v1.3.0/uber-apk-signer-1.3.0.jar')


def _ensure_tools():
    """首次运行自动准备签名工具与证书；已存在则跳过。"""
    os.makedirs(TOOLS_DIR, exist_ok=True)

    if not os.path.exists(UBER_SIGNER):
        sys.stderr.write('首次运行：正在下载 uber-apk-signer 到 %s ...\n' % UBER_SIGNER)
        from urllib.request import urlopen
        try:
            with urlopen(UBER_SIGNER_URL, timeout=180) as resp, \
                    open(UBER_SIGNER + '.part', 'wb') as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
            os.replace(UBER_SIGNER + '.part', UBER_SIGNER)
        except OSError as exc:
            sys.stderr.write(
                '下载失败（%s）。\n请手动从 %s 下载 jar，'
                '放到 %s，或用环境变量 APK_UBER_SIGNER 指定路径。\n'
                % (exc, UBER_SIGNER_URL, TOOLS_DIR))
            sys.exit(1)

    if not os.path.exists(KEYSTORE):
        sys.stderr.write('首次运行：正在生成本地签名证书 %s ...\n' % KEYSTORE)
        proc = subprocess.run(
            ['keytool', '-genkeypair', '-keystore', KEYSTORE, '-alias', KS_ALIAS,
             '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
             '-storepass', KS_PASS, '-keypass', KS_PASS,
             '-dname', 'CN=APK Rename'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            sys.stderr.write('生成证书失败：%s\n请安装 JDK（提供 keytool 命令），'
                             '或自行生成证书后用环境变量 APK_KEYSTORE 指定。\n'
                             % proc.stdout.decode('utf-8', 'replace')[-300:])
            sys.exit(1)
    sys.stderr.write('提示：%s 仅是本机生成的测试证书，请勿提交到 git（.gitignore 已排除）。\n'
                     % os.path.basename(KEYSTORE))


def main():
    _ensure_tools()

    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.daemon_threads = True
    sys.stderr.write('listening on 0.0.0.0:%d\n' % PORT)
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
