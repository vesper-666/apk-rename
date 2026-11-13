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
import signal
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

import assets
import axml

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, 'static')

TOOLS_DIR = os.environ.get('APK_TOOLS_DIR', os.path.join(ROOT, 'tools'))
UBER_SIGNER = os.environ.get('APK_UBER_SIGNER', os.path.join(TOOLS_DIR, 'uber-apk-signer.jar'))
# 签名证书属于私钥，绝不随源码分发：首次启动自动生成到运行时目录，
# 密码随机生成并保存在同目录的 .keystore_pass（已被 .gitignore 排除）。
KEYSTORE = os.environ.get('APK_KEYSTORE', os.path.join(TOOLS_DIR, 'release.keystore'))
KS_PASS = os.environ.get('APK_KEYSTORE_PASS', '')
KS_ALIAS = os.environ.get('APK_KEYSTORE_ALIAS', 'apkrename')
KS_PASS_FILE = os.environ.get('APK_KEYSTORE_PASS_FILE',
                             os.path.join(TOOLS_DIR, '.keystore_pass'))
CORS_ORIGIN = os.environ.get('APK_CORS_ORIGIN', '*')

PORT = int(os.environ.get('PORT', '8788'))
MAX_BODY = int(os.environ.get('MAX_BODY_MB', '400')) * 1024 * 1024
CMD_TIMEOUT = int(os.environ.get('CMD_TIMEOUT', '600'))
# 单个分片上限：网关通常限制 32MB，前端默认 8MB，这里留一点余量
CHUNK_MAX = int(os.environ.get('CHUNK_MAX_MB', '16')) * 1024 * 1024
# 同时在处理的请求上限：ThreadingHTTPServer 默认无限开线程，
# 大文件上传遇到网络抖动时会瞬间堆满线程导致服务僵死。
MAX_REQUESTS = int(os.environ.get('MAX_REQUESTS', '32'))
CLEAN_INTERVAL = int(os.environ.get('CLEAN_INTERVAL', '60'))
START_TIME = time.time()

PKG_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')
SIG_SUFFIXES = ('.SF', '.RSA', '.DSA', '.EC')

_build_gate = threading.Semaphore(int(os.environ.get('MAX_CONCURRENT', '2')))
_req_gate = threading.BoundedSemaphore(MAX_REQUESTS)
_req_stats = {'active': 0, 'peak': 0, 'total': 0, 'builds': 0}
_req_lock = threading.Lock()

# 上传缓存：解析后把文件暂存 15 分钟，打包时凭 uploadId 复用，
# 免得 30+MB 的 APK 在「解析」和「打包」两步里各传一遍。
UPLOAD_TTL = int(os.environ.get('UPLOAD_TTL', '900'))
_upload_store = {}
_upload_lock = threading.Lock()

# 分片上传目录：网关（如魔搭 32MB 限制）不允许一次性传大文件时，
# 前端把 APK 切成 ≤16MB 的分片依次上传，服务端按序拼回完整文件。
CHUNK_DIR = os.path.join(tempfile.gettempdir(), 'apkchunks')
_TMP_PREFIX = 'apkupload-'


def _valid_sid(sid):
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{8,64}', sid or ''))


def _chunk_dir(sid):
    return os.path.join(CHUNK_DIR, sid)


def _write_chunk_meta(d, total, kind):
    """记录总分片数与用途，供完整性校验与断点续传。

    并行上传时多个分片会同时到达，只写一次，避免并发写产生半截 JSON。
    """
    if not total:
        return
    p = os.path.join(d, 'meta.json')
    if os.path.exists(p):
        return
    try:
        with open(p + '.tmp', 'w', encoding='utf-8') as fh:
            json.dump({'total': int(total), 'kind': kind}, fh)
        os.replace(p + '.tmp', p)
    except OSError:
        pass


def _chunk_meta(d):
    try:
        with open(os.path.join(d, 'meta.json'), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _received_indices(sid):
    """已成功落盘的分片索引，前端据此跳过已传分片实现断点续传。"""
    d = _chunk_dir(sid)
    if not os.path.isdir(d):
        return []
    out = []
    for name in os.listdir(d):
        m = re.fullmatch(r'(\d{10})\.part', name)
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def _purge_chunks(now):
    """清理超过 TTL 的分片目录。由后台线程低频调用，不放在每个分片请求里。"""
    if not os.path.isdir(CHUNK_DIR):
        return
    for name in os.listdir(CHUNK_DIR):
        d = os.path.join(CHUNK_DIR, name)
        try:
            if now - os.path.getmtime(d) > UPLOAD_TTL:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass


def _cleanup_stale_files():
    """清理残留临时文件，避免服务重启后旧文件一直占着磁盘。"""
    tmp = tempfile.gettempdir()
    try:
        names = os.listdir(tmp)
    except OSError:
        return
    for name in names:
        if not (name.startswith(_TMP_PREFIX) or name.startswith('apkbuild-')):
            continue
        p = os.path.join(tmp, name)
        try:
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
        except OSError:
            pass


def _assemble_chunks(sid):
    """按序拼回完整文件，校验分片齐全后删除分片目录。"""
    d = _chunk_dir(sid)
    if not os.path.isdir(d):
        raise ApiError('上传分片已失效（超时或服务重启），请重新选择文件',
                       410, code='expired')
    indices = _received_indices(sid)
    if not indices:
        shutil.rmtree(d, ignore_errors=True)
        raise ApiError('上传分片为空，请重新选择文件')

    expected = _chunk_meta(d).get('total')
    if expected:
        missing = [i for i in range(int(expected)) if i not in indices]
        if missing:
            raise ApiError('分片不完整（缺少第 %s 片），请重新上传'
                           % ','.join(str(i) for i in missing[:5]),
                           400, code='incomplete')
    elif indices != list(range(indices[-1] + 1)):
        raise ApiError('分片不连续，请重新上传', 400, code='incomplete')

    fd, dst = tempfile.mkstemp(suffix='.apk', prefix=_TMP_PREFIX)
    total = 0
    try:
        with os.fdopen(fd, 'wb') as out:
            for i in indices:
                with open(os.path.join(d, '%010d.part' % i), 'rb') as fh:
                    while True:
                        block = fh.read(1 << 20)
                        if not block:
                            break
                        out.write(block)
                        total += len(block)
                if total > MAX_BODY:
                    raise ApiError('文件过大，最大支持 %d MB'
                                   % (MAX_BODY // 1024 // 1024), 413)
    except Exception:
        try:
            os.unlink(dst)
        except OSError:
            pass
        raise
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


def health_info():
    """给前端探活与运维排障用：能一眼看出排队、缓存、工具是否就绪。"""
    with _req_lock:
        stats = dict(_req_stats)
    with _upload_lock:
        uploads = len(_upload_store)
    return {
        'ok': True,
        'version': '2.0',
        'uptime': int(time.time() - START_TIME),
        'activeRequests': stats['active'],
        'peakRequests': stats['peak'],
        'totalRequests': stats['total'],
        'activeBuilds': stats['builds'],
        'cachedUploads': uploads,
        'toolsReady': os.path.exists(UBER_SIGNER) and os.path.exists(KEYSTORE),
        'limits': {
            'maxBodyMB': MAX_BODY // 1024 // 1024,
            'maxRequests': MAX_REQUESTS,
            'maxConcurrent': int(os.environ.get('MAX_CONCURRENT', '2')),
            'uploadTtlSec': UPLOAD_TTL,
        },
    }


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


def rewrite_zip(src, dst, manifest_bytes, icon_map=None):
    """按原顺序重写 APK：替换 manifest、替换图标位图、剔除旧签名条目。"""
    icon_map = icon_map or {}
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, 'w') as zout:
        for zi in zin.infolist():
            if _is_signature_entry(zi.filename):
                continue
            if zi.filename == 'AndroidManifest.xml':
                data = manifest_bytes
            elif zi.filename in icon_map:
                data = icon_map[zi.filename]
            else:
                data = zin.read(zi)
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
        'iconCount': len(assets.find_icon_entries(names)),
        'size': os.path.getsize(path),
    }


def build(src, new_pkg, workdir, label='', icon_data=None):
    """重写 manifest（包名 + 应用名）、替换图标，再对齐并签名。"""
    if not PKG_RE.match(new_pkg):
        raise ApiError('包名格式不正确：需形如 com.example.app（字母开头，至少两段）')

    with zipfile.ZipFile(src) as z:
        try:
            raw = z.read('AndroidManifest.xml')
        except KeyError:
            raise ApiError('APK 中没有 AndroidManifest.xml')
        names = z.namelist()

    try:
        patched = axml.set_package(raw, new_pkg)
        if label:
            patched = axml.set_label(patched, label)
    except axml.AxmlError as exc:
        raise ApiError('改写 manifest 失败：%s' % exc)

    icon_map = {}
    if icon_data:
        try:
            with zipfile.ZipFile(src) as z:
                icon_map = assets.build_icon_map(names, z.read, icon_data)
        except ValueError as exc:
            raise ApiError(str(exc))

    packed = os.path.join(workdir, 'repacked.apk')
    signed = os.path.join(workdir, 'signed.apk')
    rewrite_zip(src, packed, patched, icon_map)

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

    return signed, len(icon_map)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    # 读请求体的 socket 超时：不宜设成 CMD_TIMEOUT，否则慢连接会长期占线程
    timeout = int(os.environ.get('READ_TIMEOUT', '300'))
    server_version = 'APKRepack/2.0'

    def log_message(self, fmt, *args):
        sys.stderr.write('[%s] %s\n' % (self.log_date_time_string(), fmt % args))

    # ---------- helpers ----------
    def _cors(self):
        """允许静态托管域名跨域调用 API（页面与后端不同源时）。

        公网部署请通过 APK_CORS_ORIGIN 指定前端域名，不要保持通配。"""
        self.send_header('Access-Control-Allow-Origin', CORS_ORIGIN)
        # 允许前端读取打包结果里的图标/应用名状态与下载文件名
        self.send_header('Access-Control-Expose-Headers',
                         'Content-Disposition, X-Icon-Replaced, X-Label-Applied')
        if CORS_ORIGIN != '*':
            self.send_header('Vary', 'Origin')

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

    def _send_file(self, path, ctype, download_name=None, extra_headers=None):
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
        for key, value in (extra_headers or {}).items():
            self.send_header(key, str(value))
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

    def _read_body_to_file(self, suffix, max_size=None):
        length = int(self.headers.get('Content-Length') or 0)
        if length <= 0:
            raise ApiError('请求体为空，请先上传文件')
        limit = min(MAX_BODY, max_size or MAX_BODY)
        if length > limit:
            raise ApiError('请求体过大，最大支持 %d MB' % (limit // 1024 // 1024), 413)

        fd, path = tempfile.mkstemp(suffix=suffix, prefix=_TMP_PREFIX)
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
        u = urlparse(self.path)
        path = u.path
        if path in ('/', '/index.html'):
            self._send_file(os.path.join(STATIC, 'index.html'), 'text/html; charset=utf-8')
            return
        if path == '/api/health':
            self._send_json(health_info())
            return
        if path == '/api/chunk/status':
            # 断点续传：返回该 sid 已落盘的分片，前端只补传缺失的
            sid = (parse_qs(u.query).get('sid') or [''])[0]
            if not _valid_sid(sid):
                self._send_json({'ok': False, 'error': '分片参数错误'}, 400)
                return
            d = _chunk_dir(sid)
            meta = _chunk_meta(d) if os.path.isdir(d) else {}
            self._send_json({
                'ok': True,
                'received': _received_indices(sid),
                'total': meta.get('total'),
                'kind': meta.get('kind'),
            })
            return
        if path.startswith('/favicon.ico'):
            self.send_response(204)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._send_json({'ok': False, 'error': 'not found'}, 404)

    def do_POST(self):
        # 名额用尽直接回 503，不让 ThreadingHTTPServer 无限开线程
        if not _req_gate.acquire(blocking=False):
            self._send_json({'ok': False, 'error': '服务繁忙，请稍后重试',
                             'code': 'busy'}, 503)
            return
        with _req_lock:
            _req_stats['active'] += 1
            _req_stats['total'] += 1
            _req_stats['peak'] = max(_req_stats['peak'], _req_stats['active'])

        u = urlparse(self.path)
        path = u.path
        upload = None       # 本次请求自己落盘的临时文件（finally 负责删）
        cached = None       # 复用的暂存文件（失败时保留，供重试）
        workdir = None
        icon_tmp = None
        try:
            if path == '/api/chunk':
                qs = parse_qs(u.query)
                sid = (qs.get('sid') or [''])[0]
                idx = (qs.get('idx') or [''])[0]
                total = (qs.get('total') or [''])[0]
                kind = (qs.get('kind') or ['apk'])[0]
                if not _valid_sid(sid) or not idx.isdigit():
                    raise ApiError('分片参数错误')
                if total and (not total.isdigit() or int(total) > 10000):
                    raise ApiError('分片总数参数错误')
                if kind not in ('apk', 'icon'):
                    raise ApiError('分片类型错误')
                limit = CHUNK_MAX if kind == 'apk' else 8 * 1024 * 1024
                d = _chunk_dir(sid)
                os.makedirs(d, exist_ok=True)
                part = self._read_body_to_file('.part', max_size=limit)
                os.replace(part, os.path.join(d, '%010d.part' % int(idx)))
                _write_chunk_meta(d, total, kind)
                try:
                    os.utime(d, None)  # 刷新 TTL，续传期间不被清理
                except OSError:
                    pass
                self._send_json({'ok': True, 'idx': int(idx)})
                return

            if path == '/api/analyze':
                qs = parse_qs(u.query)
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
                qs = parse_qs(u.query)
                pkg = unquote((qs.get('package') or [''])[0]).strip()
                name = (qs.get('name') or [''])[0]
                uid = unquote((qs.get('upload_id') or [''])[0])
                label = (qs.get('label') or [''])[0].strip()
                icon_sid = (qs.get('icon_sid') or [''])[0]
                if not pkg:
                    raise ApiError('缺少 package 参数')
                if len(label) > 60:
                    raise ApiError('应用名称过长（最多 60 个字符）')
                if any(ord(c) < 32 for c in label):
                    raise ApiError('应用名称含有非法控制字符')

                icon_data = None
                if icon_sid:
                    if not _valid_sid(icon_sid):
                        raise ApiError('图标分片参数错误')
                    icon_tmp = _assemble_chunks(icon_sid)
                    with open(icon_tmp, 'rb') as fh:
                        icon_data = fh.read()
                    if not assets.is_image(icon_data):
                        raise ApiError('图标不是有效的 PNG / JPEG / WEBP 图片')

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
                with _req_lock:
                    _req_stats['builds'] += 1
                try:
                    if not _build_gate.acquire(timeout=120):
                        raise ApiError('当前排队任务较多，请稍后重试', 503)
                    try:
                        signed, icon_replaced = build(upload, pkg, workdir, label, icon_data)
                    finally:
                        _build_gate.release()
                finally:
                    with _req_lock:
                        _req_stats['builds'] -= 1
                if cached:
                    _pop_upload(uid)  # 打包成功才消费暂存
                    upload = None
                stem = os.path.splitext(os.path.basename(name))[0] or 'app'
                self._send_file(
                    signed,
                    'application/vnd.android.package-archive',
                    '%s-%s.apk' % (re.sub(r'[^A-Za-z0-9._-]', '_', stem)[:40], pkg),
                    extra_headers={
                        'X-Icon-Replaced': icon_replaced,
                        'X-Label-Applied': '1' if label else '0',
                    },
                )
                return

            self._send_json({'ok': False, 'error': 'not found'}, 404)
        except ApiError as exc:
            self._fail(exc)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001
            self._fail(exc)
        finally:
            if icon_tmp and os.path.exists(icon_tmp):
                try:
                    os.unlink(icon_tmp)
                except OSError:
                    pass
            # 只删自己落盘的临时文件；暂存文件保留，打包失败后还能重试
            if upload and upload != cached and os.path.exists(upload):
                try:
                    os.unlink(upload)
                except OSError:
                    pass
            if workdir:
                shutil.rmtree(workdir, ignore_errors=True)
            with _req_lock:
                _req_stats['active'] -= 1
            _req_gate.release()


UBER_SIGNER_URL = ('https://github.com/patrickfav/uber-apk-signer/releases/'
                   'download/v1.3.0/uber-apk-signer-1.3.0.jar')


def _resolve_keystore_pass():
    """确定签名密码：环境变量 > 本地密码文件 > 首次启动随机生成。"""
    global KS_PASS
    if KS_PASS:
        return
    if os.path.exists(KS_PASS_FILE):
        with open(KS_PASS_FILE, encoding='utf-8') as fh:
            KS_PASS = fh.read().strip()
        return
    if os.path.exists(KEYSTORE):
        sys.stderr.write(
            '错误：已存在 %s 但找不到密码。请设置 APK_KEYSTORE_PASS，'
            '或删除该证书让服务重新生成。\n' % KEYSTORE)
        sys.exit(1)
    KS_PASS = secrets.token_urlsafe(24)
    os.makedirs(os.path.dirname(KS_PASS_FILE) or '.', exist_ok=True)
    with open(KS_PASS_FILE, 'w', encoding='utf-8') as fh:
        fh.write(KS_PASS)
    try:
        os.chmod(KS_PASS_FILE, 0o600)
    except OSError:
        pass


def _ensure_tools():
    """首次运行自动准备签名工具与证书；已存在则跳过。"""
    os.makedirs(TOOLS_DIR, exist_ok=True)
    _resolve_keystore_pass()

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


def _janitor(stop):
    """后台定期清理过期分片与暂存，避免把清理成本压在每一次上传请求上。"""
    while not stop.wait(CLEAN_INTERVAL):
        now = time.time()
        try:
            _purge_chunks(now)
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write('janitor purge chunks: %r\n' % exc)
        with _upload_lock:
            try:
                _purge_uploads_locked(now)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write('janitor purge uploads: %r\n' % exc)


def main():
    _ensure_tools()
    _cleanup_stale_files()          # 上次异常退出留下的临时文件
    _purge_chunks(time.time())

    stop = threading.Event()
    threading.Thread(target=_janitor, args=(stop,), daemon=True,
                     name='apk-janitor').start()

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    server.daemon_threads = True

    def _shutdown(signum, _frame):
        sys.stderr.write('收到信号 %s，准备关闭…\n' % signum)
        stop.set()
        # shutdown() 必须在别的线程调用，不能在信号处理器里直接阻塞
        threading.Thread(target=server.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    sys.stderr.write('listening on 0.0.0.0:%d\n' % PORT)
    sys.stderr.flush()
    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        _cleanup_stale_files()
        sys.stderr.write('已关闭，临时文件已清理\n')


if __name__ == '__main__':
    main()
