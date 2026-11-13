"""APK 图标资源定位与替换。

APK 的 android:icon 指向 res/mipmap-* 或 res/drawable-* 下的资源 ID。改写
manifest 里的引用需要解析 resources.arsc，代价高且易出错；这里直接按原条目名
定位图标位图，用用户上传的图标按**原尺寸**重绘后写回，manifest 引用保持不变，
因此不需要碰二进制资源表。

覆盖常见情况：
  - 传统图标：ic_launcher.png / ic_launcher_round.png（各密度目录）
  - 自适应图标：ic_launcher_foreground.png（mipmap-anydpi-v26 下的 XML 会引用它）
  - 少量以 app_icon / ic_app / ic_logo 命名的图标

不替换 ic_launcher_background（底色），避免破坏自适应图标的原始配色；
若图标是 VectorDrawable（.xml）或 WebP 动图，位图替换不生效，analyze() 会
把可替换的图标数量返回给前端用于提示。
"""

import io
import re
import struct

_ICON_DIR = re.compile(r'^res/(?:mipmap|drawable)', re.I)
_ICON_NAME = re.compile(
    r'(?:ic_launcher|app_icon|ic_app|ic_logo)', re.I)
_BITMAP_EXT = ('.png', '.webp', '.jpg', '.jpeg')
_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
_MAX_ICON_BYTES = 8 * 1024 * 1024
_MAX_DIM = 1024


def find_icon_entries(names):
    """返回 APK 中可被替换的图标位图条目名列表。"""
    out = []
    for n in names:
        if not _ICON_DIR.match(n) or not n.lower().endswith(_BITMAP_EXT):
            continue
        base = n.rsplit('/', 1)[-1]
        # 背景层不替换：换了会让自适应图标配色突兀
        if 'background' in base.lower():
            continue
        if _ICON_NAME.search(base):
            out.append(n)
    return out


def is_image(data):
    """只接受真实图片字节，避免把任意文件塞进 APK。"""
    if not data or len(data) > _MAX_ICON_BYTES:
        return False
    return (data[:8] == _PNG_MAGIC
            or data[:3] == b'\xff\xd8\xff'
            or (data[:4] == b'RIFF' and data[8:12] == b'WEBP'))


def _png_size(data):
    if data[:8] == _PNG_MAGIC and len(data) >= 24:
        return struct.unpack_from('>II', data, 16)
    return None


def _pil_size(data):
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            return im.size
    except Exception:
        return None


def _cover(im, size):
    """等比放大并居中裁剪，保证铺满目标尺寸（图标不应留白边）。"""
    from PIL import Image
    tw, th = size
    ratio = max(tw / im.width, th / im.height)
    nw = max(1, round(im.width * ratio))
    nh = max(1, round(im.height * ratio))
    big = im.resize((nw, nh), Image.LANCZOS)
    left, top = (nw - tw) // 2, (nh - th) // 2
    return big.crop((left, top, left + tw, top + th))


def build_icon_map(apk_names, read_entry, icon_data):
    """生成 {zip条目名: 新 PNG 字节}。

    read_entry(name) 由调用方提供（通常是 ZipFile.read），用于读取原图标尺寸。
    没有 Pillow 时降级为「原图直接写回」——Android 会按内容自行缩放，功能仍可用，
    只是各密度目录下清晰度一致。
    """
    entries = find_icon_entries(apk_names)
    if not entries:
        return {}

    try:
        from PIL import Image
    except ImportError:
        return {n: icon_data for n in entries}

    sizes = []
    for name in entries:
        try:
            raw = read_entry(name)
        except Exception:
            continue
        size = _png_size(raw) if name.lower().endswith('.png') else None
        if not size:
            size = _pil_size(raw)
        if not size:
            continue
        sizes.append((name, size))

    if not sizes:
        return {}

    try:
        src = Image.open(io.BytesIO(icon_data)).convert('RGBA')
        src.load()
    except Exception as exc:
        raise ValueError('图标文件无法解码：%s' % exc)

    out = {}
    for name, (w, h) in sizes:
        w = max(1, min(int(w), _MAX_DIM))
        h = max(1, min(int(h), _MAX_DIM))
        # 自适应图标前景有安全区限制，内容缩到 66% 居中才不会被系统裁掉
        foreground = 'foreground' in name.lower()
        factor = 0.66 if foreground else 1.0
        tw = max(1, int(w * factor))
        th = max(1, int(h * factor))
        fitted = _cover(src, (tw, th))
        canvas = Image.new('RGBA', (w, h), (0, 0, 0, 0))
        canvas.paste(fitted, ((w - tw) // 2, (h - th) // 2), fitted)
        buf = io.BytesIO()
        canvas.save(buf, 'PNG', optimize=True)
        out[name] = buf.getvalue()
    return out
