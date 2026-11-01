"""Android 二进制 XML（AXML）解析与包名改写。

APK 内的 AndroidManifest.xml 不是文本，而是 AOSP 的 ResXML 二进制格式。
本模块只做两件事：
  1. 读出 <manifest> 的 package 及常用元数据（版本、应用名、SDK）；
  2. 在字符串池末尾追加新包名，并把 package 属性指向它（不改动任何已有字符串，
     因此不会波及被复用的字符串索引）。
"""

import struct

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
UTF8_FLAG = 0x100
NO_NAMESPACE = 0xFFFFFFFF

# Res_value.dataType
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


class AxmlError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def _u32s(b, o, n):
    return struct.unpack_from('<%dI' % n, b, o)


def _read_len16(buf, p):
    v = _u16(buf, p)
    if v & 0x8000:
        v = ((v & 0x7FFF) << 16) | _u16(buf, p + 2)
        return v, p + 4
    return v, p + 2


def _read_len8(buf, p):
    v = buf[p]
    if v & 0x80:
        v = ((v & 0x7F) << 8) | buf[p + 1]
        return v, p + 2
    return v, p + 1


def _write_len8(v):
    if v < 0x80:
        return bytes([v])
    return bytes([0x80 | (v >> 8), v & 0xFF])


def _write_len16(v):
    if v < 0x8000:
        return struct.pack('<H', v)
    return struct.pack('<HH', 0x8000 | (v >> 16), v & 0xFFFF)


class StringPool(object):
    """只读解析 + 追加一个字符串（不重排既有条目）。"""

    def __init__(self, buf, off):
        if _u16(buf, off) != RES_STRING_POOL_TYPE:
            raise AxmlError('未找到字符串池 chunk')
        self.off = off
        self.header_size = _u16(buf, off + 2)
        self.size = _u32(buf, off + 4)
        self.string_count = _u32(buf, off + 8)
        self.style_count = _u32(buf, off + 12)
        self.flags = _u32(buf, off + 16)
        self.strings_start = _u32(buf, off + 20)
        self.styles_start = _u32(buf, off + 24)
        self.utf8 = bool(self.flags & UTF8_FLAG)

        base = off + self.header_size
        self.offsets = list(_u32s(buf, base, self.string_count))
        self.strings = [self._decode(buf, off + self.strings_start + o) for o in self.offsets]

        if self.style_count:
            self.string_data_len = self.styles_start - self.strings_start
        else:
            self.string_data_len = self.size - self.strings_start

    # UTF-8 池：[UTF-16 码元数][字节长][UTF-8 字节][0x00]
    # UTF-16 池：[UTF-16 码元数][UTF-16LE 字节][0x0000]   —— 只有一个长度字段
    def _decode(self, buf, p):
        if self.utf8:
            _u16len, p = _read_len8(buf, p)
            blen, p = _read_len8(buf, p)
            return buf[p:p + blen].decode('utf-8', 'replace')
        clen, p = _read_len16(buf, p)
        return buf[p:p + clen * 2].decode('utf-16-le', 'replace')

    def _encode(self, s):
        """编码单个字符串。返回值会被补齐到 4 字节边界——AOSP 要求每个 chunk
        的 size 必须 4 字节对齐，否则 aapt/PackageManager 判定 manifest 损坏。"""
        if self.utf8:
            raw = s.encode('utf-8')
            u16len = len(s.encode('utf-16-le')) // 2
            out = _write_len8(u16len) + _write_len8(len(raw)) + raw + b'\x00'
        else:
            raw = s.encode('utf-16-le')
            out = _write_len16(len(raw) // 2) + raw + b'\x00\x00'
        # 追加的偏移表项固定 4 字节，故字符串数据补齐 4 字节即保证 delta 对齐
        return out + b'\x00' * (-len(out) % 4)

    def append(self, chunk, value):
        """返回 (新的 pool chunk 字节, 该字符串的索引)。已存在则原样返回。

        支持对同一个池连续追加多次：每次追加后同步内部状态，
        下一次追加的插入位置才能落在正确的地方（索引保持稳定递增）。
        """
        if value in self.strings:
            return chunk, self.strings.index(value)

        enc = self._encode(value)
        delta = 4 + len(enc)
        out = bytearray(chunk)

        # 1) 在偏移表末尾插入一条 4 字节记录（后续内容整体后移 4 字节）
        entry_pos = self.header_size + 4 * self.string_count
        out[entry_pos:entry_pos] = struct.pack('<I', self.string_data_len)

        # 2) 把新字符串追加到字符串数据区末尾
        ins = self.strings_start + 4 + self.string_data_len
        out[ins:ins] = enc

        # 3) 修正 chunk 头
        struct.pack_into('<I', out, 4, self.size + delta)
        struct.pack_into('<I', out, 8, self.string_count + 1)
        struct.pack_into('<I', out, 20, self.strings_start + 4)
        if self.styles_start:
            struct.pack_into('<I', out, 24, self.styles_start + delta)

        # 4) 同步内部状态（供下一次追加使用）
        self.size += delta
        self.string_count += 1
        self.strings_start += 4
        if self.styles_start:
            self.styles_start += delta
        self.string_data_len += len(enc)
        self.strings.append(value)

        return bytes(out), self.string_count - 1


def _decode_value(pool, data_type, data):
    if data_type == TYPE_STRING:
        return pool.strings[data] if data < len(pool.strings) else None
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return data
    if data_type == TYPE_INT_BOOLEAN:
        return bool(data)
    return None  # 资源引用 / 空值，交给前端显示为「来自资源」


def _scan(buf):
    """返回 (pool_offset, pool, {元素: {属性: (pos, type, raw)}}, 元素顺序, 待改写属性出现表)。

    pos 是属性结构体在 buf 中的绝对偏移（rawValue 在 pos+8，data 在 pos+16）。
    occ 收集 REWRITE_KEYS 中每一处属性出现（同名属性可能多次出现，如多个 provider）。
    """
    if len(buf) < 8 or _u16(buf, 0) != RES_XML_TYPE:
        raise AxmlError('不是有效的二进制 XML（缺少 RES_XML_TYPE 头）')

    root_hs = _u16(buf, 2)
    root_size = _u32(buf, 4)
    if root_size > len(buf):
        root_size = len(buf)

    pool_off = None
    pool = None
    elements = {}
    order = []
    occ = {}
    off = root_hs

    while off + 8 <= root_size:
        ctype = _u16(buf, off)
        chs = _u16(buf, off + 2)
        csz = _u32(buf, off + 4)
        if csz < 8 or off + csz > root_size:
            break

        if ctype == RES_STRING_POOL_TYPE:
            pool_off = off
            pool = StringPool(buf, off)
        elif ctype == RES_XML_START_ELEMENT_TYPE and pool is not None:
            ext = off + 16  # 8(chunk header) + 8(lineNumber/comment)
            el_name_idx = _u32(buf, ext + 4)
            attr_start = _u16(buf, ext + 8)
            attr_size = _u16(buf, ext + 10)
            attr_count = _u16(buf, ext + 12)
            el = pool.strings[el_name_idx] if el_name_idx < len(pool.strings) else ''
            aoff = ext + attr_start
            bucket = elements.setdefault(el, {})
            if el not in order:
                order.append(el)
            for i in range(attr_count):
                p = aoff + i * attr_size
                if p + 20 > root_size:
                    break
                aname_idx = _u32(buf, p + 4)
                data_type = buf[p + 15]
                data = _u32(buf, p + 16)
                key = pool.strings[aname_idx] if aname_idx < len(pool.strings) else ''
                if (el, key) in REWRITE_KEYS:
                    occ.setdefault((el, key), []).append((p, data_type, data))
                # 同名属性只保留第一个（manifest 上的 package 只有一个）
                if key and key not in bucket:
                    bucket[key] = (p, data_type, data)

        off += csz

    if pool_off is None:
        raise AxmlError('manifest 中缺少字符串池')
    return pool_off, pool, elements, order, occ


def read_info(buf):
    """读取 manifest 元数据。"""
    pool_off, pool, elements, order, _occ = _scan(buf)

    manifest = elements.get('manifest', {})
    pkg_pos, pkg_type, pkg_data = manifest.get('package', (None, None, None))
    package = None
    if pkg_pos is not None and pkg_type == TYPE_STRING and pkg_data < len(pool.strings):
        package = pool.strings[pkg_data]

    def attr(elem, name, default=None):
        item = elements.get(elem, {}).get(name)
        if not item:
            return default
        return _decode_value(pool, item[1], item[2])

    return {
        'package': package,
        'versionName': attr('manifest', 'versionName'),
        'versionCode': attr('manifest', 'versionCode'),
        'label': attr('application', 'label'),
        'minSdk': attr('uses-sdk', 'minSdkVersion'),
        'targetSdk': attr('uses-sdk', 'targetSdkVersion'),
        'sharedUserId': attr('manifest', 'sharedUserId'),
        'elements': order,
        '_pool_off': pool_off,
        '_pkg_pos': pkg_pos,
    }


def _replace_prefix(val, old_pkg, new_pkg):
    """val 等于 old_pkg 或以其为前缀时，替换前缀；否则返回 None（不动）。"""
    if val == old_pkg:
        return new_pkg
    if val.startswith(old_pkg + '.'):
        return new_pkg + val[len(old_pkg):]
    return None


def _remap_value(attr, val, old_pkg, new_pkg):
    """authorities 支持分号分隔的多值；其余属性整体替换前缀。"""
    if attr == 'authorities':
        parts = val.split(';')
        changed = False
        for i, seg in enumerate(parts):
            rep = _replace_prefix(seg, old_pkg, new_pkg)
            if rep is not None:
                parts[i] = rep
                changed = True
        return ';'.join(parts) if changed else None
    return _replace_prefix(val, old_pkg, new_pkg)


# 只有这些属性允许跟随包名改写。组件类名（activity/service 的 android:name 等）
# 绝对不能改——DEX 里的类还叫旧名，改了会运行时 ClassNotFoundException。
REWRITE_KEYS = {
    ('provider', 'authorities'),        # 权限冲突：与原应用同 authorities 会拒绝安装
    ('permission', 'name'),             # 自定义权限：签名不同 + 同名 = 拒绝安装
    ('permission-group', 'name'),
    ('permission-tree', 'name'),
    ('uses-permission', 'name'),        # 引用本应用自定义权限的，跟着一起改
    ('instrumentation', 'targetPackage'),
    # 组件上「被哪个权限保护」的引用，与声明保持一致
    ('activity', 'permission'),
    ('activity-alias', 'permission'),
    ('service', 'permission'),
    ('receiver', 'permission'),
    ('provider', 'permission'),
    ('application', 'permission'),
    # 共享 UID：原应用在装时，同名 sharedUserId + 签名不同 = 拒绝安装
    ('manifest', 'sharedUserId'),
}


def set_package(buf, new_package):
    """返回改写后的 AndroidManifest.xml 字节。"""
    pool_off, pool, elements, _, occ = _scan(buf)
    manifest = elements.get('manifest', {})
    pkg_item = manifest.get('package')
    if not pkg_item:
        raise AxmlError('manifest 中没有 package 属性')
    if pkg_item[2] >= len(pool.strings):
        raise AxmlError('manifest 字符串池异常')
    old_pkg = pool.strings[pkg_item[2]]
    if old_pkg == new_package:
        return buf  # 无需改动

    orig_pool_size = pool.size
    chunk = buf[pool_off:pool_off + orig_pool_size]
    total_delta = 0

    def append_str(value):
        nonlocal chunk, total_delta
        before = len(chunk)
        chunk, idx = pool.append(chunk, value)
        total_delta += len(chunk) - before
        return idx

    # 1) 找出所有需要跟随改写的属性值（只处理字符串类型；资源引用不动）
    targets = []  # (attr_pos, new_value)
    for (_el, attr), items in occ.items():
        for pos, dtype, data in items:
            if dtype != TYPE_STRING or data >= len(pool.strings):
                continue
            new_val = _remap_value(attr, pool.strings[data], old_pkg, new_package)
            if new_val is not None and new_val != pool.strings[data]:
                targets.append((pos, new_val))

    # 2) 先把所有新字符串追加进池（package 名 + 去重后的目标值）
    pkg_idx = append_str(new_package)
    value_idx = {}
    for _, val in targets:
        if val not in value_idx:
            value_idx[val] = append_str(val)

    # 3) 组装：替换池 chunk，之后所有位置整体平移 total_delta
    out = bytearray(buf[:pool_off]) + bytearray(chunk) + bytearray(buf[pool_off + orig_pool_size:])
    struct.pack_into('<I', out, 4, len(out))            # 根 chunk size
    p = pkg_item[0] + total_delta
    # rawValue 与 data 是两个独立的字符串索引：XmlBlock/PackageManager 读 rawValue，
    # aapt 也优先打印 rawValue，两处必须同步改，否则会出现「显示旧包名」的假象。
    struct.pack_into('<I', out, p + 8, pkg_idx)
    struct.pack_into('<I', out, p + 16, pkg_idx)
    for pos, val in targets:
        p = pos + total_delta
        struct.pack_into('<I', out, p + 8, value_idx[val])
        struct.pack_into('<I', out, p + 16, value_idx[val])
    return bytes(out)
