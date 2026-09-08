"""Generated resource trees, VERSIONINFO and manifest boundary regressions."""
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = os.path.abspath(sys.argv[1])
helpers = runpy.run_path(os.path.join(os.path.dirname(__file__), 'test_imports.py'))


def align(n):
    return (n + 3) & ~3


def version_block(key, value=b'', kind=1, children=(), count=None):
    b = bytearray(6) + key.encode('utf-16le') + b'\0\0'
    b += bytes(align(len(b)) - len(b))
    b += value
    for child in children:
        b += bytes(align(len(b)) - len(b))
        b += child
    if count is None:
        count = len(value) // 2 if kind else len(value)
    struct.pack_into('<HHH', b, 0, len(b), count, kind)
    return bytes(b)


def version(tables=None, fixed=True):
    if tables is None:
        tables = [('040904B0', {'FileVersion': '1.2.3.4-text',
                   'ProductVersion': '5.6.7.8-text', 'CompanyName': 'Компания 😀',
                   'FileDescription': 'PE analyzer', 'OriginalFilename': 'demo.exe'})]
    strings = []
    for table, fields in tables:
        strings.append(version_block(table, children=[
            version_block(key, value.encode('utf-16le') + b'\0\0')
            for key, value in fields.items()]))
    info = struct.pack('<13I', 0xfeef04bd, 0x10000, 0x10002, 0x30004,
                       0x50006, 0x70008, 0x3f, 0, 0x40004, 1, 0, 0, 0)
    children = [version_block('StringFileInfo', children=strings)] if tables else []
    children.append(version_block('VarFileInfo', children=[
        version_block('Translation', struct.pack('<HH', 0x409, 1200), kind=0)]))
    return version_block('VS_VERSION_INFO', info if fixed else b'', kind=0, children=children)


def fixture(items=None, wide=False):
    """Return a PE and offsets for mutation; item = (type, name, language, bytes)."""
    if items is None:
        items = [(10, 1, 0x409, b'opaque')]
    tree = {}
    for kind, name, language, data in items:
        tree.setdefault(kind, {}).setdefault(name, {})[language] = data
    metadata = bytearray()
    loc = {'dirs': {}, 'entries': {}, 'data': {}, 'payload': {}}
    pending = []

    def reserve(size):
        offset = align(len(metadata))
        metadata.extend(bytes(offset + size - len(metadata)))
        return offset

    def directory(nodes, path):
        keys = sorted(nodes, key=lambda k: (not isinstance(k, str), k))
        off = reserve(16 + 8 * len(keys))
        loc['dirs'][path] = 0x600 + off
        named = sum(isinstance(k, str) for k in keys)
        struct.pack_into('<IIHHHH', metadata, off, 0, 0, 0, 0, named, len(keys) - named)
        for i, key in enumerate(keys):
            ep = off + 16 + i * 8
            loc['entries'][path + (key,)] = 0x600 + ep
            value = key
            if isinstance(key, str):
                text = key.encode('utf-16le')
                noff = reserve(2 + len(text))
                struct.pack_into('<H', metadata, noff, len(text) // 2)
                metadata[noff + 2:noff + 2 + len(text)] = text
                value = 0x80000000 | noff
            if isinstance(nodes[key], dict):
                target = 0x80000000 | directory(nodes[key], path + (key,))
            else:
                target = reserve(16)
                loc['data'][path + (key,)] = 0x600 + target
                pending.append((path + (key,), target, nodes[key]))
            struct.pack_into('<II', metadata, ep, value, target)
        return off

    directory(tree, ())
    b = helpers['fixture'](wide)
    b.extend(bytes(max(0, 0x600 + len(metadata) - len(b))))
    b[0x600:0x600 + len(metadata)] = metadata
    cursor = max(0x1000, align(0x600 + len(metadata)))
    for path, off, content in pending:
        b.extend(bytes(max(0, cursor + len(content) - len(b))))
        b[cursor:cursor + len(content)] = content
        loc['payload'][path] = cursor
        struct.pack_into('<IIII', b, 0x600 + off, cursor + 0xe00, len(content), 1200, 0)
        cursor = align(cursor + len(content))
    loc['directory'] = 152 + (112 if wide else 96) + 16
    struct.pack_into('<II', b, loc['directory'], 0x1400, max(len(metadata), cursor - 0x600))
    section = 152 + (240 if wide else 224)
    loc['section'] = section
    struct.pack_into('<I', b, section + 8, len(b) - 0x200)
    struct.pack_into('<I', b, section + 16, len(b) - 0x200)
    struct.pack_into('<I', b, 152 + 56, (len(b) + 0x1dff) & ~0xfff)
    return b, loc


class ResourceTests(unittest.TestCase):
    def run_pe(self, b, *flags):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b)
            f.flush()
            return subprocess.run([BINARY, *flags, f.name], capture_output=True, timeout=10)

    def good(self, b, *flags):
        p = self.run_pe(b, *(flags or ('-r',)))
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def bad(self, b):
        p = self.run_pe(b, '--resources')
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn(b'Warning: resources:', p.stderr)
        self.assertNotIn(b'AddressSanitizer', p.stderr)
        self.assertNotIn(b'runtime error:', p.stderr)
        return p

    def test_tree_and_metadata(self):
        for wide in (False, True):
            for flag in ('-r', '--resources'):
                b, loc = fixture(wide=wide)
                out = self.good(b, flag)
                for text in (b'Type: RT_RCDATA (#10)', b'Name: #1', b'Language: 0x0409',
                             b'Size: 6 bytes', b'RVA: 0x00001E00', b'File offset: 0x00001000'):
                    self.assertIn(text, out)
                self.assertNotIn(b'opaque', out)

    def test_standard_types_metadata_only(self):
        kinds = {1: 'RT_CURSOR', 3: 'RT_ICON', 6: 'RT_STRING', 10: 'RT_RCDATA',
                 14: 'RT_GROUP_ICON', 99: 'CUSTOM'}
        b, _ = fixture([(k, 1, 0, b'NO_DECODE') for k in kinds])
        out = self.good(b)
        for name in kinds.values():
            self.assertIn(name.encode(), out)
        self.assertNotIn(b'NO_DECODE', out)

    def test_named_entries_and_multiple_languages(self):
        for wide in (False, True):
            b, _ = fixture([(10, 'данные😀', 0x409, b'one'),
                            (10, 'данные😀', 0x419, b'two'),
                            ('TYPE😀', 2, 0, b'custom')], wide)
            out = self.good(b)
            for text in ('Type: "TYPE😀"', 'Name: "данные😀"',
                         'Language: 0x0409', 'Language: 0x0419'):
                self.assertIn(text.encode(), out)
            self.assertEqual(out.count('Name: "данные😀"'.encode()), 1)

    def test_absent_and_empty(self):
        for wide in (False, True):
            b, loc = fixture([], wide)
            self.assertIn(b'No resources.', self.good(b))
            struct.pack_into('<II', b, loc['directory'], 0, 0)
            self.assertIn(b'No resources.', self.good(b))
            struct.pack_into('<I', b, 152 + (108 if wide else 92), 2)
            self.assertIn(b'No resources.', self.good(b))

    def test_optional_and_combined_help(self):
        b, _ = fixture([(24, 1, 0, b'<assembly/>')])
        self.assertNotIn(b'Type: RT_MANIFEST', self.run_pe(b).stdout)
        out = self.good(b, '-r', '-i', '-e', '-d', '-H', '-g', '-c', '--debug')
        self.assertIn(b'<assembly/>', out)
        p = subprocess.run([BINARY, '--help'], capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'-r, --resources', p.stdout)

    def test_version_fixed_and_strings(self):
        for wide in (False, True):
            b, _ = fixture([(16, 1, 0x409, version())], wide)
            out = self.good(b)
            for text in ('FileVersion [fixed]: 1.2.3.4', 'ProductVersion [fixed]: 5.6.7.8',
                         'FileVersion [040904B0]: 1.2.3.4-text',
                         'ProductVersion [040904B0]: 5.6.7.8-text',
                         'CompanyName [040904B0]: Компания 😀',
                         'FileDescription [040904B0]: PE analyzer',
                         'OriginalFilename [040904B0]: demo.exe'):
                self.assertIn(text.encode(), out)

    def test_version_multiple_translations(self):
        v = version([('040904B0', {'CompanyName': 'English'}),
                     ('041904B0', {'CompanyName': 'Русский'})], fixed=False)
        for wide in (False, True):
            b, _ = fixture([(16, 1, 0x409, v), (16, 1, 0x419, version(tables=[]))], wide)
            out = self.good(b)
            self.assertIn(b'CompanyName [040904B0]: English', out)
            self.assertIn('CompanyName [041904B0]: Русский'.encode(), out)
            self.assertEqual(out.count(b'FileVersion [fixed]'), 1)

    def test_manifest_encodings(self):
        text = '<assembly>Привет 😀</assembly>\r\n<test/>'
        data = [text.encode(), b'\xef\xbb\xbf' + text.encode(),
                b'\xff\xfe' + text.encode('utf-16le'), b'\xfe\xff' + text.encode('utf-16be'),
                text.encode('utf-16le'), text.encode('utf-16be')]
        for wide in (False, True):
            for content in data:
                b, _ = fixture([(24, 1, 0, content)], wide)
                out = self.good(b)
                self.assertIn('Привет 😀'.encode(), out)
                self.assertIn(b'\n          <test/>', out)
                self.assertNotIn(b'\r', out)

    def test_safe_terminal_output(self):
        unsafe = 'x\x1b[2J\x07\x00\x85\u202e\u2066'
        v = version([('040904B0', {'CompanyName': 'A\x1b\n\u202e'})])
        b, _ = fixture([(24, 'a\x1b\n\u202e', 0, unsafe.encode()), (16, 1, 0, v)])
        out = self.good(b)
        self.assertNotIn(b'\x1b', out)
        self.assertNotIn(b'\x07', out)
        self.assertNotIn(b'\0', out)
        self.assertNotIn('\u202e'.encode(), out)
        for text in (b'\\u001B', b'\\u0007', b'\\u0000', b'\\u0085', b'\\u202E', b'\\u2066'):
            self.assertIn(text, out)

    def test_bad_directory_ranges(self):
        for wide in (False, True):
            for rva, size in ((0, 16), (0x1400, 0), (0x1400, 15),
                              (0xfffffff0, 32), (0x3000, 16), (0x1ff8, 16)):
                b, loc = fixture(wide=wide)
                struct.pack_into('<II', b, loc['directory'], rva, size)
                self.bad(b)

    def test_truncated_directory_entry_array(self):
        b, loc = fixture()
        struct.pack_into('<I', b, loc['directory'] + 4, 20)
        self.bad(b)

    def test_declared_directory_beyond_file(self):
        b, loc = fixture()
        struct.pack_into('<I', b, loc['directory'] + 4, 0x10000)
        self.bad(b)

    def test_unavailable_directory_slot(self):
        for wide in (False, True):
            b, loc = fixture(wide=wide)
            section = bytes(b[loc['section']:loc['section'] + 40])
            short_size = (112 if wide else 96) + 16
            struct.pack_into('<H', b, 132 + 16, short_size)
            b[152 + short_size:152 + short_size + 40] = section
            self.assertIn(b'declared Resource Directory is unavailable', self.bad(b).stderr)

    def test_directory_in_headers(self):
        b, loc = fixture()
        b[0x1a0:0x1f8] = b[0x600:0x658]
        struct.pack_into('<II', b, loc['directory'], 0x1a0, 88)
        self.good(b)

    def test_ranges_cross_noncontiguous_sections(self):
        for wide in (False, True):
            for split in (0x614, 0x1002):
                b, loc = fixture([(24, 1, 0, b'<ok/>')], wide)
                tail = bytes(b[split:])
                b.extend(bytes(0x1400 + len(tail) - len(b)))
                b[0x1400:] = tail
                struct.pack_into('<H', b, 134, 2)
                struct.pack_into('<I', b, loc['section'] + 8, split - 0x200)
                struct.pack_into('<I', b, loc['section'] + 16, split - 0x200)
                struct.pack_into('<8sIIIIIIHHI', b, loc['section'] + 40,
                                 b'.rsrc2', len(tail), split + 0xe00, len(tail),
                                 0x1400, 0, 0, 0, 0, 0x40000040)
                self.assertIn(b'<ok/>', self.good(b))

    def test_payload_rva_gap(self):
        b, loc = fixture()
        # End the section after the first payload byte, preserving physical bytes.
        struct.pack_into('<I', b, loc['section'] + 8, 0xe01)
        self.bad(b)

    def test_relative_offsets_stay_inside_directory(self):
        for key in ((10,), (10, 1), (10, 1, 0x409)):
            b, loc = fixture()
            ep = loc['entries'][key]
            struct.pack_into('<I', b, ep + 4, 0x7ffffff0 | (0x80000000 if len(key) < 3 else 0))
            self.bad(b)

    def test_invalid_named_strings(self):
        for wide in (False, True):
            for content in (b'\x00\xd8', b'\x00\xdc', b'\x00\xd8A\0', b'\0\0'):
                b, loc = fixture([(10, 'AB', 0, b'data')], wide)
                ep = loc['entries'][(10, 'AB')]
                off = 0x600 + (struct.unpack_from('<I', b, ep)[0] & 0x7fffffff)
                struct.pack_into('<H', b, off, len(content) // 2)
                b[off + 2:off + 2 + len(content)] = content
                self.bad(b)
        b, loc = fixture([(10, 'AB', 0, b'data')])
        struct.pack_into('<I', b, loc['entries'][(10, 'AB')], 0xfffffffe)
        self.bad(b)

    def test_name_limit(self):
        for length in (256, 257):
            b, _ = fixture([(10, 'a' * length, 0, b'x')])
            if length == 256:
                self.good(b)
            else:
                self.assertIn(b'limit', self.bad(b).stderr)

    def test_invalid_id_and_named_counts(self):
        for value in (0x10000, 0x7fffffff):
            b, loc = fixture()
            struct.pack_into('<I', b, loc['entries'][(10,)], value)
            self.bad(b)
        b, loc = fixture()
        struct.pack_into('<HH', b, loc['dirs'][()] + 12, 1, 0)
        self.bad(b)

    def test_cycles_and_depth(self):
        for wide in (False, True):
            for target in (0, 24):
                b, loc = fixture(wide=wide)
                struct.pack_into('<I', b, loc['entries'][(10, 1)] + 4, 0x80000000 | target)
                self.assertIn(b'cycle', self.bad(b).stderr)
            b, loc = fixture(wide=wide)
            dp = loc['data'][(10, 1, 0x409)]
            struct.pack_into('<I', b, loc['entries'][(10, 1, 0x409)] + 4, 0x80000000 | (dp - 0x600))
            self.assertIn(b'depth', self.bad(b).stderr)

    def test_early_data_leaf(self):
        b, loc = fixture()
        struct.pack_into('<I', b, loc['entries'][(10,)] + 4, loc['data'][(10, 1, 0x409)] - 0x600)
        self.bad(b)

    def test_entry_budget(self):
        b, loc = fixture()
        struct.pack_into('<H', b, loc['dirs'][()] + 14, 1025)
        self.assertIn(b'limit', self.bad(b).stderr)
        # Individually small directories whose combined traversal exceeds the limit.
        b, _ = fixture([(10, n, 0, b'x') for n in range(520)])
        p = self.bad(b)
        self.assertIn(b'limit', p.stderr)
        self.assertLess(len(p.stdout), 250000)

    def test_invalid_payload_ranges(self):
        for wide in (False, True):
            for rva, size in ((0, 1), (0x1fff, 2), (0xffffffff, 2),
                              (0x1e00, 0xffffffff), (0x3000, 4)):
                b, loc = fixture(wide=wide)
                struct.pack_into('<II', b, loc['data'][(10, 1, 0x409)], rva, size)
                self.bad(b)

    def test_raw_tail_is_not_payload(self):
        b, loc = fixture()
        struct.pack_into('<I', b, loc['section'] + 16, 0xe02)
        self.bad(b)

    def test_payload_outside_directory_and_in_headers(self):
        for rva, content in ((0x1e00, b'opaque'), (0x1c0, b'header')):
            b, loc = fixture()
            struct.pack_into('<I', b, loc['directory'] + 4, 88)
            dp = loc['data'][(10, 1, 0x409)]
            struct.pack_into('<I', b, dp, rva)
            if rva == 0x1c0:
                b[0x1c0:0x1c6] = content
            self.good(b)

    def test_zero_size_payload(self):
        b, loc = fixture()
        struct.pack_into('<II', b, loc['data'][(10, 1, 0x409)], 0, 0)
        self.assertIn(b'Size: 0 bytes', self.good(b))

    def test_bad_data_entry_and_continue(self):
        b, loc = fixture([(10, 1, 0, b'a'), (24, 1, 0, b'<good/>')])
        struct.pack_into('<II', b, loc['data'][(10, 1, 0)], 0xffffffff, 2)
        self.assertIn(b'<good/>', self.bad(b).stdout)
        b, loc = fixture()
        struct.pack_into('<I', b, loc['data'][(10, 1, 0x409)] + 12, 1)
        self.bad(b)

    def test_manifest_invalid_unicode(self):
        for content in (b'\xc0\xaf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80', b'\xe2\x82',
                        b'\xff\xfeA', b'\xff\xfe\x00\xd8', b'\xfe\xff\xdc\x00'):
            b, _ = fixture([(24, 1, 0, content)])
            self.assertIn(b'encoding', self.bad(b).stderr)

    def test_manifest_size_and_partial_character(self):
        for content in (b'a' * 16385, b'a' * 16383 + '😀'.encode(),
                        b'\xff\xfe' + ('a' * 8190 + '😀').encode('utf-16le')):
            b, _ = fixture([(24, 1, 0, content)])
            p = self.bad(b)
            self.assertIn(b'truncated preview', p.stdout)
            self.assertNotIn(b'encoding', p.stderr)
            self.assertLess(len(p.stdout), 60000)
        b, _ = fixture([(24, 1, 0, b'a' * 16384)])
        self.good(b)

    def test_total_text_budget(self):
        b, _ = fixture([(24, n, 0, b'a' * 16384) for n in range(17)])
        p = self.bad(b)
        self.assertIn(b'text budget', p.stderr)
        self.assertLess(len(p.stdout), 400000)

    def test_version_bad_headers(self):
        for wide in (False, True):
            for field, val in ((0, 0), (0, 65535), (2, 65535), (4, 2)):
                v = bytearray(version())
                struct.pack_into('<H', v, field, val)
                b, _ = fixture([(16, 1, 0, v)], wide)
                self.bad(b)
        for content in (b'', b'\0' * 5, b'x' * 65537):
            b, _ = fixture([(16, 1, 0, content)])
            self.bad(b)

    def test_version_invalid_fixed_signature(self):
        v = bytearray(version())
        offset = v.index(struct.pack('<I', 0xfeef04bd))
        struct.pack_into('<I', v, offset, 0)
        b, _ = fixture([(16, 1, 0, v)])
        p = self.bad(b)
        self.assertNotIn(b'FileVersion [fixed]', p.stdout)
        self.assertIn(b'CompanyName', p.stdout)

    def test_version_invalid_string_value_and_key(self):
        for value in (b'A\0', b'\x00\xd8\0\0', b'A\0\0\0B\0\0\0'):
            child = version_block('CompanyName', value)
            table = version_block('040904B0', children=[child])
            v = version_block('VS_VERSION_INFO', kind=0,
                              children=[version_block('StringFileInfo', children=[table])])
            b, _ = fixture([(16, 1, 0, v)])
            self.bad(b)
        v = bytearray(version())
        struct.pack_into('<H', v, 6, 0xd800)
        b, _ = fixture([(16, 1, 0, v)])
        self.bad(b)

    def test_version_zero_child_and_value_overflow(self):
        for field, value in ((0, 0), (0, 65534), (2, 65535)):
            v = bytearray(version())
            off = v.index('CompanyName'.encode('utf-16le')) - 6
            struct.pack_into('<H', v, off + field, value)
            b, _ = fixture([(16, 1, 0, v)])
            self.bad(b)

    def test_version_limits_and_nested_values(self):
        v = version([('040904B0', {'CompanyName': 'x' * 1024})])
        b, _ = fixture([(16, 1, 0, v)])
        self.assertIn(b'limit', self.bad(b).stderr)
        leaf = version_block('CompanyName', b'x\0\0\0', children=[version_block('extra')])
        table = version_block('040904B0', children=[leaf])
        v = version_block('VS_VERSION_INFO', kind=0,
                          children=[version_block('StringFileInfo', children=[table])])
        b, _ = fixture([(16, 1, 0, v)])
        self.assertIn(b'depth', self.bad(b).stderr)

    def test_version_block_budget(self):
        fields = [version_block('Unused', b'x\0\0\0') for _ in range(257)]
        table = version_block('040904B0', children=fields)
        v = version_block('VS_VERSION_INFO', kind=0,
                          children=[version_block('StringFileInfo', children=[table])])
        b, _ = fixture([(16, 1, 0, v)])
        self.assertIn(b'block limit', self.bad(b).stderr)


if __name__ == '__main__':
    unittest.main()
