"""Synthetic PE32/PE32+ Debug Directory and CodeView regressions."""
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = os.path.abspath(sys.argv[1])
helpers = runpy.run_path(os.path.join(os.path.dirname(__file__), 'test_imports.py'))
GUID = bytes.fromhex('33221100554477668899aabbccddeeff')
PDB = b'C:\\symbols\\demo.pdb'


def codeview(kind=b'RSDS', path=PDB):
    if kind == b'RSDS':
        return kind + GUID + struct.pack('<I', 7) + path + b'\0'
    return kind + struct.pack('<III', 0, 0x12345678, 9) + path + b'\0'


def directory_offset(wide):
    return 152 + (112 if wide else 96) + 6 * 8


def record(b, offset=0x600, kind=2, size=None, pointer=0x800, rva=0x1600):
    if size is None:
        size = len(codeview())
    # Directory timestamp deliberately differs from the NB10 timestamp.
    struct.pack_into('<IIHHIIII', b, offset, 0, 0xaabbccdd, 0, 0,
                     kind, size, rva, pointer)


def fixture(wide=False, payload=None):
    b = helpers['fixture'](wide)
    if payload is None:
        payload = codeview()
    struct.pack_into('<II', b, directory_offset(wide), 0x1400, 28)
    record(b, size=len(payload))
    b[0x800:0x800 + len(payload)] = payload
    return b


class DebugTests(unittest.TestCase):
    def run_pe(self, b, *flags):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b)
            f.flush()
            return subprocess.run([BINARY, *flags, f.name], capture_output=True, timeout=10)

    def malformed(self, b):
        p = self.run_pe(b, '--debug')
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn(b'Warning: debug:', p.stderr)
        self.assertNotIn(b'AddressSanitizer', p.stderr)
        self.assertNotIn(b'runtime error:', p.stderr)
        return p

    def test_rsds(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                p = self.run_pe(fixture(wide), '--debug')
                self.assertEqual(p.returncode, 0, p.stderr)
                for text in (b'Debug Directory', b'CODEVIEW (2)', b'CodeView: RSDS',
                             b'GUID: 00112233-4455-6677-8899-AABBCCDDEEFF',
                             b'Age: 7', b'PDB: ' + PDB):
                    self.assertIn(text, p.stdout)

    def test_nb10(self):
        for wide in (False, True):
            p = self.run_pe(fixture(wide, codeview(b'NB10')), '--debug')
            self.assertEqual(p.returncode, 0, p.stderr)
            for text in (b'CodeView: NB10', b'Timestamp: 0x12345678', b'Age: 9', PDB):
                self.assertIn(text, p.stdout)
            self.assertNotIn(b'GUID:', p.stdout)

    def test_optional_help_and_combined_flags(self):
        b = fixture()
        self.assertNotIn(b'CodeView:', self.run_pe(b).stdout)
        p = self.run_pe(b, '--debug', '-i', '-e', '-d', '-H', '-c', '-g')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'CodeView: RSDS', p.stdout)
        p = subprocess.run([BINARY, '--help'], capture_output=True, timeout=10)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'--debug', p.stdout)

    def test_absent_directory(self):
        for wide in (False, True):
            for declared in (0, 6, 16):
                b = fixture(wide)
                struct.pack_into('<II', b, directory_offset(wide), 0, 0)
                struct.pack_into('<I', b, 152 + (108 if wide else 92), declared)
                p = self.run_pe(b, '--debug')
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b'No debug entries.', p.stdout)

    def test_invalid_directory_ranges(self):
        for wide in (False, True):
            for rva, size in ((0, 28), (0x1400, 0), (0x1400, 1),
                              (0x1400, 27), (0x1400, 29),
                              (0xfffffff0, 28), (0x3000, 28), (0x1ff0, 28)):
                with self.subTest(wide=wide, rva=rva, size=size):
                    b = fixture(wide)
                    struct.pack_into('<II', b, directory_offset(wide), rva, size)
                    self.malformed(b)

    def test_directory_limit(self):
        b = fixture()
        struct.pack_into('<I', b, directory_offset(False) + 4, 4097 * 28)
        self.assertIn(b'limit', self.malformed(b).stderr)

    def test_directory_in_headers(self):
        for wide in (False, True):
            b = fixture(wide)
            b[0x1c0:0x1dc] = b[0x600:0x61c]
            struct.pack_into('<I', b, directory_offset(wide), 0x1c0)
            p = self.run_pe(b, '--debug')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(PDB, p.stdout)

    def test_directory_virtual_tail(self):
        b = fixture()
        # File bytes still exist, but the section has no raw storage here.
        struct.pack_into('<I', b, 376 + 16, 0x410)
        self.malformed(b)

    def test_unavailable_directory_slot(self):
        for wide in (False, True):
            b = fixture(wide)
            old_section = 152 + (240 if wide else 224)
            short_size = (112 if wide else 96) + 6 * 8
            section = bytes(b[old_section:old_section + 40])
            struct.pack_into('<H', b, 132 + 16, short_size)
            b[152 + short_size:152 + short_size + 40] = section
            self.assertIn(b'declared Debug Directory is unavailable', self.malformed(b).stderr)

    def test_invalid_payload_ranges(self):
        for wide in (False, True):
            for pointer, size in ((0, 40), (0xffffffff, 40), (0x800, 0xffffffff),
                                  (0x11ff, 2), (0x1200, 4)):
                b = fixture(wide)
                record(b, pointer=pointer, size=size)
                self.malformed(b)

    def test_overlay_and_pointer_precedence(self):
        for wide in (False, True):
            for rva in (0, 0x1600, 0xffffffff):
                b = fixture(wide)
                data = codeview(b'NB10', b'overlay.pdb')
                pointer = len(b)
                b.extend(data)
                record(b, pointer=pointer, rva=rva, size=len(data))
                p = self.run_pe(b, '--debug')
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b'PDB: overlay.pdb', p.stdout)
                self.assertIn(b'CodeView: NB10', p.stdout)

    def test_missing_pointer_has_no_rva_fallback(self):
        b = fixture()
        record(b, pointer=0)
        self.malformed(b)

    def test_truncated_codeview(self):
        for wide in (False, True):
            for kind, header_size in ((b'RSDS', 24), (b'NB10', 16)):
                for size in range(header_size + 1):
                    with self.subTest(wide=wide, kind=kind, size=size):
                        b = fixture(wide, codeview(kind))
                        struct.pack_into('<I', b, 0x610, size)
                        self.malformed(b)

    def test_path_terminator_must_be_inside_payload(self):
        for kind in (b'RSDS', b'NB10'):
            data = codeview(kind)
            b = fixture(payload=data)
            struct.pack_into('<I', b, 0x610, len(data) - 1)
            self.malformed(b)

    def test_path_limit_and_empty_path(self):
        for kind in (b'RSDS', b'NB10'):
            for length in (0, 4096, 4097):
                b = fixture()
                data = codeview(kind, b'x' * length)
                pointer = len(b)
                b.extend(data)
                record(b, pointer=pointer, rva=0, size=len(data))
                if length > 4096:
                    self.malformed(b)
                else:
                    p = self.run_pe(b, '--debug')
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertIn(b'PDB: ' + (b'x' * length if length else b'<empty>'), p.stdout)

    def test_sanitize_path_and_unknown_signature(self):
        for kind in (b'RSDS', b'NB10'):
            p = self.run_pe(fixture(payload=codeview(kind, b'a\x1b\n\r\t\xff.pdb')), '--debug')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(b'PDB: a?????.pdb', p.stdout)
            self.assertNotIn(b'\x1b', p.stdout)
        p = self.run_pe(fixture(payload=b'\x1b\n\xff\x01'), '--debug')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'Unsupported CodeView signature: 1B 0A FF 01', p.stdout)
        self.assertNotIn(b'\x1b', p.stdout)

    def test_unknown_signature(self):
        p = self.run_pe(fixture(payload=b'NB09'), '--debug')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'Unsupported CodeView signature', p.stdout)

    def test_multiple_types_and_empty_payloads(self):
        for wide in (False, True):
            b = fixture(wide)
            types = [(1, b'COFF'), (2, b'CODEVIEW'), (4, b'MISC'), (16, b'REPRO'),
                     (17, b'EMBEDDED_PORTABLE_PDB'), (19, b'PDB_CHECKSUM'),
                     (20, b'EX_DLLCHARACTERISTICS'), (0xffffffff, b'UNKNOWN')]
            struct.pack_into('<I', b, directory_offset(wide) + 4, len(types) * 28)
            for i, (kind, _) in enumerate(types):
                record(b, offset=0x600 + i * 28, kind=kind,
                       size=len(codeview()) if kind == 2 else 0)
            p = self.run_pe(b, '--debug')
            self.assertEqual(p.returncode, 0, p.stderr)
            for kind, name in types:
                self.assertIn(name + b' (' + str(kind).encode() + b')', p.stdout)

    def test_bad_non_codeview_payload(self):
        b = fixture()
        record(b, kind=0xffffffff, pointer=0x11ff, size=2)
        self.malformed(b)

    def test_continues_after_bad_payload(self):
        b = fixture()
        struct.pack_into('<I', b, directory_offset(False) + 4, 56)
        record(b, pointer=0xffffffff)
        record(b, offset=0x61c)
        p = self.malformed(b)
        self.assertIn(b'record #1:', p.stderr)
        self.assertIn(b'CodeView: RSDS', p.stdout)

    def test_preserves_entries_before_truncated_record(self):
        b = fixture()
        b[0x11e4:0x1200] = b[0x600:0x61c]
        struct.pack_into('<II', b, directory_offset(False), 0x1fe4, 56)
        self.assertIn(b'CodeView: RSDS', self.malformed(b).stdout)


if __name__ == '__main__':
    unittest.main()
