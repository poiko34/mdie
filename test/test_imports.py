"""Synthetic PE import fixtures, including ILT/IAT and boundary failures."""
import os
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = os.path.abspath(sys.argv.pop(1))


def fixture(wide=False, fallback=False, bound=False):
    b = bytearray(0x1200)
    struct.pack_into('<H', b, 0, 0x5a4d)
    struct.pack_into('<I', b, 60, 128)
    b[128:132] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', b, 132, 0x8664 if wide else 0x14c,
                     1, 0, 0, 0, 240 if wide else 224, 0x102)
    o = 152
    struct.pack_into('<H', b, o, 0x20b if wide else 0x10b)
    struct.pack_into('<Q' if wide else '<I', b, o + (24 if wide else 28),
                     0x140000000 if wide else 0x400000)
    struct.pack_into('<II', b, o + 32, 0x1000, 0x200)
    struct.pack_into('<II', b, o + 56, 0x2000, 0x200)
    struct.pack_into('<I', b, o + (108 if wide else 92), 16)
    directories = o + (112 if wide else 96)
    struct.pack_into('<II', b, directories + 8, 0x1000, 40)
    struct.pack_into('<8sIIIIIIHHI', b, o + (240 if wide else 224),
                     b'.idata', 0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0xc0000040)
    struct.pack_into('<IIIII', b, 0x200, 0 if fallback else 0x1080,
                     0x12345678 if bound else 0, 0, 0x1060, 0x10a0)
    b[0x260:0x260+13] = b'KERNEL32.dll\0'
    fmt = '<QQQ' if wide else '<III'
    flag = 1 << (63 if wide else 31)
    struct.pack_into(fmt, b, 0x280, 0x10c0, flag | 42, 0)
    struct.pack_into(fmt, b, 0x2a0, *( (0x76543210, 0x76544321, 0) if bound else
                                    (0x10c0, flag | 42, 0)))
    struct.pack_into('<H', b, 0x2c0, 7)
    b[0x2c2:0x2c2+12] = b'ExitProcess\0'
    return b


class ImportTests(unittest.TestCase):
    def run_pe(self, data, *flags):
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            return subprocess.run([BINARY, *flags, f.name], capture_output=True, timeout=10)

    def test_named_and_ordinal(self):
        for wide in (False, True):
            for flag in ('-i', '--import'):
                p = self.run_pe(fixture(wide), flag)
                self.assertEqual(p.returncode, 0, p.stderr)
                for text in (b'KERNEL32.dll', b'ExitProcess', b'#42', b'0x000010A0',
                             b'0x000002A0', b'0x000010A8' if wide else b'0x000010A4'):
                    self.assertIn(text, p.stdout)

    def test_optional_and_combinable(self):
        self.assertNotIn(b'Imports / IAT', self.run_pe(fixture()).stdout)
        p = self.run_pe(fixture(), '-i', '-d', '-g')
        self.assertEqual(p.returncode, 0, p.stderr)
        for text in (b'Imports / IAT', b'Data Directories', b'Entropy map'):
            self.assertIn(text, p.stdout)

    def test_no_imports(self):
        b = fixture()
        struct.pack_into('<II', b, 152 + 96 + 8, 0, 0)
        p = self.run_pe(b, '-i')
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'No ordinary imports', p.stdout)

    def test_first_thunk_fallback(self):
        for wide in (False, True):
            p = self.run_pe(fixture(wide, fallback=True), '-i')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(b'FirstThunk fallback', p.stdout)
            self.assertIn(b'ExitProcess', p.stdout)

    def test_bound_imports(self):
        for wide in (False, True):
            for fallback in (False, True):
                p = self.run_pe(fixture(wide, fallback, True), '-i')
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn(b'0x0000000076543210', p.stdout)
                self.assertIn(b'name unavailable' if fallback else b'ExitProcess', p.stdout)
                if fallback:
                    self.assertNotIn(b'ExitProcess', p.stdout)

    def test_bad_ranges(self):
        for field, value in ((0x200, 0xfffffff8), (0x20c, 0x3000),
                             (0x210, 0), (0x210, 0x1ffe), (0x280, 0x1fff)):
            b = fixture()
            struct.pack_into('<I', b, field, value)
            p = self.run_pe(b, '-i')
            self.assertEqual(p.returncode, 2, (field, p.stderr))
            self.assertIn(b'imports:', p.stderr)

    def test_unterminated_descriptor(self):
        b = fixture()
        struct.pack_into('<I', b, 152 + 96 + 12, 20)
        p = self.run_pe(b, '-i')
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'null descriptor', p.stderr)

    def test_missing_thunk_terminator(self):
        b = fixture()
        struct.pack_into('<I', b, 0x200, 0x1ffc)
        struct.pack_into('<I', b, 0x11fc, 0x10c0)
        p = self.run_pe(b, '-i')
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'terminator', p.stderr)

    def test_name_without_null(self):
        b = fixture()
        struct.pack_into('<I', b, 0x280, 0x1ff0)
        b[0x11f0:] = b'x' * 16
        self.assertEqual(self.run_pe(b, '-i').returncode, 2)

    def test_reserved_64bit_thunk_bits(self):
        for thunk in (0x1000010c0, 0x800000010000002a):
            b = fixture(wide=True)
            struct.pack_into('<Q', b, 0x280, thunk)
            self.assertEqual(self.run_pe(b, '-i').returncode, 2)

    def test_terminal_control_characters(self):
        b = fixture()
        b[0x260:0x264] = b'\x1b[2J'
        b[0x2c2:0x2c6] = b'\x1b[2J'
        p = self.run_pe(b, '-i')
        self.assertEqual(p.returncode, 0)
        self.assertNotIn(b'\x1b', p.stdout)
        self.assertIn(b'?[2J', p.stdout)

    def test_iat_terminator_mismatch(self):
        b = fixture()
        struct.pack_into('<I', b, 0x2a8, 1)
        self.assertEqual(self.run_pe(b, '-i').returncode, 2)

    def test_directory_rva_overflow(self):
        b = fixture()
        struct.pack_into('<II', b, 152 + 96 + 8, 0xfffffff0, 40)
        self.assertEqual(self.run_pe(b, '-i').returncode, 2)

    def test_multiple_dlls(self):
        b = fixture()
        struct.pack_into('<I', b, 152 + 96 + 12, 60)
        struct.pack_into('<IIIII', b, 0x214, 0x1080, 0, 0, 0x10e0, 0x10a0)
        b[0x2e0:0x2e0+11] = b'USER32.dll\0'
        p = self.run_pe(b, '-i')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'USER32.dll', p.stdout)
        self.assertEqual(p.stdout.count(b'ExitProcess'), 2)


if __name__ == '__main__':
    unittest.main()
