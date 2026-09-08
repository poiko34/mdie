"""End-to-end parser regressions; no Windows compiler or binary fixtures needed."""
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = os.path.abspath(sys.argv.pop(1))


def fixture(pe64=False, raw=512, size=512, name=b'.text', ep=4096):
    b = bytearray(512 + size)
    struct.pack_into('<H', b, 0, 0x5A4D)
    struct.pack_into('<I', b, 60, 128)
    b[128:132] = b'PE\0\0'
    optional_size = 240 if pe64 else 224
    struct.pack_into('<HHIIIHH', b, 132, 0x8664 if pe64 else 0x14C,
                     1, 0, 0, 0, optional_size, 0x102)
    o = 152
    struct.pack_into('<H', b, o, 0x20B if pe64 else 0x10B)
    struct.pack_into('<I', b, o + 16, ep)
    struct.pack_into('<Q' if pe64 else '<I', b, o + (24 if pe64 else 28),
                     0x140000000 if pe64 else 0x400000)
    struct.pack_into('<II', b, o + 32, 4096, 512)
    struct.pack_into('<II', b, o + 56, 0x10000, 512)
    struct.pack_into('<I', b, o + (108 if pe64 else 92), 16)
    struct.pack_into('<8sIIIIIIHHI', b, o + optional_size,
                     name, size, 4096, size, raw, 0, 0, 0, 0, 0x60000020)
    b[512:] = (bytes(range(256)) * ((size + 255) // 256))[:size]
    return b


class ParserTests(unittest.TestCase):
    def run_pe(self, data, *flags, width=None):
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            if width is None:
                return subprocess.run([BINARY, *flags, f.name], capture_output=True, timeout=10)
            # A PTY makes ioctl(TIOCGWINSZ) exercise actual width handling.
            import fcntl
            import pty
            import termios
            master, slave = pty.openpty()
            try:
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, width, 0, 0))
                proc = subprocess.Popen([BINARY, *flags, f.name], stdout=slave, stderr=subprocess.PIPE)
                os.close(slave)
                slave = -1
                chunks = []
                while True:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                _, err = proc.communicate(timeout=10)
                return subprocess.CompletedProcess(proc.args, proc.returncode, b''.join(chunks), err)
            finally:
                os.close(master)
                if slave >= 0:
                    os.close(slave)

    def test_pe32_and_pe64(self):
        for wide in (False, True):
            p = self.run_pe(fixture(pe64=wide), '-d')
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(b'0x00000200', p.stdout)
            self.assertIn(b'0x0000000140000000' if wide else b'0x0000000000400000', p.stdout)

    def test_raw_beyond_eof(self):
        p = self.run_pe(fixture(raw=0x100000))
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'section #1', p.stderr)
        self.assertIn(b'EP File Offset:  N/A', p.stdout)

    def test_raw_partial_beyond_eof(self):
        p = self.run_pe(fixture()[:-1])
        self.assertEqual(p.returncode, 2)
        self.assertIn(b'raw data', p.stderr)

    def test_truncated_headers(self):
        for n in (0, 1, 60, 130, 151, 200, 375, 400):
            p = self.run_pe(fixture()[:n])
            self.assertEqual(p.returncode, 1, n)
            self.assertTrue(p.stderr, n)

    def test_header_rva(self):
        p = self.run_pe(fixture(ep=0x40))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(b'EP File Offset:  0x00000040', p.stdout)

    def test_no_entry_point(self):
        p = self.run_pe(fixture(ep=0))
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'EP File Offset:  N/A', p.stdout)

    def test_name_sanitization(self):
        for name in (b'\x1b[2Jtext', b'ab\n\r\t\xffzz', b'12345678'):
            for flags in ((), ('-g',)):
                p = self.run_pe(fixture(name=name), *flags)
                cleaned = re.sub(rb'\x1b\[[0-9;]*m', b'', p.stdout)
                self.assertNotIn(b'\x1b', cleaned)
                self.assertNotIn(b'\xff', cleaned)
                self.assertNotIn(b'\t', cleaned)
                self.assertEqual(p.returncode, 0)

    def test_negative_lfanew(self):
        b = fixture()
        struct.pack_into('<I', b, 60, 0xFFFFFFFF)
        p = self.run_pe(b)
        self.assertEqual(p.returncode, 1)
        self.assertIn(b'e_lfanew', p.stderr)

    def test_short_optional_header(self):
        b = fixture()
        struct.pack_into('<H', b, 148, 1)
        self.assertEqual(self.run_pe(b).returncode, 1)

    def test_truncated_directory_declaration(self):
        b = fixture()
        struct.pack_into('<I', b, 152 + 92, 17)
        for flags in ((), ('-d',)):
            p = self.run_pe(b, *flags)
            self.assertEqual(p.returncode, 2)
            self.assertIn(b'Data Directory', p.stderr)

    def test_fixed_entropy_windows(self):
        data = fixture(size=8192)
        # A zero-filled window followed by a uniformly distributed window.
        data[512:4608] = bytes(4096)
        for width in (40, 120):
            p = self.run_pe(data, '-g', width=width)
            graph_row = [row for row in p.stdout.splitlines() if row.startswith(b'.text')][-1]
            self.assertEqual(graph_row.count(b'\x1b[38;2;'), 2)
            self.assertIn(b'\x1b[38;2;0;0;139m', graph_row)
            self.assertIn(b'\x1b[38;2;255;0;0m', graph_row)

    def test_incomplete_window(self):
        p = self.run_pe(fixture(), '-g')
        self.assertIn(b'.text   ~', p.stdout)

    def test_extra_argument(self):
        p = self.run_pe(fixture(), 'unexpected.exe')
        self.assertEqual(p.returncode, 1)
        self.assertIn(b'extra input', p.stderr)


if __name__ == '__main__':
    unittest.main()
