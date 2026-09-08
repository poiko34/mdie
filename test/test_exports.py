"""EAT regression fixtures with names, aliases, holes and forwarders."""
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest
BINARY = os.path.abspath(sys.argv[1])
helpers = runpy.run_path(os.path.join(os.path.dirname(__file__), 'test_imports.py'))


def fixture(wide=False):
    b=helpers['fixture'](wide)
    # Export directory at RVA 0x1400, file offset 0x600; forwarders within 0x1400..0x1500.
    struct.pack_into('<II',b,152+(112 if wide else 96),0x1400,0x100)
    struct.pack_into('<IIHHIIIIIII',b,0x600,0,0,0,0,0x1490,10,4,2,0x1440,0x1460,0x1470)
    struct.pack_into('<IIII',b,0x640,0x1800,0x1810,0,0x14c0)
    struct.pack_into('<II',b,0x660,0x14a0,0x14b0)
    struct.pack_into('<HH',b,0x670,0,3)
    for off,string in [(0x690,b'demo.dll\0'),(0x6a0,b'NamedExport\0'),
                       (0x6b0,b'Forwarded\0'),(0x6c0,b'KERNEL32.Sleep\0')]:
        b[off:off+len(string)]=string
    return b


class ExportTests(unittest.TestCase):
    def run_pe(self,b,*flags):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b);f.flush()
            return subprocess.run([BINARY,*flags,f.name],capture_output=True,timeout=10)

    def test_named_ordinal_and_forwarder(self):
        for wide in (False,True):
            for flag in ('-e','--export'):
                p=self.run_pe(fixture(wide),flag)
                self.assertEqual(p.returncode,0,p.stderr)
                for text in (b'#10',b'NamedExport',b'#11',b'<ordinal only>',b'#13',
                             b'KERNEL32.Sleep',b'0x00001440',b'0x00001800',b'0x00000A00'):
                    self.assertIn(text,p.stdout)
                self.assertNotIn(b'#12 ',p.stdout)

    def test_optional_and_combinable(self):
        self.assertNotIn(b'Exports / EAT',self.run_pe(fixture()).stdout)
        p=self.run_pe(fixture(),'-e','-i','-d','-H','-g','-c')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'Exports / EAT',p.stdout)
        self.assertIn(b'Imports / IAT',p.stdout)

    def test_no_exports(self):
        b=fixture();struct.pack_into('<II',b,152+96,0,0)
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'No exports.',p.stdout)

    def test_alias(self):
        b=fixture();struct.pack_into('<H',b,0x672,0)
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.count(b'#10 '),2)
        self.assertIn(b'NamedExport',p.stdout)
        self.assertIn(b'Forwarded',p.stdout)

    def test_zero_name_count(self):
        b=fixture();struct.pack_into('<I',b,0x618,0)
        struct.pack_into('<II',b,0x620,0,0)
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(p.stdout.count(b'<ordinal only>'),3)

    def test_empty_table(self):
        b=fixture();struct.pack_into('<IIIII',b,0x614,0,0,0,0,0)
        self.assertEqual(self.run_pe(b,'-e').returncode,0)

    def test_bad_name_index(self):
        for index in (2,4,65535):
            b=fixture();struct.pack_into('<H',b,0x670,index)
            p=self.run_pe(b,'-e')
            self.assertEqual(p.returncode,2)
            self.assertIn(b'exports:',p.stderr)

    def test_invalid_ranges(self):
        for field,val in [(0x61c,0x1ffe),(0x620,0xfffffff0),(0x624,0x2000),
                          (0x60c,0),(0x660,0x1fff),(152+96,0xfffffff0)]:
            b=fixture();struct.pack_into('<I',b,field,val)
            p=self.run_pe(b,'-e')
            self.assertEqual(p.returncode,2,(field,p.stderr))
            self.assertIn(b'exports:',p.stderr)

    def test_ordinal_overflow(self):
        b=fixture();struct.pack_into('<I',b,0x610,0xfffffffe)
        self.assertEqual(self.run_pe(b,'-e').returncode,2)

    def test_counts_limited(self):
        for field in (0x614,0x618):
            b=fixture();struct.pack_into('<I',b,field,65537)
            p=self.run_pe(b,'-e')
            self.assertEqual(p.returncode,2)
            self.assertIn(b'limit',p.stderr)

    def test_forwarder_ordinal(self):
        b=fixture();b[0x6c0:0x6d0]=b'NTDLL.#123\0'+bytes(5)
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'NTDLL.#123',p.stdout)

    def test_forwarder_must_terminate_in_directory(self):
        b=fixture();struct.pack_into('<I',b,0x64c,0x14fc)
        b[0x6fc:0x704]=b'a.bbbbbb'
        self.assertEqual(self.run_pe(b,'-e').returncode,2)

    def test_exported_virtual_data(self):
        b=fixture();struct.pack_into('<I',b,376+8,0x2000)
        struct.pack_into('<I',b,152+56,0x3000)
        struct.pack_into('<I',b,0x644,0x2100)
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'File:   N/A',p.stdout)

    def test_outside_image(self):
        b=fixture();struct.pack_into('<I',b,0x644,0xffffffff)
        self.assertEqual(self.run_pe(b,'-e').returncode,2)

    def test_unmapped_target_within_image(self):
        b=fixture();struct.pack_into('<I',b,152+56,0x4000)
        struct.pack_into('<I',b,0x644,0x3100)
        self.assertEqual(self.run_pe(b,'-e').returncode,2)

    def test_sanitize_names(self):
        b=fixture()
        for off in (0x690,0x6a0):b[off:off+4]=b'\x1b[2J'
        p=self.run_pe(b,'-e')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertNotIn(b'\x1b',p.stdout)


if __name__=='__main__':unittest.main()
