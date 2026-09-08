"""Positive fixtures plus negative/conflicting build-tool evidence."""
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = os.path.abspath(sys.argv[1])
fixtures = runpy.run_path(os.path.join(os.path.dirname(__file__), 'test_imports.py'))
fixture = fixtures['fixture']


def sample(text=b'', wide=False):
    b = fixture(wide)
    b[0x600:0x600+len(text)] = text
    return b


def rich_file(valid=True):
    b = sample()
    def rol(v,n):
        n &= 31
        return ((v << n) | (v >> ((32-n)&31))) & 0xffffffff
    key = 64
    for i in range(64):
        if not 0x3c <= i < 0x40:
            key = (key + rol(b[i],i)) & 0xffffffff
    product,count=0x01020001,1
    key=(key+rol(product,count))&0xffffffff
    struct.pack_into('<IIIIII',b,64,0x536e6144^key,key,key,key,product^key,count^key)
    b[88:92]=b'Rich'
    struct.pack_into('<I',b,92,key if valid else key^1)
    return b


class CompilerTests(unittest.TestCase):
    def run_pe(self, b, *flags):
        with tempfile.NamedTemporaryFile() as f:
            f.write(b);f.flush()
            return subprocess.run([BINARY,*flags,f.name],capture_output=True,timeout=20)

    def test_unknown(self):
        p=self.run_pe(sample(),'-c')
        self.assertEqual(p.returncode,0,p.stderr)
        for x in (b'Compiler: unknown',b'Linker: unknown',b'Runtime: unknown'):
            self.assertIn(x,p.stdout)

    def test_opt_in_and_combination(self):
        normal=self.run_pe(sample(b'GCC: (GNU) 14\0Mingw-w64 runtime failure:\0'))
        self.assertEqual(normal.returncode,0,normal.stderr)
        self.assertIn(b'Compiler:        GCC / MinGW (likely)',normal.stdout)
        self.assertIn(b'Linker:          unknown',normal.stdout)
        self.assertIn(b'Runtime:         unknown',normal.stdout)
        self.assertNotIn(b'Evidence:',normal.stdout)
        self.assertNotIn(b'Build tool detection',normal.stdout)
        p=self.run_pe(sample(),'--compiler','-i','-d','-g')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn(b'Build tool detection',p.stdout)
        self.assertIn(b'Imports / IAT',p.stdout)

    def test_gcc_mingw(self):
        p=self.run_pe(sample(b'GCC: (GNU) 14.2\0Mingw-w64 runtime failure:\0'),'-c')
        self.assertIn(b'Compiler: GCC candidate [medium]',p.stdout)
        self.assertIn(b'Toolchain: MinGW GCC-compatible',p.stdout)

    def test_clang_mingw(self):
        p=self.run_pe(sample(b'clang version 19.1\0Mingw-w64 runtime failure:\0llvm-mingw\0'),'-c')
        self.assertIn(b'Compiler: LLVM/Clang candidate',p.stdout)
        self.assertIn(b'LLVM-MinGW distribution unconfirmed',p.stdout)

    def test_msvc_banner(self):
        p=self.run_pe(sample(b'Microsoft (R) Optimizing Compiler\0'),'-c')
        self.assertIn(b'Compiler: MSVC candidate',p.stdout)
        self.assertIn(b'Linker: unknown',p.stdout)

    def test_linker_markers_do_not_imply_compiler(self):
        for marker,name in ((b'LLD Linker\0',b'LLVM LLD'),(b'GNU ld (GNU Binutils)\0',b'GNU ld')):
            p=self.run_pe(sample(marker),'-c')
            self.assertIn(b'Linker: '+name+b' candidate [low]',p.stdout)
            self.assertIn(b'Compiler: unknown',p.stdout)

    def test_version_and_crt_do_not_identify_compiler(self):
        b=sample(b'msvcrt.dll\0VCRUNTIME140.dll\0ucrtbase.dll\0.pdb\0')
        b[154]=14;b[155]=40
        p=self.run_pe(b,'-c')
        self.assertIn(b'Compiler: unknown',p.stdout)
        self.assertIn(b'Linker: unknown',p.stdout)

    def test_mixed_compiler_markers(self):
        p=self.run_pe(sample(b'GCC: (GNU) 14\0clang version 19\0'),'-c')
        self.assertIn(b'Compiler: mixed evidence',p.stdout)

    def test_rich_checksum(self):
        p=self.run_pe(rich_file(),'-c')
        self.assertIn(b'Linker: Microsoft LINK-compatible',p.stdout)
        self.assertIn(b'Compiler: unknown',p.stdout)
        p=self.run_pe(rich_file(False),'-c')
        self.assertIn(b'failed structural/checksum checks',p.stdout)
        self.assertIn(b'Linker: unknown',p.stdout)

    def test_go_modern_buildinfo(self):
        for wide in (False,True):
            b=sample(wide=wide)
            b[0x600:0x620]=b'\xff Go buildinf:'+bytes([8 if wide else 4,2])+bytes(16)
            version=b'go1.23.4'
            b[0x620:0x621+len(version)]=bytes([len(version)])+version
            p=self.run_pe(b,'-c')
            self.assertIn(b'Runtime: Go build-info go1.23.4 [high]',p.stdout)

    def test_go_plain_string_not_enough(self):
        p=self.run_pe(sample(b'go1.23.4\0runtime.main\0'),'-c')
        self.assertIn(b'Runtime: unknown',p.stdout)

    def test_go_old_layout_not_overclaimed(self):
        b=sample(b'\xff Go buildinf:'+bytes([8,0])+bytes(16))
        p=self.run_pe(b,'-c')
        self.assertIn(b'possible Go [low',p.stdout)
        self.assertIn(b'Compiler: unknown',p.stdout)

    def test_clr_metadata(self):
        for wide in (False,True):
            b=sample(wide=wide)
            struct.pack_into('<II',b,152+(112 if wide else 96)+14*8,0x1100,72)
            struct.pack_into('<IHHII',b,0x300,72,2,5,0x1180,128)
            struct.pack_into('<4sHHII',b,0x380,b'BSJB',1,1,0,12)
            b[0x390:0x39c]=b'v4.0.30319\0\0'
            p=self.run_pe(b,'-c')
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertIn(b'Runtime: .NET/CLR metadata [high]',p.stdout)
            self.assertIn(b'source language unknown',p.stdout)

    def test_fake_clr_directory(self):
        b=sample()
        struct.pack_into('<II',b,152+96+14*8,0x1100,72)
        p=self.run_pe(b,'-c')
        self.assertEqual(p.returncode,2)
        self.assertNotIn(b'.NET/CLR metadata [high]',p.stdout)

    def test_overlay_ignored(self):
        b=sample()+b'clang version 99.0\0'
        p=self.run_pe(b,'-c')
        self.assertIn(b'Compiler: unknown',p.stdout)

    def test_scan_budget(self):
        b=sample();b.extend(bytes(17*1024*1024))
        struct.pack_into('<I',b,376+16,len(b)-512)
        p=self.run_pe(b,'-c')
        self.assertEqual(p.returncode,2)
        self.assertIn(b'Scan: incomplete',p.stdout)

    def test_marker_cross_chunk(self):
        b=sample();b.extend(bytes(70000))
        struct.pack_into('<I',b,376+16,len(b)-512)
        off=512+65536-5
        b[off:off+18]=b'clang version 19.0\0'
        p=self.run_pe(b,'-c')
        self.assertIn(b'Compiler: LLVM/Clang candidate',p.stdout)


if __name__ == '__main__':
    unittest.main()
