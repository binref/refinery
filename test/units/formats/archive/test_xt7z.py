import base64
import codecs
import struct
import zlib

from ... import TestUnitBase


from refinery.lib.un7z import SzArchive, SzCorruptArchive, SzPasswordRequired
from refinery.lib.un7z.headers import parse_signature_header, SIGNATURE


class Test7zipFileExtractor(TestUnitBase):

    TESTFILE1_CONTENT = 'Hello, this is a test file for 7zip archive testing.'
    TESTFILE2_CONTENT = 'Second file for testing purposes.'

    def test_simple_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAT9xtacpQAAAAAAAAAiAAAAAAAAAEerl+XBRlkrcJwwoqgijCyuEh0SqLfjamv2F2vNJGFGyHDfpAAAgTMHrg/QDrA8'
            'nzkQnJ+m1TPasi6xAvSHzZaZrISLD+EsvFULZ44Kf7Ewy47PApbKruXCaOSUsjzeqpG8VBcx66h2cV/lnGDfUjtVsyGBHmmmTaSI'
            '/atXtuwiN5mGrqyFZTC/V2VEohWua1Yk1K+jXy+32hBwnK2clyr3rN5LAbv5g2wXBiABCYCFAAcLAQABIwMBAQVdABAAAAyAlgoB'
            'ouB4BAAA'
        )
        self.assertEqual(str(data | self.load('foo.txt', pwd='boom')), 'binary')
        self.assertEqual(str(data | self.load('bar.txt', pwd='boom')), 'refinery')
        self.assertEqual(str(data | self.load(pwd='boom')), 'refinery\nbinary')

    def test_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAQXa3/2swAAAAAAAAAhAAAAAAAAAKsDpUngAFQARV0AJBlJmG8WAoyLktVrywEc3aGe27pL8HOviCZKe7dipsZBOMuv'
            'PGa8aOyjedMPAUT2o/fNEUBnTSYF/RKO6sYV5xPJZycAAAAAgTMHrg/Smro9QMCQ0v99aU2Hej2pCKJZ2zAHVVF91CzaMd7DmZYE'
            'RTgR3bxbCIU3T5S8pIeKXSNBjRg66UYcjkRHR0XA1fUMSBeSRGTLKWnV0rOoggmSTW+nXaMlCh6sNxF03hcGTQEJZgAHCwEAASMD'
            'AQEFXQAQAAAMgI4KAbh91MYAAA=='
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_copy_archive(self):
        data = base64.b64decode(
            'N3q8ryccAATV3ry4uAAAAAAAAAAhAAAAAAAAAPmK4mhIZWxsbywgdGhpcyBpcyBhIHRlc3QgZmlsZSBmb3IgN3ppcCBhcmNoaXZl'
            'IHRlc3RpbmcuU2Vjb25kIGZpbGUgZm9yIHRlc3RpbmcgcHVycG9zZXMuAACBMweuMZteOBUeTiwYUilXw9rvnuUG3YxlvmJASy/I'
            'RcLkJHEsq8dSAXwG960+okv09mOGIoYD0xKQ9cRRAhRmAoIfKshbG4ezwH/CeCc2+JwGQiGCBuwyhlFT4lCwAVcSFwZVAQljAAcL'
            'AQABIwMBAQVdABAAAAyAjgoBVneb0wAA'
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_bzip2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAASi3/WtzQAAAAAAAAAhAAAAAAAAAB4cmg5CWmg5MUFZJlNZ7/FvQgAACJ+AQAUAgABACAAv5d8QIABISqNNNqZHqaZl'
            'MDUDQ0AA0uzP4pGqpGbylTs3ER3MWtSu0wQhdiBnn8wLXLQwzHXYOA4hCTlqu8BYiSfF3JFOFCQ7/FvQgAAAgTMHrg/T9x39QMCQ'
            'zuXLdvZJSIc4yQfj74r1UdaYCw6QpvV7JtUPVRY2Uz1BTAOycUGUotfFN3hgMwv8Ps0MgqS9znjZdrxQKpouuNw8iLUVHpWMPyE4'
            '0bnXpQOqVksoU0ayFwZoAQllAAcLAQABIwMBAQVdABAAAAyAjgoBjYC0JwAA'
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_deflate_archive(self):
        data = base64.b64decode(
            'N3q8ryccAATt5tfzrgAAAAAAAAAhAAAAAAAAADZlwXg9ikEKgDAMBL+yD5Be/YJ3X1BqagOlCUn04OsVQWFOM7NQ7zIhGjseMoI8'
            'ULkTqhjmixXZSuOT3sRjTysVGds/fR56mIqTpxsAAIEzB64P0lo1/UDAkM7lyzKfD+fbU7s7uFPwYKo7zOo6/Uj9PjzSsEZ7nmBD'
            'gAjsHLAgzCKZzSxgSRKvvwmMFQFr8X3yOFNg6n4GfbnRfGm842RmcJ4KpvQU3kOUaSkT1ty7MgAXBkgBCWYABwsBAAEjAwEBBV0A'
            'EAAADICOCgGSSMI5AAA='
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_bcj_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAASemVy6WwEAAAAAAAAiAAAAAAAAAPIagZfgAWAA2V0AJpaOcAAX9+wFu+r0/5QBL0TuTr0I2yvxU9Plq7xO/c6hY0BI'
            'QykUfFcxmm1nJkkaGBLomg0YBj0sy/fHRpK4HzK+n2a7pvMs7BoPjYRR4KMdxlRcAmPnIxssdTsViK93hg6CDnFX3993m5Mx8Cdy'
            'sqgbdjmgIuHU/hAgDwEbHHEK0MFX9FapG8VxumqEuT3nPhDRaCxUlYb6lavOen3DTOPgnVNLDHxB9kA+nEpOyxx4VnQ4lfuujXqo'
            'k7i3D2S9A8FQ5BAliUOdji17F5uUn+I340aXXJ2AcgAAAIEzB64P1THNtWclRSgpPiuA+7TQfN5mduIuXz7UF31PG57homE+86d8'
            'hQKF3fC+JP0UadcypUOH6Ww2xucc1MTot1deug/A4YFZdqUkN2GjWInOvbMNUA0DXa2WV1s78S+ECgg2wXefHQY3OToME9r27ihe'
            'auMhABcGgOEBCXoABwsBAAEjAwEBBV0AEAAADICOCgFmALAlAAA='
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        stub = bytes(data | self.load('stub.exe'))
        self.assertTrue(stub.startswith(b'MZ'))
        self.assertEqual(len(stub), 301)

    def test_delta_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAARLM8XMxwAAAAAAAAAhAAAAAAAAAFo57FYBAFRIZWxsJ8e0CPk9U6wBCq1BtwFFElSsAfb4Rbr9Aw0A0Qv3UOnnCfNI'
            'CAQCuAvvDlT1CfS66vf8QRv/vff7CEW6/QMNAA72AVT1CfSsBwcLUP/+8wO/AAAAgTMHrg/TNZE9QLuUZBziaOwpkP6J08w/fkVs'
            '+HyPG7SZpyLx59aGTKBe/Ss/5caZg05niOXLSCL3QC1zKPvwdH3X1Qmq4mYeLq9lugTIg//B7nnrU+BeKBDCFWB5aZ5y8EAchzqu'
            'WHRxSHIAFwZZAQluAAcLAQABIwMBAQVdABAAAAyAngoBiR1okwAA'
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_ppmd_archive(self):
        data = base64.b64decode(
            'N3q8ryccAATTe/ZPpgAAAAAAAAAhAAAAAAAAAA30yVQASB9MFwg3MfvtCvPCySuxiY3rdpKM9ADX4DWIOyCqqLmSMhVzfYuy7Y2q'
            'wAGxqb3VwQFI9l7OLaM1uwVWAAAAgTMHrg/R1LcIoJCgd7D++v1R570Z1NON1fIMqFjQwWq/jo/5bzPedJOEHN8DUvvsJ47Iw1TX'
            'fBhj3kPcfVemL28H4h7KmrOxqUOekep67+BWmI+4rrO0rrx0gfrj802VlJPbiT0AFwY+AQloAAcLAQABIwMBAQVdABAAAAyAjgoB'
            'O3I9sQAA'
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_deflate64_archive(self):
        data = base64.b64decode(
            'N3q8ryccAASXzpbMrgAAAAAAAAAhAAAAAAAAACYfpAU9ikEKgDAMBL+yD5Be/YJ3X1BqagOlCUn04OsVQWFOM7NQ7zIhGjseMoI8'
            'ULkTqhjmixXZSuOT3sRjTysVGds/fR56mIqTpxsAAIEzB64P0lo1/UDAkM7l30UpeDKqr9MF9yyL2dyBv0cQc5Iu4RhHoFIz1b7U'
            'AjikBrUQdMTrEeqXY4mf5m4yijjl3nVzt2iWATkcaESi5zJUI7qqZBfyaSh7KWwQaqg3EkajqYAXBkgBCWYABwsBAAEjAwEBBV0A'
            'EAAADICOCgHJWZxoAAA='
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile2.txt')),
            self.TESTFILE2_CONTENT,
        )

    def test_archive_with_directory(self):
        data = base64.b64decode(
            'N3q8ryccAASj9eqasgAAAAAAAAAhAAAAAAAAAIrd+dzgAGcANV0AJBlJmG8WAoyLktVrywEc3aGe27pL8HOviCZKe7dipsZBOMuv'
            'PGa8aOyjedMPAUWAAGlONoAAAACBMweuD9HFlIygkKB3XsVAGJoF8qhc9LcNimSxiImV4QooX5zjYBk68bRjTQofjhWL9NnJgPfg'
            'rHvVrBSLCWUgvhx+he+3B5EUYJpq1wJxTDXNMFxjz7XiRR8TreI4f1hxM71tb3OgB1jstYWMTQtrt5wAFwY9AQl1AAcLAQABIwMB'
            'AQVdABAAAAyAsgoBMAaqtwAA'
        )
        self.assertEqual(
            str(data | self.load('subdir/testfile.txt')),
            self.TESTFILE1_CONTENT,
        )
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )

    def test_arm_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAATIIzSCDQIAAAAAAABaAAAAAAAAADsdSuDgBJsCBV0AP5FFhGg73t6mDyPw1CQZWyyYzE3Vdn+mon5ixJIUBIQpY02F'
            'v2lJe6GxnzJLXGwsZJXZpzb+UdXHnKUPe82PLdAlZG61KKh38/6d7qdPLD/+37ynHMn+cOMTSxCfH6DQ7WoWTTgGOIezueSGpxlO'
            'p7XgdeAZmxhb3EsSxDukg5TAxZ/pJqZIWAr4T8o+92+3kZuj+ztgmGw4/jIQ5eLuwmBfH+1V74US3b+J/IVl3sy5BJF+MkzUTr2z'
            'eVkjXHemHA0auT7L2LU7v77AlPg57roXNGAQXQLgrxPAtwa0rfz1PakECrtDd1Q6peOwykq1Faew2FCGjEcV5Nn7f9Th36hXEP46'
            'AF65vGUUaHxhBf9KWxLUQjesZRWMJh3KNNE8g4SQzv5yX4/ed5ZLofFKECqUnSYjjqGR5at2sbwnq/WlJKXsD8NGm7xAlZG1mBrk'
            '9YEXV/R39bHvjJmowx8cG+RfPdrP03d1dnfbRNmn6A7aCZpcAw/p7r5sOvYehaMMZTN/BUSSJ/mxK4PwiAXexGLq/Wyy1QwYGPhG'
            'NjCq7fMwO65OU9bG1YbWH+4zVXfv3fnIKUMnN/yfcwQ8FWgXU46QsgXBC90CFPu+c0O32IaVUVkgraSzrh0pu22K/xKEQ6kRwhgm'
            '3n2m1rhIZ5ToBzfu7nVuv2ThZRU0nor3XCWnblUAAAABBAYAAQmCDQAHCwEAAiEhAQAEAwMFAQEADISchJwACAoBDQOIhwAABQEZ'
            'AQAREQBhAHIAbQAuAGUAbABmAAAAGQIAABQKAQA6istmcbLcARUGAQAgAAAAAAA='
        )
        elf = bytes(data | self.load('arm.elf'))
        self.assertTrue(elf.startswith(b'\x7fELF'))
        self.assertEqual(len(elf), 1180)

    def test_arm64_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAT3rJk6JQEAAAAAAABaAAAAAAAAAF12mbTgAycBHV0AP5FFhGg9iabaisyW0qLC1fpGXTDqec03OekZ8hDF60sU9uwf'
            'g5Av/NmfgxPBYgkCCk31HB5WelVrwUBJ8HB88sf0w814XdTzJK4FiO8B0Vwi3f74+P2RlKMuRvYTR6l1tsJwQ96j7DhEXC+Xj+k'
            'Hqx+Qo6uUraD/OZI1RUIf5WOpeo2Ul1G4D5mbRDmT0CE93Uv15IvWZeF3k42u/RZr4n+xasSfOqIz38IXUSIkI8DFhGLf2X5W75'
            'Q8Cd+OPpwk3nh7cbbsVMJDmJUkN698jgrr19kw027oTDEIc48uXrx+3rWoia1GWIq8F/58V5AsPcp4FkvDwVADti7kBKKLLx2rM'
            'CRERDTUORQDQPCvtvSRDs2QRJOURR44h4AAAAEEBgABCYElAAcLAQACISEBAAEKAQAMgyiDKAAICgGxfcZQAAAFARkEAAAAABEV'
            'AGEAcgBtADYANAAuAGUAbABmAAAAFAoBANSkby/7stwBFQYBACAAAAAAAA=='
        )
        elf = bytes(data | self.load('arm64.elf'))
        self.assertTrue(elf.startswith(b'\x7fELF'))
        self.assertEqual(len(elf), 808)

    def test_armt_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAARUoHhj/wEAAAAAAABaAAAAAAAAACyYlHbgBF8B910AP5FFhGg73t6mDyPw1CQZ4obAtK/pg9mVj8LWTfht6u/3ELYp'
            'ZjYMYgx/HW6rIZoE3z3NYYqq4q0gTUvo4HY1p6/IpdbFB0vhQmyyYku331AQiRCbFIumn7x+o8KfoNA8Wbfk/WjXms12xc9tsCap'
            'S8SisVKvIPuWg4rVnvaUCJumKl+wA144GZyTD5Py/KCT//UJP3jCYxOC3+hHHbBMbRDHj/RgGmuFGgKuZcHGXRJNePgyiVFMiRdj'
            '5PfFXhBjNlvN1kvyRb6T6Us1BGs28dTwxZxZGpML2EOPzR07xRWy0Bbtwnvdi1U+8YCnLHqqg5Yr7gaxHR0dWQuc6d4UCpwww+/a'
            'pKk+fRf5Acph4o+Sv88Ss4N3TbSdrajWoInYtBaTTMzt2IQ0gUN/i9RKc8R0z+NdnKppQK4FHgLE9ymfyh/lbZHfRBwyGRk1JK8/'
            'ngpHpWB7ZoP0Gp3zxIZrejg2Mazt8oI+r8kE6xoTLVvJYTMKRDU2Lg9NABckVGUPHZRIwE7ZvrWgJv0CrkwbIiF6MMoqDA9Pqs2J'
            '0xjmMfnPjc+PXij+QKuR6GSjamLCdpUtznK44KgF8FMEdGUMWVvk1oeqguGxxQl3i9JGnVt0uFUmOTwnSUDAZueEjH2peQ0BcOu7'
            'l4G9pTFjilotvOesCLBX3QAAAQQGAAEJgf8ABwsBAAIhIQEABAMDBwEBAAyEYIRgAAgKASH0Qu0AAAUBGQEAERMAYQByAG0AdAAu'
            'AGUAbABmAAAAGQAUCgEAN0oHZ3Gy3AEVBgEAIAAAAAAA'
        )
        elf = bytes(data | self.load('armt.elf'))
        self.assertTrue(elf.startswith(b'\x7fELF'))
        self.assertEqual(len(elf), 1120)

    def test_ppc_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAASfEOzHDgIAAAAAAABaAAAAAAAAAJOANNDgBH8CBl0AP5FFhGg0igkKQGKupMuxyMT5+Gev27eWFPBVL+RskG25oAMP'
            '3baUKfFTyRddGqZP+TE9aKkTCbLVjwOEjB6EZMJ+2j0zm+VUvHcl4Xsc3A9HURVV6tIxfPcPMITBzIonhzarF5Fcb9GloymeHOdt'
            'cbsGim1gRsB/lNIgVawZM6E7fDynfI0NPtQnOJXydUJQWElhP2G9aRwFTYcI01KmSN/+8E4LfnQ8629d1MdG9xAkrc6OxPL/vGs2'
            'u9h58RKKjlFZHPCgUjX0szv5vgzRwkcsU2kHSxPZ2DefJFTcQ3hGQoHetZdMd+8FcK15MqySjhDQKWiuhcuW1fCf8iKJDFC2ofDa'
            'XfYF++CYj8WNjkSsZaw2DeOe6JrJt2+rffvqYFeXvte+5RyunFw1cvhSAtoMcqB6mrAkOOvRCnr7yUToUKY0F0MWc9eac00sgARp'
            'Zn1jU2fayKadmM09ZAOBuYActQlrVsNQtfq1WwDR3fpiF8tJUNt0UA0OcwD2u5g1QzuG+pz0tS2CwXDpoNmYumAsXBID15oLZUCr'
            'OWm3M/oNU6nPFQhSS9tWBNSU4ML2yXnu0o2zLYKmMrUWaCQbpYNWpte504q67UPTwqnaY34gUjNvraKt7ei9IeXnFKm1wgQwm7oa'
            'iZV6tF0CLvpESHLv2RtSHpHhAXU0fI00AsG1aottLfUAAQQGAAEJgg4ABwsBAAIhIQEABAMDAgUBAAyEgISAAAgKAZBXShEAAAUB'
            'GQEAEREAcABwAGMALgBlAGwAZgAAABkCAAAUCgEAvXU+Z3Gy3AEVBgEAIAAAAAAA'
        )
        elf = bytes(data | self.load('ppc.elf'))
        self.assertTrue(elf.startswith(b'\x7fELF'))
        self.assertEqual(len(elf), 1152)

    def test_sparc_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAASm5BGZxwEAAAAAAABaAAAAAAAAAP+jkpfgBS8Bv10AP5FFhGhEVFTiWxGbpUpBeHf01BDZmzmxB7Vha2AvsB6G4/7/'
            'c0UPIfUujZQBvpj9vkYJoT0qS9OcdelrsEgOVKUSUlibKW5oTZmwClWpOe8FHGw1OQq3PiFRxhTt9aNcuAn696pEnCobPB1qXoif'
            'vbsooIODKf44nGDcWEtYBHfeTQ3IC6g7MgzywWe0Vuhc8RNqOJ06lYoltay6BzRCspS+aqkiVXrCu9TLjXP9SCMbWz9wvU5UYIsr'
            'Oq181+N+2TPPHgeRLSBzPOszWH+TK2mR/oDzTiRjXiNBKLJi0JCT8q4dLNj4Fg2iVWgq1K396drHGdop+m8rZ6AwswsYHOAkgugd'
            'zLyY41pOHvb9UFckhkuHEutMZn0cqcoqbKZ3cuytRSVzL4cXq+NFcNy+UQ2MNykgOFwUBkBgGgx0kWFbnuWatZSzCdCPapCeqXzv'
            'TTxUiIt2ejCvx/JfLw4kQqk5XNK31YClW00UFC7bblP5O0EeF+FZeiiZZ7CfIOmAzDOvNqc2XS9V/OF2VDCPzvRA0Ki+/nMH+wOz'
            'CrfdMQtNfcvwjk9K8fDEDPDPH6Zzpys+HFSmc5JNG4IgGIPKAAEEBgABCYHHAAcLAQACISEBAAQDAwgFAQAMhTCFMAAICgFdAMMT'
            'AAAFARkBABEVAHMAcABhAHIAYwAuAGUAbABmAAAAFAoBALKjc2dxstwBFQYBACAAAAAAAA=='
        )
        elf = bytes(data | self.load('sparc.elf'))
        self.assertTrue(elf.startswith(b'\x7fELF'))
        self.assertEqual(len(elf), 1328)

    def test_ia64_lzma2_archive(self):
        data = self.download_sample('93e4a4ef84920e4223ad429fb4a95527855d7769e73b63010e7195fdd4e2f662')
        pe = bytes(data | self.load('wmisecur.exe'))
        self.assertTrue(pe.startswith(b'MZ'))
        self.assertEqual(len(pe), 40408)

    def test_bcj2_lzma2_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAT8KfEPfQEAAAAAAAAjAAAAAAAAAATKamABAN0BANngAVQA0l0AJpaOcAAX9+wFu+r0/5QBL0TuTr0I2yvxU9Plq7xO'
            '/c6hY0BIQykUfFcxmm1nJkkaGBLomg0YBj0sy/fHRpK4HzK+n2a7pvMs7BoPjYRR4KMdxlRcAmPnIxssdTsViK93hg6CDnFX3993'
            'm5Mx8CdysqgbdjmgIuHU/hAgDpaO/JGmsBKGag7zPfXX72oZ74A/pF6OlddWk3rd1AvaeCHdGklVyz6Ub3P5GtHGJJUS6D3bGur0'
            'TskdvL7F+6qE8WD0erp3z3pd9jmlcS7n9a3o4srtAAAAAAAA+QAAARIAAAEMAK///AAAAIEzB65txXT13tdVOaMRmA3Zt/g0LjsN'
            'co2gs8PiPx6Sz3Z8q9iL+11S4mF5ZdFIQBYXcovhJGH+seOxK7pXD9CD4+sQBnQ5FMk17RKJq53GQGCxFtiUKjcTlnwaWvI3zLyg'
            'LeXW7ydsq6i4H54N8UYmNlhoVuwryFz6N3VmfblgcX+RCK3RWQAXBoDzAQmAigAHCwEAASMDAQEFXQAQAAAMgK4KAQhBETwAAA=='
        )
        stub = bytes(data | self.load('stub.exe'))
        self.assertTrue(stub.startswith(b'MZ'))
        self.assertEqual(len(stub), 301)
        self.assertEqual(
            str(data | self.load('testfile.txt')),
            self.TESTFILE1_CONTENT,
        )


class TestUn7zDirect(TestUnitBase):

    TESTFILE_CONTENT = 'Hello, this is a test file for 7zip archive testing.'

    # Plain-header archive: COPY archive with encoded header replaced by raw
    # inner header bytes. Header starts at file byte 216 (after 32-byte sig + 184 data).
    PLAIN_HEADER = (
        'N3q8ryccAATXtIS4uAAAAAAAAACOAAAAAAAAAFZ3m9NIZWxsbywgdGhpcyBpcyBhIHRlc3QgZmlsZSBmb3IgN3ppcCBhcmNoaXZl'
        'IHRlc3RpbmcuU2Vjb25kIGZpbGUgZm9yIHRlc3RpbmcgcHVycG9zZXMuAACBMweuMZteOBUeTiwYUilXw9rvnuUG3YxlvmJASy/I'
        'RcLkJHEsq8dSAXwG960+okv09mOGIoYD0xKQ9cRRAhRmAoIfKshbG4ezwH/CeCc2+JwGQiGCBuwyhlFT4lCwAVcSAQQGAAIJNCEA'
        'BwsCAAEBAAEBAAw0IQAICgHEeOBMYmlyvwAABQIZBQAAAAAAETcAdABlAHMAdABmAGkAbABlAC4AdAB4AHQAAAB0AGUAcwB0AGYA'
        'aQBsAGUAMgAuAHQAeAB0AAAAGQQAAAAAFBIBAJdQ8J8ZstwBffXwnxmy3AEVCgEAIAAAACAAAAAAAA=='
    )
    HEADER_OFFSET = 216

    # The COPY archive (uncompressed) is used as the base for corruption tests
    # because byte modifications in the data region directly affect content CRCs.
    COPY_ARCHIVE = (
        'N3q8ryccAATV3ry4uAAAAAAAAAAhAAAAAAAAAPmK4mhIZWxsbywgdGhpcyBpcyBhIHRlc3QgZmlsZSBmb3IgN3ppcCBhcmNoaXZl'
        'IHRlc3RpbmcuU2Vjb25kIGZpbGUgZm9yIHRlc3RpbmcgcHVycG9zZXMuAACBMweuMZteOBUeTiwYUilXw9rvnuUG3YxlvmJASy/I'
        'RcLkJHEsq8dSAXwG960+okv09mOGIoYD0xKQ9cRRAhRmAoIfKshbG4ezwH/CeCc2+JwGQiGCBuwyhlFT4lCwAVcSFwZVAQljAAcL'
        'AQABIwMBAQVdABAAAAyAjgoBVneb0wAA'
    )

    # The directory archive contains a subdir/ entry and two testfile.txt files.
    DIR_ARCHIVE = (
        'N3q8ryccAASj9eqasgAAAAAAAAAhAAAAAAAAAIrd+dzgAGcANV0AJBlJmG8WAoyLktVrywEc3aGe27pL8HOviCZKe7dipsZBOMuv'
        'PGa8aOyjedMPAUWAAGlONoAAAACBMweuD9HFlIygkKB3XsVAGJoF8qhc9LcNimSxiImV4QooX5zjYBk68bRjTQofjhWL9NnJgPfg'
        'rHvVrBSLCWUgvhx+he+3B5EUYJpq1wJxTDXNMFxjz7XiRR8TreI4f1hxM71tb3OgB1jstYWMTQtrt5wAFwY9AQl1AAcLAQABIwMB'
        'AQVdABAAAAyAsgoBMAaqtwAA'
    )

    def test_corrupt_data_crc(self):
        data = bytearray(base64.b64decode(self.COPY_ARCHIVE))
        data[40] ^= 0xFF
        ar = SzArchive(data)
        with self.assertRaises(SzCorruptArchive):
            ar.files[0].decompress()

    def test_corrupt_header_crc(self):
        data = bytearray(base64.b64decode(self.COPY_ARCHIVE))
        data[-10] ^= 0xFF
        with self.assertRaises(SzCorruptArchive):
            SzArchive(data)

    def test_corrupt_signature(self):
        data = bytearray(base64.b64decode(self.COPY_ARCHIVE))
        data[0:6] = b'\x00' * 6
        with self.assertRaises(SzCorruptArchive):
            parse_signature_header(data)

    def test_corrupt_start_header_crc(self):
        data = bytearray(base64.b64decode(self.COPY_ARCHIVE))
        data[8:12] = b'\xFF\xFF\xFF\xFF'
        with self.assertRaises(SzCorruptArchive):
            parse_signature_header(data)

    def test_password_required(self):
        data = base64.b64decode(
            'N3q8ryccAAT9xtacpQAAAAAAAAAiAAAAAAAAAEerl+XBRlkrcJwwoqgijCyuEh0SqLfjamv2F2vNJGFGyHDfpAAAgTMHrg/QDrA8'
            'nzkQnJ+m1TPasi6xAvSHzZaZrISLD+EsvFULZ44Kf7Ewy47PApbKruXCaOSUsjzeqpG8VBcx66h2cV/lnGDfUjtVsyGBHmmmTaSI'
            '/atXtuwiN5mGrqyFZTC/V2VEohWua1Yk1K+jXy+32hBwnK2clyr3rN5LAbv5g2wXBiABCYCFAAcLAQABIwMBAQVdABAAAAyAlgoB'
            'ouB4BAAA'
        )
        ar = SzArchive(data)
        with self.assertRaises(SzPasswordRequired):
            ar.files[0].decompress()

    def test_directory_entry_returns_empty(self):
        data = base64.b64decode(self.DIR_ARCHIVE)
        ar = SzArchive(data)
        dirs = [f for f in ar.files if f.is_dir]
        self.assertTrue(len(dirs) > 0)
        self.assertEqual(dirs[0].decompress(), b'')

    def test_signature_header_parsing(self):
        data = base64.b64decode(self.COPY_ARCHIVE)
        sh = parse_signature_header(data)
        self.assertTrue(data[:6] == SIGNATURE)
        self.assertGreater(sh.next_header_size, 0)
        self.assertGreater(sh.archive_size, 0)

    def test_szfile_properties(self):
        data = base64.b64decode(self.DIR_ARCHIVE)
        ar = SzArchive(data)
        f = ar.files[0]
        _ = f.mtime
        _ = f.ctime
        _ = f.atime
        _ = f.attributes

    def test_timestamps_archive(self):
        data = base64.b64decode(
            'N3q8ryccAAS10C3/xQAAAAAAAAAhAAAAAAAAAI812xLgAFQARV0AJBlJmG8WAoyLktVrywEc3aGe27pL8HOviCZKe7dipsZBOMuv'
            'PGa8aOyjedMPAUT2o/fNEUBnTSYF/RKO6sYV5xPJZycAAAAAgTMHrg/Smro9QMCQ0v99aU2Hej2pCKJZ2zAHVVF91CzaMd7DmZYE'
            'RTgR3bxbCIU3T5S8pIeKXSNBjRg66UYcjkRHR0XA1fUMNF6W5hHQSNQq3TrRtn3T3drRp04hVVHncQZ1vIeAr+/IKY7MlD8ysCi6'
            'CGQeABcGTQEJeAAHCwEAASMDAQEFXQAQAAAMgL4KAUuzRNUAAA=='
        )
        ar = SzArchive(data)
        files = {f.name: f for f in ar.files}
        self.assertIn('testfile.txt', files)
        self.assertIn('testfile2.txt', files)
        for f in ar.files:
            self.assertIsNotNone(f.mtime)
            self.assertIsNotNone(f.ctime)
            self.assertIsNotNone(f.atime)
        self.assertEqual(
            codecs.decode(files['testfile.txt'].decompress()),
            self.TESTFILE_CONTENT,
        )

    def test_empty_file_archive(self):
        data = base64.b64decode(
            'N3q8ryccAARmgAGIpAAAAAAAAAAhAAAAAAAAAP8nbvcBADNIZWxsbywgdGhpcyBpcyBhIHRlc3QgZmlsZSBmb3IgN3ppcCBhcmNo'
            'aXZlIHRlc3RpbmcuAAAAgTMHrg/ReeggoJCgd17FQBiOPXE11yDcq9jW7gBXtxj0CGHLUht7E8Lo0jQ+6N/SmQKQoLdZSChHCO1V'
            'BGcXXeOkKi2hhSnIAPtsFqGJkgSVPzB2w1mPWDkU8OK4zUawhxOPI0d+/xcfIBcGOAEJbAAHCwEAASMDAQEFXQAQAAAMgIYKAcGF'
            'kfAAAA=='
        )
        ar = SzArchive(data)
        files = {f.name: f for f in ar.files}
        self.assertIn('empty.txt', files)
        self.assertIn('testfile.txt', files)
        self.assertEqual(files['empty.txt'].decompress(), b'')
        self.assertFalse(files['empty.txt'].is_dir)
        self.assertEqual(
            codecs.decode(files['testfile.txt'].decompress()),
            self.TESTFILE_CONTENT,
        )

    # ---- Helpers for plain-header corruption tests ----

    @staticmethod
    def _fix_crcs(data: bytearray) -> bytearray:
        # Recompute next_header_crc and start_header_crc after header modifications.
        header_offset = 32 + int.from_bytes(data[12:20], 'little')
        header_data = bytes(data[header_offset:])
        new_crc = zlib.crc32(header_data) & 0xFFFFFFFF
        struct.pack_into('<I', data, 28, new_crc)
        start_crc = zlib.crc32(bytes(data[12:32])) & 0xFFFFFFFF
        struct.pack_into('<I', data, 8, start_crc)
        return data

    def _make_modified(self, modifications: dict) -> bytearray:
        # Create modified plain-header archive with in-place byte changes.
        data = bytearray(base64.b64decode(self.PLAIN_HEADER))
        for offset, value in modifications.items():
            data[self.HEADER_OFFSET + offset] = value
        return self._fix_crcs(data)

    def _rebuild_header(self, new_header: bytes) -> bytearray:
        # Rebuild archive with a completely replaced header section.
        data = bytearray(base64.b64decode(self.PLAIN_HEADER))
        new_data = bytearray(data[:self.HEADER_OFFSET]) + bytearray(new_header)
        struct.pack_into('<Q', new_data, 20, len(new_header))
        return self._fix_crcs(new_data)

    # ---- Corruption tests using the plain-header archive ----

    def test_plain_header_sanity(self):
        data = base64.b64decode(self.PLAIN_HEADER)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_unexpected_top_level_property(self):
        # header[0] HEADER(0x01) -> invalid(0x03) => __init__.py:153
        data = self._make_modified({0: 0x03})
        with self.assertRaises(SzCorruptArchive):
            SzArchive(data)

    def test_signature_header_property_access(self):
        # Access ar.signature_header => __init__.py:128-129
        data = base64.b64decode(self.PLAIN_HEADER)
        ar = SzArchive(data)
        sh = ar.signature_header
        self.assertEqual(sh.major_version, 0)
        self.assertGreater(sh.archive_size, 0)

    def test_no_substreams_info(self):
        # Remove SUBSTREAMS_INFO block => __init__.py:193,207-208,279
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # header[0:23] = HEADER+MAIN_STREAM+PACK_INFO+UNPACK_INFO
        # header[23:35] = SUBSTREAMS_INFO block, header[35] = END main
        new_header = old_header[:23] + b'\x00' + old_header[36:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_unknown_property_in_files_info(self):
        # header[38] DUMMY(0x19) -> unknown(0x1A) => headers.py:462
        data = self._make_modified({38: 0x1A})
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_mtime_external_reference(self):
        # header[111] external=1 for MTIME => headers.py:436-437
        data = self._make_modified({111: 0x01})
        ar = SzArchive(data)
        for f in ar.files:
            self.assertIsNone(f.mtime)

    def test_attributes_external_reference(self):
        # header[131] external=1 for WIN_ATTRIBUTES => headers.py:452-453
        data = self._make_modified({131: 0x01})
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)

    def test_ctime_property(self):
        # header[108] MTIME(0x14) -> CTIME(0x12) => headers.py:442
        data = self._make_modified({108: 0x12})
        ar = SzArchive(data)
        for f in ar.files:
            self.assertIsNone(f.mtime)
            self.assertIsNotNone(f.ctime)

    def test_atime_property(self):
        # header[108] MTIME(0x14) -> ATIME(0x13) => headers.py:443-444
        data = self._make_modified({108: 0x13})
        ar = SzArchive(data)
        for f in ar.files:
            self.assertIsNone(f.mtime)
            self.assertIsNotNone(f.atime)

    def test_name_external_reference(self):
        # header[47] external=1 for NAME => headers.py:397-398
        data = self._make_modified({47: 0x01})
        ar = SzArchive(data)
        for f in ar.files:
            self.assertEqual(f.name, '')

    def test_unknown_property_in_parse_header(self):
        # Replace MAIN_STREAM with unknown prop => headers.py:498-499
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        main_body = old_header[2:36]  # 34 bytes of MAIN_STREAM content
        new_header = bytes([0x01, 0x1A, 34]) + main_body + old_header[36:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)

    def test_archive_props_in_header(self):
        # Insert ARCHIVE_PROPS before MAIN_STREAM => headers.py:480-485
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        new_header = old_header[:1] + bytes([0x02, 0x00]) + old_header[1:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_unknown_property_in_substreams(self):
        # Replace CRC in SUBSTREAMS with unknown => headers.py:366-367
        old_header = bytearray(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # header[24]=CRC(0x0A) -> unknown(0x1A), header[25]=size to skip
        # Skip 8 bytes [26..33] (the two 4-byte CRCs), leaving [34]=END-sub, [35]=END-main
        old_header[24] = 0x1A
        old_header[25] = 0x08
        data = bytearray(base64.b64decode(self.PLAIN_HEADER)[:self.HEADER_OFFSET]) + old_header
        self._fix_crcs(data)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)

    def test_undefined_crcs_in_substreams(self):
        # Use bitmask CRC with none defined => headers.py:177
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # Replace CRC section with: CRC(0x0A) not-all(0) bitmap(0x00) END-sub(0) END-main(0)
        new_sub = bytes([0x0A, 0x00, 0x00, 0x00, 0x00])
        new_header = old_header[:24] + new_sub + old_header[36:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_unknown_property_in_main_streams(self):
        # Insert unknown prop in _parse_main_streams_info => headers.py:516-517
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # Insert unknown(0x1A) + size(0) before PACK_INFO at header[2]
        new_header = old_header[:2] + bytes([0x1A, 0x00]) + old_header[2:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
        self.assertEqual(codecs.decode(ar.files[0].decompress()), self.TESTFILE_CONTENT)

    def test_unknown_property_in_unpack_info(self):
        # Add unknown prop in UNPACK_INFO => headers.py:329-330
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # header[22]=END(0x00) of UNPACK_INFO. Insert unknown before it.
        new_header = old_header[:22] + bytes([0x1A, 0x00]) + old_header[22:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)

    def test_unknown_property_in_pack_info(self):
        # Add unknown prop in PACK_INFO => headers.py:234-235
        old_header = bytes(base64.b64decode(self.PLAIN_HEADER)[self.HEADER_OFFSET:])
        # PACK_INFO at header[2..8]: [2]=0x06,[3]=0,[4]=2,[5]=SIZE,[6]=52,[7]=33,[8]=END
        new_header = old_header[:8] + bytes([0x1A, 0x00]) + old_header[8:]
        data = self._rebuild_header(new_header)
        ar = SzArchive(data)
        self.assertEqual(len(ar.files), 2)
