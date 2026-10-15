from ... import TestUnitBase
from .. import link_ole_child, rename_ole_entry

import base64
import inspect
import io
import lzma
import pathlib
import subprocess
import sys
import zipfile

import refinery


class TestDocExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('969ff75448ea54feccc0d5f652e00172af8e1848352e9a5877d705fc97fa0238')
        pipeline = self.load_pipeline(
            'xtdoc WordDoc | push [| drp | pop junk | repl var:junk | carve -ds b64 | u16 | ps1 | repl var:junk http | xtp url ]')
        c2s = pipeline(data)
        self.assertIn(B'http://depannage-vehicule-maroc'B'.com/wp-admin/c/', c2s)

    def test_invalid_byteorder_sample(self):
        data = lzma.decompress(base64.b85decode(
            '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ$G+h8_Grk;#Fn3_|q=YI!3=;Zf<EN$1i}M~G8al#Of`Dl$L8BDmlEG8Nm8#_jQGD^W'
            '(>TmU=7qxh0N0{J(-b$cI#A%n%t15^ZJfY6svc64;|-T8ytl3|x8qFJEbM-0=6v4S0q<4pT<c<f8ey++yEeMA?78>@xubCwoKr}C'
            'JR|+!rM6l{*4o>H*c;-5(}4__wKQ|i63AYZrVR<YsB8v$Q>u4{#J+%(j~;t#Tb&D3F-#6~W*C8EE-qs!79y5p5NmtH1|uM|Q`k--'
            'h8dg|9@`ssiL+1`9uYjQcD*E;lKTIo@suAu0~GlMhjOd?vaIy{ubeAG;`%<!3w64V>^GuAgK&a~F3wQ(NjuxrDInnKn`qdP2`0vq'
            'e{CU8!HVmBI&^xuNgm)I8VF_pRL=;x5+2r100GbffD`}#1t#5HvBYQl0ssI200dcD'
        ))
        test = data | self.load('ole') | bytes
        self.assertIn(B'%TMP%\\abctfhghghghgh\x8c.SCT', test)

    def test_streams_whose_names_differ_only_in_case_each_hand_out_their_own_content(self):
        data = self.download_sample('4bdc8e660ff4fb05e5b6c0a2dd70c537817f46ac3270d779fdddc8e459829c08')
        streams = data | self.load() | {'path': bytes}
        data = rename_ole_entry(data, '1Table', 'WORDDOCUMENT')
        renamed = data | self.load() | {'path': bytes}
        self.assertEqual(renamed['WordDocument'], streams['WordDocument'])
        self.assertEqual(renamed['WORDDOCUMENT'], streams['1Table'])

    def test_a_storage_whose_child_is_the_root_entry_is_listed_without_hanging(self):
        document = self.download_sample('ee103f8d64cd8fa884ff6a041db2f7aa403c502f54e26337c606044c2f205394')
        with zipfile.ZipFile(io.BytesIO(document)) as archive:
            project = archive.read('word/vbaProject.bin')
        project = link_ole_child(project, 'VBA', 0)
        script = inspect.cleandoc("""
            import sys
            from refinery.units.formats.office.xtdoc import xtdoc
            for path in sys.stdin.buffer.read() | xtdoc(list=True):
                print(path.decode())
        """)
        result = subprocess.run(
            [sys.executable, '-c', script],
            input=bytes(project),
            capture_output=True,
            cwd=pathlib.Path(refinery.__file__).parents[1],
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn('PROJECT', result.stdout.decode().split())
