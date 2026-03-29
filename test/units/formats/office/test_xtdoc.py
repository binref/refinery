from ... import TestUnitBase

import base64
import lzma


class TestDocExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('969ff75448ea54feccc0d5f652e00172af8e1848352e9a5877d705fc97fa0238')
        pipeline = self.load_pipeline(
            'xtdoc WordDoc | push [| drp | pop junk | repl var:junk | carve -ds b64 | u16 | deob-ps1-ast | repl var:junk http | xtp url ]')
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
