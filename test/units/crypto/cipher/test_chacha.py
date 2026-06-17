from ... import TestUnitBase


class TestChaCha(TestUnitBase):

    def test_chacha20_ietf_rfc8439(self):
        key = bytes.fromhex(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        nonce = bytes.fromhex('000000000000004a00000000')
        data = (
            B'Ladies and Gentlemen of the class of \'99: If I could offer you only one'
            B' tip for the future, sunscreen would be it.')
        goal = bytes.fromhex(
            '6e2e359a2568f98041ba0728dd0d6981'
            'e97e7aec1d4360c20a27afccfd9fae0b'
            'f91b65c5524733ab8f593dabcd62b357'
            '1639d624e65152ab8f530c359f0861d8'
            '07ca0dbf500d6a6156a38e088a22b65e'
            '52bc514d16ccf806818ce91ab7793736'
            '5af90bbf74a35be6b40b8eedf2785e42'
            '874d')
        test = data | self.ldu('chacha', offset=1, key=key, nonce=nonce) | bytes
        self.assertEqual(test, goal)

    def test_xchacha(self):
        key = bytes.fromhex(
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
        nonce = bytes.fromhex(
            '404142434445464748494a4b4c4d4e4f5051525354555658')
        data = bytes.fromhex(
            '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973'
            '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420'
            '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e'
            '2049742069732061626f7574207468652073697a65206f662061204765726d61'
            '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061'
            '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c'
            '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173'
            '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163'
            '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963'
            '2066616d696c792043616e696461652e')
        goal = bytes.fromhex(
            '7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87'
            'ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05'
            '3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f'
            '7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201'
            '12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc'
            '047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63'
            'd595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73'
            'c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4'
            'd0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683'
            '8a9c71f70b5b5907a66f7ea49aadc409'
        )
        test = data | self.ldu('xchacha', offset=1, key=key, nonce=nonce) | bytes
        self.assertEqual(test, goal)

    def test_rfc8439_aead_vector(self):
        key = bytes.fromhex(
            '808182838485868788898a8b8c8d8e8f'
            '909192939495969798999a9b9c9d9e9f')
        nonce = bytes.fromhex('070000004041424344454647')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        ciphertext = bytes.fromhex(
            'd31a8d34648e60db7b86afbc53ef7ec2'
            'a4aded51296e08fea9e2b5a736ee62d6'
            '3dbea45e8ca9671282fafb69da92728b'
            '1a71de0a9e060b2905d6a5b67ecd3b36'
            '92ddbd7f2d778b8c9803aee328091b58'
            'fab324e4fad675945585808b4831d7bc'
            '3ff4def08e4b7a9de576d26586cec64b'
            '6116')
        tag = bytes.fromhex('1ae10b594f09e26a7e902ecbd0600691')
        goal = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you "
            b"only one tip for the future, sunscreen would be it.")
        unit = self.ldu('chacha20poly1305', key=key, nonce=nonce, aad=aad, tag=tag)
        self.assertEqual(ciphertext | unit | bytes, goal)

    def test_authentication_roundtrip(self):
        key = bytes.fromhex(
            '808182838485868788898a8b8c8d8e8f'
            '909192939495969798999a9b9c9d9e9f')
        data = B'The binary refinery refines the finest binaries!'

        test = self.load_pipeline('|'.join((
            F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=16 -R [',
            F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=v:tag ]',
        )))
        self.assertEqual(data, data | test | bytes)

        test = self.load_pipeline('|'.join((
            F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=16 -R [',
            F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined ]',
        )))
        self.assertEqual(data, data | test | bytes)

    def test_wrong_aad_fails(self):
        key = bytes.fromhex(
            '808182838485868788898a8b8c8d8e8f'
            '909192939495969798999a9b9c9d9e9f')
        data = B'The binary refinery refines the finest binaries!'

        with self.assertRaises(ValueError):
            _ = data | self.load_pipeline('|'.join((
                F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=16 -R [',
                F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=REFYNED --tag=v:tag ]',
            ))) | None

        with self.assertRaises(ValueError):
            _ = data | self.load_pipeline('|'.join((
                F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=16 -R [',
                'put tag bogusbogustagtag',
                F'chacha20poly1305 H:{key.hex()} schokolade12 --aad=refined --tag=v:tag ]',
            ))) | None
