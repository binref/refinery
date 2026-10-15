from .. import TestUnitBase


class TestSWF(TestUnitBase):

    def test_real_world(self):
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        test = data | self.ldu('xt', 'swf') | self.load() | bytes
        self.assertIn(B'http:'B'//'B'code.flashdynamix'B'.com/AES/aes-decrypt.php', test)

    def test_a_script_listed_twice_is_numbered_like_any_repeated_path(self):
        import zlib
        from refinery.units.formats.swf import SWFTagType
        data = self.download_sample('76b19c1e705328cab4d98e546095eb5eb601d23d8102e6e0bfb0a8a6ab157366')
        original = data | self.ldu('xt', 'swf') | bytes
        self.assertEqual(original[:3], B'CWS')
        body = zlib.decompress(original[8:])
        # the header is followed by a frame rectangle of 5 + 4n bits, frame rate and frame count
        position = (5 + 4 * (body[0] >> 3) + 7) // 8 + 4
        script = None
        while position < len(body):
            header = int.from_bytes(body[position:position + 2], 'little')
            start, position = position, position + 2
            if (length := header & 0x3F) == 0x3F:
                length = int.from_bytes(body[position:position + 4], 'little')
                position += 4
            position += length
            if header >> 6 == SWFTagType.DoABC2:
                script = body[start:position]
                body = body[:position] + script + body[position:]
                break
        self.assertIsNotNone(script)
        modified = B'FWS' + original[3:4] + (8 + len(body)).to_bytes(4, 'little') + body
        abc = original | self.load('*.abc') | bytes
        scripts = modified | self.load('*.abc') | {'path': bytes}
        self.assertEqual(list(scripts), ['scripts/abc.abc/1', 'scripts/abc.abc/2'])
        self.assertTrue(all(script == abc for script in scripts.values()))
