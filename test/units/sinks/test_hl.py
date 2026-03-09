from .. import TestUnitBase


class TestHighlight(TestUnitBase):

    def test_dark_and_light_conflict(self):
        with self.assertRaises(ValueError):
            self.load(dark=True, light=True)

    def test_multiple_style_error(self):
        with self.assertRaises(ValueError):
            self.load(github=True, solarized=True)

    def test_gruvbox_python(self):
        data = b'print("hello")'
        unit = self.ldu('hlb', 'python')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1b5b 3338 3b35 3b32 3038 6d70 7269 6e74 1b5b 3339 6d1b 5b33 383b 353b 3235 336d'
            '281b 5b33 396d 1b5b 3338 3b35 3b31 3432 6d22 1b5b 3339 6d1b 5b33 383b 353b 3134'
            '326d 6865 6c6c 6f1b 5b33 396d 1b5b 3338 3b35 3b31 3432 6d22 1b5b 3339 6d1b 5b33'
            '383b 353b 3235 336d 291b 5b33 396d 0a1b 5b30 6d'
        ))

    def test_github_html(self):
        data = b'<html><body>Hello</body></html>'
        unit = self.ldu('hlg', 'html')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1b5b 3338 3b35 3b37 6d3c 1b5b 3339 6d1b 5b33 383b 353b 3131 346d 6874 6d6c 1b5b'
            '3339 6d1b 5b33 383b 353b 376d 3e1b 5b33 396d 1b5b 3338 3b35 3b37 6d3c 1b5b 3339'
            '6d1b 5b33 383b 353b 3131 346d 626f 6479 1b5b 3339 6d1b 5b33 383b 353b 376d 3e1b'
            '5b33 396d 1b5b 3338 3b35 3b37 6d48 656c 6c6f 1b5b 3339 6d1b 5b33 383b 353b 376d'
            '3c1b 5b33 396d 1b5b 3338 3b35 3b37 6d2f 1b5b 3339 6d1b 5b33 383b 353b 3131 346d'
            '626f 6479 1b5b 3339 6d1b 5b33 383b 353b 376d 3e1b 5b33 396d 1b5b 3338 3b35 3b37'
            '6d3c 1b5b 3339 6d1b 5b33 383b 353b 376d 2f1b 5b33 396d 1b5b 3338 3b35 3b31 3134'
            '6d68 746d 6c1b 5b33 396d 1b5b 3338 3b35 3b37 6d3e 1b5b 3339 6d0a 1b5b 306d'
        ))

    def test_solarized_javascript(self):
        data = b'if (var > 9) { console.log("Large!"); }'
        unit = self.ldu('hls')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1b5b 3338 3b35 3b31 3030 6d69 661b 5b33 396d 1b5b 3338 3b35 3b32 3435 6d20 1b5b'
            '3339 6d1b 5b33 383b 353b 3234 356d 281b 5b33 396d 1b5b 3338 3b35 3b31 3030 6d76'
            '6172 1b5b 3339 6d1b 5b33 383b 353b 3234 356d 201b 5b33 396d 1b5b 3338 3b35 3b32'
            '3432 6d3e 1b5b 3339 6d1b 5b33 383b 353b 3234 356d 201b 5b33 396d 1b5b 3338 3b35'
            '3b33 366d 391b 5b33 396d 1b5b 3338 3b35 3b32 3435 6d29 1b5b 3339 6d1b 5b33 383b'
            '353b 3234 356d 201b 5b33 396d 1b5b 3338 3b35 3b32 3435 6d7b 1b5b 3339 6d1b 5b33'
            '383b 353b 3234 356d 201b 5b33 396d 1b5b 3338 3b35 3b32 3435 6d63 6f6e 736f 6c65'
            '1b5b 3339 6d1b 5b33 383b 353b 3234 326d 2e1b 5b33 396d 1b5b 3338 3b35 3b32 3435'
            '6d6c 6f67 1b5b 3339 6d1b 5b33 383b 353b 3234 356d 281b 5b33 396d 1b5b 3338 3b35'
            '3b33 366d 221b 5b33 396d 1b5b 3338 3b35 3b33 366d 4c61 7267 6521 1b5b 3339 6d1b'
            '5b33 383b 353b 3336 6d22 1b5b 3339 6d1b 5b33 383b 353b 3234 356d 291b 5b33 396d'
            '1b5b 3338 3b35 3b32 3435 6d3b 1b5b 3339 6d1b 5b33 383b 353b 3234 356d 201b 5b33'
            '396d 1b5b 3338 3b35 3b32 3435 6d7d 1b5b 3339 6d0a 1b5b 306d'
        ))
