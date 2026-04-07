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
        unit = self.load('py')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1B5B 3931 6D70 7269 6E74 1B5B 306D 1B5B 3930 6D28 1B5B 306D 1B5B 3336 6D22 1B5B'
            '306D 1B5B 3336 6D68 656C 6C6F 1B5B 306D 1B5B 3336 6D22 1B5B 306D 1B5B 3930 6D29'
            '1B5B 306D 1B5B 3337 6D0A 1B5B 306D 1B5B 306D'
        ))

    def test_github_html(self):
        data = b'<html><body>Hello</body></html>'
        unit = self.load('html')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1B5B 3930 6D3C 1B5B 306D 1B5B 3931 6D68 746D 6C1B 5B30 6D1B 5B39 306D 3E1B 5B30'
            '6D1B 5B39 306D 3C1B 5B30 6D1B 5B39 316D 626F 6479 1B5B 306D 1B5B 3930 6D3E 1B5B'
            '306D 1B5B 3337 6D48 656C 6C6F 1B5B 306D 1B5B 3930 6D3C 1B5B 306D 1B5B 3930 6D2F'
            '1B5B 306D 1B5B 3931 6D62 6F64 791B 5B30 6D1B 5B39 306D 3E1B 5B30 6D1B 5B39 306D'
            '3C1B 5B30 6D1B 5B39 306D 2F1B 5B30 6D1B 5B39 316D 6874 6D6C 1B5B 306D 1B5B 3930'
            '6D3E 1B5B 306D 1B5B 3337 6D0A 1B5B 306D 1B5B 306D'
        ))

    def test_solarized_javascript(self):
        data = b'if (var > 9) { console.log("Large!"); }'
        unit = self.load('js')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1B5B 3931 6D1B 5B31 6D69 661B 5B30 6D1B 5B33 376D 201B 5B30 6D1B 5B39 306D 281B'
            '5B30 6D1B 5B39 316D 1B5B 316D 7661 721B 5B30 6D1B 5B33 376D 201B 5B30 6D1B 5B39'
            '316D 3E1B 5B30 6D1B 5B33 376D 201B 5B30 6D1B 5B33 366D 391B 5B30 6D1B 5B39 306D'
            '291B 5B30 6D1B 5B33 376D 201B 5B30 6D1B 5B39 306D 7B1B 5B30 6D1B 5B33 376D 201B'
            '5B30 6D1B 5B33 376D 636F 6E73 6F6C 651B 5B30 6D1B 5B39 306D 2E1B 5B30 6D1B 5B33'
            '376D 6C6F 671B 5B30 6D1B 5B39 306D 281B 5B30 6D1B 5B33 366D 224C 6172 6765 2122'
            '1B5B 306D 1B5B 3930 6D29 1B5B 306D 1B5B 3930 6D3B 1B5B 306D 1B5B 3337 6D20 1B5B'
            '306D 1B5B 3930 6D7D 1B5B 306D 1B5B 3337 6D0A 1B5B 306D 1B5B 306D'
        ))
