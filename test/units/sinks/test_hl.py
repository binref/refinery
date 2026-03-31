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
            '1B5B 3031 6D70 7269 6E74 1B5B 3339 6D1B 5B39 316D 281B 5B33 396D 1B5B 3936 6D22'
            '1B5B 3339 6D1B 5B39 366D 6865 6C6C 6F1B 5B33 396D 1B5B 3936 6D22 1B5B 3339 6D1B'
            '5B39 316D 291B 5B33 396D 0A1B 5B30 6D'
        ))

    def test_github_html(self):
        data = b'<html><body>Hello</body></html>'
        unit = self.load('html')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1B5B 3931 6D3C 1B5B 3339 6D1B 5B30 316D 6874 6D6C 1B5B 3339 6D1B 5B39 316D 3E1B'
            '5B33 396D 1B5B 3931 6D3C 1B5B 3339 6D1B 5B30 316D 626F 6479 1B5B 3339 6D1B 5B39'
            '316D 3E1B 5B33 396D 1B5B 3031 6D48 656C 6C6F 1B5B 3339 6D1B 5B39 316D 3C1B 5B33'
            '396D 1B5B 3931 6D2F 1B5B 3339 6D1B 5B30 316D 626F 6479 1B5B 3339 6D1B 5B39 316D'
            '3E1B 5B33 396D 1B5B 3931 6D3C 1B5B 3339 6D1B 5B39 316D 2F1B 5B33 396D 1B5B 3031'
            '6D68 746D 6C1B 5B33 396D 1B5B 3931 6D3E 1B5B 3339 6D0A 1B5B 306D'
        ))

    def test_solarized_javascript(self):
        data = b'if (var > 9) { console.log("Large!"); }'
        unit = self.load('js')
        result = data | unit | bytes
        self.assertEqual(result, bytes.fromhex(
            '1B5B 3931 6D69 661B 5B33 396D 1B5B 3031 6D20 1B5B 3339 6D1B 5B39 316D 281B 5B33'
            '396D 1B5B 3931 6D76 6172 1B5B 3339 6D1B 5B30 316D 201B 5B33 396D 1B5B 3931 6D3E'
            '1B5B 3339 6D1B 5B30 316D 201B 5B33 396D 1B5B 3936 6D39 1B5B 3339 6D1B 5B39 316D'
            '291B 5B33 396D 1B5B 3031 6D20 1B5B 3339 6D1B 5B39 316D 7B1B 5B33 396D 1B5B 3031'
            '6D20 1B5B 3339 6D1B 5B30 316D 636F 6E73 6F6C 651B 5B33 396D 1B5B 3931 6D2E 1B5B'
            '3339 6D1B 5B30 316D 6C6F 671B 5B33 396D 1B5B 3931 6D28 1B5B 3339 6D1B 5B39 366D'
            '224C 6172 6765 2122 1B5B 3339 6D1B 5B39 316D 291B 5B33 396D 1B5B 3931 6D3B 1B5B'
            '3339 6D1B 5B30 316D 201B 5B33 396D 1B5B 3931 6D7D 1B5B 3339 6D0A 1B5B 306D'
        ))
