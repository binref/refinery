from .. import TestUnitBase

from refinery.units.formats import PathPattern


class TestFormats(TestUnitBase):

    def test_path_pattern_reach_check(self):
        T = self.assertTrue
        F = self.assertFalse

        F(PathPattern('foo/bar.exe').reach('/baz/bof'))
        T(PathPattern('foo-bar.exe').reach('/baz/bof'))
        T(PathPattern('???/bar.exe').reach('/baz/bof'))
        T(PathPattern('bof/bar.exe').reach('/baz/bof'))
        T(PathPattern('??f/bar.exe').reach('/baz/bof'))
        T(PathPattern('*of/bar.exe').reach('/baz/bof'))

        F(PathPattern('foo/*/bar.exe').reach('/baz/bof'))
        T(PathPattern('baz/*/bar.exe').reach('/baz/bof'))

    def test_path_pattern_reach_exclude(self):
        F = self.assertFalse
        paths = ['secret', 'public', 'secret/key', 'public/readme.txt', 'foo', 'foo/bar.exe']
        for query in ['secret', 'secret/*', 'foo/bar.exe', '*.dll']:
            pattern = PathPattern(query, exclude=True)
            for path in paths:
                F(pattern.reach(path), F'exclusion {query} claimed to reach {path}')

    def test_path_pattern_reach_regex(self):
        T = self.assertTrue
        F = self.assertFalse
        for query in ['foo', 'baz/bar']:
            include = PathPattern(query, regex=True)
            T(include.reach('/baz/bof'))
            self.assertEqual(repr(include), '<PathPattern:RE>')
            F(PathPattern(query, regex=True, exclude=True).reach('/baz/bof'))

    def test_path_pattern_negation(self):
        T = self.assertTrue
        F = self.assertFalse

        F(PathPattern('foo').exclude)
        T(PathPattern('foo').check('foo'))
        F(PathPattern('foo').check('bar'))

        T(PathPattern('foo', exclude=True).exclude)
        T(PathPattern('foo', exclude=True).check('foo'))
        F(PathPattern('foo', exclude=True).check('bar'))

        T(PathPattern('foo', regex=True, exclude=True).exclude)
        T(PathPattern('foo', regex=True, exclude=True).check('foo'))
        F(PathPattern('foo', regex=True, exclude=True).check('bar'))

    def test_path_pattern_reach_is_sound(self):
        cases = {
            'foo/bar.exe'     : ['foo/bar.exe', 'a/foo/bar.exe'],
            'baz/*/bar.exe'   : ['baz/x/bar.exe', 'baz/x/y/bar.exe'],
            '*.dll'           : ['a.dll', 'sub/b.dll', 'a/b/c.dll'],
        }
        for query, paths in cases.items():
            pattern = PathPattern(query)
            for path in paths:
                if not pattern.check(path):
                    continue
                parts = path.split('/')
                for k in range(1, len(parts)):
                    ancestor = '/'.join(parts[:k])
                    self.assertTrue(pattern.reach(ancestor),
                        F'{query} pruned {ancestor} but matches {path}')
