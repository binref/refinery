import inspect
import itertools
import random

from refinery.lib import tools, colors


from .. import TestBase


class TestEntropy(TestBase):

    def test_low_entropy(self):
        data = B'2' * 2000
        self.assertLessEqual(tools.entropy_fallback(data), 0.001)

    def test_high_entropy_01(self):
        data = bytes((random.randrange(0, 0x100) for _ in range(2000)))
        self.assertGreaterEqual(tools.entropy_fallback(data), 0.98)

    def test_high_entropy_02(self):
        data = bytes((random.randrange(0, 0x100) for _ in range(2000)))
        self.assertGreaterEqual(tools.entropy(data), 0.98)

    def test_fallback_memoryview(self):
        for data in [
            B'FOO-BAR-BAR' * 200,
            self.generate_random_buffer(1000)
        ]:
            view = memoryview(data)
            self.assertAlmostEqual(tools.entropy(view), tools.entropy_fallback(view))

    def test_entropy_empty(self):
        self.assertEqual(tools.entropy(b''), 0.0)


class TestIndexOfCoincidence(TestBase):

    def test_empty(self):
        self.assertEqual(tools.index_of_coincidence(b''), 0.0)

    def test_single_byte(self):
        self.assertEqual(tools.index_of_coincidence(b'A'), 0.0)

    def test_uniform_data(self):
        data = b'AAAA' * 200
        ioc = tools.index_of_coincidence(data)
        self.assertAlmostEqual(ioc, 1)

    def test_random_data(self):
        data = self.generate_random_buffer(1000)
        ioc = tools.index_of_coincidence(data)
        self.assertLessEqual(ioc, 0.01)


class TestLookahead(TestBase):

    def test_empty_iterator(self):
        self.assertEqual(list(tools.lookahead([])), [])

    def test_single_element(self):
        result = list(tools.lookahead([42]))
        self.assertEqual(result, [(True, 42)])

    def test_multiple_elements(self):
        result = list(tools.lookahead([1, 2, 3]))
        self.assertEqual(result, [(False, 1), (False, 2), (True, 3)])

    def test_last_flag_only_on_final(self):
        test = list(tools.lookahead(range(5)))
        self.assertListEqual(test, list(zip(
            [False, False, False, False, True],
            range(5)
        )))


class TestBegin(TestBase):

    def test_empty_iterable(self):
        self.assertIsNone(tools.begin([]))

    def test_non_empty_iterable(self):
        result = tools.begin([1, 2, 3])
        self.assertIsNotNone(result)
        head, rest = result
        self.assertEqual(head, 1)
        self.assertEqual(list(rest), [1, 2, 3])

    def test_single_element(self):
        head, rest = tools.begin([42])
        self.assertEqual(head, 42)
        self.assertEqual(list(rest), [42])


class TestSkipFirst(TestBase):

    def test_skips_first(self):
        result = list(tools.skipfirst([10, 20, 30]))
        self.assertEqual(result, [20, 30])


class TestSplitChunks(TestBase):

    def test_basic(self):
        data = b'ABCDEFGH'
        result = list(tools.splitchunks(data, 3))
        self.assertEqual(result, [b'ABC', b'DEF', b'GH'])

    def test_truncate(self):
        data = b'ABCDEFGH'
        result = list(tools.splitchunks(data, 3, truncate=True))
        self.assertEqual(result, [b'ABC', b'DEF'])

    def test_step(self):
        data = b'ABCDEFGH'
        result = list(tools.splitchunks(data, 4, step=2))
        self.assertEqual(result, [b'ABCD', b'CDEF', b'EFGH', b'GH'])

    def test_step_with_truncate(self):
        data = b'ABCDEFGH'
        result = list(tools.splitchunks(data, 4, step=2, truncate=True))
        self.assertEqual(result, [b'ABCD', b'CDEF', b'EFGH'])

    def test_data_smaller_than_size(self):
        data = b'AB'
        result = list(tools.splitchunks(data, 5))
        self.assertEqual(result, [b'AB'])

    def test_data_smaller_than_size_truncate(self):
        data = b'AB'
        result = list(tools.splitchunks(data, 5, truncate=True))
        self.assertEqual(result, [])

    def test_exact_size(self):
        data = b'ABCD'
        result = list(tools.splitchunks(data, 4))
        self.assertEqual(result, [b'ABCD'])


class TestInfinitize(TestBase):

    def test_single_value(self):
        inf = tools.infinitize(42)
        result = list(itertools.islice(inf, 5))
        self.assertEqual(result, [42, 42, 42, 42, 42])

    def test_list(self):
        inf = tools.infinitize([1, 2, 3])
        result = list(itertools.islice(inf, 7))
        self.assertEqual(result, [1, 2, 3, 1, 2, 3, 1])

    def test_cycle_passthrough(self):
        c = itertools.cycle([1])
        self.assertIs(tools.infinitize(c), c)

    def test_repeat_passthrough(self):
        r = itertools.repeat(5)
        self.assertIs(tools.infinitize(r), r)

    def test_count_passthrough(self):
        c = itertools.count(0)
        self.assertIs(tools.infinitize(c), c)


class TestOne(TestBase):

    def test_single_element(self):
        self.assertEqual(tools.one([42]), 42)

    def test_empty_raises(self):
        with self.assertRaises(tools.NotOne) as ctx:
            tools.one([])
        self.assertTrue(ctx.exception.empty)

    def test_multiple_raises(self):
        with self.assertRaises(tools.NotOne) as ctx:
            tools.one([1, 2])
        self.assertFalse(ctx.exception.empty)


class TestIntegersOfSlice(TestBase):

    def test_basic_range(self):
        result = list(tools.integers_of_slice(slice(0, 5)))
        self.assertEqual(result, [0, 1, 2, 3, 4])

    def test_with_step(self):
        result = list(tools.integers_of_slice(slice(0, 10, 3)))
        self.assertEqual(result, [0, 3, 6, 9])

    def test_infinite(self):
        result = list(itertools.islice(tools.integers_of_slice(slice(0, None, 2)), 5))
        self.assertEqual(result, [0, 2, 4, 6, 8])

    def test_none_start(self):
        result = list(tools.integers_of_slice(slice(None, 3)))
        self.assertEqual(result, [0, 1, 2])


class TestNormalize(TestBase):

    def test_display_normalization(self):
        self.assertEqual(tools.normalize_to_display('hello_world'), 'hello-world')
        self.assertEqual(tools.normalize_to_display('foo.bar/baz'), 'foo-bar-baz')

    def test_identifier_normalization(self):
        self.assertEqual(tools.normalize_to_identifier('hello-world'), 'hello_world')
        self.assertEqual(tools.normalize_to_identifier('foo.bar/baz'), 'foo_bar_baz')

    def test_strip_leading_trailing(self):
        self.assertEqual(tools.normalize_to_display('-hello-'), 'hello')
        self.assertEqual(tools.normalize_to_display('-hello-', strip=False), '-hello-')

    def test_multiple_separators(self):
        self.assertEqual(tools.normalize_to_display('a---b___c'), 'a-b-c')


class TestExceptionToString(TestBase):

    def test_basic_exception(self):
        e = ValueError('something broke')
        self.assertEqual(tools.exception_to_string(e), 'something broke')

    def test_no_args(self):
        e = ValueError()
        self.assertEqual(tools.exception_to_string(e), 'ValueError')

    def test_multiple_args_picks_longest_string(self):
        e = Exception('short', 'much longer message here')
        self.assertIn('much longer message here', tools.exception_to_string(e))

    def test_default(self):
        e = Exception(42)
        result = tools.exception_to_string(e, default='fallback')
        self.assertEqual(result, 'fallback')


class TestDocumentation(TestBase):

    def test_removes_backtick_refs(self):
        class FakeUnit:
            """
            A unit that uses `refinery.units.encoding.hex` for encoding.
            """
        result = tools.documentation(FakeUnit)
        self.assertNotIn('`refinery.', result)
        self.assertIn('hex', result)


class TestNoLogging(TestBase):

    def test_context_manager(self):
        with tools.NoLogging() as nl:
            self.assertIsInstance(nl, tools.NoLogging)

    def test_mode_all(self):
        with tools.NoLogging(tools.NoLogging.Mode.ALL):
            pass

    def test_mode_flags(self):
        m = tools.NoLogging.Mode
        self.assertTrue(m.STD_OUT & m.ALL)
        self.assertTrue(m.STD_ERR & m.ALL)
        self.assertTrue(m.WARNING & m.ALL)
        self.assertTrue(m.LOGGING & m.ALL)


class TestTools(TestBase):

    def test_coloring(self):
        @inspect.getdoc
        class code:
            """
            async function test() {
                try {
                    const saqotesana = Uint8Array.from(atob(zobefacebi.duvusuvusa), c => c.charCodeAt(0));
                    const iv = Uint8Array.from(atob(zobefacebi.iv), c => c.charCodeAt(0));
                    const keyData = Uint8Array.from(atob(zobefacebi.key), c => c.charCodeAt(0));
                } catch (error) { }
            }
            """
        assert code is not None

        highlighted = code | self.ldu('hlg') | str
        for line1, line2 in zip(
            code.splitlines(), highlighted.splitlines()
        ):
            self.assertEqual(len(line1), colors.colored_text_length(line2))

    def test_terminalfit(self):
        @inspect.getdoc
        class data:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id ultricies. Integer eu semper mauris. Nunc sed
            nunc non ante volutpat egestas. Nam nec risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue sapien sapien ut felis. Etiam pharetra est
               non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem hendrerit, nec lobortis sem scelerisque.
            Nullam eget justo in nunc lacinia porttitor eget nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras
            leo ipsum, porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        @inspect.getdoc
        class wish:
            """
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed venenatis ac urna id
            ultricies. Integer eu semper mauris. Nunc sed nunc non ante volutpat egestas. Nam nec
            risus sed ex dignissim pharetra. Integer vel augue erat. Vivamus hendrerit convallis
            tortor in varius. Morbi sed nulla eget turpis volutpat maximus id vitae nisi:

            1. Aenean ullamcorper egestas lorem ornare ultrices.
            2. Donec quis gravida orci.
            3. Fusce auctor, orci sit amet vehicula varius, elit dolor feugiat nisl, at congue
               sapien sapien ut felis. Etiam pharetra est non turpis facilisis ullamcorper.

            Ut quis ipsum varius, pellentesque mauris nec, rutrum quam. Proin dictum neque ut sem
            hendrerit, nec lobortis sem scelerisque. Nullam eget justo in nunc lacinia porttitor eget
            nec quam. Morbi volutpat egestas risus, eget malesuada nulla vulputate eu. Cras leo ipsum,
            porttitor et malesuada a, laoreet nec metus:

            - Donec porttitor suscipit dapibus.
            - Phasellus sodales erat id imperdiet rutrum.
            - Vestibulum in augue vel libero tempor vestibulum.
            """

        self.assertEqual(tools.terminalfit(data, width=90), wish)


class TestNoLoggingProxy(TestBase):

    def test_proxy_wraps_object(self):
        class Container:
            data = [1, 2, 3]
        c = Container()
        proxied = tools.NoLoggingProxy(c)
        self.assertEqual(tools.unwrap(proxied.data), [1, 2, 3])

    def test_proxy_passthrough_for_primitives(self):
        self.assertEqual(tools.NoLoggingProxy(42), 42)
        self.assertEqual(tools.NoLoggingProxy('hello'), 'hello')
        self.assertEqual(tools.NoLoggingProxy(b'data'), b'data')

    def test_proxy_getattr(self):
        class Dummy:
            value = 99
        d = Dummy()
        p = tools.NoLoggingProxy(d)
        self.assertEqual(tools.unwrap(p.value), 99)

    def test_proxy_setattr(self):
        class Dummy:
            value = 0
        d = Dummy()
        p = tools.NoLoggingProxy(d)
        p.value = 42
        self.assertEqual(d.value, 42)

    def test_proxy_repr(self):
        original = [1, 2, 3]
        p = tools.NoLoggingProxy(original)
        self.assertEqual(repr(p), repr(original))

    def test_proxy_getitem(self):
        original = {'key': 'value'}
        p = tools.NoLoggingProxy(original)
        self.assertEqual(tools.unwrap(p['key']), 'value')

    def test_proxy_iter(self):
        original = [10, 20, 30]
        p = tools.NoLoggingProxy(original)
        result = [tools.unwrap(item) for item in p]
        self.assertEqual(result, [10, 20, 30])

    def test_proxy_call(self):
        class Adder:
            def __call__(self, a, b):
                return a + b
        adder = Adder()
        p = tools.NoLoggingProxy(adder)
        result = tools.unwrap(p(1, 2))
        self.assertEqual(result, 3)


class TestUnwrap(TestBase):

    def test_unwrap_plain_object(self):
        self.assertEqual(tools.unwrap(42), 42)

    def test_unwrap_proxy(self):
        original = [1, 2, 3]
        p = tools.NoLoggingProxy(original)
        self.assertIs(tools.unwrap(p), original)


class TestProxy(TestBase):

    def test_proxy_function(self):
        original = [1, 2]
        p = tools.proxy(original)
        self.assertEqual(tools.unwrap(p), original)
