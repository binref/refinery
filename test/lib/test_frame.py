import copy
import io

from refinery.lib.frame import Chunk, FrameUnpacker, generate_frame_header, MAGIC, MSIZE
from refinery.lib.loader import load_detached as L, load_pipeline

from .. import TestBase


class TestFraming(TestBase):

    def test_simple_frame(self):
        chunks = [B'A' * k for k in (12, 17, 20, 2, 80, 9)]
        source = io.BytesIO(B'\n'.join(chunks))
        buffer = io.BytesIO()
        unit = L('resplit [')
        unit.console = True
        for chunk in source | unit:
            buffer.write(chunk)
        buffer.seek(0)
        expected = []
        unpacked = FrameUnpacker(buffer)
        while unpacked.nextframe():
            expected.extend(c for c in unpacked)
        self.assertEqual(chunks, expected)

    def test_layered_frame_01(self):
        p = L('chop 4 [') | L('chop 2 [') | L('ccp F ]') | L('cca ?') | L('sep ]')
        self.assertEqual(p(B'OOOO' * 12), B'\n'.join([B'FOOFOO?'] * 12))

    def test_layered_frame_02(self):
        p = L('chop 4') [ L('chop 2') [ L('emit F x::') ]| L('emit x:: ?') [ L('nop') ] | L('sep') ] # noqa
        self.assertEqual(p(B'OOOO' * 12), B'\n'.join([B'FOOFOO?'] * 12))

    def test_documentation_example_01(self):
        p = L('chop 2') [ L('ccp F') | L('cca .') ] # noqa
        self.assertEqual(B'FOO.FOO.FOO.FOO.', p(B'OOOOOOOO'))

    def test_documentation_example_02(self):
        p = L('chop 4') [ L('chop 2') [ L('ccp F') | L('cca .') ] | L('sep') ] # noqa
        self.assertEqual(B'FOO.FOO.\nFOO.FOO.', p(B'OOOOOOOO'))

    def test_documentation_example_03(self):
        p = L('emit BINARY REFINERY') [ L('scope 0') | L('clower') | L('sep -') ] # noqa
        self.assertEqual(B'binary-REFINERY', p(B''))

    def test_documentation_example_04(self):
        p = L('emit aaaaaaaa namtaB') [               # noqa
            L('scope 0') | L('rex .') [               # noqa
                L('ccp N')                            # noqa
            ] | L('scope 1') | L('rev') | L('sep -')  # noqa
        ]
        self.assertEqual(B'NaNaNaNaNaNaNaNa-Batman', p(B''))

    def test_real_world_01(self):
        encoded = (
            B'''3018152148501567213310184800633409362144880559105294049701126311246081131975615343153231062913116111'''
            B'''1811157103091659005342125241030117185058391257506811185641455415793050760678905403191251022718260080'''
            B'''7906431133491248306004123002146510940169690710820141169320955312014120171102115059068660995810412198'''
            B'''2616881062361714809255109191754708061112151124515802166780656805937169201403509433094710978206187056'''
            B'''2218138176051220720074069511229205186057281368405973054061286713377066441598840591412906137750687906'''
            B'''4041396607792051271161313019124720712811569074680757406931112780654609788055291148605702141810628505'''
            B'''8151284909456087890549404926117480955908477066171262212153090600834110276067051380014345098520912112'''
            B'''2241190813511132231202511818125031403011344099331108705657086800634310034109011420913464079540893910'''
            B'''4470969005365078580853510871072121313211155088071361612710133620813710651092820619305073070401034210'''
            B'''1700736108238105500938306036107630802012367076910524001430513808135271167207124119480954609725118261'''
            B'''1783060490948006355088131302012370073291143410911132710725209182061211224310017126311126607719124590'''
            B'''8460083860575009354089740698805569074161279005364079321115309035108401031812509134770666308092051560'''
            B'''8742101371066807584059750686707610133510927307091052361073810533110580851412944099810629305007136760'''
            B'''6785058391040214112131151286507879064780654110262081570860613789054610829404903140281154709601142450'''
            B'''9822121301130413987056231204'''
        )
        decoded = (
            B'''wMIc  'prOcess'   "cALl"  crEAtE   "powErsHell  -NoNiNtErAC -NoPrOFi -WIn 00000000000000000000000000'''
            B'''0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'''
            B'''0000000000000000000000000000000000000000000000000000000000000000000000000000000000000'''
        )
        pl = L('chop 0x01DC') [                           # noqa
            L('chop 5 -t') [                              # noqa
               L('sorted -a') | L('snip 2:') | L('sep')   # noqa
            ]| L('pack 10') | L('alu --dec -sN B-S')  # noqa
        ]
        self.assertEqual(decoded, pl(encoded))

    def test_nonblocking(self):
        with io.BytesIO(bytes(range(20))) as stream:
            slow = stream | L('rex .')
            for k in range(20):
                self.assertEqual(slow.read1(20), bytes((k,)))

    def test_nonblocking_frame_collapse(self):
        with io.BytesIO(bytes(range(20))) as stream:
            slow = stream | L('chop 5') [ L('rex .') ] # noqa
            for k in range(20):
                self.assertEqual(slow.read1(20), bytes((k,)))

    def test_depth3(self):
        p = L('snip :3 3 4 5:') [           # noqa
            L('scope 1:3') | L('rex .') [   # noqa
                L('rep 3') [ L('ccp X') ]   # noqa
            ]                               # noqa
        ]                                   # noqa

        self.assertEqual(B'AAAXBXBXBXCXCXCDDD', p(B'AAABCDDD'))

    def test_continue_after_error(self):
        T = self.generate_random_buffer(16)
        aes = self.ldu('aes', key=T, iv=T, quiet=True)
        msg = [self.generate_random_buffer(3 * 16) for _ in range(12)]
        hidden = msg[7]
        msg[7] = aes.reverse(hidden)
        pipeline = self.ldu('emit', data=msg)[aes]
        self.assertEqual(aes(msg[7]), hidden)
        self.assertEqual(pipeline(B''), hidden)

    def test_empty_chunk(self):
        swap = self.ldu('swap', 'test')
        ergo = next(b'test-data' | swap) # noqa
        self.assertEqual(ergo, b'')
        self.assertEqual(ergo['test'], B'test-data')

    def test_bug_conditional_units_generate_empty_chunks(self):
        pipeline = load_pipeline('emit A | rex .. [| iff 1 [| pf boom ]]]')
        self.assertEqual(pipeline(), B'')

    def test_units_can_overwrite_parent_metavars(self):
        out, = load_pipeline('emit ABCD [| rex .... | rex B ]')
        self.assertEqual(out['offset'], 1)

    def test_history_saves_space(self):
        from refinery import Unit
        from refinery.lib.meta import LazyMetaOracle

        class inspector(Unit):
            test = self

            def process(self, data):
                meta: LazyMetaOracle = data.meta
                stack = meta.history['x']
                occupations = sum(1 for lnk, value in stack if not lnk and value)
                self.test.assertLessEqual(occupations, 2)
                self.test.assertEqual(stack[0], (False, B'X' * 1000))
                self.test.assertEqual(stack[1], (False, B'SHORTSTRING'))

        x = load_pipeline('''
              nop               [
            | put x rep[1000]:X  [
            | put x SHORTSTRING   [
            | put x rep[1000]:X    [
            | put x SHORTSTRING     [
            | put x rep[1000]:X      [
            | eat x                   [
            | inspector          ]]]]]]
            | pf {x}            ]
        ''')(B'')

        self.assertEqual(x, B'X' * 1000)

    def test_regression_unaltered_pop(self):
        pl = load_pipeline('rex "..(?P<t>..)" [| push var:t [| rex .. | pick ~0 | pop t ]| pf {t} ]')
        self.assertEqual(b'REFINERY' | pl | bytes, B'FIRY')

    def test_chunk_output_to_list(self):
        from refinery.units import Chunk
        from refinery.units.meta.chop import chop
        data = Chunk(B'Hello', [0], [True])
        self.assertEqual(data.scope, 1)
        test = data | chop(2) | [str]
        self.assertEqual(test, ['He', 'll', 'o'])

    def test_auto_index_regression(self):
        pipe = self.load_pipeline('emit 0 1 2 3 4 5 [| max index | pf {index} ]')
        self.assertEqual(0 | pipe | int, 0)
        pipe = self.load_pipeline('emit 0 1 2 3 4 5 [| put k index | max k | pf {k} ]')
        self.assertEqual(0 | pipe | int, 5)


class TestFrameHeader(TestBase):

    def test_generate_header_scope_0(self):
        header = generate_frame_header(0)
        self.assertEqual(len(header), MSIZE)
        self.assertTrue(header.startswith(MAGIC))


class TestChunk(TestBase):

    def test_basic_construction(self):
        c = Chunk(b'Hello')
        self.assertEqual(bytes(c), b'Hello')
        self.assertEqual(c.scope, 0)
        self.assertTrue(c.visible)
        self.assertEqual(c.path, [])

    def test_empty_construction(self):
        c = Chunk()
        self.assertEqual(bytes(c), b'')

    def test_chunk_with_path(self):
        c = Chunk(b'Data', path=[0, 1, 2], view=[True, True, False])
        self.assertEqual(c.scope, 3)
        self.assertFalse(c.visible)
        self.assertEqual(c.path, [0, 1, 2])
        self.assertEqual(c.view, [True, True, False])

    def test_chunk_visibility_setter(self):
        c = Chunk(b'Data', path=[0], view=[True])
        self.assertTrue(c.visible)
        c.visible = False
        self.assertFalse(c.visible)
        self.assertEqual(c.view, [False])

    def test_chunk_visibility_setter_unframed(self):
        c = Chunk(b'Data')
        self.assertTrue(c.visible)
        with self.assertRaises(AttributeError):
            c.visible = False

    def test_chunk_wrap(self):
        c = Chunk(b'Test')
        self.assertIs(Chunk.Wrap(c), c)
        c2 = Chunk.Wrap(b'Test')
        self.assertIsInstance(c2, Chunk)
        self.assertEqual(bytes(c2), b'Test')

    def test_chunk_str_valid_utf8(self):
        c = Chunk(b'Hello')
        self.assertEqual(str(c), 'Hello')

    def test_chunk_str_invalid_utf8(self):
        c = Chunk(bytes(range(0x80, 0x90)))
        result = str(c)
        # should return hex since UTF8 decode fails
        self.assertTrue(all(ch in '0123456789abcdef' for ch in result))

    def test_chunk_hash(self):
        c1 = Chunk(b'Data')
        c2 = Chunk(b'Data')
        self.assertEqual(hash(c1), hash(c2))

    def test_chunk_getitem_string_key(self):
        c = Chunk(b'Data')
        c['mykey'] = 42
        self.assertEqual(c['mykey'], 42)

    def test_chunk_getitem_slice(self):
        c = Chunk(b'Hello World')
        self.assertEqual(c[0:5], bytearray(b'Hello'))

    def test_chunk_setitem_string(self):
        c = Chunk(b'Data')
        c['var'] = 'value'
        self.assertEqual(c['var'], 'value')

    def test_chunk_setitem_bytes_slice(self):
        c = Chunk(b'Hello World')
        c[0:5] = b'Byeee'
        self.assertEqual(bytes(c), b'Byeee World')

    def test_chunk_copy(self):
        c = Chunk(b'Hello', path=[0, 1], view=[True, True])
        c['key'] = 'value'
        c2 = c.copy()
        self.assertEqual(bytes(c2), b'Hello')
        self.assertEqual(c2.path, [0, 1])
        self.assertEqual(c2.scope, 2)

    def test_chunk_copy_no_data(self):
        c = Chunk(b'Hello')
        c2 = c.copy(data=False)
        self.assertEqual(bytes(c2), b'')

    def test_chunk_truncate(self):
        c = Chunk(b'Data', path=[0, 1, 2], view=[True, True, False])
        c.truncate(1)
        self.assertEqual(c.scope, 1)
        self.assertEqual(c.path, [0])
        self.assertEqual(c.view, [True])

    def test_chunk_repr(self):
        c = Chunk(b'AB', path=[0, 1], view=[True, False])
        r = repr(c)
        self.assertIn('chunk', r)

    def test_chunk_intersect(self):
        c1 = Chunk(b'Data')
        c1['a'] = 1
        c1['b'] = 2
        c2 = Chunk(b'Data')
        c2['a'] = 1
        c2['b'] = 999
        c1.intersect(c2)
        self.assertEqual(c1.meta.get('a'), 1)

    def test_chunk_set_next_scope(self):
        c = Chunk(b'Data')
        c.set_next_scope(True)
        self.assertEqual(c._fill_scope, True)

    def test_chunk_scopable_depth_0(self):
        c = Chunk(b'Data')
        self.assertTrue(c.scopable)

    def test_chunk_scopable_depth_2(self):
        c = Chunk(b'Data', path=[0, 1], view=[True, True])
        self.assertTrue(c.scopable)
        c2 = Chunk(b'Data', path=[0, 1], view=[False, True])
        self.assertFalse(c2.scopable)

    def test_chunk_copy_is_dunder(self):
        c = Chunk(b'Hello')
        c2 = copy.copy(c)
        self.assertIsInstance(c2, Chunk)
        self.assertEqual(bytes(c2), b'Hello')

    def test_view_path_length_mismatch(self):
        with self.assertRaises(ValueError):
            Chunk(b'Data', path=[0, 1], view=[True])
