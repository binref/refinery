#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io

from refinery.lib.frame import FrameUnpacker
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
        pipeline = load_pipeline('emit A | rex .. [| iff 1 [| cfmt boom ]]]')
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
            | cfmt {x}          ]
        ''')(B'')

        self.assertEqual(x, B'X' * 1000)

    def test_regression_unaltered_pop(self):
        pl = load_pipeline('rex "..(?P<t>..)" [| push var:t [| rex .. | pick ~0 | pop t ]| cfmt {t} ]')
        self.assertEqual(b'REFINERY' | pl | bytes, B'FIRY')

    def test_chunk_output_to_list(self):
        from refinery.units import Chunk
        from refinery.units.meta.chop import chop
        data = Chunk(B'Hello', [0], [True])
        self.assertEqual(data.scope, 1)
        test = data | chop(2) | [str]
        self.assertEqual(test, ['He', 'll', 'o'])

    def test_auto_index_regression(self):
        pipe = self.load_pipeline('emit 0 1 2 3 4 5 [| max index | cfmt {index} ]')
        self.assertEqual(0 | pipe | int, 0)
        pipe = self.load_pipeline('emit 0 1 2 3 4 5 [| put k index | max k | cfmt {k} ]')
        self.assertEqual(0 | pipe | int, 5)
