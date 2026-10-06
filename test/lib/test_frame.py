import contextlib
import copy
import gc
import io
import itertools
import tracemalloc
import unittest
import weakref

from refinery.lib.frame import Chunk, FrameUnpacker, generate_frame_header, MAGIC, MSIZE
from refinery.lib.loader import load_detached as L, load_pipeline

from .. import TestBase


class _Lifetimes:
    def __init__(self):
        self.tracked: list[weakref.ref] = []
        self.notes: list[list[int]] = []

    def note(self):
        self.notes.append([k for k, ref in enumerate(self.tracked) if ref() is not None])

    def track(self, chunk: Chunk) -> Chunk:
        self.tracked.append(weakref.ref(chunk))
        return chunk


@contextlib.contextmanager
def _without_cycle_collector():
    enabled = gc.isenabled()
    gc.collect()
    gc.disable()
    try:
        yield
    finally:
        if enabled:
            gc.enable()


def _drain(pipeline):
    for chunk in pipeline:
        del chunk


def _configured(unit, nesting: int = 0, squeeze: bool = False, console: bool = False):
    unit.args.nesting = nesting
    unit.args.squeeze = squeeze
    unit.console = console
    return unit


def _peak_memory(function) -> int:
    gc.collect()
    tracemalloc.start()
    try:
        result = function()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    del result
    return peak


def _read_frames(stream) -> list[Chunk]:
    unpacker = FrameUnpacker(stream)
    chunks = []
    while unpacker.nextframe():
        chunks.extend(unpacker)
    return chunks


def _unpacked(stream) -> Chunk | None:
    return FrameUnpacker(stream).next_chunk


class _Trickle(io.RawIOBase):
    def __init__(self, data: bytes):
        self.data = memoryview(data)
        self.offset = 0
        self.sizes = itertools.cycle(range(1, 8))

    def readable(self):
        return True

    def readinto(self, buffer):
        size = min(len(buffer), next(self.sizes), len(self.data) - self.offset)
        buffer[:size] = self.data[self.offset:self.offset + size]
        self.offset += size
        return size


class _Sink:
    def __init__(self):
        self.size = 0

    def writable(self):
        return True

    def isatty(self):
        return False

    def write(self, data):
        self.size += len(data)

    def flush(self):
        pass


class _Terminal(_Sink):
    def __init__(self):
        super().__init__()
        self.data = bytearray()

    def isatty(self):
        return True

    def write(self, data):
        self.data.extend(data)


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
        with io.BytesIO(B'ABCDEFGHIJKLMNOPQRST') as stream:
            slow = stream | L('rex .')
            for k, letter in enumerate(B'ABCDEFGHIJKLMNOPQRST'):
                expected = bytes((letter,))
                if k > 0:
                    expected = B'\n' + expected
                self.assertEqual(slow.read1(20), expected)

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
        self.assertEqual(out['start'], 1)

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

    def _alive_while_producing(self, pipeline) -> list[list[int]]:
        from refinery import Unit
        lifetimes = _Lifetimes()

        class source(Unit):
            def process(self, data):
                for _ in range(4):
                    lifetimes.note()
                    yield lifetimes.track(Chunk(bytes(0x100)))

        with _without_cycle_collector():
            pipeline(source)
        return lifetimes.notes

    def test_unit_outputs_are_released_before_the_next_is_produced(self):
        from refinery import nop
        pipelines = {
            'loop': lambda source: _drain(B'' | source()),
            'list of strings': lambda source: B'' | source() | [str],
            'set of strings': lambda source: B'' | source() | {str},
            'stream': lambda source: B'' | source() | io.BytesIO(),
            'console, frame opened': lambda source: B'' | _configured(source(), 1, console=True) | io.BytesIO(),
            'next unit in a frame': lambda source: _drain(B'' | source()[nop()]),
            'framed input, frame closed': lambda source: _drain([B''] | source()),
            'framed input, frame kept': lambda source: _drain([B''] | _configured(source(), 1)),
        }
        for name, pipeline in pipelines.items():
            with self.subTest(name):
                self.assertEqual(self._alive_while_producing(pipeline), [[], [], [], []])

    def test_next_unit_keeps_only_the_first_output_it_takes_as_its_input(self):
        from refinery import nop
        self.assertEqual(
            self._alive_while_producing(lambda source: _drain(B'' | source() | nop())),
            [[], [0], [0], [0]],
        )

    def test_merge_keeps_only_its_first_piece_until_the_second_arrives(self):
        nested = Chunk(B'', path=[0, 0], view=[True, True])
        pipelines = {
            'squeezed': lambda source: _drain(B'' | _configured(source(), squeeze=True)),
            'squeezed in a frame': lambda source: _drain([B''] | _configured(source(), 1, squeeze=True)),
            'frame closed into its parent': lambda source: _drain([nested] | _configured(source(), -1)),
        }
        for name, pipeline in pipelines.items():
            with self.subTest(name):
                self.assertEqual(self._alive_while_producing(pipeline), [[], [0], [], []])

    def test_unit_output_is_freed_when_its_consumer_drops_it(self):
        from refinery import Unit
        lifetimes = _Lifetimes()

        class source(Unit):
            def process(self, data):
                for _ in range(4):
                    yield lifetimes.track(Chunk(bytes(0x100)))

        with _without_cycle_collector():
            for chunk in B'' | source():
                del chunk
                lifetimes.note()
        self.assertEqual(lifetimes.notes, [[], [], [], []])

    def test_framed_output_reaches_its_consumer_without_the_original(self):
        from refinery import Unit, nop
        nested = Chunk(B'', path=[0, 0], view=[True, True])
        pipelines = {
            'frame opened': lambda source, single: B'' | _configured(source(), 1),
            'frame kept': lambda source, single: [B''] | _configured(source(), 1),
            'next unit in a frame': lambda source, single: B'' | source()[nop()],
            'one output for each input': lambda source, single: [B''] * 4 | _configured(single(), 1),
            'squeezed in a frame': lambda source, single: [B''] | _configured(source(), 1, squeeze=True),
            'frame closed into its parent': lambda source, single: [nested] | _configured(source(), -1),
        }
        for name, pipeline in pipelines.items():
            with self.subTest(name):
                lifetimes = _Lifetimes()

                class source(Unit):
                    def process(self, data):
                        for _ in range(4):
                            yield lifetimes.track(Chunk(bytes(0x100)))

                class single(Unit):
                    def process(self, data):
                        return lifetimes.track(Chunk(bytes(0x100)))

                with _without_cycle_collector():
                    for _ in pipeline(source, single):
                        lifetimes.note()
                self.assertTrue(lifetimes.notes)
                self.assertEqual(lifetimes.notes, [[]] * len(lifetimes.notes))

    def test_unit_inputs_are_released_before_the_next_is_read(self):
        from refinery import Unit
        pipelines = {
            'frame closed': lambda source, spy: _drain(B'' | source()[spy()]),
            'frame kept': lambda source, spy: _drain(B'' | source()[_configured(spy(), 1)]),
            'frame opened': lambda source, spy: _drain(B'' | source()[_configured(spy(), 2)]),
            'stream': lambda source, spy: B'' | source()[spy()] | io.BytesIO(),
        }
        for name, pipeline in pipelines.items():
            with self.subTest(name):
                lifetimes = _Lifetimes()

                class source(Unit):
                    def process(self, data):
                        for _ in range(4):
                            lifetimes.note()
                            yield Chunk(bytes(0x100))

                class spy(Unit):
                    def process(self, data):
                        return lifetimes.track(data)

                with _without_cycle_collector():
                    pipeline(source, spy)
                self.assertEqual(lifetimes.notes, [[], [], [], []])

    def test_invisible_inputs_are_released_before_the_next_is_read(self):
        from refinery import Unit, scope
        lifetimes = _Lifetimes()

        class source(Unit):
            def process(self, data):
                for _ in range(4):
                    lifetimes.note()
                    yield Chunk(bytes(0x100))

        class spy(Unit):
            def filter(self, chunks):
                for chunk in chunks:
                    yield lifetimes.track(chunk)
                    del chunk

        last_visible = scope(slice(3, 4))
        with _without_cycle_collector():
            _drain(B'' | _configured(source(), 1) | last_visible | _configured(spy(), -1))
        self.assertEqual(len(lifetimes.tracked), 4)
        self.assertEqual(lifetimes.notes, [[], [], [], []])

    def test_unit_input_is_released_when_its_run_ends(self):
        from refinery import Unit
        inputs = {
            'unframed input': (B'data', False),
            'framed input': ([B'data', B'more'], False),
            'framed input, filter stops early': ([B'data', B'more'], True),
        }
        for name, (data, stop_early) in inputs.items():
            with self.subTest(name):
                lifetimes = _Lifetimes()

                class spy(Unit):
                    def filter(self, chunks):
                        if stop_early:
                            chunks = itertools.islice(chunks, 1)
                        yield from chunks

                    def process(self, data):
                        return lifetimes.track(data)

                with _without_cycle_collector():
                    unit = spy()
                    _drain(data | unit)
                    lifetimes.note()
                self.assertEqual(lifetimes.notes, [[]])

    @unittest.expectedFailure
    def test_abandoned_run_releases_its_input(self):
        from refinery import Unit
        lifetimes = _Lifetimes()

        class halves(Unit):
            def process(self, data):
                lifetimes.track(data)
                yield data[:1]
                yield data[1:]

        with _without_cycle_collector():
            unit = B'AB' | halves()
            next(unit)
            del unit
            lifetimes.note()
        self.assertEqual(lifetimes.notes, [[]])

    def test_closing_a_frame_merges_a_repeated_chunk_correctly(self):
        self.assertEqual(load_pipeline('emit AB [[| rep 3 ]| nop ]') | bytes, B'ABABAB')

    def test_chunk_emitted_repeatedly_can_be_squeezed_in_a_frame(self):
        from refinery import Unit

        class thrice(Unit):
            def process(self, data):
                yield data
                yield data
                yield data

        self.assertEqual([B'AB'] | thrice()[:] | [bytes], [B'ABABAB'])

    def test_squeezed_unframed_output_converts_to_a_string(self):
        from refinery import chop
        self.assertEqual(B'ABC' | chop(1)[:] | [str], ['ABC'])

    def test_squeezing_no_output_gives_no_output_with_and_without_a_frame(self):
        from refinery import rex
        self.assertEqual(B'ABC' | rex('X')[:] | [bytes], [])
        self.assertEqual([B'ABC'] | rex('X')[:] | [bytes], [])

    @unittest.expectedFailure
    def test_squeezing_one_chunk_passed_on_with_different_labels_keeps_no_label(self):
        merged, = load_pipeline('emit A [| bruteforce x 1 -a AB []') | [...]
        self.assertEqual(merged, B'AA')
        self.assertNotIn('x', merged.meta.variable_names())

    def test_squeezing_a_single_output_hands_it_on_without_a_copy(self):
        from refinery import Unit
        outputs = []

        class source(Unit):
            def process(self, data):
                outputs.append(Chunk(B'output'))
                yield outputs[-1]

        squeezed, = B'' | _configured(source(), squeeze=True)
        self.assertIs(squeezed, outputs[0])

    def test_console_writes_a_large_framed_chunk_without_copying_it(self):
        from refinery import Unit
        size = 0x1000000

        class source(Unit):
            def process(self, data):
                yield Chunk(size)

        sink = _Sink()
        peak = _peak_memory(lambda: B'' | _configured(source(), 1, console=True) | sink)
        self.assertGreater(sink.size, size)
        self.assertLess(peak, size * 1.5)

    def test_unit_reading_another_unit_gets_the_line_breaks_between_its_outputs(self):
        self.assertEqual(load_pipeline('emit A B | nop') | bytes, B'A\nB')

    def test_output_that_looks_like_a_frame_header_is_kept(self):
        from refinery import emit, nop
        header = generate_frame_header(1)
        self.assertEqual(B'' | emit(header) | [bytes], [header])
        self.assertEqual(B'' | emit(header) | nop() | [bytes], [header])

    def test_framed_hop_in_python_copies_the_data_once(self):
        from refinery import nop
        data = bytes(0x1000000)
        self.assertLess(_peak_memory(lambda: _drain(data | nop()[nop()])), len(data) * 2.5)

    def test_list_input_is_copied_once(self):
        from refinery import nop
        data = bytes(0x1000000)
        self.assertLess(_peak_memory(lambda: _drain([data] | nop())), len(data) * 1.5)

    def test_list_input_is_taken_when_piped(self):
        from refinery import nop
        first = Chunk(B'A')
        first.meta['x'] = 1
        items = [first, 'B']
        unit = items | nop()
        items.clear()
        first.meta['x'] = 2
        outputs = list(unit)
        self.assertEqual(outputs, [B'A', B'B'])
        self.assertEqual(outputs[0].meta['x'], 1)
        with self.assertRaises(UnicodeEncodeError):
            ['\udc80'] | nop()

    def test_list_input_whose_metadata_cannot_be_serialized_is_refused_when_piped(self):
        from refinery import nop
        chunk = Chunk(B'data')
        chunk.meta['x'] = object()
        with self.assertRaises(TypeError):
            [chunk] | nop()

    def test_copy_of_a_unit_keeps_its_list_input_when_the_original_is_dropped(self):
        from refinery import cca, ccp, chop
        self.assertEqual(([B'abcd', B'ef'] | chop(2))[:] | [bytes], [B'abcd', B'ef'])
        self.assertEqual(([B'a', B'b'] | ccp(B'x'))[cca(B'y')] | [bytes], [B'xay', B'xby'])

    def test_metadata_changed_in_place_by_a_unit_reaches_no_other_chunk(self):
        from refinery import Unit

        class twice(Unit):
            def process(self, data):
                data.meta['x'] = [0]
                yield data
                yield data

        class appender(Unit):
            def process(self, data):
                data.meta['x'].append(1)
                return data

        outputs = B'' | _configured(twice(), 1) | appender() | [...]
        self.assertEqual([chunk.meta['x'] for chunk in outputs], [[0, 1], [0, 1]])

    def test_framed_input_in_a_memoryview(self):
        from refinery import nop
        framed = generate_frame_header(1) + Chunk(B'A', path=[0], view=[True]).pack()
        self.assertEqual(memoryview(framed) | nop() | [bytes], [B'A'])

    def test_bytes_input_is_copied_once(self):
        from refinery import nop
        data = bytes(0x1000000)
        self.assertLess(_peak_memory(lambda: _drain(data | nop())), len(data) * 1.5)

    def test_single_unshared_output_is_not_copied(self):
        from refinery import Unit, nop
        data = bytes(0x1000000)
        self.assertLess(_peak_memory(lambda: _drain(data | nop() | nop())), len(data) * 1.5)
        kept = []

        class keeper(Unit):
            def process(self, data):
                kept.append(Chunk(B'kept'))
                return kept[-1]

        result, = B'' | keeper() | nop()
        self.assertIsNot(result, kept[0])
        self.assertEqual(result, kept[0])

    def test_next_unit_takes_the_first_output_uncopied_once_its_producer_drops_it(self):
        from refinery import Unit, nop
        size = 0x1000000

        class outputs(Unit):
            def process(self, data):
                for length in (size, 1):
                    output = Chunk(length)
                    yield output

        self.assertLess(_peak_memory(lambda: _drain(B'' | outputs() | nop())), size * 1.5)

    def test_kept_output_is_copied_even_if_frame_locals_were_read_during_import(self):
        import importlib.util
        import sys
        from refinery.lib import frame

        def read_locals(current, event, arg):
            if event == 'call':
                current.f_locals

        spec = importlib.util.spec_from_file_location('frame_imported_under_a_tracer', frame.__file__)
        assert spec is not None and spec.loader is not None
        traced = importlib.util.module_from_spec(spec)
        tracer = sys.gettrace()
        sys.settrace(read_locals)
        try:
            spec.loader.exec_module(traced)
        finally:
            sys.settrace(tracer)
        kept = [traced.Chunk(B'kept')]
        received = traced.FrameUnpacker(traced.ChunkFeed(kept)).next_chunk
        self.assertIsNot(received, kept[0])
        self.assertEqual(received, kept[0])

    def test_reading_a_unit_gives_the_bytes_it_writes(self):
        from refinery import emit
        self.assertEqual((B'' | emit(B'A', B'', B'B')).read(), B'A\n\nB')
        unit = B'' | emit(B'A', B'', B'B')
        self.assertEqual(list(iter(unit.read1, B'')), [B'A', B'\n', B'\nB'])
        written = B'' | _configured(emit(B'A', B'B'), 1, console=True) | io.BytesIO()
        self.assertEqual((B'' | _configured(emit(B'A', B'B'), 1)).read(), written.getvalue())

    def test_terminal_shows_an_empty_last_output_without_an_empty_line(self):
        from refinery import emit
        for outputs, shown in (
            ([B'A', B''], B'A\n'),
            ([B'A', B'', B'B'], B'A\n\nB\n'),
            ([B''], B''),
            ([B'A\n', B'B'], B'A\nB\n'),
            ([B'A' * 0x1000, B'B'], B'A' * 0x1000 + B'\nB\n'),
        ):
            with self.subTest(outputs=outputs):
                terminal = _Terminal()
                B'' | emit(*outputs) | terminal
                self.assertEqual(terminal.data, shown)

    def test_partly_read_unit_continues_when_piped(self):
        from refinery import emit, nop
        unit = B'' | emit(B'ABCDEF', B'GHI')
        self.assertEqual(unit.read(2), B'AB')
        self.assertEqual(unit | nop() | bytes, B'CDEF\nGHI')
        unit = B'' | emit(B'header\nbody one', B'body two')
        self.assertEqual(unit.readline(), B'header\n')
        self.assertEqual(unit | nop() | bytes, B'body one\nbody two')

    def test_partly_read_unit_continues_when_written(self):
        from refinery import emit
        unit = B'' | emit(B'ABCDEF', B'GHI')
        self.assertEqual(unit.read(2), B'AB')
        self.assertEqual(unit | bytes, B'CDEF\nGHI')
        unit = B'' | emit(B'header\nbody one', B'body two')
        self.assertEqual(unit.readline(), B'header\n')
        self.assertEqual((unit | io.BytesIO()).getvalue(), B'body one\nbody two')
        unit = B'' | emit(B'ABCDEF', B'GHI')
        self.assertEqual(unit.read(2), B'AB')
        self.assertEqual(B''.join(unit), B'CDEF\nGHI')

    def test_unit_handles_errors_in_passing_on_its_own_output(self):
        from refinery import Unit, nop
        from refinery.units import LogLevel

        class unserializable(Unit):
            def process(self, data):
                data.meta['x'] = object()
                return data

        producer = _configured(unserializable(), 1)
        producer.log_level = LogLevel.WARNING
        self.assertEqual(B'' | producer | nop() | [], [])

    def test_partial_read_of_a_unit_does_not_copy_the_rest(self):
        from refinery import nop
        size = 0x1000000
        unit = bytes(size) | nop()
        self.assertEqual(unit.read(1), B'\0')

        def read_on():
            for _ in range(100):
                unit.read(1)

        self.assertLess(_peak_memory(read_on), size // 16)
        self.assertEqual(len(unit.read()), size - 101)

    def test_readline_is_linear(self):
        import time
        from refinery import nop
        line = B'x' * 0x100000 + B'\n'
        unit = line + B'rest' | nop()
        start = time.perf_counter()
        self.assertEqual(unit.readline(), line)
        self.assertLess(time.perf_counter() - start, 1)
        self.assertEqual(unit.readline(), B'rest')
        self.assertEqual(unit.readline(), B'')
        unit = line | nop()
        self.assertEqual(unit.readline(3), B'xxx')
        self.assertEqual(len(unit.readline()), len(line) - 3)

    def test_read_with_size_allocates_only_what_arrives(self):
        from refinery import nop
        unit = B'abc' | nop()
        data = []
        self.assertLess(_peak_memory(lambda: data.append(unit.read(1 << 30))), 0x100000)
        self.assertEqual(data, [B'abc'])

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


class TestFrameStream(TestBase):

    def _chunks(self, *sizes: int) -> list[Chunk]:
        chunks = []
        for position, size in enumerate(sizes):
            chunk = Chunk(bytes(range(256)) * (size // 256) + bytes(range(size % 256)), path=[position], view=[True])
            chunk.meta['x'] = position
            chunks.append(chunk)
        return chunks

    def _stream(self, chunks: list[Chunk]) -> bytes:
        return generate_frame_header(1) + B''.join(chunk.pack() for chunk in chunks)

    def assertChunksEqual(self, read: list[Chunk], chunks: list[Chunk]):
        self.assertEqual(read, chunks)
        self.assertEqual([c.path for c in read], [c.path for c in chunks])
        self.assertEqual([c.meta['x'] for c in read], [c.meta['x'] for c in chunks])

    def test_input_from_a_file_is_read_into_a_chunk_of_its_size(self):
        import os
        import tempfile
        size = 0x1000000
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'input')
            with open(path, 'wb') as stream:
                stream.write(bytes(size))
            with open(path, 'rb') as stream:
                peak = _peak_memory(lambda: FrameUnpacker(stream).next_chunk)
        self.assertLess(peak, size * 1.2)

    def test_input_from_a_compressed_file_is_decompressed_once(self):
        import gzip
        import os
        import tempfile

        class CountingFile(io.FileIO):
            total = 0

            def read(self, size: int | None = -1, /) -> bytes:
                data = super().read(size)
                self.total += len(data)
                return data

        data = bytes(range(256)) * 0x1000
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'input.gz')
            with gzip.open(path, 'wb') as stream:
                stream.write(data)
            with CountingFile(path) as file, gzip.GzipFile(fileobj=file) as stream:
                self.assertEqual(_unpacked(stream), data)
                self.assertEqual(file.total, os.path.getsize(path))

    def test_input_from_a_damaged_compressed_file_is_not_cut_short(self):
        import gzip
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'input.gz')
            with gzip.open(path, 'wb') as stream:
                stream.write(bytes(range(256)) * 0x1000)
            with open(path, 'ab') as stream:
                stream.write(B'\n')
            with gzip.open(path) as stream:
                with self.assertRaises(gzip.BadGzipFile):
                    _unpacked(stream)

    def test_input_that_arrives_in_tiny_pieces_is_read_about_as_fast_as_it_arrives(self):
        import time
        data = bytes(range(256)) * 0x1000
        piece = bytearray(8)
        trickle = _Trickle(data)
        start = time.perf_counter()
        while trickle.readinto(piece):
            pass
        arrival = time.perf_counter() - start
        start = time.perf_counter()
        chunk = _unpacked(_Trickle(data))
        reading = time.perf_counter() - start
        self.assertLess(reading, arrival * 4)
        self.assertEqual(chunk, data)

    def test_input_from_a_pipe_is_read_completely(self):
        import os
        import threading
        data = B''.join(k.to_bytes(4, 'little') for k in range(0x100000))
        r, w = os.pipe()

        def feed():
            with os.fdopen(w, 'wb') as stream:
                for k in range(0, len(data), 0x10000):
                    stream.write(data[k:k + 0x10000])
                    stream.flush()

        thread = threading.Thread(target=feed)
        thread.start()
        with os.fdopen(r, 'rb') as stream:
            chunk = FrameUnpacker(stream).next_chunk
        thread.join()
        self.assertEqual(chunk, data)

    def test_large_framed_chunk_is_read_with_one_copy(self):
        size = 0x1000000
        stream = io.BytesIO(generate_frame_header(1) + Chunk(size, path=[0], view=[True]).pack())
        peak = _peak_memory(lambda: FrameUnpacker(stream).next_chunk)
        self.assertLess(peak, size * 1.2)

    def test_frame_stream_read_in_small_pieces(self):
        chunks = self._chunks(0, 1, 0x3FFF, 0x4000, 0x10001)
        chunks[2].meta['large'] = bytes(0x20000)
        self.assertChunksEqual(_read_frames(_Trickle(self._stream(chunks))), chunks)

    def test_large_chunk_is_read_with_pure_python_msgpack(self):
        import msgpack
        import msgpack.fallback
        from unittest.mock import patch
        chunks = self._chunks(0x30000, 3, 0x10000)
        with patch.object(msgpack, 'Unpacker', msgpack.fallback.Unpacker):
            self.assertChunksEqual(_read_frames(io.BytesIO(self._stream(chunks))), chunks)

    def test_truncated_frame_stream_raises(self):
        data = self._stream(self._chunks(0x20000))
        for end in (MSIZE - 1, MSIZE + 1, MSIZE + 20, len(data) - 0x10000, len(data) - 1):
            with self.subTest(end=end):
                with self.assertRaises(ValueError):
                    _read_frames(io.BytesIO(data[:end]))

    @unittest.expectedFailure
    def test_chunk_that_claims_more_data_than_the_stream_holds_is_refused_cheaply(self):
        head = bytearray(Chunk(0x10000, path=[0], view=[True]).serialize()[0])
        head[-4:] = (0x4000000).to_bytes(4, 'big')
        stream = io.BytesIO(generate_frame_header(1) + head + B'tiny')

        def read():
            with self.assertRaises(ValueError):
                _read_frames(stream)

        self.assertLess(_peak_memory(read), 0x1000000)


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

    def test_serialized_chunk_equals_msgpack_of_its_items(self):
        import msgpack
        for size in (0, 1, 0x3FFF, 0x4000, 0x4001, 0xFFFF, 0x10000, 0x10001):
            with self.subTest(size=size):
                chunk = Chunk(bytes(range(256)) * (size // 256) + bytes(range(size % 256)), path=[3], view=[True])
                chunk.meta['x'] = 'value'
                pieces = chunk.serialize()
                items = (chunk.path, chunk.view, chunk.meta.serialize(1), None, bytes(chunk))
                self.assertEqual(B''.join(pieces), msgpack.packb(items))
                if size >= 0x4000:
                    self.assertIs(pieces[~0], chunk)

    def _memory_kept_by_a_dropped_chunk(self, *keys: str) -> int:
        warmup = Chunk(B'\0' * 0x100000)
        for key in keys:
            warmup.meta[key]
        del warmup
        data = B'\1' * 0x100000
        gc.collect()
        gc.disable()
        tracemalloc.start()
        try:
            start, _ = tracemalloc.get_traced_memory()
            chunk = Chunk(data)
            for key in keys:
                chunk.meta[key]
            del chunk
            end, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            gc.enable()
        return end - start

    def test_dropped_chunk_is_freed_without_the_cycle_collector(self):
        self.assertLess(self._memory_kept_by_a_dropped_chunk('sha256'), 0x100000 // 16)

    def test_chunk_whose_file_type_was_read_is_freed(self):
        self.assertLess(self._memory_kept_by_a_dropped_chunk('magic', 'ext', 'mime'), 0x100000 // 16)

    def test_metadata_of_a_freed_chunk_refuses_to_derive_values(self):
        meta = Chunk(B'data').meta
        with self.assertRaises(RuntimeError):
            meta['sha256']
