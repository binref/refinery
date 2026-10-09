import gc
import tracemalloc

from unittest import mock

from refinery.lib.solid import SolidClaim, SolidStream, SolidStreamTruncated

from .. import TestBase

MB = 1 << 20


class Decoder:
    """
    A decoder that yields fresh copies of the given pieces from the given restart points and records
    where it was started, which pieces it decoded, and where each started decoder was released. It
    raises `ValueError` instead of yielding a piece that starts at the position given as `broken`.
    """
    def __init__(self, *pieces: bytes, restarts=(0,), broken=None, gaps=None):
        self.pieces = []
        position = 0
        for k, piece in enumerate(pieces):
            self.pieces.append((position, piece))
            position += len(piece) + (gaps or {}).get(k, 0)
        self.restarts = restarts
        self.broken = broken
        self.starts = []
        self.decoded = []
        self.released = []

    def restart(self, offset):
        return max(r for r in self.restarts if r <= offset)

    def decode(self, origin):
        self.starts.append(origin)
        try:
            for position, piece in self.pieces:
                if position < origin:
                    continue
                if position == self.broken:
                    raise ValueError(F'The piece at {position} is broken.')
                self.decoded.append(position)
                yield position, bytearray(piece)
        finally:
            self.released.append(origin)

    def stream(self, volatile=False):
        return SolidStream(self.decode, self.restart, volatile=volatile)


class Traced:
    """
    Traces memory allocations; `held` is the memory that remains allocated since tracing started.
    """
    def __enter__(self):
        gc.collect()
        tracemalloc.start()
        self.base = tracemalloc.get_traced_memory()[0]
        return self

    def __exit__(self, *_):
        tracemalloc.stop()

    @property
    def held(self) -> int:
        gc.collect()
        return tracemalloc.get_traced_memory()[0] - self.base

    @property
    def peak(self) -> int:
        return tracemalloc.get_traced_memory()[1] - self.base


class TestSolidStream(TestBase):

    def test_files_read_in_order_are_decoded_in_one_pass(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual([bytes(f()) for f in files], [B'A' * 10, B'B' * 10, B'C' * 10])
        self.assertEqual(decoder.starts, [0])
        self.assertEqual(decoder.decoded, [0, 10, 20])

    def test_files_read_in_reverse_order_are_decoded_in_one_pass(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual([bytes(f()) for f in reversed(files)], [B'C' * 10, B'B' * 10, B'A' * 10])
        self.assertEqual(decoder.starts, [0])
        self.assertEqual(decoder.decoded, [0, 10, 20])

    def test_a_file_spanning_several_pieces_is_assembled(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10)
        stream = decoder.stream()
        self.assertEqual(bytes(stream.claim(5, 20)()), B'A' * 5 + B'B' * 10 + B'C' * 5)

    def test_a_file_decoded_before_its_turn_is_kept_until_it_is_read(self):
        stream = Decoder(bytes(4 * MB), bytes(1)).stream()
        early = stream.claim(0, 4 * MB)
        late = stream.claim(4 * MB, 1)
        with Traced() as traced:
            late()
            self.assertGreater(traced.held, 4 * MB)
            early()
            self.assertLess(traced.held, MB)

    def test_a_file_that_nobody_claims_is_not_kept(self):
        decoder = Decoder(bytes(4 * MB), bytes(1))
        stream = decoder.stream()
        unread = stream.claim(0, 4 * MB)
        late = stream.claim(4 * MB, 1)
        del unread
        with Traced() as traced:
            late()
            self.assertLess(traced.held, MB)
        self.assertEqual(decoder.decoded, [0, 4 * MB])

    def test_a_file_that_was_read_is_not_kept_when_it_is_passed_again(self):
        decoder = Decoder(bytes(4 * MB), bytes(1))
        stream = decoder.stream()
        first = stream.claim(0, 4 * MB)
        last = stream.claim(4 * MB, 1)
        first()
        last()
        with Traced() as traced:
            stream.claim(4 * MB, 1)()
            self.assertLess(traced.held, MB)
        self.assertEqual(decoder.starts, [0, 0])

    def test_reading_a_file_again_decodes_it_again(self):
        decoder = Decoder(B'A' * 10, B'B' * 10)
        stream = decoder.stream()
        file = stream.claim(0, 10)
        self.assertEqual(bytes(file()), B'A' * 10)
        self.assertEqual(bytes(file()), B'A' * 10)
        self.assertEqual(decoder.starts, [0, 0])

    def test_the_decoder_is_released_when_no_file_needs_more_data(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10)
        stream = decoder.stream()
        first = stream.claim(0, 10)
        second = stream.claim(10, 10)
        second()
        self.assertEqual(decoder.released, [0])
        self.assertEqual(decoder.decoded, [0, 10])
        self.assertEqual(bytes(first()), B'A' * 10)
        self.assertEqual(decoder.starts, [0])

    def test_a_gap_cuts_only_the_file_that_spans_it(self):
        decoder = Decoder(B'A' * 10, B'B' * 5, B'C' * 10, gaps={1: 5})
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        with self.assertRaises(SolidStreamTruncated) as cut:
            files[1]()
        self.assertEqual(bytes(cut.exception.partial), B'B' * 5)
        self.assertEqual(bytes(files[2]()), B'C' * 10)
        self.assertEqual(decoder.starts, [0])

    def test_the_end_of_the_stream_cuts_every_waiting_file_in_one_pass(self):
        decoder = Decoder(B'A' * 10, B'B' * 5)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(4)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        partial = []
        for file in files[1:]:
            with self.assertRaises(SolidStreamTruncated) as cut:
                file()
            partial.append(bytes(cut.exception.partial))
        self.assertEqual(partial, [B'B' * 5, B'', B''])
        self.assertEqual(decoder.starts, [0])

    def test_a_failure_is_raised_for_every_later_file_without_decoding_again(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10, B'D' * 10, broken=20)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(4)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        errors = []
        for file in files[2:]:
            with self.assertRaises(ValueError) as failure:
                file()
            errors.append(failure.exception)
        self.assertEqual([str(e) for e in errors], ['The piece at 20 is broken.'] * 2)
        self.assertEqual(decoder.starts, [0])
        self.assertEqual(bytes(files[1]()), B'B' * 10)

    def test_a_failure_raised_again_keeps_the_message_of_a_builtin_exception(self):
        expected = str(UnicodeDecodeError('utf-8', B'\xFF', 0, 1, 'invalid start byte'))

        def decode(origin):
            yield 0, bytearray(B'A' * 10)
            B'\xFF'.decode('utf8')

        stream = SolidStream(decode)
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        messages = []
        for file in files[1:]:
            with self.assertRaises(UnicodeDecodeError) as failure:
                file()
            messages.append(str(failure.exception))
        self.assertEqual(messages, [expected, expected])

    def test_a_failure_does_not_affect_files_after_the_next_restart_point(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10, B'D' * 10, restarts=(0, 20), broken=10)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(4)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        with self.assertRaises(ValueError):
            files[1]()
        self.assertEqual(bytes(files[3]()), B'D' * 10)
        self.assertEqual(bytes(files[2]()), B'C' * 10)
        self.assertEqual(decoder.starts, [0, 20])

    def test_a_failure_before_the_restart_point_of_a_file_does_not_fail_it(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10, restarts=(0, 20), broken=10)
        stream = decoder.stream()
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual(bytes(files[0]()), B'A' * 10)
        self.assertEqual(bytes(files[2]()), B'C' * 10)
        with self.assertRaises(ValueError):
            files[1]()
        self.assertEqual(decoder.starts, [0, 20])

    def test_a_unit_that_no_file_needs_is_not_decoded(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10, restarts=(0, 10, 20))
        stream = decoder.stream()
        first = stream.claim(0, 10)
        last = stream.claim(20, 10)
        self.assertEqual(bytes(first()), B'A' * 10)
        self.assertEqual(bytes(last()), B'C' * 10)
        self.assertEqual(decoder.decoded, [0, 20])

    def test_running_out_of_memory_is_not_remembered(self):
        attempts = []

        def decode(origin):
            attempts.append(origin)
            if len(attempts) == 1:
                raise MemoryError
            yield 0, B'A' * 10

        file = SolidStream(decode).claim(0, 10)
        with self.assertRaises(MemoryError):
            file()
        self.assertEqual(bytes(file()), B'A' * 10)

    def test_running_out_of_memory_while_a_piece_is_handed_out_cuts_no_file_short(self):
        decoder = Decoder(B'A' * 10 + B'B' * 10 + B'C' * 10, B'D' * 10)
        stream = decoder.stream()
        a, b, c, d = (stream.claim(k * 10, 10) for k in range(4))
        feed = SolidClaim._feed

        def scarce(claim, *args):
            if claim is b:
                raise MemoryError
            return feed(claim, *args)

        with mock.patch.object(SolidClaim, '_feed', autospec=True, side_effect=scarce):
            with self.assertRaises(MemoryError):
                a()
        self.assertEqual(bytes(d()), B'D' * 10)
        self.assertEqual(bytes(c()), B'C' * 10)
        self.assertEqual(bytes(b()), B'B' * 10)

    def test_pieces_that_the_decoder_overwrites_are_copied(self):
        window = bytearray(10)

        def decode(origin):
            for k, letter in enumerate(B'ABC'):
                window[:] = bytes([letter]) * 10
                yield k * 10, window

        stream = SolidStream(decode, volatile=True)
        files = [stream.claim(k * 10, 10) for k in range(3)]
        self.assertEqual([bytes(f()) for f in reversed(files)], [B'C' * 10, B'B' * 10, B'A' * 10])

    def test_a_file_without_size_takes_the_piece_at_its_offset(self):
        decoder = Decoder(B'A' * 10, B'B' * 4, B'C' * 7, gaps={0: 4, 1: 4})
        stream = decoder.stream()
        files = [stream.claim(0), stream.claim(14), stream.claim(22)]
        self.assertEqual([bytes(f()) for f in reversed(files)], [B'C' * 7, B'B' * 4, B'A' * 10])
        self.assertEqual(decoder.starts, [0])

    def test_a_file_without_size_read_again_takes_the_same_empty_piece(self):
        decoder = Decoder(B'A' * 10, B'', B'C' * 5)
        stream = decoder.stream()
        empty = stream.claim(10)
        last = stream.claim(10, 5)
        self.assertEqual(bytes(empty()), B'')
        self.assertEqual(bytes(empty()), B'')
        self.assertEqual(bytes(last()), B'C' * 5)

    def test_a_file_whose_size_exceeds_the_stream_allocates_no_more_than_the_data(self):
        stream = Decoder(bytes(MB)).stream()
        file = stream.claim(0, 64 * MB)
        with Traced() as traced:
            with self.assertRaises(SolidStreamTruncated) as cut:
                file()
            self.assertEqual(len(cut.exception.partial), MB)
            self.assertLess(traced.peak, 8 * MB)

    def test_a_file_without_size_whose_offset_starts_no_piece_has_no_data(self):
        decoder = Decoder(B'A' * 10, B'B' * 4)
        stream = decoder.stream()
        with self.assertRaises(SolidStreamTruncated):
            stream.claim(5)()
        with self.assertRaises(SolidStreamTruncated):
            stream.claim(20)()

    def test_a_file_claimed_while_decoding_is_served_by_the_same_pass(self):
        decoder = Decoder(B'A' * 10, B'B' * 10, B'C' * 10)
        stream = decoder.stream()
        first = stream.claim(0, 10)
        last = stream.claim(20, 10)
        first()
        middle = stream.claim(10, 10)
        self.assertEqual(bytes(middle()), B'B' * 10)
        self.assertEqual(bytes(last()), B'C' * 10)
        self.assertEqual(decoder.starts, [0])

    def test_a_file_that_spans_restart_points_is_decoded_once_before_it_fails(self):
        decoder = Decoder(*(bytes([k]) * 10 for k in range(10)), restarts=range(0, 100, 10), broken=90)
        stream = decoder.stream()
        with self.assertRaises(ValueError):
            stream.claim(0, 100)()
        self.assertEqual(decoder.decoded, list(range(0, 90, 10)))

    def test_skipping_ahead_to_the_next_file_does_not_look_at_every_waiting_file(self):
        lookups = []

        def restart(offset):
            lookups.append(offset)
            return offset - offset % 4

        def decode(origin):
            for position in range(origin, 8000, 4):
                yield position, bytes(4)

        stream = SolidStream(decode, restart)
        files = [stream.claim(position, 4) for position in range(0, 8000, 8)]
        for file in files:
            file()
        self.assertLess(len(lookups), 10 * len(files))
