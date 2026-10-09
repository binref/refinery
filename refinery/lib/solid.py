"""
Streams of decoded data from which several files are read, such as the solid blocks of an archive.
An extractor creates one `SolidClaim` for every file that it lists, and the file is read by calling
its claim. The stream is decoded forward, and decoded bytes are kept only for claims that are alive
and have not been read: A file that is decoded before its turn is kept until it is read, and a file
that nobody claims is not kept at all.
"""
from __future__ import annotations

import heapq
import itertools
import weakref

from typing import TYPE_CHECKING

from refinery.lib.tools import copy_exception

if TYPE_CHECKING:
    from typing import Callable, Iterable, Iterator

    from refinery.lib.types import buf

    Pieces = Iterable[tuple[int, buf]]


class SolidStreamTruncated(EOFError):
    """
    Raised when a claim is read and the decoded stream has no data at the given offset inside the
    claimed range. The bytes of the range before that offset are available as `partial`.
    """
    def __init__(self, offset: int, partial: buf):
        super().__init__(F'The decoded stream has no data at offset {offset:#x}.')
        self.partial = partial


class SolidClaim:
    """
    A claim on the bytes of a `SolidStream` from `offset` to `offset + size`. Calling the claim
    returns these bytes. A claim without a size takes the decoded piece that starts at its offset.
    """
    __slots__ = (
        'stream',
        'offset',
        'size',
        '_data',
        '_filled',
        '_wanted',
        '_cut',
        '__weakref__',
    )

    def __init__(self, stream: SolidStream, offset: int, size: int | None):
        self.stream = stream
        self.offset = offset
        self.size = size
        self._data: buf | None = None
        self._filled = 0
        self._wanted = True
        self._cut = False

    def __call__(self) -> buf:
        return self.stream.read(self)

    @property
    def next(self) -> int:
        """
        The position of the first byte that the claim is still missing.
        """
        return self.offset + self._filled

    @property
    def complete(self) -> bool:
        if (size := self.size) is None:
            return self._data is not None
        return self._filled >= size

    def _needs(self, position: int) -> bool:
        if (size := self.size) is None:
            return position <= self.offset
        return position < self.offset + size

    def _feed(self, position: int, piece: memoryview, volatile: bool):
        offset = self.offset
        if (size := self.size) is None:
            if position == offset:
                self._data = bytes(piece) if volatile else piece
            else:
                self._cut = True
            return
        filled = self._filled
        start = offset + filled - position
        stop = min(offset + size - position, len(piece))
        if stop <= start:
            return
        if filled == 0 and stop - start == size and not volatile:
            self._data = piece[start:stop]
        else:
            if (data := self._data) is None:
                data = self._data = bytearray()
            assert isinstance(data, bytearray)
            data += piece[start:stop]
        self._filled = filled + stop - start

    def _reset(self):
        self._data = None
        self._filled = 0
        self._cut = False

    def _take(self) -> buf:
        data = self._data
        self._reset()
        self._wanted = False
        if data is None:
            return B''
        return data

    def _truncated(self) -> SolidStreamTruncated:
        offset = self.next
        if (data := self._data) is None:
            data = B''
        elif self.size is not None:
            data = memoryview(data)[:offset - self.offset]
        return SolidStreamTruncated(offset, data)


class SolidStream:
    """
    A decoded stream from which several files are read. The function `decode` receives a restart
    point and returns the decoded stream from there as pairs of a position and a piece of data. No
    piece may start before the restart point or before the end of the previous piece, and the stream
    has no data in a range that no piece covers. The function `restart` receives an offset and
    returns the restart point at or before it; by default, the stream is decoded from its start.
    Decoding from a restart point yields the same data as decoding from any earlier one. The stream
    only decodes the parts that an unread claim needs: It skips ahead to the restart point of the
    next claim that needs data when no claim needs the data before it. Decoding has to be
    deterministic: When it fails, the stream remembers the error for the restart point at or before
    the failure, and a read that would decode across the failure from there raises the same error
    without decoding again; claims behind a later restart point are not affected. If `volatile` is
    set, the decoder may overwrite a piece once the next one is requested; the stream then copies
    every byte that it keeps.
    """
    def __init__(
        self,
        decode: Callable[[int], Pieces],
        restart: Callable[[int], int] | None = None,
        volatile: bool = False,
    ):
        self._decode = decode
        self._restart = restart
        self._volatile = volatile
        self._pieces: Iterator[tuple[int, buf]] | None = None
        self._position = 0
        self._start: int | None = None
        self._claims: weakref.WeakSet[SolidClaim] = weakref.WeakSet()
        self._queue: list[tuple[int, int, weakref.ref[SolidClaim]]] = []
        self._order = itertools.count()
        self._failures: dict[int, tuple[int, Exception]] = {}

    def claim(self, offset: int, size: int | None = None) -> SolidClaim:
        """
        Claim the given range of the stream. Without a size, the claim takes the piece that starts
        at the given offset.
        """
        claim = SolidClaim(self, offset, size)
        self._claims.add(claim)
        if self._pieces is not None and not self._passed(claim) and not self._doomed(claim):
            self._enqueue(claim)
        return claim

    def read(self, claim: SolidClaim) -> buf:
        """
        Return the bytes of the given claim, decoding the stream as far as necessary.
        """
        claim._wanted = True
        try:
            self._fill(claim)
        except BaseException:
            claim._reset()
            claim._wanted = False
            raise
        self._prune()
        if not self._queue:
            self._pieces = None
        return claim._take()

    def _origin(self, offset: int) -> int:
        if (restart := self._restart) is None:
            return 0
        if (origin := restart(offset)) > offset:
            raise RuntimeError(F'The restart point {origin:#x} lies after the offset {offset:#x}.')
        return origin

    def _passed(self, claim: SolidClaim) -> bool:
        if (need := claim.next) < self._position:
            return True
        return claim.size is None and need == self._start

    def _doomed(self, claim: SolidClaim) -> bool:
        failure = self._failures.get(self._origin(claim.next))
        return failure is not None and claim._needs(failure[0])

    def _fill(self, claim: SolidClaim):
        if (
            self._pieces is not None
            and not claim.complete
            and not claim._cut
            and not self._passed(claim)
        ):
            self._enqueue(claim)
        while not claim.complete:
            if claim._cut:
                raise claim._truncated()
            if (failure := self._failures.get(self._origin(claim.next))) and claim._needs(failure[0]):
                raise copy_exception(failure[1])
            if self._pieces is None or self._passed(claim):
                self._begin(self._origin(claim.next))
            else:
                self._skip()
            pieces = self._pieces
            assert pieces is not None
            try:
                position, piece = next(pieces)
            except StopIteration:
                self._end()
                continue
            except MemoryError:
                self._pieces = None
                raise
            except Exception as error:
                self._fail(error)
                if self._doomed(claim):
                    raise
                continue
            except BaseException:
                self._pieces = None
                raise
            try:
                self._distribute(position, piece)
            except BaseException:
                self._pieces = None
                raise

    def _enqueue(self, claim: SolidClaim):
        heapq.heappush(self._queue, (claim.next, next(self._order), weakref.ref(claim)))

    def _prune(self):
        queue = self._queue
        while queue and self._pending(queue[0]) is None:
            heapq.heappop(queue)

    def _begin(self, origin: int):
        self._resume(origin)
        self._queue.clear()
        for claim in self._claims:
            if (
                claim._wanted
                and not claim._cut
                and not claim.complete
                and claim.next >= origin
                and not self._doomed(claim)
            ):
                self._enqueue(claim)

    def _resume(self, origin: int):
        self._pieces = iter(self._decode(origin))
        self._position = origin
        self._start = None

    def _skip(self):
        if self._restart is None:
            return
        self._prune()
        if (queue := self._queue) and (origin := self._origin(queue[0][0])) > self._position:
            self._resume(origin)

    @staticmethod
    def _pending(entry: tuple[int, int, weakref.ref[SolidClaim]]) -> SolidClaim | None:
        need, _, ref = entry
        if (claim := ref()) is None or not claim._wanted or claim.complete or claim.next != need:
            return None
        return claim

    def _end(self):
        for entry in self._queue:
            if (claim := self._pending(entry)) is not None:
                claim._cut = True
        self._queue.clear()
        self._pieces = None

    def _fail(self, error: Exception):
        self._queue.clear()
        self._pieces = None
        position = self._position
        self._failures[self._origin(position)] = position, copy_exception(error)

    def _distribute(self, position: int, piece: buf):
        end = position + len(piece)
        self._position = end
        self._start = position
        limit = end if end > position else position + 1
        queue = self._queue
        if not queue or queue[0][0] >= limit:
            return
        view = memoryview(piece)
        volatile = self._volatile
        waiting = []
        while queue and queue[0][0] < limit:
            entry = heapq.heappop(queue)
            if (claim := self._pending(entry)) is None:
                continue
            if entry[0] < position:
                claim._cut = True
                continue
            claim._feed(position, view, volatile)
            if not claim.complete and not claim._cut:
                waiting.append((claim.next, entry[1], entry[2]))
        for entry in waiting:
            heapq.heappush(queue, entry)
