from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Iterable, Iterator

from refinery.lib.argformats import sliceobj
from refinery.lib.tools import begin
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


@dataclass
class _PickState:
    slices: Deque[slice]
    chunks: Iterator[Chunk]
    accessor: slice | None = None
    consumed: bool = False
    discarded: int = 0
    remaining: list[Chunk] = field(default_factory=list)

    def next(self):
        try:
            self.accessor = self.slices.popleft()
        except IndexError:
            return False
        else:
            return True

    def __bool__(self):
        return bool(self.slices)

    def discardable(self):
        a = self.accessor
        if not a.stop:
            return False
        if a.stop < 0:
            return False
        if (a.step or 1) <= 0:
            return False
        return all(t.start >= a.stop for t in self.slices)


class pick(Unit):
    """
    Picks sequences from the array of multiple inputs. For example, `pick 0 2:`
    will return all but the second ingested input (which has index `1`).
    """
    def __init__(self, *bounds: Param[slice, Arg.Bounds(nargs='*', default=[0])]):
        super().__init__(bounds=[sliceobj(s) for s in bounds])

    def process(self, data: Chunk):
        if not data.visible:
            yield data
            return

        state: _PickState = data.temp
        a = state.accessor
        lower = a.start
        upper = a.stop

        if lower is not None:
            lower -= state.discarded
        if upper is not None:
            upper -= state.discarded
        if state.consumed:
            yield from state.remaining[slice(lower, upper, a.step)]
            return

        while lower:
            try:
                chunk = next(state.chunks)
            except StopIteration:
                upper = None
                break
            if chunk.visible:
                lower -= 1
                upper -= 1
                state.discarded += 1
            else:
                yield chunk
        if upper is None:
            yield from state.chunks
            return
        while upper:
            try:
                chunk = next(state.chunks)
            except StopIteration:
                break
            if chunk.visible:
                upper -= 1
                state.discarded += 1
            yield chunk

    def filter(self, chunks: Iterable[Chunk]):
        chunks = begin(chunks)
        if chunks is None:
            return
        container, chunks = chunks
        if container.scope < 1:
            raise RuntimeError(F'{self.__class__.__name__} cannot be used outside a frame; maybe you meant to use snip?')
        container = container.copy()
        container.visible = True
        state = _PickState(deque(self.args.bounds), chunks)
        while state.next():
            if not state.consumed:
                if not state.discardable():
                    self.log_debug(F'consumed input into buffer after {state.discarded} skips')
                    for chunk in state.chunks:
                        if not chunk.visible:
                            yield chunk
                            continue
                        state.remaining.append(chunk)
                    state.consumed = True
            container.temp = state
            yield container


class p1(pick):
    """
    A shortcut for `refinery.pick` with the argument `0:1`.
    """
    def __init__(self):
        super().__init__(slice(0, 1))


class p2(pick):
    """
    A shortcut for `refinery.pick` with the argument `0:2`.
    """
    def __init__(self):
        super().__init__(slice(0, 2))


class p3(pick):
    """
    A shortcut for `refinery.pick` with the argument `0:3`.
    """
    def __init__(self):
        super().__init__(slice(0, 3))


class b2f(pick):
    """
    Short for "back to front". This unit is a shortcut for `refinery.pick` with argument `::-1`:
    It will reorder the chunks in the current frame in reverse order.
    """
    def __init__(self):
        super().__init__(slice(None, None, -1))
