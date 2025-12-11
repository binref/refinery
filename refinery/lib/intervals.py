"""
Classes that implement different kinds of interval unions. These are primarily used by code
related to `refinery.lib.emulator` for representing memory regions that have been mapped or
written to.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from bisect import bisect_right
from typing import ClassVar, Generic, Iterator, TypeVar

Value = TypeVar('Value')
"""
A generic type variable representing the value type for `refinery.lib.intervals.IntervalUnion`.
Intervals `[A,B]` are stored by mapping `A` to a `refinery.lib.intervals.Value` object which
contains all additional information about the interval. In particular, `B` can be computed from
this object. The `refinery.lib.intervals.MemoryIntervalUnion` implementation, for example, uses
a `bytearray` type for the `refinery.lib.intervals.Value`.
"""


class IntervalUnion(ABC, Generic[Value]):
    """
    An abstract class representing a generic union of intervals. Intervals inserted into the union
    are automatically fused if they overlap or touch.
    """

    value_type: ClassVar[type]
    """
    This class variable contains the type of `refinery.lib.intervals.Value`.
    """

    def __init__(self):
        self._starts: list[int] = []
        self._values: dict[int, Value] = {}

    @abstractmethod
    def sizeof(self, d: int | Value) -> int:
        """
        Compute the length of the interval from the stored `refinery.lib.intervals.Value` value.
        """

    @abstractmethod
    def insert(
        self,
        start: int,
        value: Value,
        new_start: int,
        new_value: Value,
    ) -> Value:
        """
        Insert new interval data into an interval that already exists and covers the start of the
        newly inserted interval.
        """

    @abstractmethod
    def extend(
        self,
        start: int,
        value: Value,
        new_delta: int,
        new_value: Value
    ) -> Value:
        """
        This function extends the interval given by `(start;value)` with the data from the interval
        `(new_start;new_value)`. Instead of `new_start`, however, the function expects the parameter
        `new_delta` which is computed as subtracting `new_start` from the result of calling the
        method `refinery.lib.intervals.IntervalUnion.endof` for the interval `(start;value)`.
        """

    def endof(self, start: int, value: int | Value | None = None):
        """
        Compute the end of an interval. A `refinery.lib.intervals.Value` can be provided; if none
        is given, the interval is assumed to exist in the union and its value is recovered from the
        internal storage.
        """
        if value is None:
            value = self._starts[start]
        return start + self.sizeof(value)

    def clear(self):
        """
        Remove all intervals from the union.
        """
        self._starts.clear()
        self._values.clear()

    def __len__(self):
        return len(self._starts)

    def __iter__(self):
        for start in self._starts:
            yield (start, self._values[start])

    def _insertion_point(self, point: int, append: bool = False):
        """
        Find the insertion point for any given integer value. The result is a tuple containing:
        - An index into the sorted array of interval starts. If an interval already covers the point,
          then this index points to the start of that interval. If no interval covers the point, this
          value is the index where a new interval start would have to be inserted.
        - The start of an existing interval that covers the point, or `None` if this does not exist.
        - The value of an existing interval that covers the point, or `None` if this does not exist.
        An interval `[A,B]` covers a point `P` if `A <= P <= B+X` where `X` is `1` if the `append`
        parameter is `True`, and `0` otherwise.
        """
        index = bisect_right(self._starts, point)
        start = None
        value = None
        if index > 0:
            _start = self._starts[index - 1]
            _value = self._values[_start]
            if point in range(_start, _start + self.sizeof(_value) + append):
                index = index - 1
                start = _start
                value = _value
        return index, start, value

    def addi(self, start: int, value: Value):
        """
        Insert a new interval into the union.
        """
        starts = self._starts
        values = self._values

        index_of_start, cursor_start, cursor_value = self._insertion_point(
            start, value is not None)
        index_of_next = index_of_start + int(cursor_start is not None)

        if cursor_value is None or cursor_start is None:
            cursor_start = start
            cursor_value = values[cursor_start] = self.value_type()
            index_of_start = index_of_next
            index_of_next = index_of_next + 1
            starts.append(cursor_start)
            starts.sort()
            if starts[index_of_start] != cursor_start:
                raise RuntimeError(
                    F'Adding 0x{cursor_start:X} into sorted lookup table failed; '
                    'value did not end up at the expected position.')

        cursor_value = self.insert(cursor_start, cursor_value, start, value)
        end = cursor_start + self.sizeof(cursor_value)

        insert_value = None
        insert_start = 0
        index_after_merge = len(starts)

        for index_after_merge in range(index_of_next, index_after_merge):
            temp = starts[index_after_merge]
            if temp > end:
                break
            insert_start = temp
            insert_value = values.pop(insert_start)
        else:
            if insert_value is not None:
                index_after_merge += 1

        if insert_value is not None:
            del starts[index_of_next:index_after_merge]
            if (insert_delta := end - insert_start) >= 0:
                self.extend(
                    cursor_start,
                    cursor_value,
                    insert_delta,
                    insert_value,
                )

        return cursor_start

    def overlap(self, start: int, value: int | Value) -> Iterator[tuple[int, Value]]:
        """
        Generate all intervals in the union that overlap with the given interval.
        """
        starts = self._starts
        values = self._values
        lower, _, _ = self._insertion_point(start)
        upper, b, _ = self._insertion_point(self.endof(start, value))
        for k in range(lower, upper + bool(b)):
            start = starts[k]
            value = values[start]
            yield (start, value)

    def __contains__(self, value: int | tuple[int, Value]):
        args = value
        if isinstance(args, int):
            args = (args, None)
        return self.overlaps(*args)

    def overlaps(self, start: int, value: int | Value | None = None) -> bool:
        """
        Return whether the given interval or point overlaps with any interval in the union.
        """
        if value is None:
            _, base, _ = self._insertion_point(start)
            return base is not None
        return any(self.overlap(start, value))

    def boundary(self) -> tuple[int, int] | None:
        """
        Determine the lowest and highest point of this interval union. If no intervals are in the
        union, the return value is None.
        """
        if not self._starts:
            return None
        lower = self._starts[0]
        upper = self._starts[-1] + self.sizeof(self._values[self._starts[-1]])
        return lower, upper

    def gaps(self, lower: int = 0, upper: int | None = None):
        """
        Generate the sequence of gaps between all intervals in this interval union as (start,end)
        tuples. This is notably different from how intervals are stored in the union, namely as
        (start,length) tuples.
        """
        for interval in self:
            start, val = interval
            if upper is not None and start > upper:
                break
            if start > lower:
                yield (lower, start)
            lower = start + self.sizeof(val)
        if upper is not None and lower < upper:
            yield (lower, upper)


class IntIntervalUnion(IntervalUnion[int]):
    """
    An `refinery.lib.intervals.IntervalUnion` of `(start, length)` pairs. Notably, the length of an
    inclusive interval `[A,B]` is computed as `(B-A+1)`.
    """
    value_type = int

    def sizeof(self, d: int) -> int:
        return d

    def insert(self, start: int, value: int, new_start: int, new_value: int) -> int:
        self._values[start] = value = max(value, new_start - start + new_value)
        return value

    def extend(self, start: int, value: int, new_delta: int, new_value: int) -> int:
        self._values[start] = value = value + new_value - new_delta
        return value


class MemoryIntervalUnion(IntervalUnion[bytearray]):
    """
    An `refinery.lib.intervals.IntervalUnion` of memory patches, implemented as `(start, data)`
    paris. Each `data` value is a `bytearray` which contains the region of memory that starts at
    the base address `start`.
    """

    value_type = bytearray

    def sizeof(self, d: int | bytearray) -> int:
        if isinstance(d, int):
            return d
        return len(d)

    def insert(self, start: int, value: bytearray, new_start: int, new_value: bytearray) -> bytearray:
        rva = new_start - start
        end = rva + len(new_value)
        value[rva:end] = new_value
        return value

    def extend(self, start: int, value: bytearray, new_delta: int, new_value: bytearray) -> bytearray:
        view = memoryview(new_value)
        value.extend(view[new_delta:])
        return value
