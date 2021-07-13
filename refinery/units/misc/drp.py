#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

from .. import arg, Unit
from ...lib.suffixtree import SuffixTree
from ...lib.types import INF


class stackdepth:
    def __init__(self, depth):
        self.depth = depth
        self.default = sys.getrecursionlimit()

    def __enter__(self):
        if self.depth > self.default:
            sys.setrecursionlimit(self.depth)
        return self

    def __exit__(self, *args):
        sys.setrecursionlimit(self.default)
        return False


class drp(Unit):
    """
    Detect Repeating Patterns - detects the most prevalent repeating byte pattern
    in a chunk of data. The unit computes a suffix tree which may require a lot of
    memory for large buffers.
    """
    def __init__(
        self,
        consecutive: arg.switch('-c', help='Assume that the repeating pattern is consecutive when observable.') = False,
        min: arg.number('-n', help='Minimum size of the pattern to search for. Default is {default}.') = 1,
        max: arg.number('-N', help='Maximum size of the pattern to search for. Default is {default}.') = INF,
        len: arg.number('-l', help='Set the exact size of the pattern. This is equivalent to --min=N --max=N.') = None,
        all: arg.switch('-a', help='Produce one output for each repeating pattern that was detected.') = False,
        threshold: arg.number('-t', help='Patterns must match this performance threshold in percent, lest they be discarded.') = 20,
        weight: arg.number('-w', help='Specifies how much longer patterns are favored over small ones. Default is {default}.') = 0,
        buffer: arg.number('-b', group='BFR', help='Maximum number of bytes to inspect at once. The default is {default}.') = 1024,
        chug  : arg.switch('-g', group='BFR', help='Compute the prefix tree for the entire buffer instead of chunking it.') = False
    ):
        if len is not None:
            min = max = len
        super().__init__(
            min=min,
            max=max,
            all=all,
            consecutive=consecutive,
            weight=weight,
            buffer=buffer,
            chug=chug,
            threshold=threshold
        )

    def _get_patterns(self, data):
        with stackdepth(len(data)):
            tree = SuffixTree(data)
        min_size = self.args.min
        max_size = self.args.max
        patterns = set()
        cursor = 0
        while cursor < len(data):
            node = tree.root
            rest = data[cursor:]
            remaining = len(rest)
            length = 0
            offset = None
            while node.children and length < remaining:
                for child in node.children.values():
                    if tree.data[child.start] == rest[length]:
                        node = child
                        break
                if node.start >= cursor:
                    break
                offset = node.start - length
                length = node.end + 1 - offset
            if offset is None:
                cursor += 1
                continue
            length = min(remaining, length)
            if max_size >= length >= min_size:
                pattern = rest[:length].tobytes()
                patterns.add(pattern)
            cursor += length
        del tree
        return patterns

    @staticmethod
    def _consecutive_count(data, pattern):
        length = len(pattern)
        if length == 1:
            return data.count(pattern)
        view = memoryview(data)
        return max(sum(1 for i in range(k, len(view), length) if view[i:i + length] == pattern)
            for k in range(len(pattern)))

    @staticmethod
    def _truncate_pattern(pattern):
        offset = 0
        for byte in pattern[1:]:
            if byte == pattern[offset]:
                offset += 1
            else:
                offset = 0
        if offset > 0:
            pattern = pattern[:-offset]
        return pattern

    def process(self, data):
        memview = memoryview(data)
        weight = 1 + (self.args.weight / 10)

        if self.args.chug:
            patterns = self._get_patterns(memview)
        else:
            patterns = set()
            chunksize = self.args.buffer
            for k in range(0, len(memview), chunksize):
                patterns |= self._get_patterns(memview[k:k + chunksize])
        if not patterns:
            raise RuntimeError('unexpected state: no repeating sequences found')

        self.log_debug('removing duplicate pattern detections')
        duplicates = set()
        maxlen = max(len(p) for p in patterns)
        for pattern in sorted(patterns, key=len):
            for k in range(2, maxlen // len(pattern) + 1):
                repeated = pattern * k
                if repeated in patterns:
                    duplicates.add(repeated)
        patterns -= duplicates

        self.log_debug(F'counting coverage of {len(patterns)} patterns')
        pattern_count = {p: data.count(p) for p in patterns}
        pattern_performance = dict(pattern_count)

        for consecutive in (False, True):
            if consecutive:
                self.log_debug(F're-counting coverage of {len(patterns)} patterns')
                patterns = {self._truncate_pattern(p) for p in patterns}
                pattern_performance = {p: self._consecutive_count(data, p) for p in patterns}

            self.log_debug('evaluating pattern performance')
            for pattern, count in pattern_performance.items():
                pattern_performance[pattern] = count * (len(pattern) ** weight)
            best_performance = max(pattern_performance.values())
            for pattern, performance in pattern_performance.items():
                pattern_performance[pattern] = performance / best_performance

            self.log_debug('removing patterns below performance threshold')
            threshold = self.args.threshold
            patterns = {p for p in patterns if pattern_performance[p] * 100 >= threshold}

            if not self.args.consecutive:
                break

        if self.args.all:
            for pattern in sorted(patterns, key=pattern_performance.get, reverse=True):
                yield self.labelled(pattern, count=pattern_count[pattern])
            return

        best_patterns = [p for p in patterns if pattern_performance[p] == 1.0]

        if len(best_patterns) > 1:
            self.log_warn('could not determine unique best repeating pattern, returning the first of these:')
            for k, pattern in enumerate(best_patterns):
                self.log_warn(F'{k:02d}.: {pattern.hex()}')

        yield best_patterns[0]
