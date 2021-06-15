#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import collections
import sys

from .. import arg, Unit
from ...lib.suffixtree import SuffixTree


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
        chunksize: arg.number(metavar='chunksize', help='Maximum number of bytes to inspect at once. The default is {default}') = 1024
    ):
        super().__init__(chunksize=chunksize, consecutive=consecutive)

    def _get_patterns(self, data):
        with stackdepth(len(data)):
            tree = SuffixTree(data)
        patterns = {}
        shadowed = collections.defaultdict(int)
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
            pattern = rest[:length].tobytes()
            shadowed[pattern] = 1
            patterns[pattern] = patterns.get(pattern, 0) + 1
            cursor += length
        del tree
        for child in patterns:
            for parent, count in patterns.items():
                if len(parent) <= len(child):
                    continue
                shadowed[child] += count * parent.count(child)
        for child in patterns:
            patterns[child] += shadowed[child]
        return {
            pattern: len(pattern) * count
            for pattern, count in patterns.items()
            if len(pattern) > 1
        }

    def process(self, data):
        memview = memoryview(data)
        patterns = collections.defaultdict(int)
        chunksize = self.args.chunksize
        for k in range(0, len(memview), chunksize):
            for p, count in self._get_patterns(memview[k:k + chunksize]).items():
                patterns[p] += count
        if not patterns:
            raise RuntimeError('unexpected state: no repeating sequences found')
        self.log_debug('evaluating pattern performance')
        scan_max_performance = max(patterns.values())
        best_patterns = [
            sequence for sequence, performance in patterns.items()
            if performance >= scan_max_performance
        ]
        if len(best_patterns) > 1:
            self.log_warn('could not determine unique best repeating pattern, returning the first of these:')
            for k, p in enumerate(best_patterns):
                self.log_warn(F'{k:02d}.: {p.hex()}')
        result = best_patterns[0]
        if self.args.consecutive:
            offset = 0
            for byte in result[1:]:
                if byte == result[offset]:
                    offset += 1
                else:
                    offset = 0
            if offset > 0:
                result = result[:-offset]
        return result
