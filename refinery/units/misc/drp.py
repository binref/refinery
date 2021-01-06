#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import numpy as np
import sys

from .. import Unit
from ...lib.suffixtree import SuffixTree, Node


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
    def process(self, data):
        with stackdepth(len(data)):
            tree = SuffixTree(memoryview(data))
            scan = {}

        def leafcount(node: Node):
            if not node.children:
                return 1
            try:
                return scan[node]
            except KeyError:
                scan[node] = count = sum(leafcount(c) for c in node)
                return count

        with stackdepth(len(tree.data)):
            scan = {bytes(node.label): leafcount(node) for node in tree}

        del tree
        mean = np.fromiter(scan.values(), dtype=np.float).mean()

        for pattern, performance in list(scan.items()):
            if performance < mean:
                scan.pop(pattern)

        patterns = set(scan)
        finished = False

        while not finished:
            finished = True
            for r in patterns:
                for p in patterns:
                    if r in p and scan[r] > scan[p] > scan[r] - mean:
                        scan.pop(r)
                        patterns.discard(r)
                        finished = False
                        break
                if not finished:
                    break

        best_patterns = []
        best_performance = 0

        for pattern, count in scan.items():
            performance = len(pattern) * count
            if performance >= best_performance:
                if performance > best_performance:
                    best_patterns[:] = []
                best_performance = performance
                best_patterns.append(pattern)

        assert best_patterns, 'did not find a single pattern'

        if len(best_patterns) > 1:
            self.log_warn('could not determine unique best repeating pattern, returning the first of these:')
            for k, p in enumerate(best_patterns):
                self.log_warn(F'{k:02d}.: {p.hex()}')

        return best_patterns[0]
