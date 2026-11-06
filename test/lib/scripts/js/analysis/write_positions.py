from __future__ import annotations

import inspect

WRITE_POSITIONS = [
    ('assignment', 'console.log(TARGET = 9);'),
    ('compound assignment', 'console.log(TARGET += 5);'),
    ('postfix increment', 'console.log(TARGET++);'),
    ('prefix decrement', 'console.log(--TARGET);'),
    ('delete', 'console.log(delete TARGET);'),
    ('array pattern', 'console.log([TARGET] = [9]);'),
    ('array pattern with default', 'console.log([TARGET = 7] = []);'),
    ('object pattern', 'console.log({ p: TARGET } = { p: 9 });'),
    ('nested pattern', 'console.log([{ p: TARGET }] = [{ p: 9 }]);'),
    ('for-in head', inspect.cleandoc("""
        for (TARGET in { a: 1 }) {
          console.log("in");
        }
    """)),
    ('for-of head', inspect.cleandoc("""
        for (TARGET of [7]) {
          console.log("of");
        }
    """)),
]
