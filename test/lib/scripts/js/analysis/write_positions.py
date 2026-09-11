"""
Every position a member expression can be written in, as a template with a `TARGET` placeholder.

The list describes `is_member_write_target` and `is_simple_assignment_target` — analysis predicates —
so it lives in the analysis test package and is imported by the deobfuscation-side tests that need the
same positions spelled the same way.
"""
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
