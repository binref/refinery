"""
Programs that read a table through an accessor, a function like `function A(i) { return T[i]; }`
over an array `var T = [...]`, and programs whose functions read other names declared outside
them. A call folds to the value it reads where that name holds one value nothing changes and that
value is in place before the call runs. Every other call stays, or becomes the read it makes. A
function that changes an array it reads, or hands the array out, keeps every call, since what a
call answers then depends on every call made before it.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
    printed,
)

#: Programs calling an accessor whose table, or a function whose constant, is in place before every
#: call runs and never changes, mapped to what Node prints for them.
A_CALL_THE_TABLE_IS_IN_PLACE_FOR = {
    a_program("""
        function A(i) { return T[i > 1 ? i - 3 : i - -2]; }
        var T = ['a', 'b', 'c', 'd'];
        console.log(A(0), A(2), A(-1));
        """): 'c undefined b\n',
    a_program("""
        var T = ['x', 'y'];
        class C {
          m() {
            function A(i) { return T[i - 1]; }
            return A(2);
          }
        }
        console.log(new C().m());
        """): 'y\n',
    a_program("""
        function A(s) { return s + K; }
        var K = '!';
        console.log(A('a'));
        """): 'a!\n',
    a_program("""
        function outer(n) {
          var T = ['p', 'q'];
          function A(i) { return T[i]; }
          return A(1) + n;
        }
        console.log(outer(process.argv.length));
        """): 'q2\n',
    a_program("""
        function A(s) { return s + '!'; }
        var K = 'k';
        console.log(A(K));
        """): 'k!\n',
    a_program("""
        function A() { return typeof T; }
        var T = ['x'];
        console.log(A());
        """): 'object\n',
}

#: Programs calling an accessor once before its table is in place and once after, mapped to what
#: Node prints for them and to the text the deobfuscation writes: the first call becomes the read of
#: the table it makes, which fails as the call did, and only the second becomes the element.
A_CALL_BEFORE_THE_TABLE_IS_IN_PLACE = {
    a_program("""
        function A(i) { return T[i]; }
        try { console.log(A(0)); } catch (e) { console.log(e.name); }
        var T = ['x'];
        console.log(A(0));
        """): (
        'TypeError\nx\n',
        a_program("""
            try {
              console.log(T[0]);
            } catch (e) {
              console.log(e.name);
            }
            var T = ['x'];
            console.log('x');
            """),
    ),
    a_program("""
        function A(i) { return T[i]; }
        try { console.log(A(0)); } catch (e) { console.log(e.name); }
        let T = ['x'];
        console.log(A(0));
        """): (
        'ReferenceError\nx\n',
        a_program("""
            try {
              console.log(T[0]);
            } catch (e) {
              console.log(e.name);
            }
            let T = ['x'];
            console.log('x');
            """),
    ),
    a_program("""
        function A(i) { return T[i]; }
        function g() { return A(0); }
        try { g(); } catch (e) { console.log(e.name); }
        var T = ['x'];
        console.log(g());
        """): (
        'TypeError\nx\n',
        a_program("""
            try {
              T[0];
            } catch (e) {
              console.log(e.name);
            }
            var T = ['x'];
            console.log('x');
            """),
    ),
}

#: Programs calling an accessor whose table changes, may change, is handed out, or is not the one
#: the accessor reads, and a function that writes the value it reads, mapped to what Node prints
#: for them. None of these calls has a value the file decides.
A_CALL_WHOSE_TABLE_MAY_CHANGE = {
    a_program("""
        function A(i) { return T[i]; }
        var T = ['x'];
        console.log(A(0));
        T[0] = 'y';
        console.log(A(0));
        """): 'x\ny\n',
    a_program("""
        function A(i) { return T[i]; }
        var T = ['x'];
        console.log(A(0));
        T = ['y'];
        console.log(A(0));
        """): 'x\ny\n',
    a_program("""
        function A(i) { return T[i]; }
        var T = ['b', 'a'];
        function s(x) { x.sort(); }
        console.log(A(0));
        s(T);
        console.log(A(0));
        """): 'b\na\n',
    a_program("""
        function A(i) { return T[i]; }
        var T = [[1], [2]];
        A(0).push(5);
        console.log(A(0).length);
        """): '2\n',
    a_program("""
        function A() { return T; }
        var T = ['b', 'a'];
        console.log(A() === A());
        """): 'true\n',
    a_program("""
        var T = ['x'];
        var o = { T: ['y'] };
        with (o) { var A = function (i) { return T[i]; }; }
        console.log(A(0));
        """): 'y\n',
    a_program("""
        function outer(s) {
          var T = ['p'];
          eval(s);
          function A(i) { return T[i]; }
          return A(0);
        }
        console.log(outer(process.argv[2] || "T = ['e']"));
        """): 'e\n',
    a_program("""
        var a;
        function f() { a = 2; return a; }
        console.log(f(), a);
        """): '2 2\n',
}

#: Programs calling a function that changes or hands out an array it reads, mapped to what Node
#: prints for them.
A_CALL_CHANGING_THE_ARRAY_IT_READS = {
    a_program("""
        const data = ['first', 'second', 'third'];
        const f = () => data.shift();
        var a = f();
        function g() { return f(); }
        var b = f();
        console.log(a, b, g());
        """): 'first second third\n',
    a_program("""
        const data = ['first', 'second', 'third'];
        const f = () => data.shift();
        for (var i = 0; i < 2; i++) console.log(f());
        console.log(f());
        """): 'first\nsecond\nthird\n',
    a_program("""
        const data = ['first', 'second', 'third'];
        const f = () => data.shift();
        if (Math.random() > 2) console.log(f());
        console.log(f());
        """): 'first\n',
    a_program("""
        const T = [1, 2];
        const g = () => T;
        g().push(3);
        console.log(T.length);
        """): '3\n',
}

#: A script whose table a host reads by name, and so may have rewritten before the call runs.
A_TABLE_A_HOST_READS = a_program("""
    function A(i) { return T[i]; }
    var T = ['x'];
    console.log(A(0));
    """)

#: Programs whose recursive function reads one of its own locals before the declaration of that
#: local has run in the inner call, mapped to what Node prints for them.
A_RECURSIVE_CALL_READING_A_LOCAL_BEFORE_ITS_DECLARATION = {
    a_program("""
        function F(n) {
          if (n === 0) { return g(); }
          const g = () => 5;
          function K() { return F(0); }
          return K();
        }
        try { console.log(F(1)); } catch (e) { console.log(e.name); }
        """): 'ReferenceError\n',
    a_program("""
        function F(n) {
          if (n === 0) { return t; }
          let t = 5;
          function K() { return F(0); }
          return K();
        }
        try { console.log(F(1)); } catch (e) { console.log(e.name); }
        """): 'ReferenceError\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATableReadThroughAnAccessorStillPrintsTheSame(TestBase):

    def test_a_call_the_table_is_in_place_for(self):
        rows = A_CALL_THE_TABLE_IS_IN_PLACE_FOR
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_before_the_table_is_in_place(self):
        rows = {
            source: prints
            for source, (prints, _) in A_CALL_BEFORE_THE_TABLE_IS_IN_PLACE.items()
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_whose_table_may_change(self):
        rows = A_CALL_WHOSE_TABLE_MAY_CHANGE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_changing_the_array_it_reads(self):
        rows = A_CALL_CHANGING_THE_ARRAY_IT_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_recursive_call_reading_a_local_before_its_declaration(self):
        rows = A_RECURSIVE_CALL_READING_A_LOCAL_BEFORE_ITS_DECLARATION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestATableReadThroughAnAccessorIsFolded(TestBase):

    def test_the_accessor_is_gone_once_the_table_is_in_place_for_every_call(self):
        rows = A_CALL_THE_TABLE_IS_IN_PLACE_FOR
        self.assertEqual(
            {source: 'A(' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )

    def test_a_call_before_the_table_is_in_place_becomes_the_read_it_makes(self):
        rows = A_CALL_BEFORE_THE_TABLE_IS_IN_PLACE
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) + '\n' for source in rows},
            {source: written for source, (_, written) in rows.items()},
        )

    def test_a_call_whose_table_may_change_is_left_as_it_is(self):
        rows = A_CALL_WHOSE_TABLE_MAY_CHANGE
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_call_changing_the_array_it_reads_is_left_as_it_is(self):
        rows = A_CALL_CHANGING_THE_ARRAY_IT_READS
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_call_into_a_table_a_host_reads_is_left_as_it_is(self):
        source = A_TABLE_A_HOST_READS
        self.assertEqual(
            (
                deobfuscate_source(source),
                deobfuscate_source(source, entrypoints=('T',)),
            ),
            (
                "console.log('x');",
                printed(source),
            ),
        )
