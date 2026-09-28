"""
Programs that read a table through an accessor over an array `var T = [...]`, a function like

    function A(i) { return T[i]; }

and programs whose functions read other names declared outside them. A call folds to the value it
reads where that name holds one value nothing changes and that value is in place before the call
runs. Every other call stays, or becomes the read it makes. A function that changes an array it
reads, or hands the array out, keeps every call, since what a call answers then depends on every
call made before it.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    deobfuscate_source,
    host_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
    printed,
)

from refinery.units.scripting.js import js

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
    a_program("""
        var T = ['a', 'b'];
        function A(t) { return t === T ? 'same' : 'diff'; }
        console.log(A(T));
        """): 'same\n',
}

#: Programs whose folded call runs a function that calls another one declared inside a function the
#: fold is running, mapped to what Node prints for them and to the text the deobfuscation writes: a
#: helper declared after a `return`, a sibling declaration and a recursive one are each in place
#: wherever they are called, since a declaration is in place from the start of the run declaring it.
A_CALL_INTO_A_FUNCTION_A_RUNNING_FUNCTION_DECLARES = {
    a_program("""
        function outer(x) {
          return helper(x) + 1;
          function helper(y) { return y * 2; }
        }
        console.log(outer(3));
        """): ('7\n', 'console.log(7);'),
    a_program("""
        function outer(x) {
          function h1(y) { return h2(y) + 1; }
          function h2(y) { return y * 2; }
          return h1(x);
        }
        console.log(outer(3));
        """): ('7\n', 'console.log(7);'),
    a_program("""
        function outer(n) {
          function fact(k) { return k <= 1 ? 1 : k * fact(k - 1); }
          return fact(n);
        }
        console.log(outer(5));
        """): ('120\n', 'console.log(120);'),
}

#: A program whose folded call runs a closure that a call it made earlier created and handed out
#: before putting the name the closure reads in place, mapped to what Node prints for it.
A_CLOSURE_READING_A_NAME_ITS_RUN_HAS_NOT_PUT_IN_PLACE = {
    a_program("""
        function mk(early) {
          var get = function () { return V; };
          if (early) return get;
          var V = 'set';
          return function () { return P(); };
        }
        function P() { var g = mk(true); return g(); }
        console.log(mk(false)());
        """): 'undefined\n',
}

#: Programs whose function declares a name in a block that it also reads for another binding, or
#: whose folded call is written in such a function, mapped to what Node prints for them. The name
#: read outside the block is the other binding, whatever the block put under the name.
A_BLOCK_DECLARING_A_NAME_THE_FUNCTION_ALSO_READS = {
    a_program("""
        const e = 3;
        function f(n) { var s = e * n; for (let e = 0; e < 2; e++) s += e; return s + e; }
        console.log(f(2));
        """): '10\n',
    a_program("""
        const T = 'outer';
        function f() { var a = T; { let T = 'inner'; } return a + T; }
        console.log(f());
        """): 'outerouter\n',
    a_program("""
        var T = ['a', 'b', 'c'];
        var N = 3;
        function A(i) { for (let N = 0; N < 1; N++) {} return T[i % N]; }
        console.log(A(4));
        """): 'b\n',
    a_program("""
        function f(x) { { let x = 2; } return x; }
        console.log(f(5));
        """): '5\n',
    a_program("""
        function A() { return T; }
        function G() { { let T = 'inner'; } return A(); }
        console.log(G());
        var T = 'outer';
        """): 'undefined\n',
}

#: Programs calling a function before the name it reads is in place, from a function that is folded
#: later in the same pass, mapped to what Node prints for them. The read written in place of the
#: first call names the binding the function reads, not a global of that name.
A_READ_WRITTEN_BEFORE_ITS_NAME_IS_IN_PLACE_AND_FOLDED_AGAIN = {
    a_program("""
        function outer() {
          function A() { return typeof Math; }
          function G() { return A(); }
          var r = G();
          var Math = 5;
          return r;
        }
        console.log(outer());
        """): 'undefined\n',
    a_program("""
        function A() { return typeof escape; }
        function G() { return A(); }
        try { console.log(G()); } catch (e) { console.log(e.name); }
        let escape = 'x';
        """): 'ReferenceError\n',
}

#: Programs whose one write of a name stands where its statement evaluates it on some runs only,
#: below `&&`, in an arm of a conditional, on the right of a logical assignment, in a `switch`
#: clause test, past an optional link, in a class field initializer or in a branch of a static
#: block, and whose call reads the name after that statement, mapped to what Node prints for them.
#: The statement completes on a run that skips the write.
A_CALL_AFTER_A_WRITE_ITS_STATEMENT_MAY_SKIP = {
    a_program("""
        var c;
        Math.random() > 2 && (c = 5);
        function g() { return c; }
        console.log(g());
        """): 'undefined\n',
    a_program("""
        var c;
        class A { x = (c = 5); }
        function g() { return c; }
        console.log(g());
        """): 'undefined\n',
    a_program("""
        var c;
        class A { static { if (Math.random() > 2) { c = 5; } } }
        function g() { return c; }
        console.log(g());
        """): 'undefined\n',
    a_program("""
        function A(i) { return T[i]; }
        var T;
        Math.random() > 2 && (T = ['x', 'y']);
        try { console.log(A(1)); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
    a_program("""
        function A(i) { return T[i]; }
        var T;
        Math.random() > 2 ? (T = ['x', 'y']) : 0;
        try { console.log(A(1)); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
    a_program("""
        function A(i) { return T[i]; }
        var T;
        var y = 1;
        y ||= (T = ['x', 'y']);
        try { console.log(A(1)); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
    a_program("""
        function A(i) { return T[i]; }
        var T;
        switch (process.argv.length) {
          case process.argv.length: break;
          case (T = ['x', 'y']).length: break;
        }
        try { console.log(A(1)); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
    a_program("""
        function A(s) { return s + '!'; }
        var K;
        var o = process.argv[99];
        o?.m(K = 'k');
        console.log(A(K));
        """): 'undefined!\n',
    a_program("""
        var f;
        Math.random() > 2 && (f = function () { return 1; });
        try { console.log(f()); } catch (e) { console.log(e.name); }
        """): 'TypeError\n',
}

#: Programs folding a chain of array methods that calls back into a function not yet in place where
#: the chain runs, mapped to what Node prints for them.
A_CHAIN_CALLING_BACK_INTO_A_FUNCTION_NOT_YET_IN_PLACE = {
    a_program("""
        try { console.log([1, 2].map(g).join('')); } catch (e) { console.log(e.name); }
        const g = x => x + 1;
        """): 'ReferenceError\n',
    a_program("""
        try { console.log([1, 2].map(g).join('')); } catch (e) { console.log(e.name); }
        var g = function (x) { return x + 1; };
        """): 'TypeError\n',
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

#: Scripts whose table code the file cannot read rewrites before the accessor is called, a direct
#: `eval` in a function and a `Function` body, mapped to what a host running them as a classic
#: script prints. The code runs where a table of the script is in reach, and no reference records
#: it.
A_SCRIPT_TABLE_THAT_CODE_IT_CANNOT_READ_REWRITES = {
    a_program("""
        var T = ['a', 'b'];
        function h(s) { eval(s); }
        h(process.argv[2] || "T[1] = 'z'");
        function A(i) { return T[i]; }
        console.log(A(1));
        """): 'z\n',
    a_program("""
        var T = ['a', 'b'];
        Function(process.argv[2] || "T[1] = 'z'")();
        function A(i) { return T[i]; }
        console.log(A(1));
        """): 'z\n',
}

#: Scripts whose table is rewritten in plain sight before the accessor is called, by an indirect
#: `eval` and by a store on the global object under a runtime key, mapped to what a host running
#: them as a classic script prints.
A_SCRIPT_TABLE_REWRITTEN_IN_PLAIN_SIGHT = {
    a_program("""
        var T = ['a', 'b'];
        (0, eval)(process.argv[2] || "T[1] = 'z'");
        function A(i) { return T[i]; }
        console.log(A(1));
        """): 'z\n',
    a_program("""
        var T = ['a', 'b'];
        this[process.argv[2] || 'T'] = ['y', 'z'];
        function A(i) { return T[i]; }
        console.log(A(1));
        """): 'z\n',
}

#: Programs whose function calls a method on its table or on an element of it, or iterates it,
#: mapped to what Node prints for them. Nothing changes the table, so every call has one value.
A_CALL_THAT_CALLS_A_METHOD_ON_THE_TABLE = {
    a_program("""
        const T = ['a', 'b'];
        var A = function (i) { return T[i].charCodeAt(0); };
        console.log(A(1));
        """): '98\n',
    a_program("""
        const T = ['a', 'b', 'c'];
        function A(i) { return T.slice(i).join('-'); }
        console.log(A(1));
        """): 'b-c\n',
    a_program("""
        const T = ['x', 'y'];
        function A(c) { return T.indexOf(c); }
        console.log(A('y'));
        """): '1\n',
    a_program("""
        const T = ['a', 'b'];
        function A() { var s = ''; for (var c of T) s += c; return s; }
        console.log(A());
        """): 'ab\n',
}

#: A program whose folded call runs a function that holds a table and a closure reading it, mapped
#: to what Node prints for it.
A_CALL_WHOSE_CLOSURE_READS_A_TABLE_OF_ITS_FUNCTION = {
    a_program("""
        function outer(x) { const T = ['a', 'b']; const A = i => T[i]; return A(x) + A(1 - x); }
        console.log(outer(1));
        """): 'ba\n',
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
    a_program("""
        function F(n) {
          if (n === 0) { return typeof g; }
          const g = () => 5;
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

    def test_a_script_table_that_other_code_rewrites(self):
        rows = {
            **A_SCRIPT_TABLE_THAT_CODE_IT_CANNOT_READ_REWRITES,
            **A_SCRIPT_TABLE_REWRITTEN_IN_PLAIN_SIGHT,
        }
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_script_table_rewritten_in_plain_sight_under_the_trusting_model(self):
        rows = A_SCRIPT_TABLE_REWRITTEN_IN_PLAIN_SIGHT
        self.assertEqual(
            {
                source: (
                    host_behavior(source),
                    host_behavior(source.encode('utf8') | js | str),
                )
                for source in rows
            },
            each_program_still_prints(rows),
        )

    def test_a_call_that_calls_a_method_on_the_table(self):
        rows = A_CALL_THAT_CALLS_A_METHOD_ON_THE_TABLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_whose_closure_reads_a_table_of_its_function(self):
        rows = A_CALL_WHOSE_CLOSURE_READS_A_TABLE_OF_ITS_FUNCTION
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

    def test_a_call_into_a_function_a_running_function_declares(self):
        rows = {
            source: prints
            for source, (prints, _) in A_CALL_INTO_A_FUNCTION_A_RUNNING_FUNCTION_DECLARES.items()
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_closure_reading_a_name_its_run_has_not_put_in_place(self):
        rows = A_CLOSURE_READING_A_NAME_ITS_RUN_HAS_NOT_PUT_IN_PLACE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_block_declaring_a_name_the_function_also_reads(self):
        rows = A_BLOCK_DECLARING_A_NAME_THE_FUNCTION_ALSO_READS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_read_written_before_its_name_is_in_place_and_folded_again(self):
        rows = A_READ_WRITTEN_BEFORE_ITS_NAME_IS_IN_PLACE_AND_FOLDED_AGAIN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_chain_calling_back_into_a_function_not_yet_in_place(self):
        rows = A_CHAIN_CALLING_BACK_INTO_A_FUNCTION_NOT_YET_IN_PLACE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_call_after_a_write_its_statement_may_skip(self):
        rows = A_CALL_AFTER_A_WRITE_ITS_STATEMENT_MAY_SKIP
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

    def test_a_call_into_a_function_a_running_function_declares_becomes_its_value(self):
        rows = A_CALL_INTO_A_FUNCTION_A_RUNNING_FUNCTION_DECLARES
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) for source in rows},
            {source: written for source, (_, written) in rows.items()},
        )

    def test_a_closure_reading_a_name_its_run_has_not_put_in_place_is_left_as_it_is(self):
        rows = A_CLOSURE_READING_A_NAME_ITS_RUN_HAS_NOT_PUT_IN_PLACE
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_chain_calling_back_into_a_function_not_yet_in_place_is_left_as_it_is(self):
        rows = A_CHAIN_CALLING_BACK_INTO_A_FUNCTION_NOT_YET_IN_PLACE
        self.assertEqual(
            {source: deobfuscate_source(source, module=True) for source in rows},
            {source: printed(source) for source in rows},
        )

    def test_a_call_into_a_table_stays_only_where_a_host_reads_the_table(self):
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


class TestATableReadThroughAnAccessorIsNotYetFolded(TestBase):
    """
    Calls whose value the program decides but that stay. A method called on the table or on one
    of its elements counts as a possible change of the table, because the question whether an
    array may change does not tell a method of the array from one of its elements, nor a method
    that changes the array from one that only reads it. A closure a folded call creates reads the
    table of the run that created it, and a function value the interpreter holds does not carry
    that run, so the read is refused.
    """

    @unittest.expectedFailure
    def test_a_call_that_calls_a_method_on_the_table_is_folded(self):
        rows = A_CALL_THAT_CALLS_A_METHOD_ON_THE_TABLE
        self.assertEqual(
            {source: 'A(' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )

    @unittest.expectedFailure
    def test_a_call_whose_closure_reads_a_table_of_its_function_is_folded(self):
        rows = A_CALL_WHOSE_CLOSURE_READS_A_TABLE_OF_ITS_FUNCTION
        self.assertEqual(
            {source: 'outer(' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )
