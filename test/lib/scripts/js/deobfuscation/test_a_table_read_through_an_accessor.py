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

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    host_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
    printed,
    prints,
)

from refinery.lib.scripts.js.options import ExecutionModel
from refinery.units.scripting.djs import djs

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
                    host_behavior(source.encode('utf8') | djs | str),
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
            {
                source: 'A(' in deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: False for source in rows},
        )

    def test_a_call_before_the_table_is_in_place_becomes_the_read_it_makes(self):
        rows = A_CALL_BEFORE_THE_TABLE_IS_IN_PLACE
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module) + '\n'
                for source in rows
            },
            {source: written for source, (_, written) in rows.items()},
        )

    def test_a_call_whose_table_may_change_is_left_as_it_is(self):
        rows = A_CALL_WHOSE_TABLE_MAY_CHANGE
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: printed(source) for source in rows},
        )

    def test_a_call_changing_the_array_it_reads_is_left_as_it_is(self):
        rows = A_CALL_CHANGING_THE_ARRAY_IT_READS
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: printed(source) for source in rows},
        )

    def test_a_call_into_a_function_a_running_function_declares_becomes_its_value(self):
        rows = A_CALL_INTO_A_FUNCTION_A_RUNNING_FUNCTION_DECLARES
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: written for source, (_, written) in rows.items()},
        )

    def test_a_closure_reading_a_name_its_run_has_not_put_in_place_is_left_as_it_is(self):
        rows = A_CLOSURE_READING_A_NAME_ITS_RUN_HAS_NOT_PUT_IN_PLACE
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: printed(source) for source in rows},
        )

    def test_a_chain_calling_back_into_a_function_not_yet_in_place_is_left_as_it_is(self):
        rows = A_CHAIN_CALLING_BACK_INTO_A_FUNCTION_NOT_YET_IN_PLACE
        self.assertEqual(
            {
                source: deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
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
            {
                source: 'A(' in deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: False for source in rows},
        )

    @unittest.expectedFailure
    def test_a_call_whose_closure_reads_a_table_of_its_function_is_folded(self):
        rows = A_CALL_WHOSE_CLOSURE_READS_A_TABLE_OF_ITS_FUNCTION
        self.assertEqual(
            {
                source: 'outer(' in deobfuscate_source(source, execution=ExecutionModel.module)
                for source in rows
            },
            {source: False for source in rows},
        )


def with_words(count: int, program: str) -> str:
    """
    *program* with its string `"WORDS"` holding *count* words joined by `|`: the table an
    obfuscation splits into the strings of the program, longer than a fold may write into the text
    where *count* is above 260.
    """
    words = '|'.join(F'w{index:04}' for index in range(count))
    return program.replace('"WORDS"', F'"{words}"')


#: Programs whose functions read a table a method chain builds, mapped to what Node prints for each
#: run as a CommonJS file: a string split into the strings of the program and read through an
#: accessor, with the split, the receiver or the table changed before or after, read before it is
#: built, handed out, built twice, or built by a chain that throws, and chains of other methods.
A_TABLE_A_METHOD_CHAIN_BUILDS: dict[str, Program] = {
    'two tables built from each other': Program(
        with_words(300, a_program("""
            var a, b;
            function ra(i) { return a[i]; }
            function rb(i) { return b[i]; }
            a = "WORDS".split("|").concat(b);
            b = a.slice(0, 3).concat(a);
            var f = globalThis[ra(5)] || function () {};
            f(rb(6));
            console.log(ra(3), rb(4));
            """)),
        prints('w0003 w0001'),
        Reading.COMMONJS,
    ),
    'a table of 200 words': Program(
        with_words(200, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(199));
            """)),
        prints('w0003 w0199'),
        Reading.COMMONJS,
    ),
    'a table mapped by a callback reading a name changed later': Program(
        with_words(300, a_program("""
            var SC;
            var k = "-";
            (function () {
              var stringArray = "WORDS".split("|").map(function (s) { return s + k; });
              SC = function (index) {
                return stringArray[index];
              };
            })();
            k = "+";
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003- w0299-'),
        Reading.COMMONJS,
    ),
    'a table mapped by a callback reading a constant': Program(
        with_words(300, a_program("""
            var SC;
            var k = "-";
            (function () {
              var stringArray = "WORDS".split("|").map(function (s) { return s + k; });
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003- w0299-'),
        Reading.COMMONJS,
    ),
    'a table handed to the global object': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              globalThis.leak = stringArray;
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'a table split on a parameter': Program(
        with_words(300, a_program("""
            var SC;
            function make(sep) {
              var stringArray = "WORDS".split(sep);
              return function (index) {
                return stringArray[index];
              };
            }
            SC = make("|");
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'a table split by a replaced split': Program(
        with_words(300, a_program("""
            String.prototype.split = function () { return ["a", "b", "c", "d"]; };
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('d undefined'),
        Reading.COMMONJS,
    ),
    'a table a timer pushes to': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              setTimeout(function () { stringArray.push("x"); }, 0);
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            SC.call(null, 0);
            console.log(SC(3), SC(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'a table read at the top of the file': Program(
        with_words(300, a_program("""
            var t = "WORDS".split("|");
            var f = globalThis[t[5]] || function () {};
            f(t[6]);
            console.log(t[3], t[299]);
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'a table of 300 words': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'a table of 3000 words': Program(
        with_words(3000, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) {
                return stringArray[index];
              };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(2999));
            """)),
        prints('w0003 w2999'),
        Reading.COMMONJS,
    ),
    'a table whose chain throws': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".repeat(-1).split("|");
              SC = function (index) { return stringArray[index]; };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3));
            """)),
        ('', 'RangeError'),
        Reading.COMMONJS,
    ),
    'a table built by each of two calls': Program(
        with_words(300, a_program("""
            function mk() {
              var stringArray = "WORDS".split("|");
              return function (index) { return stringArray[index]; };
            }
            var A = mk(), B = mk();
            var f = globalThis[A(5)] || function () {};
            f(B(6));
            console.log(A(3), B(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'chain read before declarator': Program(
        a_program("""
            function g() { return t[1]; }
            var first;
            try { first = g(); } catch (e) { first = e.name; }
            var t = 'a|b|c'.split('|');
            console.log(first, g());
            """),
        prints('TypeError b'),
        Reading.COMMONJS,
    ),
    'chain identity': Program(
        a_program("""
            var t = 'a|b'.split('|');
            function g() { return t; }
            console.log(g() === g(), g() === t, g().length);
            """),
        prints('true true 2'),
        Reading.COMMONJS,
    ),
    'chain mutated later': Program(
        a_program("""
            var t = 'a|b|c'.split('|');
            t.reverse();
            function g(i) { return t[i]; }
            console.log(g(0), g(2));
            """),
        prints('c a'),
        Reading.COMMONJS,
    ),
    'chain aliased and mutated': Program(
        a_program("""
            var t = 'a|b|c'.split('|');
            var u = t;
            u[0] = 'z';
            function g(i) { return t[i]; }
            console.log(g(0));
            """),
        prints('z'),
        Reading.COMMONJS,
    ),
    'chain in function read before': Program(
        a_program("""
            function outer() {
              function g() { return t.length; }
              var r;
              try { r = g(); } catch (e) { r = e.name; }
              var t = 'abc'.split('');
              return [r, g()];
            }
            console.log(outer());
            """),
        prints("[ 'TypeError', 3 ]"),
        Reading.COMMONJS,
    ),
    'chain const tdz': Program(
        a_program("""
            function g() { return t[0]; }
            var first;
            try { first = g(); } catch (e) { first = e.name; }
            const t = 'p|q'.split('|');
            console.log(first, g());
            """),
        prints('ReferenceError p'),
        Reading.COMMONJS,
    ),
    'chain receiver from user object': Program(
        a_program("""
            var shared = ['a', 'b'];
            var o = { m: function () { return shared; } };
            var t = o.m();
            shared.push('c');
            function g() { return t.length; }
            console.log(g());
            """),
        prints('3'),
        Reading.COMMONJS,
    ),
    'chain slice of mutated source': Program(
        a_program("""
            var src = ['a', 'b'];
            var t = src.slice(0);
            src.push('c');
            function g() { return t.length + src.length; }
            console.log(g());
            """),
        prints('5'),
        Reading.COMMONJS,
    ),
    'chain freeze literal': Program(
        a_program("""
            var t = Object.freeze('a|b'.split('|'));
            function g() { return Object.isFrozen(t) + ':' + t[1]; }
            console.log(g());
            """),
        prints('true:b'),
        Reading.COMMONJS,
    ),
    'chain concat alias': Program(
        a_program("""
            var a = 'x|y'.split('|');
            var t = a.concat();
            a[0] = 'changed';
            function g() { return t[0] + a[0]; }
            console.log(g());
            """),
        prints('xchanged'),
        Reading.COMMONJS,
    ),
    'chain reverse returns receiver': Program(
        a_program("""
            var a = 'x|y|z'.split('|');
            var t = a.reverse();
            a.push('w');
            function g() { return t.length + ':' + t[0]; }
            console.log(g());
            """),
        prints('4:z'),
        Reading.COMMONJS,
    ),
    'chain sort returns receiver': Program(
        a_program("""
            var t = 'c|a|b'.split('|').sort();
            function g(i) { return t[i]; }
            console.log(g(0), g(2));
            """),
        prints('a c'),
        Reading.COMMONJS,
    ),
    'chain in loop varies': Program(
        a_program("""
            var parts = ['a|b', 'c|d'];
            var seen = [];
            for (var i = 0; i < 2; i++) {
              var t = parts[i].split('|');
              seen.push(g());
            }
            function g() { return t[0]; }
            console.log(seen.join(), g());
            """),
        prints('a,c c'),
        Reading.COMMONJS,
    ),
    'chain receiver var reassigned later': Program(
        a_program("""
            var s = 'a|b';
            var t = s.split('|');
            s = 'c|d';
            function g() { return t[0] + s; }
            console.log(g());
            """),
        prints('ac|d'),
        Reading.COMMONJS,
    ),
    'chain stringified': Program(
        a_program("""
            var t = 'a|b'.split('|');
            function g() { return String(t) + t.join('-'); }
            console.log(g());
            """),
        prints('a,ba-b'),
        Reading.COMMONJS,
    ),
    'chain reads global changed before': Program(
        a_program("""
            var cfg = { sep: '|' };
            cfg.sep = ',';
            var t = 'a|b,c'.split(cfg.sep);
            function g() { return t[0]; }
            console.log(g());
            """),
        prints('a|b'),
        Reading.COMMONJS,
    ),
    'chain with getter on receiver type': Program(
        a_program("""
            Object.defineProperty(Array.prototype, 'first', { get: function () { return this[0]; }, configurable: true });
            var t = 'm|n'.split('|');
            function g() { return t.first; }
            console.log(g());
            """),
        prints('m'),
        Reading.COMMONJS,
    ),
    'chain twice in two functions': Program(
        a_program("""
            function make() {
              var t = 'a|b'.split('|');
              return function () { return t; };
            }
            var f1 = make(), f2 = make();
            f1().push('c');
            function g() { return f2().length; }
            console.log(g(), f1().length);
            """),
        prints('2 3'),
        Reading.COMMONJS,
    ),
    'a table read by a local accessor': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split("|");
              function SC(i) { return t[i]; }
              return SC(3) + SC(299);
            }
            console.log(f());
            """)),
        prints('w0003w0299'),
        Reading.COMMONJS,
    ),
    'read before the chain': Program(
        with_words(300, a_program("""
            function f() {
              function SC(i) { return t[i]; }
              var first;
              try { first = SC(3); } catch (e) { first = e.name; }
              var t = "WORDS".split("|");
              return first + ':' + SC(3);
            }
            console.log(f());
            """)),
        prints('TypeError:w0003'),
        Reading.COMMONJS,
    ),
    'let tdz closure': Program(
        with_words(300, a_program("""
            function f() {
              var SC = function (i) { return t[i]; };
              var first;
              try { first = SC(3); } catch (e) { first = e.name; }
              let t = "WORDS".split("|");
              return first + ':' + SC(3);
            }
            console.log(f());
            """)),
        prints('ReferenceError:w0003'),
        Reading.COMMONJS,
    ),
    'declarator before the chain': Program(
        with_words(300, a_program("""
            function f() {
              try {
                var SC = function (i) { return t[i]; }, x = SC(3), t = "WORDS".split("|");
                return x;
              } catch (e) {
                return e.name + ':' + SC(4);
              }
            }
            console.log(f());
            """)),
        ('', 'TypeError'),
        Reading.COMMONJS,
    ),
    'declarator after the chain': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split("|"), SC = function (i) { return t[i]; }, x = SC(3) + SC(4);
              return x;
            }
            console.log(f());
            """)),
        prints('w0003w0004'),
        Reading.COMMONJS,
    ),
    'chain mutated in a later declarator': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split("|"), cut = (t.length = 2), SC = function (i) { return t[i]; };
              return [SC(1), SC(3)].join();
            }
            console.log(f());
            """)),
        prints('w0001,'),
        Reading.COMMONJS,
    ),
    'chain split on a later declared separator': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split(sep), sep = "|";
              function SC(i) { return t[i]; }
              return [SC(0).length, typeof SC(1)].join();
            }
            console.log(f());
            """)),
        prints('1799,undefined'),
        Reading.COMMONJS,
    ),
    'chain table reversed by reader': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split("|");
              function SC(i) { return t[i]; }
              var a = SC(0);
              t.reverse();
              return a + SC(0);
            }
            console.log(f());
            """)),
        prints('w0000w0299'),
        Reading.COMMONJS,
    ),
    'chain with a hole in operator': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split("|").concat([, 'x']);
              function SC(i) { return (i in t) + ':' + t[i]; }
              return [SC(300), SC(301), t.length].join();
            }
            console.log(f());
            """)),
        prints('false:undefined,true:x,302'),
        Reading.COMMONJS,
    ),
    'chain with a hole small control': Program(
        a_program("""
            function f() {
              var t = 'a|b'.split('|').concat([, 'x']);
              function SC(i) { return (i in t) + ':' + t[i]; }
              return [SC(2), SC(3), t.length].join();
            }
            console.log(f());
            """),
        prints('false:undefined,true:x,4'),
        Reading.COMMONJS,
    ),
    'chain hole prototype index': Program(
        with_words(300, a_program("""
            Array.prototype[300] = 'proto';
            function f() {
              var t = "WORDS".split("|").concat([, 'x']);
              function SC(i) { return t[i]; }
              return [SC(300), SC(301)].join();
            }
            console.log(f());
            """)),
        prints('proto,x'),
        Reading.COMMONJS,
    ),
}

#: Programs reading a table a method chain builds after a call of a function the deobfuscation
#: cannot see, whose name the table itself supplies, mapped to what Node prints for each run as a
#: CommonJS file.
A_TABLE_READ_AFTER_AN_UNKNOWN_CALL: dict[str, Program] = {
    'a table read after a call of an unknown function': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) { return stringArray[index]; };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(3), SC(299));
            """)),
        prints('w0003 w0299'),
        Reading.COMMONJS,
    ),
    'read before the chain unknown call': Program(
        with_words(300, a_program("""
            function f() {
              function SC(i) { return t[i]; }
              var first;
              try { first = SC(3); } catch (e) { first = e.name; }
              var t = "WORDS".split("|");
              var g = globalThis[SC(5)] || function () {};
              g(SC(6));
              return first + ':' + SC(3);
            }
            console.log(f());
            """)),
        prints('TypeError:w0003'),
        Reading.COMMONJS,
    ),
    'hole in operator unknown call': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|").concat([, 'x']);
              SC = function (index) { return (index in stringArray) + ':' + stringArray[index]; };
            })();
            var f = globalThis[SC(5)] || function () {};
            f(SC(6));
            console.log(SC(300), SC(301));
            """)),
        prints('false:undefined true:x'),
        Reading.COMMONJS,
    ),
    'declarators chain after reader call': Program(
        with_words(300, a_program("""
            function f() {
              try {
                var SC = function (i) { return t[i]; }, x = SC(3), t = "WORDS".split("|");
                var g = globalThis[SC(5)] || function () {};
                g(SC(6));
                return x;
              } catch (e) {
                return e.name + ':' + SC(4);
              }
            }
            console.log(f());
            """)),
        ('', 'TypeError'),
        Reading.COMMONJS,
    ),
    'chain reads a later declarator separator': Program(
        with_words(300, a_program("""
            function f() {
              var t = "WORDS".split(sep), sep = "|";
              var g = globalThis[t[5]] || function () {};
              g(t[6]);
              function SC(i) { return t[i]; }
              return [SC(0).length, typeof SC(1)].join();
            }
            console.log(f());
            """)),
        prints('1799,undefined'),
        Reading.COMMONJS,
    ),
    'out of range negative and string keys': Program(
        with_words(300, a_program("""
            var SC;
            (function () {
              var stringArray = "WORDS".split("|");
              SC = function (index) { return stringArray[index]; };
            })();
            var f = globalThis[SC(5)] || Function('i', 'Object.prototype.length2 = 1; return i;');
            f(SC(6));
            console.log(SC(-1), SC('length'), SC('constructor') === Array, SC('1e2'), SC('0x10'), SC(1.5));
            """)),
        prints('undefined 300 true undefined undefined undefined'),
        Reading.COMMONJS,
    ),
}

#: Programs of `A_TABLE_A_METHOD_CHAIN_BUILDS` whose calls of the accessor fold to the strings they
#: read, mapped to the text the deobfuscation writes for each.
FOLDED_FROM_A_TABLE_A_METHOD_CHAIN_BUILDS: dict[str, str] = {
    'a table of 300 words': inspect.cleandoc(
        """
            var f = globalThis.w0005 || function() {};
            f('w0006');
            console.log('w0003', 'w0299');
        """
    ),
    'a table of 3000 words': inspect.cleandoc(
        """
            var f = globalThis.w0005 || function() {};
            f('w0006');
            console.log('w0003', 'w2999');
        """
    ),
    'a table mapped by a callback reading a constant': inspect.cleandoc(
        """
            var f = globalThis['w0005-'] || function() {};
            f('w0006-');
            console.log('w0003-', 'w0299-');
        """
    ),
}


def deobfuscated_by_the_unit(source: str) -> str:
    """
    The text `refinery.djs` writes for *source* under its default reading of a CommonJS file for
    Node, which trusts the code `eval` and `Function` run.
    """
    return source.encode('utf8') | djs.assemble('-c', '-e', 'node') | str


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATableAMethodChainBuildsStillPrintsTheSame(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in {**A_TABLE_A_METHOD_CHAIN_BUILDS, **A_TABLE_READ_AFTER_AN_UNKNOWN_CALL}.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in {**A_TABLE_A_METHOD_CHAIN_BUILDS, **A_TABLE_READ_AFTER_AN_UNKNOWN_CALL}.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_each_table_read_after_an_unknown_call_still_prints_it_where_the_unit_trusts_eval(self):
        for label, row in A_TABLE_READ_AFTER_AN_UNKNOWN_CALL.items():
            with self.subTest(label=label):
                self.assertEqual(behavior(deobfuscated_by_the_unit(row.text)), row.prints)


class TestATableAMethodChainBuildsIsFolded(TestBase):

    def test_each_call_of_the_accessor_reads_as_pinned(self):
        self.assertEqual(
            {
                label: deobfuscate_source(A_TABLE_A_METHOD_CHAIN_BUILDS[label].text, execution=ExecutionModel.commonjs)
                for label in FOLDED_FROM_A_TABLE_A_METHOD_CHAIN_BUILDS
            },
            FOLDED_FROM_A_TABLE_A_METHOD_CHAIN_BUILDS,
        )
