from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, deobfuscate_within, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.cff import JsStateMachineUnflattening
from refinery.lib.scripts.js.deobfuscation.evaluator import JsFunctionEvaluator

#: The functions the machines below compute their state with: `sum` adds up the state, and `slice`
#: reads a part of a table, which a machine's call spreads into the state it starts in.
PRELUDE = inspect.cleandoc(
    """
    function sum(array) {
      for (var total = 0, i = 0; i < array["length"]; i++) {
        total += array[i];
      }
      return total;
    }
    var seq = [4, 5, 6, 7];
    function slice(min, max) {
      return seq["slice"](min, max);
    }
    """
)

#: A function that decodes the key of a scope object from two numbers.
DECODER = inspect.cleandoc(
    """
    var names = "AlabelB";
    function dec(start, length) {
      return names["slice"](start, start + length);
    }
    """
)

#: A function that decodes a key from two numbers, in a table that names one of the keys.
LABELS = inspect.cleandoc(
    """
    var names = "labelother";
    function dec(start, length) {
      return names["slice"](start, start + length);
    }
    """
)

#: The function `grade(n)`, whose body is a machine of two blocks. The state starts as `START`,
#: whose sum is 15. The first block stores a label under `STORE`, runs `PAYLOAD` and moves the
#: state to the sum 16; the second returns the label, read after `READ`. No state reaches 17.
GRADE = inspect.cleandoc(
    """
    function grade(n) {
      function M(states, scope = { A: {} }, runtime) {
        while (sum(states) !== 0) {
          L: switch (sum(states)) {
            FIRST
              STORE = n > 10 ? 'big' : 'small';
              PAYLOAD
              states[0] += states[1] - 4;
              break L;
            SECOND
              return ret = true, scope.A.label + READ'!';
            case 17:
              return ret = true, 'wrong';
          }
        }
      }
      var ret;
      var res = M(START);
      if (ret) {
        return res;
      }
    }
    """
)


def graded(
    payload: str = '',
    read: str = '',
    *,
    start: str = '[...slice(0, 3)]',
    store: str = 'scope["A"]["label"]',
    first: str = 'case 15:',
    second: str = 'case 16:',
    before: str = '',
    prelude: str = PRELUDE,
    after: str = 'console.log(grade(3), grade(30));',
) -> str:
    """
    A program that defines *prelude* and `GRADE` with its parts replaced, between *before* and
    *after*.
    """
    machine = (
        GRADE
        .replace('FIRST', first)
        .replace('SECOND', second)
        .replace('STORE', store)
        .replace('PAYLOAD', payload)
        .replace('READ', read)
        .replace('START', start)
    )
    return '\n'.join(part for part in (before, prelude, machine, after) if part)


A_FUNCTION_WHOSE_BODY_IS_A_MACHINE = graded()

THE_MACHINE_OF_THE_PROGRAM = PRELUDE + '\n' + inspect.cleandoc(
    """
    function M(states, scope = { A: {} }, runtime) {
      while (sum(states) !== 9) {
        L: switch (sum(states)) {
          case 15:
            scope.A.total = 0;
            for (scope.A.i = 0; scope.A.i < 3; scope.A.i++) {
              scope.A.total += scope.A.i;
            }
            states[1] += states[0] - 7;
            break L;
          case 12:
            return console.log('total', scope.A.total);
        }
      }
    }
    M([...slice(0, 3)]);
    """
)

A_FUNCTION_TAKEN_APART_INTO_THE_MACHINE_OF_THE_PROGRAM = PRELUDE + '\n' + inspect.cleandoc(
    """
    function M(states, scope = { A: {} }, runtime, arg) {
      while (sum(states) !== 9) {
        L: switch (sum(states)) {
          case 15:
            scope.A.double = function (...r) {
              return M([...slice(1, 4)], { A: scope.A, B: {} }, runtime, r);
            };
            console.log((1, scope.A.double)(4));
            states[1] += states[0] - 7;
            break L;
          case 12:
            console.log((1, scope.A.double)(5));
            states[2] += states[1] - 5;
            break L;
          case 18:
            [scope.B.x] = arg;
            scope.B.y = scope.B.x * 2;
            return scope.B.y + 1;
        }
      }
    }
    M([...slice(0, 3)]);
    """
)

KEYS_A_FUNCTION_DECODES_FROM_THE_STATE = graded(
    store='scope[dec(states[0] - 4, 1)][dec(states[0] - 3, 5)]',
    prelude=F'{PRELUDE}\n{DECODER}',
)

JUMPS_AHEAD_OF_THE_TRANSITION_NEVER_TAKEN = graded(
    'if (states[2] == 99) { states[0] += states[1] - 1; break L; }'
    ' if (!(states[1] == 5)) { states[0] += states[2] - 1; break L; }'
)

A_JUMP_AHEAD_OF_THE_TRANSITION_THAT_IS_TAKEN = graded(
    'if (states[1] == 5) { states[0] += states[1] - 4; break L; }'
    ' states[0] += states[2] - 4; break L;'
)

A_JUMP_TO_ITS_OWN_BLOCK_NEVER_TAKEN = graded('if (states[0] == 100) { break L; }')

CASE_TESTS_READING_THE_STATE = graded(
    first='case 777: case states[1] + 10:',
    second='case states[2] != 9 && states[0] + 11:',
)

A_CASE_TEST_READING_THE_SUM = graded(second='case sum(states) != 12 && states[0] + 11:')

A_HELPER_THAT_IS_NO_SUM = graded(
    first='case 13:',
    second='case 15:',
    prelude=PRELUDE.replace(
        'for (var total = 0, i = 0; i < array["length"]; i++) {\n    total += array[i];\n  }\n  return total;',
        'return array[0] * 2 + array[1];',
    ),
)

A_TABLE_ALSO_SEARCHED_BY_A_METHOD_THAT_ONLY_READS_IT = graded(
    after='console.log(seq.indexOf(6), seq.join("-"));\nconsole.log(grade(3), grade(30));'
)

A_TABLE_READ_BY_A_METHOD_UNDER_A_COMPUTED_KEY = graded(
    prelude=PRELUDE.replace('return seq["slice"](min, max);', 'return seq[method](min, max);').replace(
        'var seq', 'var method = "slice";\nvar seq'
    ),
)

A_CLOSURE_DECODING_A_KEY_FROM_ITS_OWN_PARAMETER_NAMED_LIKE_THE_STATE = graded(
    'scope.A.pick = function (states) { return scope.A[dec(states[0] - 4, 5)]; };',
    '(1, scope.A.pick)([5]) + ',
    prelude=F'{PRELUDE}\n{LABELS}',
)

A_ZERO_CHANGING_SIGN_READ_BY_A_HELPER_THAT_TELLS_THE_SIGNS_APART = inspect.cleandoc(
    """
    function sum(a) {
      return a[2] !== 0 ? a[2] : 1 / a[0] > 0 ? 9 : 16;
    }
    function grade(n) {
      function M(states, scope = { A: {} }, runtime) {
        while (sum(states) !== 9) {
          L: switch (sum(states)) {
            case 15:
              scope.A.label = n > 10 ? 'big' : 'small';
              if (n > 10) {
                states[2] = 0, states[0] = 0;
              } else {
                states[2] = 0, states[0] = -0;
              }
              break L;
            case 16:
              return ret = true, scope.A.label + '!';
          }
        }
      }
      var ret;
      var res = M([1, 0, 15]);
      if (ret) {
        return res;
      }
    }
    console.log(grade(3), grade(30));
    """
)

A_CASE_TEST_ASKING_A_HELPER_ABOUT_A_NEGATIVE_ZERO_THEN_A_ZERO = PRELUDE + '\n' + inspect.cleandoc(
    """
    function positive(x) {
      return 1 / x > 0;
    }
    var out = [];
    function M(states, scope = { A: {} }, runtime) {
      while (sum(states) !== 100) {
        L: switch (sum(states)) {
          case 15:
            out.push('a');
            states[2] = -0, states[0] += 2;
            break L;
          case positive(states[2]) && states[1] + 6:
            out.push('y');
            states[0] += 88;
            break L;
          case 11:
            out.push('z');
            states[2] = 0, states[1] += 1;
            break L;
          case 12:
            out.push('w');
            states[0] += 88;
            break L;
        }
      }
    }
    M([...slice(0, 3)]);
    console.log(out.join(''));
    """
)

THE_CODE_READS_THE_LENGTH_OF_THE_STATE = graded('console.log(states.length);')

THE_CODE_HANDS_THE_STATE_TO_A_FUNCTION = graded(
    'show(states);',
    after='function show(a) { console.log(a[0]); }\nconsole.log(grade(3), grade(30));',
)

A_CLOSURE_READS_THE_STATE_WHEN_IT_IS_CALLED = graded(
    'scope.A.peek = function () { return states[0]; };',
    '(1, scope.A.peek)() + ',
)

THE_CODE_STORES_INTO_THE_STATE_OUTSIDE_THE_TRANSITION = graded('console.log(states[2] = 6);')

THE_CODE_READS_AN_ELEMENT_THE_STATE_DOES_NOT_HAVE = graded('console.log(states[7]);')

THE_CODE_READS_THE_RUNTIME_PARAMETER = graded(read='typeof runtime + ')

THE_MACHINE_READS_ITS_ARGUMENTS = graded(read='arguments.length + ')

A_CLOSURE_DECODES_A_KEY_FROM_THE_STATE_WHEN_IT_IS_CALLED = graded(
    'scope.A.peek = function () { return scope.A[dec(states[0] - 4, 5)]; };',
    '(1, scope.A.peek)() + ',
    prelude=F'{PRELUDE}\n{LABELS}',
)

A_CATCH_PARAMETER_NAMED_LIKE_THE_STATE_READ_BY_A_DECODED_KEY = graded(
    'try { throw [5]; } catch (states) { scope.A.caught = scope.A[dec(states[0] - 4, 5)]; }',
    'scope.A.caught + ',
    prelude=F'{PRELUDE}\n{LABELS}',
)

A_WRAPPER_HANDING_THE_MACHINE_ANOTHER_RUNTIME = PRELUDE + '\n' + inspect.cleandoc(
    """
    function M(states, scope = { A: {} }, runtime, arg) {
      while (sum(states) !== 9) {
        L: switch (sum(states)) {
          case 15:
            scope.A.greet = function (...r) {
              return M([...slice(1, 4)], { A: scope.A, B: {} }, 0, r);
            };
            console.log((1, scope.A.greet)('a'), (1, scope.A.greet)('b', '?'));
            states[1] += states[0] - 7;
            states[2] += states[1] - 5;
            break L;
          case 18:
            [scope.B.name, scope.B.mark = '!'] = arg;
            return 'hi ' + scope.B.name + scope.B.mark;
        }
      }
    }
    M([...slice(0, 3)]);
    """
)

A_HELPER_THAT_COUNTS_ITS_CALLS = graded(
    before='var calls = 0;',
    prelude=PRELUDE.replace('function sum(array) {', 'function sum(array) {\n  calls++;'),
    after='console.log(grade(3), grade(30), calls);',
)

THE_CODE_REPLACES_THE_HELPER = graded(
    'sum = function (array) { return array[0] + array[1] + array[2]; };'
)

THE_TABLE_IS_STORED_TO_AFTER_A_CALL = graded(
    after='console.log(grade(3));\nseq[0] = 4;\nconsole.log(grade(30));'
)

THE_TABLE_IS_CHANGED_THROUGH_ANOTHER_NAME = graded(
    after='var other = seq;\nconsole.log(grade(3));\nother.push(9);\nconsole.log(grade(30), seq.length);'
)

THE_TABLE_IS_HANDED_TO_A_FUNCTION_THAT_SORTS_IT = graded(
    after='function order(a) { a.sort(); }\nconsole.log(grade(3));\norder(seq);\nconsole.log(grade(30));'
)

THE_ARRAY_METHOD_THE_TABLE_IS_READ_WITH_IS_REPLACED = graded(
    before=(
        'var original = Array.prototype.slice;\n'
        'Array.prototype.slice = function (a, b) { console.log("slice"); return original.call(this, a, b); };'
    ),
)

THE_STRING_METHOD_THE_KEYS_ARE_DECODED_WITH_IS_REPLACED = graded(
    store='scope[dec(states[0] - 4, 1)][dec(states[0] - 3, 5)]',
    before=(
        'var cut = String.prototype.slice;\n'
        'String.prototype.slice = function (a, b) { console.log("cut"); return cut.call(this, a, b); };'
    ),
    prelude=F'{PRELUDE}\n{DECODER}',
)

THE_ARRAY_ITERATOR_IS_REPLACED_AND_THE_START_STATE_SPREADS_A_LITERAL = graded(
    start='[...[4, 5, 6]]',
    before='Array.prototype[Symbol.iterator] = function* () { yield 5; yield 5; yield 6; };',
)

THE_ARRAY_ITERATOR_IS_DEFINED_ANEW_AND_THE_START_STATE_SPREADS_A_LITERAL = graded(
    start='[...[4, 5, 6]]',
    before=(
        'Object.defineProperty(Array.prototype, Symbol.iterator, '
        '{ value: function* () { yield 5; yield 5; yield 6; } });'
    ),
)

A_JUMP_WHOSE_CONDITION_READS_MORE_THAN_THE_STATE = graded(
    'if (n > 100) { states[0] += states[1] - 4; break L; }'
)

A_START_STATE_THAT_READS_A_PARAMETER = graded(start='[n - n + 4, ...slice(1, 3)]')

A_JUMP_WHOSE_CONDITION_COMPARES_TWO_NEW_ARRAYS = graded(
    'if ([] === []) { states[0] += states[1] - 3; break L; }'
)

A_MACHINE_INSIDE_A_FUNCTION_OF_A_MACHINE_WITH_THE_SAME_NAMES = PRELUDE + '\n' + LABELS + '\n' + inspect.cleandoc(
    """
    function grade(n) {
      function M(states, scope = { A: {} }, runtime) {
        while (sum(states) !== 0) {
          L: switch (sum(states)) {
            case 15:
              scope.A.label = n > 10 ? 'big' : 'small';
              scope.A.inner = function () {
                function M(states, scope = { B: {} }, runtime) {
                  while (sum(states) !== 0) {
                    L: switch (sum(states)) {
                      case 16:
                        scope.B[dec(states[0] - 5, 5)] = states.length;
                        return done = true, scope.B.label;
                    }
                  }
                }
                var done;
                var result = M([5, 5, 6]);
                if (done) {
                  return result;
                }
              };
              states[0] += states[1] - 4;
              break L;
            case 16:
              return ret = true, scope.A.label + (1, scope.A.inner)() + '!';
          }
        }
      }
      var ret;
      var res = M([...slice(0, 3)]);
      if (ret) {
        return res;
      }
    }
    console.log(grade(3), grade(30));
    """
)

#: The recovered body of `grade` in every machine of `GRADE` whose recovery stores the label under
#: the key it was written with.
GRADE_RECOVERED = inspect.cleandoc(
    """
    function grade(n) {
      var A = {};
      A["label"] = n > 10 ? 'big' : 'small';
      return A.label + '!';
    }
    """
)

#: Each machine the recovery reads, mapped to code its recovery writes. The function evaluator runs
#: first, as it does in the pipeline: it folds a start state that reads no state, `[...slice(0, 3)]`.
RECOVERED = {
    A_FUNCTION_WHOSE_BODY_IS_A_MACHINE: GRADE_RECOVERED,
    THE_MACHINE_OF_THE_PROGRAM: inspect.cleandoc(
        """
        var A = {};
        A.total = 0;
        for (A.i = 0; A.i < 3; A.i++) {
          A.total += A.i;
        }
        console.log('total', A.total);
        """
    ),
    A_FUNCTION_TAKEN_APART_INTO_THE_MACHINE_OF_THE_PROGRAM: inspect.cleandoc(
        """
        var A = {};
        A.double = function(x_1) {
          var B = {};
          B.x = x_1;
          B.y = B.x * 2;
          return B.y + 1;
        };
        console.log((1, A.double)(4));
        console.log((1, A.double)(5));
        """
    ),
    KEYS_A_FUNCTION_DECODES_FROM_THE_STATE: GRADE_RECOVERED.replace('A["label"]', "A['label']"),
    JUMPS_AHEAD_OF_THE_TRANSITION_NEVER_TAKEN: GRADE_RECOVERED,
    A_JUMP_AHEAD_OF_THE_TRANSITION_THAT_IS_TAKEN: GRADE_RECOVERED,
    A_JUMP_TO_ITS_OWN_BLOCK_NEVER_TAKEN: GRADE_RECOVERED,
    CASE_TESTS_READING_THE_STATE: GRADE_RECOVERED,
    A_CASE_TEST_READING_THE_SUM: GRADE_RECOVERED,
    A_HELPER_THAT_IS_NO_SUM: GRADE_RECOVERED,
    A_TABLE_ALSO_SEARCHED_BY_A_METHOD_THAT_ONLY_READS_IT: GRADE_RECOVERED,
    A_CLOSURE_DECODING_A_KEY_FROM_ITS_OWN_PARAMETER_NAMED_LIKE_THE_STATE: inspect.cleandoc(
        """
        function grade(n) {
          var A = {};
          A["label"] = n > 10 ? 'big' : 'small';
          A.pick = function(states) {
            return A[dec(states[0] - 4, 5)];
          };
          return A.label + (1, A.pick)([5]) + '!';
        }
        """
    ),
    A_ZERO_CHANGING_SIGN_READ_BY_A_HELPER_THAT_TELLS_THE_SIGNS_APART: inspect.cleandoc(
        """
        function grade(n) {
          var A = {};
          A.label = n > 10 ? 'big' : 'small';
          if (!(n > 10)) {
            return A.label + '!';
          }
        }
        """
    ),
    A_CASE_TEST_ASKING_A_HELPER_ABOUT_A_NEGATIVE_ZERO_THEN_A_ZERO: inspect.cleandoc(
        """
        var out = [];
        out.push('a');
        out.push('z');
        out.push('y');
        console.log(out.join(''));
        """
    ),
}

#: Machines the recovery leaves as they are, each mapped to the reason.
KEPT = {
    THE_CODE_READS_THE_LENGTH_OF_THE_STATE: 'the state is read as a whole',
    THE_CODE_HANDS_THE_STATE_TO_A_FUNCTION: 'the state is handed out',
    A_CLOSURE_READS_THE_STATE_WHEN_IT_IS_CALLED: 'the state is read after the run',
    THE_CODE_STORES_INTO_THE_STATE_OUTSIDE_THE_TRANSITION: 'the state is stored to by the payload',
    THE_CODE_READS_AN_ELEMENT_THE_STATE_DOES_NOT_HAVE: 'the state is read out of its range',
    THE_CODE_READS_THE_RUNTIME_PARAMETER: 'the scaffolding is read',
    THE_MACHINE_READS_ITS_ARGUMENTS: 'the scaffolding is read',
    A_WRAPPER_HANDING_THE_MACHINE_ANOTHER_RUNTIME: 'the scaffolding is read',
    A_CLOSURE_DECODES_A_KEY_FROM_THE_STATE_WHEN_IT_IS_CALLED: 'the state is read after the run',
    A_CATCH_PARAMETER_NAMED_LIKE_THE_STATE_READ_BY_A_DECODED_KEY: 'a key reads no state of the run',
    A_HELPER_THAT_COUNTS_ITS_CALLS: 'a helper has an effect',
    THE_CODE_REPLACES_THE_HELPER: 'a helper is replaced',
    THE_TABLE_IS_STORED_TO_AFTER_A_CALL: 'the table changes',
    THE_TABLE_IS_CHANGED_THROUGH_ANOTHER_NAME: 'the table changes',
    THE_TABLE_IS_HANDED_TO_A_FUNCTION_THAT_SORTS_IT: 'the table changes',
    THE_ARRAY_METHOD_THE_TABLE_IS_READ_WITH_IS_REPLACED: 'a built-in a helper calls is replaced',
    THE_STRING_METHOD_THE_KEYS_ARE_DECODED_WITH_IS_REPLACED: 'a built-in a helper calls is replaced',
    THE_ARRAY_ITERATOR_IS_REPLACED_AND_THE_START_STATE_SPREADS_A_LITERAL: 'arrays iterate otherwise',
    THE_ARRAY_ITERATOR_IS_DEFINED_ANEW_AND_THE_START_STATE_SPREADS_A_LITERAL: 'arrays iterate otherwise',
    A_JUMP_WHOSE_CONDITION_READS_MORE_THAN_THE_STATE: 'the next block is not decided by the state',
    A_START_STATE_THAT_READS_A_PARAMETER: 'the next block is not decided by the state',
    A_JUMP_WHOSE_CONDITION_COMPARES_TWO_NEW_ARRAYS: 'the next block is not decided by the state',
}


class TestArrayMachines(TestJsDeobfuscator):

    def _recovered(self, source: str) -> str:
        return self._run_transformers(source, JsFunctionEvaluator, JsStateMachineUnflattening)

    def test_each_machine_the_recovery_reads_is_written_as_code(self):
        for source, code in RECOVERED.items():
            with self.subTest(source):
                recovered = self._recovered(source)
                self.assertIn(code, recovered)
                self.assertNotIn('switch (sum(states))', recovered)

    def test_a_table_read_by_a_method_under_a_key_another_pass_decides_is_recovered(self):
        """
        The key `method` holds is folded by another pass, after which the table is only read by a
        method that leaves it as it is.
        """
        self.assertEqual(
            self._deobfuscate(A_TABLE_READ_BY_A_METHOD_UNDER_A_COMPUTED_KEY),
            "console.log('small!', 'big!');",
        )

    def test_each_machine_whose_run_the_recovery_cannot_decide_is_kept(self):
        for source, reason in KEPT.items():
            with self.subTest(reason=reason, source=source):
                self.assertIn('switch (sum(states))', self._deobfuscate(source))

    def test_a_machine_inside_a_function_of_a_recovered_machine_keeps_its_own_names(self):
        """
        The inner machine reads the length of its state and is kept; the recovery of the outer one
        substitutes none of its state into the inner one, whose names are the same.
        """
        deobfuscated = self._deobfuscate(A_MACHINE_INSIDE_A_FUNCTION_OF_A_MACHINE_WITH_THE_SAME_NAMES)
        self.assertEqual(deobfuscated.count('switch (sum(states))'), 1)
        self.assertIn('scope.B[dec(states[0] - 5, 5)] = states.length;', deobfuscated)

    def test_a_machine_of_a_thousand_blocks_and_a_state_of_a_hundred_numbers_is_recovered_in_time(self):
        blocks = 1000
        cases = '\n'.join(
            F'case {block}: out.push({block}); states[0] += states[{1 + block % 99}] + 1; break L;'
            for block in range(1, blocks + 1)
        )
        state = ', '.join(['1'] + ['0'] * 99)
        source = inspect.cleandoc(
            """
            function sum(array) {
              for (var total = 0, i = 0; i < array["length"]; i++) {
                total += array[i];
              }
              return total;
            }
            function run(out) {
              function M(states, scope = { A: {} }, runtime) {
                while (sum(states) !== END) {
                  L: switch (sum(states)) {
            CASES
                  }
                }
              }
              M([STATE]);
              return out;
            }
            console.log(run([]).length);
            """
        ).replace('END', str(blocks + 1)).replace('CASES', cases).replace('STATE', state)
        result = deobfuscate_within(source, 60)
        self.assertIsNotNone(result)
        self.assertNotIn('switch (sum(states))', result or '')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameForEachArrayMachine(TestJsDeobfuscator):

    def _machines(self):
        yield from RECOVERED
        yield from KEPT
        yield A_TABLE_READ_BY_A_METHOD_UNDER_A_COMPUTED_KEY
        yield A_MACHINE_INSIDE_A_FUNCTION_OF_A_MACHINE_WITH_THE_SAME_NAMES

    def test_each_machine_recovered_after_the_evaluator_prints_what_it_printed(self):
        for source in RECOVERED:
            with self.subTest(source):
                recovered = self._run_transformers(source, JsFunctionEvaluator, JsStateMachineUnflattening)
                self.assertEqual(behavior(source), behavior(recovered))

    def test_each_machine_deobfuscated_prints_what_it_printed(self):
        for source in self._machines():
            with self.subTest(source):
                self.assertEqual(behavior(source), behavior(self._deobfuscate(source)))
