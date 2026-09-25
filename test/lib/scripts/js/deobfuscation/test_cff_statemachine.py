from __future__ import annotations

import inspect
import threading
import unittest

from unittest import mock

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts import TREE_RECURSION_DEPTH
from refinery.lib.scripts.js.deobfuscation.cff import JsGeneratorCFFUnflattening, statemachine
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from refinery.lib.tools import RecursionDepth


class TestGeneratorCFFUnflattening(TestJsDeobfuscator):

    FIZZBUZZ_CFF = inspect.cleandoc(
        """
        function fizzbuzz(n) {
          function* ECU0cy7(eFGm4GL, QmFNlk, AT7hsy7, sYhBnK = {
            ["GrHow6O"]: {}
          }) {
            while (eFGm4GL + QmFNlk + AT7hsy7 !== -182) {
              with (sYhBnK["Pia5Vq"] || sYhBnK) {
                switch (eFGm4GL + QmFNlk + AT7hsy7) {
                  case sYhBnK["GrHow6O"]["_TkmcFL"] + -375:
                  case 210:
                  case 17:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [95, -148];
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 200, QmFNlk += AT7hsy7 - -792, AT7hsy7 += QmFNlk - 183;
                    break;
                  case -125:
                  case QmFNlk - 131:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [99, 225];
                    GrHow6O["QOwuVkJ"] = [];
                    for (GrHow6O["z947WD2"] = 1; GrHow6O["z947WD2"] <= n; GrHow6O["z947WD2"]++) {
                      if (GrHow6O["z947WD2"] % 15 === QmFNlk + -66) {
                        GrHow6O["QOwuVkJ"]["push"]('FizzBuzz');
                      } else {
                        if (GrHow6O["z947WD2"] % (QmFNlk + -63) === 0) {
                          GrHow6O["QOwuVkJ"]["push"]('Fizz');
                        } else {
                          if (GrHow6O["z947WD2"] % (QmFNlk + -61) === eFGm4GL + 46) {
                            GrHow6O["QOwuVkJ"]["push"]('Buzz');
                          } else {
                            GrHow6O["QOwuVkJ"]["push"](GrHow6O["z947WD2"]);
                          }
                        }
                      }
                    }
                    return DL1uIO3 = true, GrHow6O["QOwuVkJ"];
                    eFGm4GL += AT7hsy7 - 326, QmFNlk += AT7hsy7 - -101, AT7hsy7 += QmFNlk - -196;
                    break;
                  case -142:
                  case sYhBnK["GrHow6O"]["_TkmcFL"] + 12:
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += QmFNlk - 193, QmFNlk += eFGm4GL - 563;
                    break;
                  case 29:
                  case 222:
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 205, QmFNlk += AT7hsy7 - -618, AT7hsy7 += QmFNlk - 183;
                    break;
                  default:
                  case -31:
                    [sYhBnK["GrHow6O"]["HwIYcaT"], sYhBnK["GrHow6O"]["_TkmcFL"]] = [142, -215];
                    sYhBnK["Pia5Vq"] = sYhBnK["GrHow6O"], eFGm4GL += AT7hsy7 - 210, QmFNlk += AT7hsy7 - -530, AT7hsy7 += QmFNlk - 445;
                    break;
                  case eFGm4GL - 67:
                    sYhBnK["Pia5Vq"] = sYhBnK["YS6RFB"], eFGm4GL += QmFNlk - 370, QmFNlk += AT7hsy7 - -149, AT7hsy7 += QmFNlk - -79;
                    break;
                }
              }
            }
          }
          var DL1uIO3;
          var WLHepXQ = ECU0cy7(-46, 66, -85)["next"]()["value"];
          if (DL1uIO3) {
            return WLHepXQ;
          }
        }
        console["log"](fizzbuzz(20000));
        """
    )

    def test_generator_cff_fizzbuzz(self):
        result = self._deobfuscate(self.FIZZBUZZ_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function fizzbuzz(n) {
                  var QOwuVkJ, z947WD2;
                  QOwuVkJ = [];
                  for (z947WD2 = 1; z947WD2 <= n; z947WD2++) {
                    if (z947WD2 % 15 === 0) {
                      QOwuVkJ.push('FizzBuzz');
                    } else {
                      if (z947WD2 % 3 === 0) {
                        QOwuVkJ.push('Fizz');
                      } else {
                        if (z947WD2 % 5 === 0) {
                          QOwuVkJ.push('Buzz');
                        } else {
                          QOwuVkJ.push(z947WD2);
                        }
                      }
                    }
                  }
                  return QOwuVkJ;
                }
                console.log(fizzbuzz(20000));
                """
            ),
            result,
        )

    WITH_DISSOLUTION_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    x = globalThis;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, x;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_with_statement_dissolved(self):
        result = self._run_transformer(self.WITH_DISSOLUTION_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              x = globalThis;
              return x;
            }
            """
        ))

    SHARED_WRAPPER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case -10:
                    scope.R = {};
                    scope.R.k = -10;
                    a = 20, b = 10;
                    break;
                  case scope.R.k + 40:
                    var wrapper = function(...rest) {
                      return gen(25, 10, scope, rest)["next"]()["value"];
                    };
                    a = 80, b = -30;
                    break;
                  case 50:
                    return x = true, wrapper(1, 2);
                    break;
                  case scope.R.k + 45:
                    return x = true, args[0] + args[1];
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, -15)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_shared_wrapper_routing(self):
        result = self._deobfuscate(self.SHARED_WRAPPER_CFF)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var R;
              R = {};
              R.k = -10;
              var wrapper = function(...rest) {
                return rest[0] + rest[1];
              };
              return wrapper(1, 2);
            }
            """
        ))

    GUARDED_PREDICATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {}, args) {
            while (a + b + c !== 200) {
              with (scope) {
                switch (a + b + c) {
                  case 10:
                    scope.R = {};
                    scope.R.k = 50;
                    a = 20, b = 30, c = -10;
                    break;
                  case a != 30 && a + 20:
                    var wrapper = function(...rest) {
                      return gen(10, 20, 20, scope, rest)["next"]()["value"];
                    };
                    a = 60, b = 30, c = 10;
                    break;
                  case 100:
                    return x = true, wrapper(1, 2);
                    break;
                  case scope.R.k + 0:
                    return x = true, "resolved";
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 10, -5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_guarded_predicate(self):
        result = self._deobfuscate(self.GUARDED_PREDICATE_CFF)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var R;
              R = {};
              R.k = 50;
              var wrapper = function(...rest) {
                return "resolved";
              };
              return wrapper(1, 2);
            }
            """
        ))

    NESTED_WRAPPER_ARG_REBIND_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.run = function(...a) {
                      return gen(25, 25, scope, a)["next"]()["value"];
                    };
                    return done = true, scope.run;
                    break;
                  case 50:
                    return done = true, function(seed) {
                      var args;
                      args = seed * 2;
                      return args + 1;
                    }(args[0]);
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_nested_wrapper_arg_rebind(self):
        """
        The wrapper `run` has a rest-parameter named `a` that collides with a state variable, and
        its recovered body contains a nested function that binds the generator's argument variable
        `args` as its own local. Threading `run`'s arguments must mint a fresh parameter (`args_1`)
        rather than reuse the colliding `a`, and must leave the nested `var args` untouched instead
        of capturing it. Verified equivalent to the original under Node: `outer()(7)` returns `15`
        for both, as do the other drivers.
        """
        result = self._run_transformer(self.NESTED_WRAPPER_ARG_REBIND_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var run;
              run = function(...args_1) {
                return function(seed) {
                  var args;
                  args = seed * 2;
                  return args + 1;
                }(args_1[0]);
              };
              return run;
            }
            """
        ))

    REDIRECT_VAR_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    y = 42;
                    a = 30, b = 20;
                    break;
                  case 50:
                    return x = true, y;
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_redirect_var_removed(self):
        result = self._run_transformer(self.REDIRECT_VAR_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              y = 42;
              return y;
            }
            """
        ))

    COMPUTED_REDIRECT_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {NS: {}}, args) {
            while (a + b + c !== 200) {
              with (scope["RV"] || scope) {
                switch (a + b + c) {
                  case 30:
                    scope["RV"] = scope["NS"];
                    a = 40, b = 50, c = 10;
                    break;
                  case 100:
                    data = args;
                    a = 20, b = 30, c = 100;
                    break;
                  case 150:
                    return DR = true, val;
                    break;
                }
              }
            }
          }
          var DR;
          var result = gen(10, 10, 10)["next"]()["value"];
          if (DR) { return result; }
        }
"""
    )

    def test_generator_cff_computed_redirect_resolved(self):
        result = self._run_transformer(self.COMPUTED_REDIRECT_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              data = void 0;
              return val;
            }
            """
        ))

    LOOPING_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.i < 3) {
                      a = 20, b = 10;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    console.log(scope.i);
                    scope.i = scope.i + 1;
                    a = 20, b = 0;
                    break;
                  case 50:
                    return x = true, "done";
                    break;
                }
              }
            }
          }
          var x;
          var result = gen(5, 5)["next"]()["value"];
          if (x) { return result; }
        }
"""
    )

    def test_generator_cff_loop_body_not_duplicated(self):
        result = self._deobfuscate(self.LOOPING_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var i;
                  i = 0;
                  while (i < 3) {
                    console.log(i);
                    i = i + 1;
                  }
                  return "done";
                }
                """
            ),
            result,
        )

    def test_generator_cff_machine_with_more_blocks_than_the_limit_is_declined(self):
        """
        `LOOPING_CFF` runs four blocks. Under a limit of three the recovery leaves the generator as
        it is rather than recover the blocks it read; under a limit of four it recovers it.
        """
        source = self.LOOPING_CFF
        with mock.patch.object(statemachine, '_MAX_BLOCKS', 3):
            self.assertEqual(
                self._run_transformers(source),
                self._run_transformer(source, JsGeneratorCFFUnflattening),
            )
        with mock.patch.object(statemachine, '_MAX_BLOCKS', 4):
            self.assertNotIn('function*', self._run_transformer(source, JsGeneratorCFFUnflattening))

    CONTINUE_IN_LOOP_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.i < 5) {
                      a = 30, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    if (scope.i % 2 === 0) {
                      scope.i = scope.i + 1;
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 10;
                    }
                    break;
                  case 40:
                    console.log(scope.i);
                    scope.i = scope.i + 1;
                    a = 20, b = 0;
                    break;
                  case 50:
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_continue_in_loop(self):
        result = self._deobfuscate(self.CONTINUE_IN_LOOP_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var i;
                  i = 0;
                  while (i < 5) {
                    if (i % 2 === 0) {
                      i = i + 1;
                    } else {
                      console.log(i);
                      i = i + 1;
                    }
                  }
                  return "result";
                }
                """
            ),
            result,
        )

    HEADER_PAYLOAD_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope.i = scope.i + 1;
                    if (scope.i < 4) {
                      a = 20, b = 10;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    console.log(scope.i);
                    a = 20, b = 0;
                    break;
                  case 50:
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_header_payload_before_condition(self):
        result = self._deobfuscate(self.HEADER_PAYLOAD_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var i;
                  i = 0;
                  while (true) {
                    i = i + 1;
                    if (!(i < 4)) {
                      break;
                    }
                    console.log(i);
                  }
                  return "result";
                }
                """
            ),
            result,
        )

    COMPUTED_MEMBER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope["counter"] = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope["counter"] = scope["counter"] + 1;
                    if (scope["counter"] < 3) {
                      a = 20, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    console.log(scope["counter"]);
                    return done = true, scope["counter"];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_computed_member_scope(self):
        result = self._deobfuscate(self.COMPUTED_MEMBER_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var counter;
                  counter = 0;
                  while (true) {
                    counter = counter + 1;
                    if (!(counter < 3)) {
                      break;
                    }
                  }
                  console.log(counter);
                  return counter;
                }
                """
            ),
            result,
        )

    SEQUENCE_STATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.items = [], scope.i = 0, a = 20, b = 0;
                    break;
                  case 20:
                    scope.items.push(scope.i), scope.i = scope.i + 1, a = 30, b = 0;
                    break;
                  case 30:
                    if (scope.i < 4) {
                      a = 20, b = 0;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    console.log(scope.items);
                    return done = true, scope.items;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_sequence_state_assignments(self):
        result = self._deobfuscate(self.SEQUENCE_STATE_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var i, items;
                  items = [], i = 0;
                  while (true) {
                    items.push(i), i = i + 1;
                    if (!(i < 4)) {
                      break;
                    }
                  }
                  console.log(items);
                  return items;
                }
                """
            ),
            result,
        )

    NESTED_CONDITIONAL_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.x = 7;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.x > 5) {
                      a = 30, b = 0;
                    } else {
                      a = 40, b = 0;
                    }
                    break;
                  case 30:
                    if (scope.x > 10) {
                      a = 50, b = 0;
                    } else {
                      a = 60, b = 0;
                    }
                    break;
                  case 40:
                    console.log("alpha");
                    a = 50, b = 0;
                    break;
                  case 50:
                    console.log("beta");
                    return done = true, "end";
                    break;
                  case 60:
                    console.log("gamma");
                    return done = true, "end";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_nested_conditional_join(self):
        result = self._deobfuscate(self.NESTED_CONDITIONAL_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  console.log("gamma");
                  return "end";
                }
                """
            ),
            result,
        )

    COMPUTED_ROUTING_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope["count"] = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    scope["count"] = scope["count"] + 1;
                    console.log("tick");
                    if (scope["count"] < 3) {
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 0;
                    }
                    break;
                  case 30:
                    console.log("done");
                    return done = true, scope["count"];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_computed_routing_member(self):
        result = self._deobfuscate(self.COMPUTED_ROUTING_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var count;
                  count = 0;
                  while (true) {
                    count = count + 1;
                    console.log("tick");
                    if (!(count < 3)) {
                      break;
                    }
                  }
                  console.log("done");
                  return count;
                }
                """
            ),
            result,
        )

    BOOKKEEPING_LEAK_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.pred = 1;
                    console.log("start");
                    a = 20, b = 0;
                    break;
                  case 20:
                    console.log("end");
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_bookkeeping_suppressed(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  console.log("start");
                  console.log("end");
                  return "result";
                }
                """
            ),
            self._deobfuscate(self.BOOKKEEPING_LEAK_CFF),
        )

    SHARED_INTERMEDIATE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.x = 0;
                    if (scope.x === 0) {
                      a = 20, b = 0;
                    } else {
                      a = 30, b = 0;
                    }
                    break;
                  case 20:
                    console.log("path-a");
                    a = 40, b = 0;
                    break;
                  case 30:
                    console.log("path-b");
                    a = 40, b = 0;
                    break;
                  case 40:
                    console.log("shared");
                    return done = true, "done";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_shared_intermediate_node(self):
        result = self._deobfuscate(self.SHARED_INTERMEDIATE_CFF)
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  console.log("path-a");
                  console.log("shared");
                  return "done";
                }
                """
            ),
            result,
        )

    BARE_SCOPE_CONDITION_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.ready = 1;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.ready) {
                      console.log("go");
                      a = 50, b = 0;
                    } else {
                      console.log("wait");
                      a = 50, b = 0;
                    }
                    break;
                  case 50:
                    return done = true, "ok";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_bare_scope_condition_stripped(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  console.log("go");
                  return "ok";
                }
                """
            ),
            self._deobfuscate(self.BARE_SCOPE_CONDITION_CFF),
        )

    MIXED_SEQUENCE_BRANCH_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (scope.x) {
                      console.log("mixed"), a = 40, b = 0;
                    } else {
                      console.log("other"), a = 40, b = 0;
                    }
                    break;
                  case 40:
                    console.log("end");
                    return done = true, "result";
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_mixed_sequence_branch_preserved(self):
        """
        The branch condition `scope.x` reads a member never written on the empty default scope, so it
        is `undefined` and the recovery must declare `var x;` for the stripped bare read rather than
        leave an unbound free `x`. The redirect sibling keeps `var extra;` for the same reason.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  var x;
                  if (x) {
                    console.log("mixed");
                  } else {
                    console.log("other");
                  }
                  console.log("end");
                  return "result";
                }
                """
            ),
            self._deobfuscate(self.MIXED_SEQUENCE_BRANCH_CFF),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_generator_cff_mixed_sequence_branch_behaviour_preserved(self):
        """
        `wrapper()` takes the else branch (`scope.x` is `undefined`), prints `other` then `end`, and
        returns `"result"`. Dropping the read to a bare free `x` would throw a `ReferenceError` before
        any output, so the recovered code diverges unless it declares the name.
        """
        source = self.MIXED_SEQUENCE_BRANCH_CFF
        invoke = '\nconsole.log(JSON.stringify(wrapper()));'
        self.assertEqual(
            behavior(source + invoke),
            behavior(self._deobfuscate(source) + invoke),
        )

    FREE_NAMES_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    x = 1;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, x + y;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_free_names_stay_bare(self):
        result = self._run_transformer(self.FREE_NAMES_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              x = 1;
              return x + y;
            }
            """
        ))

    LABELED_CONTINUE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    LBL: for (var i = 0; i < 3; i++) {
                      if (i === 1) continue LBL;
                    }
                    return done = true, i;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_labeled_continue_preserved(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
                  LBL: for (var i = 0; i < 3; i++) {
                    if (i === 1) {
                      continue LBL;
                    }
                  }
                  return i;
                }
                """
            ),
            self._deobfuscate(self.LABELED_CONTINUE_CFF),
        )

    FREE_FORMS_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    freeCall();
                    freeObj.method();
                    freeVar = 5;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, freeVal;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_free_forms_stay_free(self):
        result = self._run_transformer(self.FREE_FORMS_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              freeCall();
              freeObj.method();
              freeVar = 5;
              return freeVal;
            }
            """
        ))

    NAMESPACE_LOCAL_DEEP_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.local = 7;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, local + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_namespace_local_deep_write_recovered(self):
        """
        The complement of the free-name tests: a genuine namespace-local with a `scope.NS.local`
        defining write is proven local, so bare `local` is qualified back to `NS.local`. This is
        what distinguishes the fix from simply never qualifying.
        """
        result = self._run_transformer(self.NAMESPACE_LOCAL_DEEP_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              NS.local = 7;
              return NS.local + 1;
            }
            """
        ))

    NAMESPACE_LOCAL_BARE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.member = 7;
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, member + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_namespace_local_bare_write_recovered(self):
        result = self._run_transformer(self.NAMESPACE_LOCAL_BARE_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              NS.member = 7;
              return NS.member + 1;
            }
            """
        ))

    NAMESPACE_LOCAL_DESTRUCTURING_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    [scope.NS.p, scope.NS.q] = [3, 4];
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, p + q;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_namespace_local_destructuring_recovered(self):
        result = self._run_transformer(self.NAMESPACE_LOCAL_DESTRUCTURING_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var NS = {};
              [NS.p, NS.q] = [3, 4];
              return NS.p + NS.q;
            }
            """
        ))

    SIBLING_NAMESPACE_HOME_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.make = function(...rest) {
                      return gen(20, 30, {NS: {}, Sub: {}}, rest)["next"]()["value"];
                    };
                    return done = true, NS.make;
                    break;
                  case 50:
                    Sub.slot = args;
                    scope.RV = scope.Sub;
                    a = 70, b = 0;
                    break;
                  case 70:
                    return done = true, slot[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_sibling_namespace_home_canonical(self):
        """
        A member of a sibling namespace `Sub` distinct from the main default `NS` is written
        qualified (`Sub.slot`, while the `with` redirect is unset) and later read bare (`slot`,
        while the redirect points at `Sub`). Node resolves both to `scope.Sub.slot`, so the recovery
        must canonicalize the member to `Sub.slot` in both positions independently of the momentary
        redirect. `Sub` reaches the scope as an object-literal argument the wrapper threads to the
        shared generator, a fresh object for every call of the wrapper, so it is declared as
        `var Sub = {}` in the wrapper's recovered body.
        """
        result = self._run_transformer(self.SIBLING_NAMESPACE_HOME_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.make = function(...rest) {
                var Sub = {};
                Sub.slot = rest;
                return Sub.slot[0];
              };
              return NS.make;
            }
            """
        ))

    AMBIGUOUS_NAMESPACE_HOME_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.Alt = {};
                    scope.NS.v = 11;
                    scope.Alt.v = 22;
                    scope.RV = scope.Alt;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, v;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_ambiguous_namespace_home_declined(self):
        """
        The member `v` is written under two sibling namespaces (`scope.NS.v` and `scope.Alt.v`), so it
        has no single canonical home — under the `with`-redirect a bare `v` resolves to `NS.v` or
        `Alt.v` depending on the routing state at each use, which redirect-independent qualification
        cannot express. Recovery of the whole generator is declined and it is returned unchanged,
        rather than emitting a bare `v` that would resolve to a free variable. Node-verified: the
        original and the returned form both evaluate `outer()` to 22.
        """
        result = self._run_transformer(self.AMBIGUOUS_NAMESPACE_HOME_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              function* gen(a, b, scope = { NS: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.Alt = {};
                        scope.NS.v = 11;
                        scope.Alt.v = 22;
                        scope.RV = scope.Alt;
                        a = 40, b = 0;
                        break;
                      case 40:
                        return done = true, v;
                        break;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) {
                return result;
              }
            }
            """
        ))

    CATCH_PARAM_QUALIFY_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.x = 5;
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    try {
                      throw 9;
                    } catch (x) {
                      scope.NS.x = x;
                    }
                    return done = true, x + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_catch_param_does_not_leak_qualification(self):
        """
        The namespace-local `x` is shadowed by a `catch (x)` binding in one statement and read
        bare in a sibling statement. The catch exemption must stay confined to the catch clause so
        the later read still qualifies to `NS.x`. Original and recovered both return 10 under Node.
        """
        result = self._run_transformer(self.CATCH_PARAM_QUALIFY_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.x = 5;
              try {
                throw 9;
              } catch (x) {
                NS.x = x;
              }
              return NS.x + 1;
            }
            """
        ))

    ARROW_PARAM_QUALIFY_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.x = 100;
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, ((x) => x + 1)(5);
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_arrow_param_not_qualified(self):
        """
        An arrow parameter that shares a name with the namespace-local `x` is its own binding, so it
        must stay bare rather than be rewritten to the invalid `(NS.x) => NS.x + 1`. Original and
        recovered both return 6 under Node.
        """
        result = self._run_transformer(self.ARROW_PARAM_QUALIFY_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.x = 100;
              return (x => x + 1)(5);
            }
            """
        ))

    OBJECT_SHORTHAND_QUALIFY_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.x = 7;
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, {x};
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_object_shorthand_qualified(self):
        """
        A namespace-local read through an object shorthand `{x}` must expand to `{x: NS.x}`; leaving
        it bare would read a global. Original and recovered both return {x: 7} under Node.
        """
        result = self._run_transformer(self.OBJECT_SHORTHAND_QUALIFY_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.x = 7;
              return { x: NS.x };
            }
            """
        ))

    COMPOUND_ASSIGNMENT_HOME_CFF = inspect.cleandoc(
        """
        function outer(seed) {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.c ||= 3;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, c + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_compound_assignment_home(self):
        """
        A member whose only defining write is a logical assignment (`scope.NS.c ||= 3`) is still a
        namespace-local, so its bare read must qualify to `NS.c`. Original and recovered both return
        4 under Node.
        """
        result = self._run_transformer(self.COMPOUND_ASSIGNMENT_HOME_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer(seed) {
              var NS = {};
              NS.c ||= 3;
              return NS.c + 1;
            }
            """
        ))

    PLAIN_PARAM_WRAPPER_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(a) {
                      return gen(40, 0, scope, a)["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    return done = true, args[0] + args[1];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_plain_param_wrapper_preserved(self):
        """
        A wrapper with a plain (non-rest) parameter colliding with a state variable must stay plain
        after its argument name is minted fresh, not become `...args_1`, so the caller's single
        array argument keeps its binding. Original and recovered both return 3 for `outer()([1,2])`.
        """
        result = self._run_transformer(self.PLAIN_PARAM_WRAPPER_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var w = function(args_1) {
                return args_1[0] + args_1[1];
              };
              return w;
            }
            """
        ))

    WRAPPER_REST_FREE_REFERENCE_CFF = inspect.cleandoc(
        """
        var sink;
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(...data) {
                      return gen(40, 0, scope, data)["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    sink = data;
                    return done = true, args[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        var data = 999;
"""
    )

    def test_generator_cff_wrapper_rest_free_reference(self):
        """
        The wrapper's rest name `data` also occurs as a free global read in the recovered body, so
        reusing it as the argument name would capture that global; a fresh name must be minted
        instead. Original and recovered both yield sink == 999 under Node.
        """
        result = self._run_transformer(self.WRAPPER_REST_FREE_REFERENCE_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            var sink;
            function outer() {
              var w = function(...args_1) {
                sink = data;
                return args_1[0];
              };
              return w;
            }
            var data = 999;
            """
        ))

    WRAPPER_SHORTHAND_ARG_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(...rest) {
                      return gen(40, 0, scope, rest)["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    return done = true, {args};
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_wrapper_shorthand_arg_rebound(self):
        """
        The threaded argument holder read through a shorthand `{args}` must expand to `{args: rest}`
        so the property value binds the wrapper parameter. Original and recovered both return
        {args: [5, 6]} for `outer()(5, 6)` under Node.
        """
        result = self._run_transformer(self.WRAPPER_SHORTHAND_ARG_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var w = function(...rest) {
                return { args: rest };
              };
              return w;
            }
            """
        ))

    STATE_NAME_IN_PROPERTY_SLOTS_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(i, b, scope = {NS: {}}, args) {
            while (i + b !== 100) {
              with (scope.RV || scope) {
                switch (i + b) {
                  case 10:
                    scope.RV = scope.NS;
                    i = 40, b = 0;
                    break;
                  case 40:
                    var o = { i: 1 };
                    return done = true, [o.i, i, { i }.i, { i: 2 }.i];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
"""
    )

    def test_generator_cff_state_value_reaches_only_the_slots_that_read_the_name(self):
        """
        The state variable `i` also spells a member property, an object key and a shorthand
        property. Only the shorthand is a read of the binding, so only it takes the state value and
        expands to `{i: 40}`; substituting into the other two emits `o.40` and `{40: 2}`, which no
        engine parses. Original and recovered both return [1, 40, 40, 2] under Node.
        """
        result = self._run_transformer(
            self.STATE_NAME_IN_PROPERTY_SLOTS_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var o = { i: 1 };
              return [o.i, 40, { i: 40 }.i, { i: 2 }.i];
            }
            """
        ))

    PER_CALL_NAMESPACE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.keep = function(...rest) {
                      return gen(20, 30, {NS: scope.NS, Loc: {}}, rest)["next"]()["value"];
                    };
                    return done = true, NS.keep;
                    break;
                  case 50:
                    [Loc.p, Loc.q] = args;
                    scope.RV = scope.Loc;
                    a = 70, b = 0;
                    break;
                  case 70:
                    return done = true, function () { return p + q; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_per_call_namespace_is_a_local_of_the_wrapper(self):
        """
        Each call of the wrapper hands the generator a fresh `Loc`, which the closure it returns
        keeps; the recovered wrapper declares `Loc` itself, and the argument store becomes its
        parameters.
        """
        result = self._run_transformer(self.PER_CALL_NAMESPACE_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.keep = function(p_1, q_1) {
                var Loc = {};
                Loc.p = p_1, Loc.q = q_1;
                return function() {
                  return Loc.p + Loc.q;
                };
              };
              return NS.keep;
            }
            """
        ))

    PER_CALL_SCOPE_VARIABLE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var hold = function(...rest) {
                      return gen(20, 30, {}, rest)["next"]()["value"];
                    };
                    return done = true, hold;
                    break;
                  case 50:
                    scope.t = args[0];
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_per_call_scope_variable_is_a_local_of_the_wrapper(self):
        result = self._run_transformer(self.PER_CALL_SCOPE_VARIABLE_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var hold = function(...rest) {
                var t;
                t = rest[0];
                return function() {
                  return t;
                };
              };
              return hold;
            }
            """
        ))

    ARGUMENT_STORE_WITH_REST_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.count = function(...rest) {
                      return gen(20, 30, {NS: scope.NS, Loc: {}}, rest)["next"]()["value"];
                    };
                    return done = true, NS.count;
                    break;
                  case 50:
                    [Loc.first, ...Loc.others] = args;
                    scope.RV = scope.Loc;
                    a = 70, b = 0;
                    break;
                  case 70:
                    return done = true, first + ":" + others.length;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_argument_store_with_a_rest_slot_becomes_a_rest_parameter(self):
        result = self._run_transformer(
            self.ARGUMENT_STORE_WITH_REST_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              NS.count = function(first_1, ...others_1) {
                var Loc = {};
                Loc.first = first_1, Loc.others = others_1;
                return Loc.first + ":" + Loc.others.length;
              };
              return NS.count;
            }
            """
        ))

    SCOPE_NAME_REBOUND_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.list = [];
                    scope.fill = function (scope) {
                      scope.push(1);
                      return scope.length;
                    };
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, fill(list);
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_scope_members_below_a_rebinding_of_the_scope_name_stay(self):
        result = self._run_transformer(self.SCOPE_NAME_REBOUND_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var fill, list;
              list = [];
              fill = function(scope) {
                scope.push(1);
                return scope.length;
              };
              return fill(list);
            }
            """
        ))

    UNREADABLE_WRAPPER_SCOPE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(...rest) {
                      return gen(40, 0, make(), rest)["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    return done = true, args[0] + typeof k;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    STATE_READ_BY_A_CLOSURE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.peek = function () { return a; };
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, peek();
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    MAIN_RUN_WRITES_ITS_ARGUMENTS_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    args = [7];
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, args[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ACCESSOR_SCOPE_DEFAULT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {get NS() { return {}; }}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    NS.x = 1;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, NS.x;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_INITIALIZER_WITH_AN_EFFECT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(...rest) {
                      return gen(40, 0, {Loc: {a: note()}}, rest)["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    return done = true, args[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    WRAPPER_HANDING_ON_ANOTHER_ARGUMENT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var w = function(...rest) {
                      return gen(40, 0, scope, [9])["next"]()["value"];
                    };
                    return done = true, w;
                    break;
                  case 40:
                    return done = true, args[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    GUARD_WITH_MORE_TO_DO_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { console.log("guard"); return result; }
          return 2;
        }
        """
    )

    UNGUARDED_RETURN_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          console.log("after", result);
          return 2;
        }
        """
    )

    GENERATOR_RETURN_WITHOUT_THE_FLAG_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
          return 2;
        }
        """
    )

    RESULT_READ_AFTER_THE_GUARD_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    console.log("ran");
                    a = 90, b = 10;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
          return result === undefined ? "none" : result;
        }
        """
    )

    FUNCTION_BETWEEN_GENERATOR_AND_CALL_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, helper();
                    break;
                }
              }
            }
          }
          function helper() { return 3; }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_recovery_declines_what_it_cannot_express(self):
        """
        A wrapper handing the generator a scope object a call makes, a nested function reading a
        state variable when it is called, a run storing to the argument holder the main call never
        passes, a scope object whose namespace an accessor makes afresh on every read, a namespace
        nothing refers to whose initializer calls a function, and a wrapper handing on an argument
        other than its own parameter: each generator is left as it is. So is one whose call is not
        the obfuscator's scaffolding exactly: a guard that does more than return the result, a
        return of the generator no guard turns into a return of the function, a result read after
        the guard, and a declaration standing between the generator and its call.
        """
        for source in (
            self.UNREADABLE_WRAPPER_SCOPE_CFF,
            self.STATE_READ_BY_A_CLOSURE_CFF,
            self.MAIN_RUN_WRITES_ITS_ARGUMENTS_CFF,
            self.ACCESSOR_SCOPE_DEFAULT_CFF,
            self.NAMESPACE_INITIALIZER_WITH_AN_EFFECT_CFF,
            self.WRAPPER_HANDING_ON_ANOTHER_ARGUMENT_CFF,
            self.GUARD_WITH_MORE_TO_DO_CFF,
            self.UNGUARDED_RETURN_CFF,
            self.GENERATOR_RETURN_WITHOUT_THE_FLAG_CFF,
            self.RESULT_READ_AFTER_THE_GUARD_CFF,
            self.FUNCTION_BETWEEN_GENERATOR_AND_CALL_CFF,
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    MAIN_SLOT_NAMED_LIKE_A_WRAPPER_SLOT_CFF = inspect.cleandoc(
        """
        function outer(n) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = n;
                    var hold = function(...rest) {
                      return gen(20, 30, {}, rest)["next"]()["value"];
                    };
                    return done = true, [hold, function () { return t; }];
                    break;
                  case 50:
                    scope.t = args[0];
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_main_slot_is_declared_beside_a_wrapper_slot_of_its_name(self):
        """
        The wrapper's run keeps its own `t` on the scope object each call makes, and the main run
        keeps another on its own. Declaring the wrapper's must not stop the main run's from being
        declared, or the main run's `t` becomes a global every call of `outer` shares.
        """
        result = self._run_transformer(
            self.MAIN_SLOT_NAMED_LIKE_A_WRAPPER_SLOT_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer(n) {
              var t;
              t = n;
              var hold = function(...rest) {
                var t;
                t = rest[0];
                return function() {
                  return t;
                };
              };
              return [hold, function() {
                return t;
              }];
            }
            """
        ))

    DEFAULT_READING_A_SLOT_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              switch (a + b) {
                case 10:
                  scope.v = 3;
                  a = 40, b = 0;
                  break;
                case 40:
                  return done = true, function (f = () => scope.v) { var scope; return f(); };
                  break;
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_parameter_default_does_not_see_the_body_it_belongs_to(self):
        """
        The default `() => scope.v` is evaluated in the scope of the parameter list, where the
        body's `var scope` does not exist, so it reads the generator's scope object.
        """
        result = self._run_transformer(self.DEFAULT_READING_A_SLOT_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var v;
              v = 3;
              return function(f = () => v) {
                var scope;
                return f();
              };
            }
            """
        ))

    VAR_IN_A_BLOCK_WITH_A_LET_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.local = 7;
                    a = 40, b = 0;
                    break;
                  case 40:
                    { let t = 0; var local = 3; }
                    return done = true, local + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BLOCK_FUNCTION_WITH_A_HOME_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.f = 0;
                    NS.r = 0;
                    scope.RV = scope.NS;
                    a = 40, b = 0;
                    break;
                  case 40:
                    if (a > 0) {
                      function f() { return "fn"; }
                      r = f();
                    }
                    return done = true, r;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    FUNCTION_DECLARATION_WITH_A_HOME_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.member = 7;
                    function member() { return 1; }
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, typeof member;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    PAYLOAD_DECLARING_THE_ARGUMENT_HOLDER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    var args = [7];
                    return done = true, args[0];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_payload_declaring_the_argument_holder_reads_its_declaration(self):
        result = self._run_transformer(
            self.PAYLOAD_DECLARING_THE_ARGUMENT_HOLDER_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var args = [7];
              return args[0];
            }
            """
        ))

    FLAG_AND_RESULT_OF_AN_OUTER_FUNCTION_CFF = inspect.cleandoc(
        """
        function outer() {
          var result, done;
          function inner() {
            function* gen(a, b, scope = {}, args) {
              while (a + b !== 100) {
                with (scope) {
                  switch (a + b) {
                    case 10:
                      return done = true, 5;
                      break;
                  }
                }
              }
            }
            done = void 0;
            result = gen(5, 5)["next"]()["value"];
            if (done) { return result; }
          }
          inner();
          return [result, done];
        }
        """
    )

    GENERATOR_CALLED_BEFORE_ITS_DECLARATION_CFF = inspect.cleandoc(
        """
        function wrapper() {
          var other = function () { return gen(40, 0)["next"]()["value"]; };
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, other;
                    break;
                  case 40:
                    return done = true, 7;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    RESULT_STORED_ON_AN_OBJECT_CFF = inspect.cleandoc(
        """
        function wrapper(box) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, 42;
                    break;
                }
              }
            }
          }
          var done;
          box.result = gen(5, 5)["next"]()["value"];
        }
        """
    )

    RETURNED_CALL_IN_A_BLOCK_CFF = inspect.cleandoc(
        """
        function wrapper(c) {
          if (c) {
            function* gen(a, b, scope = {}, args) {
              while (a + b !== 100) {
                with (scope) {
                  switch (a + b) {
                    case 10:
                      console.log("ran");
                      a = 90, b = 10;
                      break;
                  }
                }
              }
            }
            return gen(5, 5)["next"]()["value"];
          }
          return "after";
        }
        """
    )

    CALL_IN_A_LOOP_CFF = inspect.cleandoc(
        """
        function wrapper() {
          var seen = [];
          for (var i = 0; i < 3; i++) {
            function* gen(a, b, scope = {}, args) {
              while (a + b !== 100) {
                with (scope) {
                  switch (a + b) {
                    case 10:
                      scope.t = (scope.t || 0) + 1;
                      seen.push(scope.t);
                      a = 90, b = 10;
                      break;
                  }
                }
              }
            }
            gen(5, 5)["next"]()["value"];
          }
          return seen.join(",");
        }
        """
    )

    WRAPPER_MAKING_ITSELF_AGAIN_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.w = function(...r) { return gen(20, 30, scope, r)["next"]()["value"]; };
                    return done = true, scope.w;
                    break;
                  case 50:
                    scope.w = function(...r) { return gen(20, 30, scope, r)["next"]()["value"]; };
                    return done = true, 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    COPIED_SLOT_CHANGED_BY_THE_CREATOR_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = 1;
                    scope.w = function(...rest) {
                      return gen(20, 30, {t: scope.t}, rest)["next"]()["value"];
                    };
                    scope.f = w();
                    scope.t = 2;
                    return done = true, f;
                    break;
                  case 50:
                    return done = true, function () { return t; };
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    HANDED_ON_NAMESPACE_REBOUND_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.keep = function(...rest) {
                      return gen(20, 30, {NS: scope.NS, Loc: {}}, rest)["next"]()["value"];
                    };
                    return done = true, [NS.keep, function () { return typeof NS; }];
                    break;
                  case 50:
                    NS = 5;
                    return done = true, 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ARGUMENT_STORE_IN_A_LOOP_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    NS.count = function(...rest) {
                      return gen(20, 30, {NS: scope.NS, Loc: {}}, rest)["next"]()["value"];
                    };
                    return done = true, NS.count;
                    break;
                  case 50:
                    Loc.n = 0;
                    a = 55, b = 0;
                    break;
                  case 55:
                    [Loc.first, ...Loc.others] = args;
                    a = 60, b = 0;
                    break;
                  case 60:
                    Loc.others.push(0);
                    Loc.n = Loc.n + 1;
                    if (Loc.n < 3) {
                      a = 55, b = 0;
                    } else {
                      a = 70, b = 0;
                    }
                    break;
                  case 70:
                    return done = true, Loc.first + ":" + Loc.others.length;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    FLAG_RAISED_BY_A_WRAPPER_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.w = function(...rest) {
                      return gen(40, 0, {}, rest)["next"]()["value"];
                    };
                    scope.v = w();
                    a = 90, b = 10;
                    break;
                  case 40:
                    return done = true, 42;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
          return "after";
        }
        """
    )

    RECEIVER_AND_ARGUMENTS_OF_THE_GENERATOR_CFF = inspect.cleandoc(
        """
        var host = { method: function () {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, [this === host, arguments.length];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        } };
        """
    )

    YIELD_IN_A_CASE_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.x = yield 1;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, x;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
          return "fell";
        }
        """
    )

    SLOT_NAMED_LIKE_A_PARAMETER_CFF = inspect.cleandoc(
        """
        function wrapper(t) {
          var get = function () { return t; };
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.t = 5;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, [get, t];
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    SLOT_UNDER_A_STRING_KEY_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope["a-b"] = 2;
                    a = 40, b = 0;
                    break;
                  case 40:
                    return done = true, scope["a-b"] + 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    STRICT_BLOCK_FUNCTION_CFF = inspect.cleandoc(
        """
        'use strict';
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              switch (a + b) {
                case 10:
                  scope.peek = function () { { function a() {} } return a; };
                  a = 40, b = 0;
                  break;
                case 40:
                  return done = true, scope.peek();
                  break;
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_CHANGED_AFTER_THE_WRAPPER_RAN_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case -10:
                    scope.R = {};
                    scope.R.k = -10;
                    a = 20, b = 10;
                    break;
                  case 30:
                    var wrapper = function(...rest) {
                      return gen(25, 10, scope, rest)["next"]()["value"];
                    };
                    a = 40, b = 10;
                    break;
                  case 50:
                    scope.v = wrapper(1, 2);
                    scope.R.k = 100;
                    a = 30, b = 30;
                    break;
                  case 60:
                    return done = true, v;
                  case scope.R.k + 45:
                    return done = true, "predicate";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, -15)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    CASE_TEST_THE_MACHINE_CANNOT_READ_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.u = Date.now() > 0 ? 35 : 0;
                    a = 20, b = 15;
                    break;
                  case scope.u:
                    return done = true, "predicate";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BODY_RUNNING_ON_INTO_THE_NEXT_CASE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    console.log("first");
                    a = 20, b = 10;
                  case 20:
                    console.log("runs on");
                    a = 50, b = 50;
                    break;
                  case 30:
                    return done = true, "second";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    STATE_READ_BETWEEN_TRANSITION_STORES_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    a = 20, console.log(a), b = 15;
                    break;
                  case 35:
                    return done = true, "end";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    STATE_STORED_BEFORE_THE_PAYLOAD_READS_IT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    a = 20;
                    console.log(a);
                    b = 15;
                    break;
                  case 35:
                    return done = true, "end";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BRANCH_STORING_A_STATE_IT_CANNOT_READ_CFF = inspect.cleandoc(
        """
        function outer(flag) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (flag) {
                      a = Date.now() > 0 ? 30 : 0;
                      b += 5;
                    } else {
                      b += 20;
                    }
                    break;
                  case 15:
                    return done = true, "the entry value of a";
                  case 40:
                    return done = true, "the stored value of a";
                  case 30:
                    return done = true, "the other branch";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BRANCH_READING_A_STATE_IT_STORED_CFF = inspect.cleandoc(
        """
        function outer(flag) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (flag) {
                      a = 20;
                      console.log(a);
                      b += 5;
                    } else {
                      b += 20;
                    }
                    break;
                  case 30:
                    return done = true, "end";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    LAST_BODY_WITHOUT_A_BREAK_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 30:
                    return done = true, "last";
                  case 10:
                    console.log("first");
                    a = 20, b = 10;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_WITH_A_SETTER_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {set k(value) { console.log("set", value); }}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.k = 25;
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the stored value";
                  default:
                    return done = true, "the setter kept nothing";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_WITH_A_PROTOTYPE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {__proto__: {k: 25}}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case scope.NS.k + 10:
                    return done = true, "the inherited value";
                  case 10:
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_namespace_holding_more_than_data_is_declined(self):
        """
        A namespace whose literal defines a setter, and one whose literal gives it a prototype: a
        store to a member runs code, and a read finds what the prototype holds, so neither member
        holds what the stores the recovery reads put there. Each generator is left as it is.
        """
        for source in (self.NAMESPACE_WITH_A_SETTER_CFF, self.NAMESPACE_WITH_A_PROTOTYPE_CFF):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    FALSE_BESIDE_A_ZERO_DISCRIMINANT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    a = 5, b = -5;
                    break;
                  case a != 5 && a - 10:
                    return done = true, "the guarded case";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_case_test_making_false_does_not_match_a_zero(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return "default";
                }
                """
            ),
            self._run_transformer(
                self.FALSE_BESIDE_A_ZERO_DISCRIMINANT_CFF, JsGeneratorCFFUnflattening
            ),
        )

    PREDICATE_CASE_BEFORE_A_LITERAL_CASE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    a = 20, b = 15;
                    break;
                  case a + 15:
                    return done = true, "the first match";
                  case 35:
                    return done = true, "the literal match";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_first_matching_case_in_source_order_runs(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return "the first match";
                }
                """
            ),
            self._run_transformer(
                self.PREDICATE_CASE_BEFORE_A_LITERAL_CASE_CFF, JsGeneratorCFFUnflattening
            ),
        )

    ROUTING_SLOT_GIVEN_BY_THE_NAMESPACE_LITERAL_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {k: 25}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the literal value";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_routing_slot_holds_what_its_namespace_literal_gives_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return "the literal value";
                }
                """
            ),
            self._run_transformer(
                self.ROUTING_SLOT_GIVEN_BY_THE_NAMESPACE_LITERAL_CFF, JsGeneratorCFFUnflattening
            ),
        )

    ROUTING_SLOTS_STORED_BY_DESTRUCTURING_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case scope.NS.p + 20:
                    return done = true, "routed by p";
                  case 10:
                    [scope.NS.p, scope.NS.q] = [15, -40];
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case scope.NS.q + 75:
                    return done = true, "routed by q";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_routing_slots_stored_by_destructuring_route_and_are_dropped(self):
        """
        The first case test reads `p` before the entry block stores it, which makes `NaN` and does
        not match; afterwards `p` is `15` and routes to its case. Only case tests read `p` and `q`,
        so their store goes with them.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return "routed by p";
                }
                """
            ),
            self._run_transformer(
                self.ROUTING_SLOTS_STORED_BY_DESTRUCTURING_CFF, JsGeneratorCFFUnflattening
            ),
        )

    ROUTING_SLOT_READ_UNDER_A_COMPUTED_KEY_CFF = inspect.cleandoc(
        """
        function outer(name) {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.k = 25;
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, scope.NS[name];
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_routing_store_stays_for_a_read_under_a_computed_key(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer(name) {
                  var NS = {};
                  NS.k = 25;
                  return NS[name];
                }
                """
            ),
            self._run_transformer(
                self.ROUTING_SLOT_READ_UNDER_A_COMPUTED_KEY_CFF, JsGeneratorCFFUnflattening
            ),
        )

    MATCHED_CASE_THE_RECOVERY_CANNOT_READ_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    a = 20, b = 15;
                    break;
                  case 35:
                    console.log("runs on");
                  case 36:
                    return done = true, "after running on";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_READ_OF_A_NAME_NO_SLOT_HOLDS_YET_CFF = inspect.cleandoc(
        """
        function outer() {
          var k = 5;
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case k + 30:
                    scope.NS.k = 1;
                    return done = true, "the outer k";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_SLOT_STORED_IN_A_LOOP_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 3;
                    scope.j = 3;
                    for (var t = 0; t < 2; t++) {
                      scope.j = scope.i;
                      scope.i = 7;
                    }
                    a = 20, b = 15;
                    break;
                  case scope.j + 28:
                    return done = true, "the value of the last iteration";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    WRAPPER_CALLED_BEFORE_THE_ROUTING_STORE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    scope.NS.early = function(...rest) {
                      return gen(20, 15, {NS: scope.NS}, rest)["next"]()["value"];
                    };
                    scope.v = early();
                    a = 20, b = 10;
                    break;
                  case 30:
                    scope.NS.k = 25;
                    a = 40, b = 10;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the stored value";
                  case 50:
                    return done = true, v;
                  default:
                    return done = true, "not stored yet";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_SLOT_WRITTEN_BARE_UNDER_THE_REDIRECT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.k = 25;
                    scope.RV = scope.NS;
                    a = 20, b = 10;
                    break;
                  case 30:
                    k = 7;
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the entry value";
                  default:
                    return done = true, "the bare store";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BLOCK_REACHED_WITH_TWO_STATES_CFF = inspect.cleandoc(
        """
        function outer(flag) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (flag) {
                      a = 1, b = 2;
                    } else {
                      a = 2, b = 1;
                    }
                    break;
                  case 3:
                    a += b;
                    break;
                  case 5:
                    return done = true, "five";
                  case 4:
                    return done = true, "four";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_routing_the_obfuscator_does_not_write_is_declined(self):
        """
        The obfuscator stores constants in its routing slots once, before anything else in the
        block the machine starts in, reads them only in case tests, and gives every block one
        state. Each generator here breaks that, and is left as it is: the matched case runs on into
        the next, a case test ahead of the match reads a name the machine does not know or a slot
        stored from an expression it cannot evaluate, a routing slot is stored in a loop, stored
        again after a wrapper ran, stored after a wrapper was called, written bare through the
        `with` statement, written by a function the leading stores store, or written under a key
        only known at runtime, the object holding it is replaced behind its store or in a later
        block or given another prototype, its store runs a setter a prototype holds, and a block is
        reached with two states, one pair of them told apart only by the sign of a zero.
        """
        for source in (
            self.MATCHED_CASE_THE_RECOVERY_CANNOT_READ_CFF,
            self.ROUTING_READ_OF_A_NAME_NO_SLOT_HOLDS_YET_CFF,
            self.CASE_TEST_THE_MACHINE_CANNOT_READ_CFF,
            self.ROUTING_SLOT_STORED_IN_A_LOOP_CFF,
            self.ROUTING_CHANGED_AFTER_THE_WRAPPER_RAN_CFF,
            self.WRAPPER_CALLED_BEFORE_THE_ROUTING_STORE_CFF,
            self.ROUTING_SLOT_WRITTEN_BARE_UNDER_THE_REDIRECT_CFF,
            self.ROUTING_SLOT_WRITTEN_BY_A_STORED_FUNCTION_CFF,
            self.ROUTING_SLOT_WRITTEN_UNDER_A_COMPUTED_KEY_CFF,
            self.NAMESPACE_REPLACED_BEHIND_THE_ROUTING_STORE_CFF,
            self.NAMESPACE_REPLACED_AFTER_THE_ROUTING_STORE_CFF,
            self.NAMESPACE_PROTOTYPE_REPLACED_CFF,
            self.ROUTING_STORE_THROUGH_AN_INHERITED_SETTER_CFF,
            self.BLOCK_REACHED_WITH_TWO_STATES_CFF,
            self.NEGATIVE_ZERO_STATE_CFF,
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    def test_generator_cff_recovery_declines_a_body_the_obfuscator_does_not_write(self):
        """
        A body that runs on into the next case, a state variable stored and read before the
        transition that ends the body, a branch storing a state variable before its transition,
        from an expression the machine cannot evaluate or where the branch reads it back, a
        condition storing a state variable, a class taking a state variable's name, a payload
        leaving the switch by a `break` of its own, a function declared behind a `return`, and a
        variable declared in a body no run reaches: the obfuscator ends every body in one
        transition and declares nothing in it, and each generator is left as it is.
        """
        for source in (
            self.BODY_RUNNING_ON_INTO_THE_NEXT_CASE_CFF,
            self.STATE_READ_BETWEEN_TRANSITION_STORES_CFF,
            self.STATE_STORED_BEFORE_THE_PAYLOAD_READS_IT_CFF,
            self.BRANCH_STORING_A_STATE_IT_CANNOT_READ_CFF,
            self.BRANCH_READING_A_STATE_IT_STORED_CFF,
            self.CONDITION_STORING_A_STATE_VARIABLE_CFF,
            self.CLASS_NAMED_LIKE_A_STATE_VARIABLE_CFF,
            self.BREAK_OUT_OF_A_PAYLOAD_CFF,
            self.HELPER_DECLARED_BEHIND_THE_RETURN_CFF,
            self.VAR_DECLARED_IN_A_BODY_NO_RUN_REACHES_CFF,
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    def test_generator_cff_bare_name_every_object_inherits_is_declined(self):
        """
        The obfuscator rewrites only the variables of the function it flattens; a call of any other
        name stays bare inside its `with` statement, which finds `toString` on the object it reads,
        as every object inherits it, before the function or global of that name the program means.
        """
        for source in (
            self.PAYLOAD_NAME_THE_SCOPE_OBJECT_INHERITS_CFF,
            self.GLOBAL_CALLED_BY_A_NAME_THE_SCOPE_OBJECT_INHERITS_CFF,
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    def test_generator_cff_last_body_needs_no_break(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  console.log("first");
                  return "last";
                }
                """
            ),
            self._run_transformer(self.LAST_BODY_WITHOUT_A_BREAK_CFF, JsGeneratorCFFUnflattening),
        )

    def test_generator_cff_body_that_leaves_the_state_as_it_is_is_declined(self):
        """
        The first body stores no state and leaves the switch, so the machine dispatches the same
        state again, forever; the generator never returns and is left as it is.
        """
        source = inspect.cleandoc(
            """
            function outer() {
              function* gen(a, b, scope = {}, args) {
                while (a + b !== 100) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        console.log("again");
                        break;
                      case 20:
                        return done = true, "never";
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            """
        )
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsGeneratorCFFUnflattening),
        )

    def test_generator_cff_recovery_declines_what_its_new_home_would_change(self):
        """
        A flag and a result some other function reads, a generator called from outside its
        scaffolding, a result stored on an object, a returned call inside a block, a call inside a
        loop, a key a wrapper copies from its creator that the creator then changes, a namespace a
        wrapper hands on and rebinds, a namespace a wrapper hands on under a name a parameter binds
        between it and its creator, a flag a wrapper raises before code behind the guard, a
        generator reading its own receiver and arguments or suspending, a slot named like a
        parameter the function around the call reads, a slot under a key no declaration can bind,
        and a block function in strict code: the recovered code would mean something else where it
        lands, and each generator is left as it is.
        """
        for source in (
            self.FLAG_AND_RESULT_OF_AN_OUTER_FUNCTION_CFF,
            self.GENERATOR_CALLED_BEFORE_ITS_DECLARATION_CFF,
            self.RESULT_STORED_ON_AN_OBJECT_CFF,
            self.RETURNED_CALL_IN_A_BLOCK_CFF,
            self.CALL_IN_A_LOOP_CFF,
            self.COPIED_SLOT_CHANGED_BY_THE_CREATOR_CFF,
            self.HANDED_ON_NAMESPACE_REBOUND_CFF,
            self.HANDED_ON_NAMESPACE_BOUND_BY_A_PARAMETER_CFF,
            self.FLAG_RAISED_BY_A_WRAPPER_CFF,
            self.RECEIVER_AND_ARGUMENTS_OF_THE_GENERATOR_CFF,
            self.YIELD_IN_A_CASE_CFF,
            self.SLOT_NAMED_LIKE_A_PARAMETER_CFF,
            self.SLOT_UNDER_A_STRING_KEY_CFF,
            self.STRICT_BLOCK_FUNCTION_CFF,
        ):
            with self.subTest(source):
                self.assertEqual(
                    self._run_transformers(source),
                    self._run_transformer(source, JsGeneratorCFFUnflattening),
                )

    def test_generator_cff_wrapper_making_itself_again_is_declined_in_time(self):
        """
        The wrapper's run makes the same wrapper again, so recovering every wrapper the recovered
        code holds never ends. The recovery has to give up instead; a run that does not end within
        a minute fails here rather than hanging the suite.
        """
        source = self.WRAPPER_MAKING_ITSELF_AGAIN_CFF
        outcome: list[str] = []

        def recover():
            outcome.append(self._run_transformer(source, JsGeneratorCFFUnflattening))

        worker = threading.Thread(target=recover, daemon=True)
        worker.start()
        worker.join(60)
        self.assertEqual(outcome, [self._run_transformers(source)])

    def test_generator_cff_recovery_survives_a_deep_expression_beside_the_call(self):
        """
        The checks that ask whether the scaffolding is private read the whole function around the
        call, which holds a chain of two thousand additions here; the recovery still goes through
        under the recursion depth the unit runs with.
        """
        chain = ' + '.join(['q'] * 2000)
        source = inspect.cleandoc(
            F"""
            function wrapper(q) {{
              var s = {chain};
              function* gen(a, b, scope = {{}}, args) {{
                while (a + b !== 100) {{
                  with (scope) {{
                    switch (a + b) {{
                      case 10:
                        return done = true, s;
                        break;
                    }}
                  }}
                }}
              }}
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) {{ return result; }}
            }}
            """
        )
        with RecursionDepth(TREE_RECURSION_DEPTH):
            result = self._run_transformer(source, JsGeneratorCFFUnflattening)
        self.assertNotIn('function*', result)

    NAMESPACE_REPLACED_AFTER_THE_ROUTING_STORE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    [scope.NS.k] = [25];
                    scope.RV = scope.NS;
                    a = 20, b = 10;
                    break;
                  case 30:
                    scope.NS = {k: 7};
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the value of the routing store";
                  default:
                    return done = true, "the value of the new namespace";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_REPLACED_BEHIND_THE_ROUTING_STORE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    [scope.NS.k] = [25];
                    scope.NS = {};
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the value of the routing store";
                  default:
                    return done = true, "no value";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_SLOT_WRITTEN_BY_A_STORED_FUNCTION_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.bump = function () { scope.NS.k = 99; };
                    [scope.NS.k] = [25];
                    a = 20, b = 10;
                    break;
                  case 30:
                    scope.NS.bump();
                    a = 40, b = 10;
                    break;
                  case scope.NS.k + 25:
                    return done = true, "the value of the routing store";
                  default:
                    return done = true, "the value the function stored";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_SLOT_WRITTEN_UNDER_A_COMPUTED_KEY_CFF = inspect.cleandoc(
        """
        function outer(key) {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    [scope.NS.k] = [25];
                    scope.NS[key] = 7;
                    a = 20, b = 15;
                    break;
                  case scope.NS.k + 10:
                    return done = true, "the value of the routing store";
                  default:
                    return done = true, "the value stored under the key";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_PROTOTYPE_REPLACED_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case scope.NS.k + 20:
                    return done = true, "the value of the prototype";
                  case 10:
                    scope.NS.__proto__ = {k: 15};
                    a = 20, b = 15;
                    break;
                  default:
                    return done = true, "no value";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_STORE_THROUGH_AN_INHERITED_SETTER_CFF = inspect.cleandoc(
        """
        Object.defineProperty(Object.prototype, "p", {
          set: function (value) {},
          get: function () { return 99; },
          configurable: true,
        });
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    [scope.NS.p] = [15];
                    a = 20, b = 15;
                    break;
                  case scope.NS.p + 20:
                    return done = true, "the value of the store";
                  default:
                    return done = true, "the value of the getter";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NEGATIVE_ZERO_STATE_CFF = inspect.cleandoc(
        """
        function outer(flag) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (flag) {
                      a = -0, b = 7;
                    } else {
                      a = 0, b = 7;
                    }
                    break;
                  case 7:
                    return done = true, 1 / a;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    CONDITION_STORING_A_STATE_VARIABLE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if ((a = 7) > 3) {
                      b += 1;
                    } else {
                      b += 2;
                    }
                    break;
                  case 11:
                    return done = true, "a is still 5";
                  case 13:
                    return done = true, "a became 7";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    CLASS_NAMED_LIKE_A_STATE_VARIABLE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    class a {}
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, "the state variable changed";
                  case 20:
                    return done = true, "the class took the store";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    BREAK_OUT_OF_A_PAYLOAD_CFF = inspect.cleandoc(
        """
        function outer() {
          var count = 0;
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    console.log("ten");
                    if (count++ === 0) break;
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, count;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    HANDED_ON_NAMESPACE_BOUND_BY_A_PARAMETER_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {MAIN: {}}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    [scope.MAIN.p] = [5];
                    scope.MAIN.mk = function (MAIN) {
                      return function (...r) {
                        return gen(40, 0, {MAIN: MAIN}, r)["next"]()["value"];
                      };
                    };
                    a = 20, b = 30;
                    break;
                  case scope.MAIN.p + 35:
                    return done = true, "p is five";
                  case 40:
                    return done = true, "p is not five";
                  case 50:
                    return done = true, scope.MAIN.mk({p: 100})();
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ENTRY_STATE_AT_THE_END_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 100:
                    return done = true, "the loop ran";
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(50, 50)["next"]()["value"];
          if (done) { return result; }
          return "the loop never ran";
        }
        """
    )

    NAMESPACE_READ_AS_A_WHOLE_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case scope.NS.k + 10:
                    return done = true, JSON.stringify(scope.NS);
                  case 10:
                    [scope.NS.k] = [25];
                    a = 20, b = 15;
                    break;
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    DESTRUCTURING_INTO_A_REST_ELEMENT_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    [scope.NS.p, ...scope.NS.r] = [1, 2];
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, scope.NS.r;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    FRACTIONAL_STATES_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, c, scope = {}, args) {
            while (a + b + c !== 100) {
              with (scope) {
                switch (a + b + c) {
                  case 0.6:
                    return done = true, "the sum rounded once";
                  case 0.6000000000000001:
                    return done = true, "the sum rounded at every step";
                }
              }
            }
          }
          var done;
          var result = gen(0.1, 0.2, 0.3)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    ROUTING_BESIDE_AN_OBJECT_POLYFILL_CFF = inspect.cleandoc(
        """
        Object.assign = Object.assign || function (target) { return target; };
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case scope.NS.p + 20:
                    return done = true, "routed by p";
                  case 10:
                    [scope.NS.p] = [15];
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  default:
                    return done = true, "default";
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    WRAPPER_MADE_IN_A_WRAPPER_PARAMETER_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {q: 9}}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.NS.w1 = function (x = scope.NS.w2 = function (...r) {
                      return gen(30, 0, {NS: scope.NS}, r)["next"]()["value"];
                    }, ...rest) {
                      return gen(20, 0, {NS: {q: 3}}, rest)["next"]()["value"];
                    };
                    a = 40, b = 10;
                    break;
                  case 20:
                    return done = true, "w1 ran";
                  case scope.NS.q + 21:
                    return done = true, "q is nine";
                  case 30:
                    return done = true, "q is not nine";
                  case 50:
                    return done = true, [scope.NS.w1(), scope.NS.w2()];
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    NAMESPACE_WITH_A_PROTO_METHOD_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {__proto__() { return "an own method"; }}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, scope.NS.__proto__();
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    CONDITION_OF_BRANCHES_TO_ONE_BLOCK_CFF = inspect.cleandoc(
        """
        function outer(list) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    if (list.shift()) {
                      a = 20, b = 15;
                    } else {
                      a = 20, b = 15;
                    }
                    break;
                  case 35:
                    return done = true, list.length;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_machine_starting_at_its_end_state_is_left_as_it_is(self):
        source = self.ENTRY_STATE_AT_THE_END_CFF
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsGeneratorCFFUnflattening),
        )

    def test_generator_cff_namespace_used_whole_keeps_its_routing_store(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  var NS = {};
                  [NS.k] = [25];
                  return JSON.stringify(NS);
                }
                """
            ),
            self._run_transformer(self.NAMESPACE_READ_AS_A_WHOLE_CFF, JsGeneratorCFFUnflattening),
        )

    def test_generator_cff_destructuring_into_a_rest_element_stays_whole(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  var NS = {};
                  [NS.p, ...NS.r] = [1, 2];
                  return NS.r;
                }
                """
            ),
            self._run_transformer(
                self.DESTRUCTURING_INTO_A_REST_ELEMENT_CFF, JsGeneratorCFFUnflattening
            ),
        )

    def test_generator_cff_state_variables_add_up_the_way_the_switch_adds_them(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  return "the sum rounded at every step";
                }
                """
            ),
            self._run_transformer(self.FRACTIONAL_STATES_CFF, JsGeneratorCFFUnflattening),
        )

    def test_generator_cff_routing_beside_a_patch_of_another_object_key_is_recovered(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                Object.assign = Object.assign || function(target) {
                  return target;
                };
                function outer() {
                  return "routed by p";
                }
                """
            ),
            self._run_transformer(
                self.ROUTING_BESIDE_AN_OBJECT_POLYFILL_CFF, JsGeneratorCFFUnflattening
            ),
        )

    def test_generator_cff_wrapper_made_in_a_wrapper_parameter_reads_the_run_around_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer() {
                  var NS = { q: 9 };
                  NS.w1 = function(x = NS.w2 = function(...r) {
                    return "q is nine";
                  }, ...rest) {
                    return "w1 ran";
                  };
                  return [NS.w1(), NS.w2()];
                }
                """
            ),
            self._run_transformer(
                self.WRAPPER_MADE_IN_A_WRAPPER_PARAMETER_CFF, JsGeneratorCFFUnflattening
            ),
        )

    def test_generator_cff_namespace_method_named_proto_holds_data(self):
        self.assertNotIn(
            'function*',
            self._run_transformer(
                self.NAMESPACE_WITH_A_PROTO_METHOD_CFF, JsGeneratorCFFUnflattening
            ),
        )

    def test_generator_cff_condition_of_branches_to_one_block_is_still_evaluated(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer(list) {
                  list.shift();
                  return list.length;
                }
                """
            ),
            self._run_transformer(
                self.CONDITION_OF_BRANCHES_TO_ONE_BLOCK_CFF, JsGeneratorCFFUnflattening
            ),
        )

    HELPER_DECLARED_BEHIND_THE_RETURN_CFF = inspect.cleandoc(
        """
        function outer(n) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    console.log("start");
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, helper(n);
                    function helper(k) { return k * 2; }
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    VAR_DECLARED_IN_A_BODY_NO_RUN_REACHES_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    y = 3;
                    return done = true, typeof globalThis.y;
                  case 99:
                    var y;
                    a = 1;
                    break;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    CONDITION_OF_BRANCHES_TO_ONE_BLOCK_IN_A_LOOP_CFF = inspect.cleandoc(
        """
        function outer(list) {
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    scope.i = 0;
                    a = 20, b = 0;
                    break;
                  case 20:
                    if (scope.i < 3) {
                      a = 20, b = 10;
                    } else {
                      a = 50, b = 0;
                    }
                    break;
                  case 30:
                    if (list.shift()) {
                      a = 20, b = 20;
                    } else {
                      a = 20, b = 20;
                    }
                    break;
                  case 40:
                    scope.i = scope.i + 1;
                    a = 20, b = 0;
                    break;
                  case 50:
                    return done = true, list.length;
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    PAYLOAD_NAME_THE_SCOPE_OBJECT_INHERITS_CFF = inspect.cleandoc(
        """
        function outer() {
          var toString = function () { return "outer"; };
          function* gen(a, b, scope = {}, args) {
            while (a + b !== 100) {
              with (scope) {
                switch (a + b) {
                  case 10:
                    return done = true, toString();
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    GLOBAL_CALLED_BY_A_NAME_THE_SCOPE_OBJECT_INHERITS_CFF = inspect.cleandoc(
        """
        function outer() {
          function* gen(a, b, scope = {NS: {}}, args) {
            while (a + b !== 100) {
              with (scope.RV || scope) {
                switch (a + b) {
                  case 10:
                    scope.RV = scope.NS;
                    a = 20, b = 15;
                    break;
                  case 35:
                    return done = true, toString();
                }
              }
            }
          }
          var done;
          var result = gen(5, 5)["next"]()["value"];
          if (done) { return result; }
        }
        """
    )

    def test_generator_cff_condition_of_branches_to_one_block_in_a_loop_runs_each_turn(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function outer(list) {
                  var i;
                  i = 0;
                  while (i < 3) {
                    list.shift();
                    i = i + 1;
                  }
                  return list.length;
                }
                """
            ),
            self._run_transformer(
                self.CONDITION_OF_BRANCHES_TO_ONE_BLOCK_IN_A_LOOP_CFF, JsGeneratorCFFUnflattening
            ),
        )

    def test_generator_cff_declined_recovery_leaves_every_node_under_its_parent(self):
        source = inspect.cleandoc(
            """
            function outer() {
              function* gen(a, b, scope = {}, args) {
                while (a + b !== 100) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        console.log("head"), a = 20, b = 15;
                        break;
                      case 35:
                        return done = true, function () { return a; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            """
        )
        ast = JsParser(source).parse()
        JsGeneratorCFFUnflattening().visit(ast)
        detached = [
            child for node in ast.walk() for child in node.children() if child.parent is not node
        ]
        self.assertIn('function*', JsSynthesizer().convert(ast))
        self.assertEqual([], detached)


#: The statements that run each fixture of `TestGeneratorCFFUnflattening` and print what it did,
#: appended to the fixture and to its recovery alike. A fixture that already prints on its own
#: needs none; every other one is called with arguments that reach the paths its machine recovers,
#: and a name it reads from outside is given a value the recovery could lose.
ENTRY_POINTS = {
    'FIZZBUZZ_CFF': '',
    'WITH_DISSOLUTION_CFF': 'console.log(wrapper() === globalThis);',
    'SHARED_WRAPPER_CFF': 'console.log(wrapper());',
    'GUARDED_PREDICATE_CFF': 'console.log(wrapper());',
    'NESTED_WRAPPER_ARG_REBIND_CFF': 'console.log(outer()(7), outer()(1, 2));',
    'REDIRECT_VAR_CFF': 'console.log(wrapper(), y);',
    'COMPUTED_REDIRECT_CFF': 'var args = "a", val = "v"; console.log(wrapper(), data);',
    'LOOPING_CFF': 'console.log(wrapper());',
    'CONTINUE_IN_LOOP_CFF': 'console.log(wrapper());',
    'HEADER_PAYLOAD_CFF': 'console.log(wrapper());',
    'COMPUTED_MEMBER_CFF': 'console.log(wrapper());',
    'SEQUENCE_STATE_CFF': 'console.log(wrapper());',
    'NESTED_CONDITIONAL_CFF': 'console.log(wrapper());',
    'COMPUTED_ROUTING_CFF': 'console.log(wrapper());',
    'BOOKKEEPING_LEAK_CFF': 'console.log(wrapper());',
    'SHARED_INTERMEDIATE_CFF': 'console.log(wrapper());',
    'BARE_SCOPE_CONDITION_CFF': 'console.log(wrapper());',
    'MIXED_SEQUENCE_BRANCH_CFF': 'var x = 1; console.log(wrapper());',
    'FREE_NAMES_CFF': 'var y = 2; console.log(wrapper(), x);',
    'LABELED_CONTINUE_CFF': 'var i = 7; console.log(wrapper(), i);',
    'FREE_FORMS_CFF': (
        'var freeObj = { method: function () { console.log("m"); } };'
        ' function freeCall() { console.log("c"); }'
        ' var freeVal = "v";'
        ' console.log(wrapper(), freeVar);'
    ),
    'NAMESPACE_LOCAL_DEEP_CFF': 'var local = 1; console.log(wrapper());',
    'NAMESPACE_LOCAL_BARE_CFF': 'var member = 1; console.log(wrapper());',
    'NAMESPACE_LOCAL_DESTRUCTURING_CFF': 'var p = 1, q = 1; console.log(wrapper());',
    'SIBLING_NAMESPACE_HOME_CFF': 'var make = outer(); console.log(make(7), make(8, 9));',
    'AMBIGUOUS_NAMESPACE_HOME_CFF': 'var v = 1; console.log(outer());',
    'CATCH_PARAM_QUALIFY_CFF': 'var x = 1; console.log(outer());',
    'ARROW_PARAM_QUALIFY_CFF': 'var x = 1; console.log(outer());',
    'OBJECT_SHORTHAND_QUALIFY_CFF': 'var x = 1; console.log(JSON.stringify(outer()));',
    'COMPOUND_ASSIGNMENT_HOME_CFF': 'var c = 1; console.log(outer(0));',
    'PLAIN_PARAM_WRAPPER_CFF': 'console.log(outer()([1, 2]));',
    'WRAPPER_REST_FREE_REFERENCE_CFF': 'console.log(outer()(5), sink);',
    'WRAPPER_SHORTHAND_ARG_CFF': 'console.log(JSON.stringify(outer()(5, 6)));',
    'STATE_NAME_IN_PROPERTY_SLOTS_CFF': 'var i = 1; console.log(JSON.stringify(outer()));',
    'PER_CALL_NAMESPACE_CFF': (
        'var keep = outer(); var one = keep(1, 2), two = keep(3, 4); console.log(one(), two());'
    ),
    'PER_CALL_SCOPE_VARIABLE_CFF': (
        'var hold = outer(); var one = hold(1), two = hold(2); console.log(one(), two(), typeof t);'
    ),
    'ARGUMENT_STORE_WITH_REST_CFF': 'var count = outer(); console.log(count(1, 2, 3), count(4));',
    'SCOPE_NAME_REBOUND_CFF': 'console.log(outer());',
    'UNREADABLE_WRAPPER_SCOPE_CFF': 'function make() { return { k: 1 }; } console.log(outer()(5));',
    'STATE_READ_BY_A_CLOSURE_CFF': 'console.log(outer());',
    'MAIN_RUN_WRITES_ITS_ARGUMENTS_CFF': 'var args = "global"; console.log(outer(), args);',
    'ACCESSOR_SCOPE_DEFAULT_CFF': 'console.log(outer());',
    'NAMESPACE_INITIALIZER_WITH_AN_EFFECT_CFF': (
        'function note() { console.log("noted"); return 1; } console.log(outer()(5));'
    ),
    'WRAPPER_HANDING_ON_ANOTHER_ARGUMENT_CFF': 'console.log(outer()(5));',
    'GUARD_WITH_MORE_TO_DO_CFF': 'console.log(wrapper());',
    'UNGUARDED_RETURN_CFF': 'console.log(wrapper());',
    'GENERATOR_RETURN_WITHOUT_THE_FLAG_CFF': 'console.log(wrapper());',
    'RESULT_READ_AFTER_THE_GUARD_CFF': 'console.log(wrapper());',
    'FUNCTION_BETWEEN_GENERATOR_AND_CALL_CFF': 'console.log(wrapper());',
    'MAIN_SLOT_NAMED_LIKE_A_WRAPPER_SLOT_CFF': (
        'var one = outer(1), two = outer(2);'
        ' console.log(one[1](), two[1](), one[0](3)(), typeof t);'
    ),
    'DEFAULT_READING_A_SLOT_CFF': 'console.log(wrapper()());',
    'VAR_IN_A_BLOCK_WITH_A_LET_CFF': 'console.log(wrapper());',
    'BLOCK_FUNCTION_WITH_A_HOME_CFF': 'console.log(JSON.stringify(wrapper()));',
    'FUNCTION_DECLARATION_WITH_A_HOME_CFF': 'console.log(wrapper());',
    'PAYLOAD_DECLARING_THE_ARGUMENT_HOLDER_CFF': 'console.log(wrapper());',
    'FLAG_AND_RESULT_OF_AN_OUTER_FUNCTION_CFF': 'console.log(JSON.stringify(outer()));',
    'GENERATOR_CALLED_BEFORE_ITS_DECLARATION_CFF': 'console.log(wrapper()());',
    'RESULT_STORED_ON_AN_OBJECT_CFF': 'var box = {}; wrapper(box); console.log(box.result);',
    'RETURNED_CALL_IN_A_BLOCK_CFF': 'console.log(wrapper(true));',
    'CALL_IN_A_LOOP_CFF': 'console.log(wrapper());',
    'WRAPPER_MAKING_ITSELF_AGAIN_CFF': 'console.log(outer()());',
    'COPIED_SLOT_CHANGED_BY_THE_CREATOR_CFF': 'console.log(outer()());',
    'HANDED_ON_NAMESPACE_REBOUND_CFF': 'var r = outer(); r[0](); console.log(r[1]());',
    'ARGUMENT_STORE_IN_A_LOOP_CFF': 'var count = outer(); console.log(count(1, 2, 3), count(4));',
    'FLAG_RAISED_BY_A_WRAPPER_CFF': 'console.log(wrapper());',
    'RECEIVER_AND_ARGUMENTS_OF_THE_GENERATOR_CFF': (
        'console.log(JSON.stringify(host.method(1, 2, 3)));'
    ),
    'YIELD_IN_A_CASE_CFF': 'console.log(wrapper());',
    'SLOT_NAMED_LIKE_A_PARAMETER_CFF': 'var r = wrapper("param"); console.log(r[0](), r[1]);',
    'SLOT_UNDER_A_STRING_KEY_CFF': 'console.log(wrapper());',
    'STRICT_BLOCK_FUNCTION_CFF': 'console.log(outer());',
    'ROUTING_CHANGED_AFTER_THE_WRAPPER_RAN_CFF': 'console.log(outer());',
    'CASE_TEST_THE_MACHINE_CANNOT_READ_CFF': 'console.log(outer());',
    'BODY_RUNNING_ON_INTO_THE_NEXT_CASE_CFF': 'console.log(outer());',
    'STATE_READ_BETWEEN_TRANSITION_STORES_CFF': 'console.log(outer());',
    'STATE_STORED_BEFORE_THE_PAYLOAD_READS_IT_CFF': 'console.log(outer());',
    'BRANCH_STORING_A_STATE_IT_CANNOT_READ_CFF': 'console.log(outer(true), outer(false));',
    'BRANCH_READING_A_STATE_IT_STORED_CFF': 'console.log(outer(true), outer(false));',
    'LAST_BODY_WITHOUT_A_BREAK_CFF': 'console.log(outer());',
    'NAMESPACE_WITH_A_SETTER_CFF': 'console.log(outer());',
    'NAMESPACE_WITH_A_PROTOTYPE_CFF': 'console.log(outer());',
    'FALSE_BESIDE_A_ZERO_DISCRIMINANT_CFF': 'console.log(outer());',
    'PREDICATE_CASE_BEFORE_A_LITERAL_CASE_CFF': 'console.log(outer());',
    'ROUTING_SLOT_GIVEN_BY_THE_NAMESPACE_LITERAL_CFF': 'console.log(outer());',
    'ROUTING_SLOTS_STORED_BY_DESTRUCTURING_CFF': 'console.log(outer());',
    'ROUTING_SLOT_READ_UNDER_A_COMPUTED_KEY_CFF': 'console.log(outer("k"), outer("get"));',
    'MATCHED_CASE_THE_RECOVERY_CANNOT_READ_CFF': 'console.log(outer());',
    'ROUTING_READ_OF_A_NAME_NO_SLOT_HOLDS_YET_CFF': 'console.log(outer());',
    'ROUTING_SLOT_STORED_IN_A_LOOP_CFF': 'console.log(outer());',
    'WRAPPER_CALLED_BEFORE_THE_ROUTING_STORE_CFF': 'console.log(outer());',
    'ROUTING_SLOT_WRITTEN_BARE_UNDER_THE_REDIRECT_CFF': 'console.log(outer());',
    'BLOCK_REACHED_WITH_TWO_STATES_CFF': 'console.log(outer(true), outer(false));',
    'NAMESPACE_REPLACED_AFTER_THE_ROUTING_STORE_CFF': 'console.log(outer());',
    'NAMESPACE_REPLACED_BEHIND_THE_ROUTING_STORE_CFF': 'console.log(outer());',
    'ROUTING_SLOT_WRITTEN_BY_A_STORED_FUNCTION_CFF': 'console.log(outer());',
    'ROUTING_SLOT_WRITTEN_UNDER_A_COMPUTED_KEY_CFF': 'console.log(outer("k"), outer("x"));',
    'NAMESPACE_PROTOTYPE_REPLACED_CFF': 'console.log(outer());',
    'ROUTING_STORE_THROUGH_AN_INHERITED_SETTER_CFF': 'console.log(outer());',
    'NEGATIVE_ZERO_STATE_CFF': 'console.log(outer(true), outer(false));',
    'CONDITION_STORING_A_STATE_VARIABLE_CFF': 'console.log(outer());',
    'CLASS_NAMED_LIKE_A_STATE_VARIABLE_CFF': 'console.log(outer());',
    'BREAK_OUT_OF_A_PAYLOAD_CFF': 'console.log(outer());',
    'HANDED_ON_NAMESPACE_BOUND_BY_A_PARAMETER_CFF': 'console.log(outer());',
    'ENTRY_STATE_AT_THE_END_CFF': 'console.log(outer());',
    'NAMESPACE_READ_AS_A_WHOLE_CFF': 'console.log(outer());',
    'DESTRUCTURING_INTO_A_REST_ELEMENT_CFF': 'console.log(outer());',
    'FRACTIONAL_STATES_CFF': 'console.log(outer());',
    'ROUTING_BESIDE_AN_OBJECT_POLYFILL_CFF': 'console.log(outer());',
    'WRAPPER_MADE_IN_A_WRAPPER_PARAMETER_CFF': 'console.log(outer());',
    'NAMESPACE_WITH_A_PROTO_METHOD_CFF': 'console.log(outer());',
    'CONDITION_OF_BRANCHES_TO_ONE_BLOCK_CFF': 'console.log(outer([1, 2, 3]));',
    'HELPER_DECLARED_BEHIND_THE_RETURN_CFF': 'console.log(outer(4));',
    'VAR_DECLARED_IN_A_BODY_NO_RUN_REACHES_CFF': 'console.log(outer());',
    'CONDITION_OF_BRANCHES_TO_ONE_BLOCK_IN_A_LOOP_CFF': 'console.log(outer([1, 0, 1, 1]));',
    'PAYLOAD_NAME_THE_SCOPE_OBJECT_INHERITS_CFF': 'console.log(outer());',
    'GLOBAL_CALLED_BY_A_NAME_THE_SCOPE_OBJECT_INHERITS_CFF': 'console.log(outer());',
}

@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameForEachRecoveredFixture(TestJsDeobfuscator):

    def _fixtures(self):
        for name, value in vars(TestGeneratorCFFUnflattening).items():
            if isinstance(value, str) and 'function*' in value:
                yield name, value

    def _program(self, name: str) -> str:
        return F'{getattr(TestGeneratorCFFUnflattening, name)}\n{ENTRY_POINTS[name]}'

    def _programs(self):
        for name, _ in self._fixtures():
            yield name, self._program(name)

    def test_every_fixture_has_an_entry_point(self):
        self.assertEqual({name for name, _ in self._fixtures()}, set(ENTRY_POINTS))

    def test_each_fixture_recovered_alone_prints_what_it_printed(self):
        for name, program in self._programs():
            with self.subTest(name):
                recovered = self._run_transformer(program, JsGeneratorCFFUnflattening)
                self.assertEqual(behavior(program), behavior(recovered))

    def test_each_fixture_deobfuscated_prints_what_it_printed(self):
        for name, program in self._programs():
            with self.subTest(name):
                self.assertEqual(behavior(program), behavior(self._deobfuscate(program)))
