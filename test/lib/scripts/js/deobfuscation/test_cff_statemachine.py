from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.cff import JsGeneratorCFFUnflattening


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

    REDIRECT_QUALIFY_CFF = inspect.cleandoc(
        """
        function wrapper() {
          function* gen(a, b, c, scope = {NS: {}}, args) {
            while (a + b + c !== 200) {
              with (scope.RV || scope) {
                switch (a + b + c) {
                  case 30:
                    scope.Sub = {};
                    scope.RV = scope.NS;
                    a = 40, b = 50, c = 10;
                    break;
                  case 100:
                    Sub.arr = args;
                    scope.RV = scope.Sub;
                    a = 20, b = 30, c = 100;
                    break;
                  case 150:
                    return DR = true, scope.NS.extra + val;
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

    def test_generator_cff_redirect_qualification_levels(self):
        """
        A degenerate multi-level-redirect sample: bare `Sub` is used while the `with` redirect still
        points at `NS`, so `Sub` never resolves and the original throws a `ReferenceError`. The
        recovery keeps the genuinely free `val`/`extra`/`args` bare (they have no namespace-defining
        write) and recovers `Sub` from its `scope.Sub` writes, remaining an equivalent throwing
        program.
        """
        result = self._deobfuscate(self.REDIRECT_QUALIFY_CFF)
        self.assertEqual(result, inspect.cleandoc(
            """
            function wrapper() {
              var extra;
              var Sub;
              Sub = {};
              Sub.arr = args;
              return extra + val;
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
              data = args;
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
        self.assertEqual(
            inspect.cleandoc(
                """
                function wrapper() {
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
        shared generator, making it a structural namespace emitted as `var Sub = {}`. Verified
        equivalent to the original under Node: the recovered `outer()(7)` returns `7`, as does the
        original.
        """
        result = self._run_transformer(self.SIBLING_NAMESPACE_HOME_CFF, JsGeneratorCFFUnflattening)
        self.assertEqual(result, inspect.cleandoc(
            """
            function outer() {
              var NS = {};
              var Sub = {};
              NS.make = function(...rest) {
                Sub.slot = rest;
                return Sub.slot[0];
              };
              return NS.make;
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
