"""
The recovery of a machine of control-flow flattening that stands in a function whose code the
recovery of the machine around it wrote: the generator held by a variable, the flag a property of an
object the function makes for each call, and the return of `undefined` that ends the function behind
the guard. Each program below holds such a machine, written by hand in that shape, and each row says
what Node prints for it run as a CommonJS file; the deobfuscation prints the same. Where the recovery
takes a machine apart, the text it writes is pinned; where something outside the scaffolding may
reach the flag, the generator or the result, it leaves the machine as it is.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.cff import JsGeneratorCFFUnflattening
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


def recovered(source: str) -> str:
    ast = JsParser(source).parse()
    JsGeneratorCFFUnflattening().visit(ast)
    return JsSynthesizer().convert(ast)


def written(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


#: Programs holding a machine inside a function in the shape the recovery of the machine around it
#: writes, mapped to what Node prints for each run as a CommonJS file.
NESTED: dict[str, Program] = {
    'an inner machine as the recovery of the outer one leaves it': Program(
        a_program("""
            function outer(p_1) {
              var G, R;
              var NS = {};
              NS.p = p_1;
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (NS.p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                        if (a > 1000) { a = 0, b = 0; break; }
                      case 20:
                        return NS.flag = true, 'positive';
                      case 30:
                        console.log('other');
                        a = 0, b = 0;
                        break;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('other', 'positive undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag handed to a function': Program(
        a_program("""
            function look(o) { return JSON.stringify(o); }
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        console.log(look(NS));
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('{}', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag read under a computed key': Program(
        a_program("""
            function outer(p, key) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        console.log(NS[key]);
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1, 'flag'));
            """),
        prints('undefined', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the flag read after the guard': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 0, b = 0; break; }
                      case 20:
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              console.log('flag', NS.flag);
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('flag undefined', '1 undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag shared by every call': Program(
        a_program("""
            var NS = {};
            function outer(p) {
              var G, R;
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 0, b = 0; break; }
                      case 20:
                        outer(p - 1);
                        console.log('back', p);
                        a = 0, b = 0;
                        break;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return 'fell ' + p;
            }
            console.log(outer(1));
            """),
        prints('back 1', 'fell 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a name undefined bound in the function': Program(
        a_program("""
            function outer(p) {
              var undefined = 1;
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 0, b = 0; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('flagged undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the generator stored twice': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        G = null;
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the generator read by its own name in the code it runs': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        return NS.flag = true, typeof g + p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('function1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a wrapper in the inner machine calling it by its own name': Program(
        a_program("""
            function outer(p_1) {
              var G, R;
              var NS = {};
              NS.p = p_1;
              G = function* g(a, b, scope = { M: {} }, args) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        M.helper = function(...rest) {
                          return g(40, 10, { M: scope.M, L: {} }, rest)["next"]()["value"];
                        };
                        a = 15, b = 5;
                        break;
                      case 20:
                        return NS.flag = true, M.helper(NS.p) + M.helper(NS.p + 1);
                      case 50:
                        [L.x] = args;
                        a = 50, b = 10;
                        break;
                      case 60:
                        return L.x * 10;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('30'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a setter on every object named like the flag': Program(
        a_program("""
            Object.defineProperty(Object.prototype, 'flag', { set(v) { console.log('set', v); }, configurable: true });
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('set undefined', 'set true', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag made with a setter for it': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = { set flag(v) { console.log('set', v); } };
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('set undefined', 'set true', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the implicit return returning a bound name undefined': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 0, b = 0; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                    }
                  }
                }
              };
              NS.flag = void 0;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
              function undefined() {}
            }
            console.log(outer(1), typeof outer(-1));
            """),
        prints('flagged function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a flag variable every call shares, raised by a recursive call': Program(
        a_program("""
            var done;
            function outer(p) {
              function* gen(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        outer(p - 1);
                        console.log('back', p);
                        a = 0, b = 0;
                        break;
                      case 30:
                        return done = true, 'flagged ' + p;
                    }
                  }
                }
              }
              done = void 0;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
              return 'fell ' + p;
            }
            console.log(outer(1));
            """),
        prints('back 1', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a flag property every call shares, raised by a recursive call': Program(
        a_program("""
            var NS = {};
            function outer(p) {
              var G, R;
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        outer(p - 1);
                        console.log('back', p);
                        a = 0, b = 0;
                        break;
                      case 30:
                        return NS.flag = true, 'flagged ' + p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return 'fell ' + p;
            }
            console.log(outer(1));
            """),
        prints('back 1', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a method of the object of the flag reads it through this': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              NS.get = function () { return this.flag; };
              NS.set = function (v) { this.flag = v; };
              NS.set('stale');
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        console.log('flag seen by the method:', NS.get());
                        a = 15, b = 5;
                        break;
                      case 20:
                        return NS.flag = true, p;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1));
            """),
        prints('flag seen by the method: undefined', '1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a method of the object of the flag raises it through this': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              NS.raise = function () { this.flag = true; };
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        NS.raise();
                        a = 15, b = 5;
                        break;
                      case 20:
                        console.log('ran on');
                        a = 0, b = 0;
                        break;
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return 'fell ' + p;
            }
            console.log(outer(1));
            """),
        prints('ran on', 'undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag given a prototype with an accessor for it': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              NS.__proto__ = { set flag(v) { console.log('set', v); }, get flag() { return 0; } };
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('set undefined', 'set true', 'set undefined', 'set true', 'undefined undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag asked whether it owns the flag': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 0, b = 0; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return 'fell ' + NS.hasOwnProperty('flag') + ' ' + NS.valueOf().flag;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('flagged fell true undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the generator stored to a let before its declaration': Program(
        a_program("""
            function outer(p) {
              var NS = {};
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
              let G, R;
            }
            try { console.log(outer(1)); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag reached through the constructor of its prototype': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              Object.defineProperty(NS.constructor.prototype, 'flag', { set(v) { console.log('set', v); }, get() { return 0; }, configurable: true });
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('set undefined', 'set true', 'set undefined', 'set true', 'undefined undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a scope object of the inner machine holding a property named like the object of the flag': Program(
        a_program("""
            function outer(p) {
              var G, R;
              var NS = {};
              G = function* g(a, b, scope = { NS: {} }) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            console.log(outer(1), outer(-1));
            """),
        prints('undefined undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag made only after the call': Program(
        a_program("""
            function outer(p) {
              var G, R;
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
              var NS = {};
            }
            try { console.log(outer(1)); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag made in a branch the call does not always take': Program(
        a_program("""
            function outer(p) {
              var G, R;
              if (p > 5) { var NS = {}; }
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              return undefined;
            }
            try { console.log(outer(1)); } catch (e) { console.log(e.name); }
            try { console.log(outer(9)); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError', 'flagged'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object of the flag made only after the call, in a loop behind the guard': Program(
        a_program("""
            function outer(p) {
              var G, R;
              G = function* g(a, b, scope = {}) {
                while (a + b !== 0) {
                  with (scope) {
                    switch (a + b) {
                      case 10:
                        if (p > 0) { a = 15, b = 5; break; } else { a = 25, b = 5; break; }
                      case 20:
                        return NS.flag = true, 'flagged';
                      case 30:
                        return NS.flag = true, 'other';
                    }
                  }
                }
              };
              NS.flag = undefined;
              R = G(5, 5).next().value;
              if (NS.flag) {
                return R;
              }
              while (p < -100) { var NS = {}; p++; }
              return 'after';
            }
            try { console.log(outer(1)); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}

#: The rows of `NESTED` whose machine the recovery takes apart, mapped to the text it writes.
NESTED_RECOVERED: dict[str, str] = {
    'an inner machine as the recovery of the outer one leaves it': inspect.cleandoc(
        """
            function outer(p_1) {
              var G, R;
              var NS = {};
              NS.p = p_1;
              if (NS.p > 0) {
                return 'positive';
              }
              console.log('other');
            }
            console.log(outer(1), outer(-1));
        """
    ),
    'a wrapper in the inner machine calling it by its own name': inspect.cleandoc(
        """
            function outer(p_1) {
              var G, R;
              var NS = {};
              NS.p = p_1;
              var M = {};
              M.helper = function(x_1) {
                var L = {};
                L.x = x_1;
                return L.x * 10;
              };
              return M.helper(NS.p) + M.helper(NS.p + 1);
            }
            console.log(outer(1));
        """
    ),
    'the implicit return returning a bound name undefined': inspect.cleandoc(
        """
            function outer(p) {
              var G, R;
              var NS = {};
              if (p > 0) {
                return 'flagged';
              }
              return undefined;
              function undefined() {}
            }
            console.log(outer(1), typeof outer(-1));
        """
    ),
}

#: The rows of `NESTED` whose machine the recovery leaves as it is: the flag's object is not a
#: namespace of the function's own made before the call, the flag is read after the guard or shared
#: by every call, a name the scaffolding spells `undefined` with is bound, or the generator is
#: stored twice, read by its own name in the code it runs, or held by a `let`.
NESTED_KEPT = [
    'the object of the flag handed to a function',
    'the object of the flag read under a computed key',
    'the flag read after the guard',
    'the object of the flag shared by every call',
    'a name undefined bound in the function',
    'the generator stored twice',
    'the generator read by its own name in the code it runs',
    'a setter on every object named like the flag',
    'the object of the flag made with a setter for it',
    'a flag variable every call shares, raised by a recursive call',
    'a flag property every call shares, raised by a recursive call',
    'a method of the object of the flag reads it through this',
    'a method of the object of the flag raises it through this',
    'the object of the flag given a prototype with an accessor for it',
    'the object of the flag asked whether it owns the flag',
    'the generator stored to a let before its declaration',
    'the object of the flag reached through the constructor of its prototype',
    'a scope object of the inner machine holding a property named like the object of the flag',
    'the object of the flag made only after the call',
    'the object of the flag made in a branch the call does not always take',
    'the object of the flag made only after the call, in a loop behind the guard',
]

@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANestedMachineBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in NESTED.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in NESTED.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestANestedMachineIsTakenApartOnlyWhereItsScaffoldingIsPrivate(TestBase):

    def test_every_row_is_either_taken_apart_or_kept(self):
        self.assertEqual(set(NESTED), {*NESTED_RECOVERED, *NESTED_KEPT})

    def test_each_machine_taken_apart_reads_as_pinned(self):
        self.assertEqual(
            {label: recovered(NESTED[label].text) for label in NESTED_RECOVERED},
            NESTED_RECOVERED,
        )

    def test_each_machine_kept_is_left_as_it_is(self):
        for label in NESTED_KEPT:
            with self.subTest(label=label):
                source = NESTED[label].text
                self.assertEqual(recovered(source), written(source))
