"""
The recovery of a machine of control-flow flattening that stands in a function whose code the
recovery of the machine around it wrote: the generator held by a variable, the flag a property of an
object the function makes for each call, and the return of `undefined` that ends the function behind
the guard. Each program below holds such a machine, written by hand in that shape, and each row says
what Node prints for it run as a CommonJS file; the deobfuscation prints the same. Where the
recovery takes a machine apart, the text it writes is pinned; where something outside the
scaffolding may reach the flag, the generator or the result, it leaves the machine as it is. A
function the obfuscation declares in a block of a flattened function reads a copy of the block's
scope object, made when it is called, where the recovered code shares one variable; the recovery
goes ahead where every store to it runs before the function is made. Two files the obfuscation
wrote for one program, every function of which it flattened, are read as text and never run.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.cff import JsStateMachineUnflattening
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


def deobfuscated(source: str) -> str:
    return deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)


def recovered(source: str) -> str:
    ast = JsParser(source).parse()
    JsStateMachineUnflattening().visit(ast)
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
              Object.defineProperty(NS.constructor.prototype, 'flag', {
                set(v) { console.log('set', v); }, get() { return 0; }, configurable: true,
              });
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


#: Programs holding a machine whose block hands its scope object to a function declared in it,
#: mapped to what Node prints for each run as a CommonJS file.
HANDED_ON: dict[str, Program] = {
    'a block scope object stored once before the function it hands on is made': Program(
        a_program("""
            function outer(n) {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = n * 10;
                        B.helper = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.result = B.helper(n);
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.result;
                      case 50:
                        [L.x] = args;
                        a = 60, b = 0;
                        break;
                      case 60:
                        return L.x + B.v;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer(3));
            """),
        prints('33'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored again in a loop while a closure keeps the old one': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        F.keep = [];
                        for (const k of [1, 2]) {
                          scope.B = {};
                          B.v = k;
                          B.make = function(...rest) {
                            return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                          };
                          F.keep.push(B.make());
                        }
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.keep.map((read) => read()).join(' ');
                      case 50:
                        return function() { return B.v; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer());
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored by a closure': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = 1;
                        F.renew = function() { B = { v: 2 }; };
                        B.make = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.read = B.make();
                        F.renew();
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.read() + ' ' + B.v;
                      case 50:
                        return function() { return B.v; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer());
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object handed on through a function made by the function it was handed to': Program(
        a_program("""
            function outer(n) {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = n;
                        B.first = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.result = B.first(2);
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.result;
                      case 50:
                        [L.x] = args;
                        L.second = function(...rest) {
                          return gen(70, 10, { F: scope.F, B: scope.B, M: {} }, rest)["next"]()["value"];
                        };
                        return L.second(L.x) + 1;
                      case 80:
                        [M.y] = args;
                        return M.y * 100 + B.v;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer(7));
            """),
        prints('208'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored in a block ahead of the one making the function': Program(
        a_program("""
            function outer(n) {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = n * 10;
                        a = 15, b = 0;
                        break;
                      case 15:
                        B.helper = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.result = B.helper(n);
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.result;
                      case 50:
                        [L.x] = args;
                        a = 60, b = 0;
                        break;
                      case 60:
                        return L.x + B.v;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer(3));
            """),
        prints('33'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored on one branch only before the function is made': Program(
        a_program("""
            function outer(n) {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = { v: -1 };
                        if (n > 2) { a = 12, b = 0; } else { a = 15, b = 0; }
                        break;
                      case 12:
                        scope.B = {};
                        B.v = n * 10;
                        a = 15, b = 0;
                        break;
                      case 15:
                        B.helper = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.result = B.helper(n);
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.result;
                      case 50:
                        [L.x] = args;
                        a = 60, b = 0;
                        break;
                      case 60:
                        return L.x + B.v;
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer(3), outer(1));
            """),
        prints('33 0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the wrapper is made by a hoisted declaration called before a later store': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = 1;
                        F.keep = mk();
                        scope.B = {};
                        B.v = 2;
                        function mk() {
                          B.make = function(...rest) {
                            return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                          };
                          return B.make();
                        }
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.keep() + ' ' + B.v;
                      case 50:
                        return function() { return B.v; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer());
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored by eval after a closure of the function it hands on kept it': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = 1;
                        B.make = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.read = B.make();
                        eval('B = { v: 2 }');
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.read() + ' ' + B.v;
                      case 50:
                        return function() { return B.v; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer());
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a block scope object stored by a class field initializer that runs after the function it hands on': Program(
        a_program("""
            function outer() {
              function* gen(a, b, scope = { F: {} }, args) {
                while (a + b !== 100) {
                  with (scope.RV || scope) {
                    switch (a + b) {
                      case 10:
                        scope.B = {};
                        B.v = 1;
                        F.K = class { x = (B = { v: 2 }); };
                        B.make = function(...rest) {
                          return gen(40, 10, { F: scope.F, B: scope.B, L: {} }, rest)["next"]()["value"];
                        };
                        F.read = B.make();
                        new F.K();
                        a = 20, b = 0;
                        break;
                      case 20:
                        return done = true, F.read() + ' ' + B.v;
                      case 50:
                        return function() { return B.v; };
                    }
                  }
                }
              }
              var done;
              var result = gen(5, 5)["next"]()["value"];
              if (done) { return result; }
            }
            console.log(outer());
            """),
        prints('1 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}

#: The rows of `HANDED_ON` the recovery takes apart, mapped to the text it writes: every store to
#: the scope object runs before the function is made, and never after.
HANDED_ON_RECOVERED: dict[str, str] = {
    'a block scope object stored once before the function it hands on is made': inspect.cleandoc(
        """
            function outer(n) {
              var F = {};
              var B;
              B = {};
              B.v = n * 10;
              B.helper = function(x_1) {
                var L = {};
                L.x = x_1;
                return L.x + B.v;
              };
              F.result = B.helper(n);
              return F.result;
            }
            console.log(outer(3));
        """
    ),
    'a block scope object handed on through a function made by the function it was handed to': inspect.cleandoc(
        """
            function outer(n) {
              var F = {};
              var B;
              B = {};
              B.v = n;
              B.first = function(x_1) {
                var L = {};
                L.x = x_1;
                L.second = function(y_1) {
                  var M = {};
                  M.y = y_1;
                  return M.y * 100 + B.v;
                };
                return L.second(L.x) + 1;
              };
              F.result = B.first(2);
              return F.result;
            }
            console.log(outer(7));
        """
    ),
    'a block scope object stored in a block ahead of the one making the function': inspect.cleandoc(
        """
            function outer(n) {
              var F = {};
              var B;
              B = {};
              B.v = n * 10;
              B.helper = function(x_1) {
                var L = {};
                L.x = x_1;
                return L.x + B.v;
              };
              F.result = B.helper(n);
              return F.result;
            }
            console.log(outer(3));
        """
    ),
}

#: The rows of `HANDED_ON` the recovery leaves as they are: a store may run after the function is
#: made, by a loop, a closure, a branch, a hoisted call, `eval` or a class field initializer.
HANDED_ON_KEPT = [
    'a block scope object stored again in a loop while a closure keeps the old one',
    'a block scope object stored by a closure',
    'a block scope object stored on one branch only before the function is made',
    'the wrapper is made by a hoisted declaration called before a later store',
    'a block scope object stored by eval after a closure of the function it hands on kept it',
    'a block scope object stored by a class field initializer that runs after the function it hands on',
]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAHandedOnScopeObjectBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in HANDED_ON.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in HANDED_ON.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAHandedOnScopeObjectIsSharedOnlyWhereItsStoresComeFirst(TestBase):

    def test_every_row_is_either_taken_apart_or_kept(self):
        self.assertEqual(set(HANDED_ON), {*HANDED_ON_RECOVERED, *HANDED_ON_KEPT})

    def test_each_machine_taken_apart_reads_as_pinned(self):
        self.assertEqual(
            {label: recovered(HANDED_ON[label].text) for label in HANDED_ON_RECOVERED},
            HANDED_ON_RECOVERED,
        )

    def test_each_machine_kept_is_left_as_it_is(self):
        for label in HANDED_ON_KEPT:
            with self.subTest(label=label):
                source = HANDED_ON[label].text
                self.assertEqual(recovered(source), written(source))


#: A file the obfuscation wrote with control-flow flattening alone for a program of functions inside
#: functions, and its deobfuscation: every machine taken apart, the inner ones in the shape the
#: recovery of the outer one wrote.
FLATTENED_TWICE = inspect.cleandoc(
    """
    function* jvuXTJ(dY6CQr, i2z9nrB, zEZVXp9, BX02bWn, C0_pQa3 = {
      ["o_d8Hjl"]: {}
    }, GCqasx) {
      while (dY6CQr + i2z9nrB + zEZVXp9 + BX02bWn !== 0) {
        with (C0_pQa3["L64oM4"] || C0_pQa3) {
          __p_xK0I: switch (dY6CQr + i2z9nrB + zEZVXp9 + BX02bWn) {
            case 130:
              return undefined;
            case 190:
            case 30:
            case -140:
              [KVKZmr["cFd5H4X"], KVKZmr["d6VElg"] = ', '] = GCqasx;
              KVKZmr["XoxTxv"] = function* K2ccHR(S4ZRZ5S, rXawjM, ZoiSud, faHkpw = {
                ["QCmjtyw"]: {}
              }, _WUzWoo) {
                while (S4ZRZ5S + rXawjM + ZoiSud !== -160) {
                  with (faHkpw["R7G9Qb"] || faHkpw) {
                    __p_uhsX: switch (S4ZRZ5S + rXawjM + ZoiSud) {
                      case -197:
                      case rXawjM - -159:
                        faHkpw["R7G9Qb"] = faHkpw["aAVArK"], S4ZRZ5S += 211, rXawjM += -117, ZoiSud += -221;
                        break __p_uhsX;
                      case -153:
                        return undefined;
                      default:
                        return x2wlOR;
                        faHkpw["R7G9Qb"] = faHkpw["aAVArK"], rXawjM += 62, ZoiSud += -271;
                        break __p_uhsX;
                        if (ZoiSud < 90) {
                          faHkpw["R7G9Qb"] = faHkpw["QCmjtyw"], S4ZRZ5S += -211, rXawjM += 117, ZoiSud += 221;
                          break __p_uhsX;
                        }
                      case faHkpw["QCmjtyw"]["n1Q5W7K"] + 41:
                      case -99:
                        for (const entry of KVKZmr["cFd5H4X"]) {
                          z80HZjY["push"]((1, MvmeD2R)(entry));
                        }
                        return KVKZmr["VOWVDsv"] = true, z80HZjY["join"](KVKZmr["d6VElg"]);
                        faHkpw["R7G9Qb"] = faHkpw["zUe9aRL"], S4ZRZ5S += 148, rXawjM += -215, ZoiSud += -163;
                        break __p_uhsX;
                      case faHkpw["QCmjtyw"]["n1Q5W7K"] + -240:
                        [aAVArK["cj8ac0"]] = _WUzWoo;
                        aAVArK["ZgXAjM"] = function* JjcmlK(KWhODL6, XFSbn9c, j1HV1L, Ctgh46, ecB36E = {
                          ["ZxOnPud"]: {}
                        }) {
                          while (KWhODL6 + XFSbn9c + j1HV1L + Ctgh46 !== -150) {
                            with (ecB36E["PDoThDd"] || ecB36E) {
                              __p_HV0d: switch (KWhODL6 + XFSbn9c + j1HV1L + Ctgh46) {
                                case ecB36E["ZxOnPud"]["KUJglBd"] + 209:
                                  ecB36E["PDoThDd"] = ecB36E["ScMiwsz"], KWhODL6 += -656, j1HV1L += 270;
                                  break __p_HV0d;
                                case ecB36E["ZxOnPud"]["KUJglBd"] + 31:
                                  ecB36E["PDoThDd"] = ecB36E["ZxOnPud"], XFSbn9c += 491, Ctgh46 += -313;
                                  break __p_HV0d;
                                case 217:
                                case j1HV1L - -171:
                                default:
                                case -166:
                                  [ecB36E["ZxOnPud"]["n0MnCU"], ecB36E["ZxOnPud"]["Wzv4yDo"], ecB36E["ZxOnPud"]["KUJglBd"]] = [109, 60, -77];
                                  ecB36E["PDoThDd"] = ecB36E["ZxOnPud"], KWhODL6 += 554, XFSbn9c += -175, j1HV1L += 24, Ctgh46 += 31;
                                  break __p_HV0d;
                                case Ctgh46 - -234:
                                case -24:
                                  [ecB36E["ZxOnPud"]["n0MnCU"], ecB36E["ZxOnPud"]["Wzv4yDo"], ecB36E["ZxOnPud"]["KUJglBd"]] = [-56, -102, 27];
                                  ZxOnPud["m5Ho_Z9"] = '"';
                                  ZxOnPud["hdEeet"] = String(aAVArK["cj8ac0"]);
                                  return aAVArK["rJbcju"] = true, ZxOnPud["m5Ho_Z9"] + ZxOnPud["hdEeet"] + ZxOnPud["m5Ho_Z9"];
                                  KWhODL6 += 174, XFSbn9c += 100, j1HV1L += -519, Ctgh46 += -150;
                                  break __p_HV0d;
                                case KWhODL6 - 298:
                                case 204:
                                  ecB36E["PDoThDd"] = ecB36E["dIGreb"], KWhODL6 += -439, XFSbn9c += 391, j1HV1L += 518, Ctgh46 += -163;
                                  break __p_HV0d;
                                case 45:
                                case 137:
                                case -142:
                                  ecB36E["PDoThDd"] = ecB36E["gTuvrcW"], KWhODL6 += -179, j1HV1L += -108;
                                  break __p_HV0d;
                              }
                            }
                          }
                        };
                        aAVArK["rJbcju"] = undefined;
                        aAVArK["x2wlOR"] = (S4ZRZ5S + 122, aAVArK["ZgXAjM"])(-(S4ZRZ5S + 324), -189, 626, 11)["next"]()["value"];
                        if (aAVArK["rJbcju"]) {
                          faHkpw["R7G9Qb"] = faHkpw["aAVArK"], S4ZRZ5S += 180, rXawjM += 87;
                          break __p_uhsX;
                        } else {
                          faHkpw["R7G9Qb"] = faHkpw["aAVArK"], S4ZRZ5S += 180, rXawjM += 149, ZoiSud += -271;
                          break __p_uhsX;
                        }
                      case 68:
                      case rXawjM - -185:
                        [faHkpw["QCmjtyw"]["I7DLyF"], faHkpw["QCmjtyw"]["n1Q5W7K"]] = [166, -68];
                        faHkpw["R7G9Qb"] = faHkpw["ELHLU7Y"], S4ZRZ5S += 306, rXawjM += -270, ZoiSud += -405;
                        break __p_uhsX;
                      case -77:
                      case 167:
                        [faHkpw["QCmjtyw"]["I7DLyF"], faHkpw["QCmjtyw"]["n1Q5W7K"]] = [-117, 29];
                        QCmjtyw["MvmeD2R"] = function (...__p_VIKL) {
                          return K2ccHR(-121, -180, 90, {
                            ["QCmjtyw"]: faHkpw["QCmjtyw"],
                            ["aAVArK"]: {}
                          }, __p_VIKL)["next"]()["value"];
                        };
                        QCmjtyw["z80HZjY"] = [];
                        faHkpw["R7G9Qb"] = faHkpw["QCmjtyw"], S4ZRZ5S += 140, rXawjM += 73, ZoiSud += -310;
                        break __p_uhsX;
                      case -78:
                        faHkpw["R7G9Qb"] = faHkpw["aAVArK"], S4ZRZ5S += 224, rXawjM += 131, ZoiSud += -221;
                        break __p_uhsX;
                    }
                  }
                }
              };
              KVKZmr["VOWVDsv"] = undefined;
              C0_pQa3["L64oM4"] = C0_pQa3["KVKZmr"], dY6CQr += -524, i2z9nrB += 534, BX02bWn += 12;
              break __p_xK0I;
            case BX02bWn - 79:
            case 38:
              [HZLCxt["e5ZytlN"]] = GCqasx;
              HZLCxt["ehk3YU"] = function* C4_Q9q(zB0A6C, wSVrmv, zFgjWOk, JZ44H3 = {
                ["cHppSjA"]: {}
              }, zvD4s4) {
                while (zB0A6C + wSVrmv + zFgjWOk !== -89) {
                  with (JZ44H3["at2ak6"] || JZ44H3) {
                    __p_fYQR: switch (zB0A6C + wSVrmv + zFgjWOk) {
                      case zB0A6C != -179 && zB0A6C - -141:
                        return k52qwrg;
                        JZ44H3["at2ak6"] = JZ44H3["XqBkkz3"], zB0A6C += -32, wSVrmv += -133, zFgjWOk += 216;
                        break __p_fYQR;
                      case zFgjWOk - 48:
                      case -52:
                      case -93:
                        JZ44H3["at2ak6"] = JZ44H3["EAR9uNJ"], zB0A6C += -67, wSVrmv += 241, zFgjWOk += -93;
                        break __p_fYQR;
                      case 73:
                      case 212:
                      case -234:
                        [JZ44H3["cHppSjA"]["KbdMO3f"], JZ44H3["cHppSjA"]["ZO7zhaE"], JZ44H3["cHppSjA"]["k0aBXC"]] = [-70, -182, -124];
                      case 245:
                      case wSVrmv - 211:
                        [JZ44H3["cHppSjA"]["KbdMO3f"], JZ44H3["cHppSjA"]["ZO7zhaE"], JZ44H3["cHppSjA"]["k0aBXC"]] = [-249, 132, -52];
                        return undefined;
                      case zB0A6C != -107 && zB0A6C - -141:
                        JZ44H3["XqBkkz3"]["k52qwrg"] = (zB0A6C + 180, ImJowg)(-158, zB0A6C + 187)["next"]()["value"];
                        if (JXZx8e1) {
                          JZ44H3["at2ak6"] = JZ44H3["XqBkkz3"], zB0A6C += 72;
                          break __p_fYQR;
                        } else {
                          JZ44H3["at2ak6"] = JZ44H3["XqBkkz3"], zB0A6C += 40, wSVrmv += -133, zFgjWOk += 216;
                          break __p_fYQR;
                        }
                        if (zFgjWOk != -186) {
                          JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += 127, wSVrmv += -303, zFgjWOk += 279;
                          break __p_fYQR;
                        }
                      default:
                        [XqBkkz3["y9cQZN"]] = zvD4s4;
                        XqBkkz3["ImJowg"] = function* G9chPl(SpKFkW, d1utBks, Xv8ctPL = {
                          ["nPjbWZE"]: {}
                        }) {
                          while (SpKFkW + d1utBks !== 25) {
                            with (Xv8ctPL["icTlJX"] || Xv8ctPL) {
                              __p_YB5z: switch (SpKFkW + d1utBks) {
                                case -200:
                                case -100:
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["nPjbWZE"], SpKFkW += 247, d1utBks += 199;
                                  break __p_YB5z;
                                  if (d1utBks != -177) {
                                    Xv8ctPL["icTlJX"] = Xv8ctPL["nPjbWZE"], SpKFkW += 247, d1utBks += 199;
                                    break __p_YB5z;
                                  }
                                case SpKFkW - -129:
                                  return XqBkkz3["JXZx8e1"] = true, aeufhk;
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["Bt4kXkW"], SpKFkW += 83, d1utBks += 61;
                                  break __p_YB5z;
                                case 186:
                                case -150:
                                  [Xv8ctPL["nPjbWZE"]["kqToLRg"]] = [-148];
                                  nPjbWZE["V9oaAm3"] = XqBkkz3["y9cQZN"] * 2;
                                  nPjbWZE["aeufhk"] = nPjbWZE["V9oaAm3"] + '';
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["nPjbWZE"], SpKFkW += 232, d1utBks += -249;
                                  break __p_YB5z;
                                  if (!(d1utBks == 8)) {
                                    SpKFkW += -7, d1utBks += 182;
                                    break __p_YB5z;
                                  }
                                case SpKFkW - -247:
                                  [Xv8ctPL["nPjbWZE"]["kqToLRg"]] = [46];
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["U3DIA_"], SpKFkW += -164, d1utBks += -57;
                                  break __p_YB5z;
                                  if (d1utBks == -220) {
                                    Xv8ctPL["icTlJX"] = Xv8ctPL["aPZv2P"], SpKFkW += -157, d1utBks += -239;
                                    break __p_YB5z;
                                  }
                                case 206:
                                case -149:
                                case Xv8ctPL["nPjbWZE"]["kqToLRg"] + 151:
                                  [Xv8ctPL["nPjbWZE"]["kqToLRg"]] = [-58];
                                  return XqBkkz3["JXZx8e1"] = true, aeufhk;
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["c0J_5j_"], SpKFkW += -229, d1utBks += 251;
                                  break __p_YB5z;
                                case -245:
                                case -202:
                                case SpKFkW - 241:
                                  return XqBkkz3["JXZx8e1"] = true, aeufhk;
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["XiDGqaM"], SpKFkW += -239, d1utBks += 431;
                                  break __p_YB5z;
                                default:
                                  Xv8ctPL["icTlJX"] = Xv8ctPL["nPjbWZE"], d1utBks += 424;
                                  break __p_YB5z;
                                  if (d1utBks != -177) {
                                    Xv8ctPL["icTlJX"] = Xv8ctPL["nPjbWZE"], d1utBks += 424;
                                    break __p_YB5z;
                                  }
                              }
                            }
                          }
                        };
                        XqBkkz3["JXZx8e1"] = undefined;
                        JZ44H3["at2ak6"] = JZ44H3["XqBkkz3"], zB0A6C += -192, wSVrmv += 282, zFgjWOk += 5;
                        break __p_fYQR;
                      case 188:
                        JZ44H3["cHppSjA"]["VpzV5U"] = '!';
                        return HZLCxt["Io5Figp"] = true, vBewCm + VpzV5U;
                        JZ44H3["at2ak6"] = JZ44H3["NW35Zz"], zB0A6C += 158, wSVrmv += -451, zFgjWOk += 16;
                        break __p_fYQR;
                      case zB0A6C - 22:
                      case 135:
                        JZ44H3["YgoVlLK"] = {};
                        JZ44H3["YgoVlLK"]["kHNKcSK"] = function (...__p_tNxp) {
                          return C4_Q9q(13, 45, -191, {
                            ["YgoVlLK"]: JZ44H3["YgoVlLK"],
                            ["cHppSjA"]: JZ44H3["cHppSjA"],
                            ["XqBkkz3"]: {}
                          }, __p_tNxp)["next"]()["value"];
                        };
                        vBewCm = (1, JZ44H3["YgoVlLK"]["kHNKcSK"])(wSVrmv + -186);
                        JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += -29, wSVrmv += 5, zFgjWOk += 221;
                        break __p_fYQR;
                      case zFgjWOk - -126:
                        [JZ44H3["cHppSjA"]["KbdMO3f"], JZ44H3["cHppSjA"]["ZO7zhaE"], JZ44H3["cHppSjA"]["k0aBXC"]] = [50, 102, -152];
                        cHppSjA["vBewCm"] = 'none';
                        if (HZLCxt["e5ZytlN"]) {
                          JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += -129, wSVrmv += 205, zFgjWOk += -144;
                          break __p_fYQR;
                        } else {
                          JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += -158, wSVrmv += 210, zFgjWOk += 77;
                          break __p_fYQR;
                        }
                      case -2:
                        JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += 65, wSVrmv += 165, zFgjWOk += -237;
                        break __p_fYQR;
                        if (!(zB0A6C == -52)) {
                          JZ44H3["at2ak6"] = JZ44H3["XqBkkz3"], zB0A6C += -55, wSVrmv += 303, zFgjWOk += -212;
                          break __p_fYQR;
                        }
                      case 80:
                      case 85:
                        return undefined;
                      case 176:
                      case 72:
                      case -151:
                        JZ44H3["at2ak6"] = JZ44H3["l_Tu5wd"], zB0A6C += -84, wSVrmv += -8, zFgjWOk += -217;
                        break __p_fYQR;
                        if (!(zB0A6C == 97)) {
                          JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zB0A6C += -113, wSVrmv += 141, zFgjWOk += -16;
                          break __p_fYQR;
                        }
                      case wSVrmv - -41:
                        JZ44H3["at2ak6"] = JZ44H3["nWYhMIi"], zB0A6C += 65, wSVrmv += 21, zFgjWOk += -284;
                        break __p_fYQR;
                        if (!(wSVrmv > -139)) {
                          JZ44H3["at2ak6"] = JZ44H3["cHppSjA"], zFgjWOk += -67;
                          break __p_fYQR;
                        }
                    }
                  }
                }
              };
              HZLCxt["Io5Figp"] = undefined;
              HZLCxt["kfH8XnY"] = (1, HZLCxt["ehk3YU"])(142, -16, -67)["next"]()["value"];
              if (HZLCxt["Io5Figp"]) {
                C0_pQa3["L64oM4"] = C0_pQa3["HZLCxt"], zEZVXp9 += -249, BX02bWn += 286;
                break __p_xK0I;
              } else {
                C0_pQa3["L64oM4"] = C0_pQa3["HZLCxt"], dY6CQr += 69, zEZVXp9 += -249, BX02bWn += 286;
                break __p_xK0I;
              }
            case C0_pQa3["o_d8Hjl"]["JmFMC_"] + 436:
            case -214:
            case -231:
              [tQpHT6U["iHnYV1"], ...tQpHT6U["bL1h6a"]] = GCqasx;
              tQpHT6U["aPbM7e"] = function* V7iy8o(UT0zpL, TiV129, WykehV, Pjfsst2 = {
                ["NtzlfSJ"]: {}
              }) {
                while (UT0zpL + TiV129 + WykehV !== 213) {
                  with (Pjfsst2["XoibgTF"] || Pjfsst2) {
                    __p_CGMy: switch (UT0zpL + TiV129 + WykehV) {
                      case WykehV - 359:
                        [Pjfsst2["NtzlfSJ"]["yoqRCn"], Pjfsst2["NtzlfSJ"]["P7kS3_2"]] = [179, 39];
                        NtzlfSJ["aHTZ_H"] = tQpHT6U["iHnYV1"];
                        for (const value of tQpHT6U["bL1h6a"]) {
                          NtzlfSJ["aHTZ_H"] += value;
                        }
                        if (NtzlfSJ["aHTZ_H"] > UT0zpL + 249) {
                          Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 129, TiV129 += 53, WykehV += -226;
                          break __p_CGMy;
                        } else {
                          Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 291, TiV129 += 374, WykehV += -388;
                          break __p_CGMy;
                        }
                      default:
                        Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 375, TiV129 += 7, WykehV += 11;
                        break __p_CGMy;
                      case Pjfsst2["NtzlfSJ"]["P7kS3_2"] + 195:
                        Pjfsst2["XoibgTF"] = Pjfsst2["HHERhO"], UT0zpL += -344, TiV129 += 323;
                        break __p_CGMy;
                        if (WykehV < -(UT0zpL + -384)) {
                          Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"];
                          break __p_CGMy;
                        }
                      case -234:
                      case -27:
                        return tQpHT6U["ZAViEr"] = true, 'big ' + aHTZ_H;
                        Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 713, TiV129 += -83, WykehV += -162;
                        break __p_CGMy;
                      case UT0zpL - -35:
                        return tQpHT6U["ZAViEr"] = true, 'small ' + aHTZ_H;
                        Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 551, TiV129 += -404;
                        break __p_CGMy;
                      case TiV129 - 55:
                      case -211:
                        [Pjfsst2["NtzlfSJ"]["yoqRCn"], Pjfsst2["NtzlfSJ"]["P7kS3_2"]] = [-230, 95];
                        Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 750, TiV129 += -361, WykehV += -311;
                        break __p_CGMy;
                      case WykehV - 65:
                        Pjfsst2["XoibgTF"] = Pjfsst2["NtzlfSJ"], UT0zpL += 230, TiV129 += 141, WykehV += -311;
                        break __p_CGMy;
                        if (UT0zpL > -178) {
                          Pjfsst2["XoibgTF"] = Pjfsst2["bva3pmc"], UT0zpL += -61, TiV129 += -233, WykehV += 77;
                          break __p_CGMy;
                        }
                      case UT0zpL - -45:
                      case 77:
                      case UT0zpL - -143:
                      case 202:
                      case 139:
                    }
                  }
                }
              };
              tQpHT6U["ZAViEr"] = undefined;
              C0_pQa3["L64oM4"] = C0_pQa3["tQpHT6U"], i2z9nrB += 217, BX02bWn += -529;
              break __p_xK0I;
            case BX02bWn - 139:
              return KWNdHsR;
              C0_pQa3["L64oM4"] = C0_pQa3["qTZ3Rq"], i2z9nrB += 14, zEZVXp9 += 79, BX02bWn += 248;
              break __p_xK0I;
            case -19:
              return undefined;
            case -91:
            case C0_pQa3["o_d8Hjl"]["CUWeDT"] + -424:
            case -236:
              return pnQr9yy;
              C0_pQa3["L64oM4"] = C0_pQa3["buF6LO"], dY6CQr += 51, BX02bWn += 19;
              break __p_xK0I;
            case -189:
            case -81:
            case zEZVXp9 - -347:
              return kfH8XnY;
              C0_pQa3["L64oM4"] = C0_pQa3["HZLCxt"], dY6CQr += 69;
              break __p_xK0I;
            case BX02bWn - -292:
            case -61:
            case 141:
              C0_pQa3["L64oM4"] = C0_pQa3["HZLCxt"], dY6CQr += 291, i2z9nrB += -233, zEZVXp9 += -609, BX02bWn += 445;
              break __p_xK0I;
            default:
              [qTZ3Rq["Z4B2sY"]] = GCqasx;
              qTZ3Rq["qSVgOKu"] = function* aCjcEK(Hj0b9Bh, F2JU6Rs, YWiUXg, DXrl1KZ, RUmNtnR = {
                ["nb9rrI"]: {}
              }) {
                while (Hj0b9Bh + F2JU6Rs + YWiUXg + DXrl1KZ !== 111) {
                  with (RUmNtnR["z2_Q1WT"] || RUmNtnR) {
                    __p_wSU1: switch (Hj0b9Bh + F2JU6Rs + YWiUXg + DXrl1KZ) {
                      case 184:
                      case YWiUXg - -261:
                        return qTZ3Rq["LUjxt2A"] = true, EMiF3y;
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["JOShYXz"], Hj0b9Bh += -324, F2JU6Rs += 29, YWiUXg += 262, DXrl1KZ += 35;
                        break __p_wSU1;
                      case DXrl1KZ - 477:
                        if (qTZ3Rq["Z4B2sY"] > 1000) {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 396, F2JU6Rs += 131, YWiUXg += -112, DXrl1KZ += -658;
                          break __p_wSU1;
                        } else {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 310, F2JU6Rs += 131, YWiUXg += -72, DXrl1KZ += -658;
                          break __p_wSU1;
                        }
                      case Hj0b9Bh - -97:
                      case 86:
                      case 193:
                        [RUmNtnR["nb9rrI"]["yYJfHw"], RUmNtnR["nb9rrI"]["rUdhi3i"], RUmNtnR["nb9rrI"]["NCOHyCt"]] = [-134, 78, -152];
                        return qTZ3Rq["LUjxt2A"] = true, 'negative';
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -147, F2JU6Rs += -48, YWiUXg += 217, DXrl1KZ += 81;
                        break __p_wSU1;
                      case Hj0b9Bh != 192 && YWiUXg - -162:
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 362, F2JU6Rs += 150, YWiUXg += 63, DXrl1KZ += -413;
                        break __p_wSU1;
                      case -245:
                        return qTZ3Rq["LUjxt2A"] = true, 'large ' + EMiF3y;
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 354;
                        break __p_wSU1;
                      case -95:
                      case 122:
                      case RUmNtnR["nb9rrI"]["NCOHyCt"] + -114:
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 362, F2JU6Rs += 180, YWiUXg += -102, DXrl1KZ += -413;
                        break __p_wSU1;
                      case 117:
                      case 99:
                        return qTZ3Rq["LUjxt2A"] = true, 'zero';
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 127, F2JU6Rs += -259, DXrl1KZ += 164;
                        break __p_wSU1;
                      case DXrl1KZ - -82:
                        [RUmNtnR["nb9rrI"]["yYJfHw"], RUmNtnR["nb9rrI"]["rUdhi3i"], RUmNtnR["nb9rrI"]["NCOHyCt"]] = [-7, -48, 196];
                        if (qTZ3Rq["Z4B2sY"] < 0) {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -524, F2JU6Rs += 53, YWiUXg += 39, DXrl1KZ += 115;
                          break __p_wSU1;
                        } else {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -524, F2JU6Rs += 53, YWiUXg += 47, DXrl1KZ += 273;
                          break __p_wSU1;
                        }
                      case RUmNtnR["nb9rrI"]["NCOHyCt"] + -347:
                        return qTZ3Rq["LUjxt2A"] = true, 'negative';
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], YWiUXg += 8, DXrl1KZ += 158;
                        break __p_wSU1;
                      case 15:
                      case -173:
                      case 192:
                        if (qTZ3Rq["Z4B2sY"] === 0) {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], F2JU6Rs += 188, YWiUXg += -86;
                          break __p_wSU1;
                        } else {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 127, F2JU6Rs += -71, YWiUXg += -86, DXrl1KZ += 164;
                          break __p_wSU1;
                        }
                      case YWiUXg - 7:
                        return qTZ3Rq["LUjxt2A"] = true, 'huge ' + EMiF3y;
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -86, YWiUXg += 40;
                        break __p_wSU1;
                      case YWiUXg - -184:
                      case -38:
                        RUmNtnR["nb9rrI"]["EMiF3y"] = qTZ3Rq["Z4B2sY"] % 2 === 0 ? 'even' : 'odd';
                        if (qTZ3Rq["Z4B2sY"] > Hj0b9Bh + 305) {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -261, F2JU6Rs += 201, YWiUXg += -45;
                          break __p_wSU1;
                        } else {
                          RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += 403, F2JU6Rs += 332, YWiUXg += -117, DXrl1KZ += -658;
                          break __p_wSU1;
                        }
                      default:
                        return qTZ3Rq["LUjxt2A"] = true, 'zero';
                        RUmNtnR["z2_Q1WT"] = RUmNtnR["nb9rrI"], Hj0b9Bh += -20, F2JU6Rs += -119, YWiUXg += -234, DXrl1KZ += 496;
                        break __p_wSU1;
                    }
                  }
                }
              };
              qTZ3Rq["LUjxt2A"] = undefined;
              qTZ3Rq["KWNdHsR"] = (1, qTZ3Rq["qSVgOKu"])(i2z9nrB + -320, -114, zEZVXp9 + 206, 84)["next"]()["value"];
              if (qTZ3Rq["LUjxt2A"]) {
                C0_pQa3["L64oM4"] = C0_pQa3["qTZ3Rq"], dY6CQr += 347, i2z9nrB += -751, zEZVXp9 += 84;
                break __p_xK0I;
              } else {
                C0_pQa3["L64oM4"] = C0_pQa3["qTZ3Rq"], dY6CQr += 347, i2z9nrB += -737, zEZVXp9 += 163, BX02bWn += 248;
                break __p_xK0I;
              }
            case C0_pQa3["o_d8Hjl"]["JmFMC_"] + 285:
              return Jehe8JQ;
              C0_pQa3["L64oM4"] = C0_pQa3["KVKZmr"], i2z9nrB += -902, zEZVXp9 += 594;
              break __p_xK0I;
            case dY6CQr != 5 && dY6CQr - 121:
            case 169:
              C0_pQa3["tQpHT6U"]["OUvpE7i"] = (1, aPbM7e)(-239, -120, 169)["next"]()["value"];
              if (ZAViEr) {
                C0_pQa3["L64oM4"] = C0_pQa3["tQpHT6U"], dY6CQr += -41;
                break __p_xK0I;
              } else {
                C0_pQa3["L64oM4"] = C0_pQa3["tQpHT6U"], dY6CQr += 106, i2z9nrB += 26, zEZVXp9 += -117, BX02bWn += 93;
                break __p_xK0I;
              }
            case C0_pQa3["o_d8Hjl"]["CUWeDT"] + -84:
              console["log"]((1, gzflAJ)(1, 2, 3), (1, gzflAJ)(5, 6));
              return console["log"]((1, qa6mfQ)(true), (1, qa6mfQ)(false));
              C0_pQa3["L64oM4"] = C0_pQa3["wlmJoA"], dY6CQr += -363, i2z9nrB += 91, zEZVXp9 += 609, BX02bWn += -445;
              break __p_xK0I;
            case zEZVXp9 - -242:
            case -21:
              return undefined;
            case 153:
            case -129:
            case BX02bWn - 411:
              [buF6LO["CcHqMM"], buF6LO["m2YDIuJ"]] = GCqasx;
              buF6LO["ddXN4q_"] = function* mSDDLau(RZ1LR0f, Kn09lww, mQcNQA = {
                ["Y93MNH"]: {}
              }) {
                while (RZ1LR0f + Kn09lww !== 71) {
                  with (mQcNQA["vwPo56u"] || mQcNQA) {
                    __p_KxF8: switch (RZ1LR0f + Kn09lww) {
                      case -4:
                      case -36:
                      case -148:
                        mQcNQA["vwPo56u"] = mQcNQA["Y93MNH"], RZ1LR0f += 62, Kn09lww += -294;
                        break __p_KxF8;
                        if (RZ1LR0f < 257) {
                          mQcNQA["vwPo56u"] = mQcNQA["Y93MNH"], RZ1LR0f += 62, Kn09lww += -294;
                          break __p_KxF8;
                        }
                      case -236:
                      case -197:
                      default:
                        return buF6LO["x_7aFl"] = true, -1;
                        mQcNQA["vwPo56u"] = mQcNQA["GCqalXS"], RZ1LR0f += 307;
                        break __p_KxF8;
                      case 208:
                      case -16:
                      case -207:
                        [mQcNQA["Y93MNH"]["Li88Cw"], mQcNQA["Y93MNH"]["yrif8l"], mQcNQA["Y93MNH"]["tbRfrP"]] = [-6, 249, 122];
                        Y93MNH["N4Eemf"] = 0;
                        for (const item of buF6LO["CcHqMM"]) {
                          if ((1, buF6LO["m2YDIuJ"])(item)) {
                            return buF6LO["x_7aFl"] = true, Y93MNH["N4Eemf"];
                          }
                          Y93MNH["N4Eemf"]++;
                        }
                        mQcNQA["vwPo56u"] = mQcNQA["Y93MNH"], RZ1LR0f += -195, Kn09lww += 166;
                        break __p_KxF8;
                      case -67:
                      case -88:
                        [mQcNQA["Y93MNH"]["Li88Cw"], mQcNQA["Y93MNH"]["yrif8l"], mQcNQA["Y93MNH"]["tbRfrP"]] = [91, 23, 31];
                        mQcNQA["vwPo56u"] = mQcNQA["Y93MNH"], RZ1LR0f += -307, Kn09lww += 159;
                        break __p_KxF8;
                        if (RZ1LR0f < RZ1LR0f + 0) {
                          mQcNQA["vwPo56u"] = mQcNQA["Y93MNH"], RZ1LR0f += -307, Kn09lww += 159;
                          break __p_KxF8;
                        }
                    }
                  }
                }
              };
              buF6LO["x_7aFl"] = undefined;
              buF6LO["pnQr9yy"] = (1, buF6LO["ddXN4q_"])(145, -(zEZVXp9 + 756))["next"]()["value"];
              if (buF6LO["x_7aFl"]) {
                C0_pQa3["L64oM4"] = C0_pQa3["buF6LO"], dY6CQr += -27;
                break __p_xK0I;
              } else {
                C0_pQa3["L64oM4"] = C0_pQa3["buF6LO"], dY6CQr += 24, BX02bWn += 19;
                break __p_xK0I;
              }
            case -237:
              [C0_pQa3["o_d8Hjl"]["CUWeDT"], C0_pQa3["o_d8Hjl"]["JmFMC_"]] = [192, -199];
              o_d8Hjl["qa6mfQ"] = function (...__p_B6w1) {
                return jvuXTJ(135, -28, -186, -46, {
                  ["o_d8Hjl"]: C0_pQa3["o_d8Hjl"],
                  ["HZLCxt"]: {}
                }, __p_B6w1)["next"]()["value"];
              };
              o_d8Hjl["gzflAJ"] = function (...__p_54W9) {
                return jvuXTJ(46, -389, 190, 390, {
                  ["o_d8Hjl"]: C0_pQa3["o_d8Hjl"],
                  ["tQpHT6U"]: {}
                }, __p_54W9)["next"]()["value"];
              };
              o_d8Hjl["GPgIgQ"] = function (...__p_eyXp) {
                return jvuXTJ(696, -21, -404, -81, {
                  ["o_d8Hjl"]: C0_pQa3["o_d8Hjl"],
                  ["KVKZmr"]: {}
                }, __p_eyXp)["next"]()["value"];
              };
              o_d8Hjl["aoaT3J6"] = function (...__p_PRzC) {
                return jvuXTJ(218, -225, -404, 206, {
                  ["o_d8Hjl"]: C0_pQa3["o_d8Hjl"],
                  ["buF6LO"]: {}
                }, __p_PRzC)["next"]()["value"];
              };
              o_d8Hjl["gbZCW7F"] = function (...__p_jc2D) {
                return jvuXTJ(-129, 512, -202, -72, {
                  ["o_d8Hjl"]: C0_pQa3["o_d8Hjl"],
                  ["qTZ3Rq"]: {}
                }, __p_jc2D)["next"]()["value"];
              };
              C0_pQa3["L64oM4"] = C0_pQa3["o_d8Hjl"], dY6CQr += 254, i2z9nrB += 212, zEZVXp9 += -259, BX02bWn += 39;
              break __p_xK0I;
            case C0_pQa3["o_d8Hjl"]["JmFMC_"] + 411:
              C0_pQa3["KVKZmr"]["Jehe8JQ"] = (1, XoxTxv)(-134, -104, 405)["next"]()["value"];
              if (VOWVDsv) {
                C0_pQa3["L64oM4"] = C0_pQa3["KVKZmr"], dY6CQr += -126;
                break __p_xK0I;
              } else {
                C0_pQa3["L64oM4"] = C0_pQa3["KVKZmr"], dY6CQr += -126, i2z9nrB += -902, zEZVXp9 += 594;
                break __p_xK0I;
              }
            case 53:
            case i2z9nrB - 361:
              [C0_pQa3["o_d8Hjl"]["CUWeDT"], C0_pQa3["o_d8Hjl"]["JmFMC_"]] = [-136, 47];
              return undefined;
            case -136:
            case i2z9nrB - -167:
              return undefined;
            case i2z9nrB - -56:
              return OUvpE7i;
              C0_pQa3["L64oM4"] = C0_pQa3["tQpHT6U"], dY6CQr += 147, i2z9nrB += 26, zEZVXp9 += -117, BX02bWn += 93;
              break __p_xK0I;
            case C0_pQa3["o_d8Hjl"]["CUWeDT"] + -183:
              console["log"]((1, gbZCW7F)(-5), (1, gbZCW7F)(0), (1, gbZCW7F)(7), (1, gbZCW7F)(250), (1, gbZCW7F)(5000));
              console["log"]((1, aoaT3J6)([3, 8, 12], x => {
                return x > 5;
              }), (1, aoaT3J6)([1], x => {
                return x > 5;
              }));
              console["log"]((1, GPgIgQ)(['a', 'b']), (1, GPgIgQ)([1, 2, 3], '/'));
              C0_pQa3["L64oM4"] = C0_pQa3["o_d8Hjl"], dY6CQr += -15, i2z9nrB += 114;
              break __p_xK0I;
            case 33:
              return undefined;
          }
        }
      }
    }
    jvuXTJ(-50, -212, -176, 201)["next"]()["value"];
    """
)

FLATTENED_TWICE_DEOBFUSCATED = inspect.cleandoc(
    """
    function qa6mfQ(e5ZytlN) {
      var vBewCm;
      var YgoVlLK;
      vBewCm = 'none';
      if (e5ZytlN) {
        YgoVlLK = {};
        YgoVlLK.kHNKcSK = function(y9cQZN) {
          y9cQZN * 2;
          y9cQZN * 2 + '';
          return y9cQZN * 2 + '';
        };
        vBewCm = (1, YgoVlLK.kHNKcSK)(3);
      }
      return vBewCm + '!';
    }
    function gzflAJ(iHnYV1, ...bL1h6a) {
      var aHTZ_H;
      aHTZ_H = iHnYV1;
      for (const value of bL1h6a) {
        aHTZ_H += value;
      }
      if (aHTZ_H > 10) {
        return 'big ' + aHTZ_H;
      }
      return 'small ' + aHTZ_H;
    }
    function aoaT3J6(CcHqMM, m2YDIuJ) {
      var N4Eemf;
      N4Eemf = 0;
      for (const item of CcHqMM) {
        if (m2YDIuJ(item)) {
          return N4Eemf;
        }
        N4Eemf++;
      }
      return -1;
    }
    function GPgIgQ(...__p_eyXp) {
      function MvmeD2R(cj8ac0) {
        var hdEeet;
        hdEeet = String(cj8ac0);
        return '"' + hdEeet + '"';
      }
      var z80HZjY;
      var cFd5H4X, d6VElg;
      [cFd5H4X, d6VElg = ', '] = __p_eyXp;
      z80HZjY = [];
      for (const entry of cFd5H4X) {
        z80HZjY.push(MvmeD2R(entry));
      }
      return z80HZjY.join(d6VElg);
    }
    console.log('negative', 'zero', 'odd', 'large even', 'huge even');
    console.log(aoaT3J6([3, 8, 12], x => {
      return x > 5;
    }), aoaT3J6([1], x => {
      return x > 5;
    }));
    console.log(GPgIgQ(['a', 'b']), GPgIgQ([1, 2, 3], '/'));
    console.log(gzflAJ(1, 2, 3), gzflAJ(5, 6));
    console.log(qa6mfQ(true), qa6mfQ(false));
    """
)


#: The file a later version of the obfuscation wrote for the same program, and its deobfuscation.
FLATTENED_TWICE_AGAIN = inspect.cleandoc(
    """
    function* L9Hmk_(vwSDGEv, UOhdtOb, y4WZFZE, rknTMf, I2jooF = {
      ["_H0keXa"]: {}
    }, Dvws4H) {
      while (vwSDGEv + UOhdtOb + y4WZFZE + rknTMf !== -69) {
        with (I2jooF["o7UuCi"] || I2jooF) {
          __p_uWAH: switch (vwSDGEv + UOhdtOb + y4WZFZE + rknTMf) {
            case y4WZFZE - -370:
            case -100:
              return undefined;
            case -225:
            case UOhdtOb - -156:
              return DfHlyQ;
              I2jooF["o7UuCi"] = I2jooF["ZGIwnT"], vwSDGEv += rknTMf - 449, UOhdtOb += y4WZFZE - -220, y4WZFZE += vwSDGEv - -191, rknTMf += y4WZFZE - 160;
              break __p_uWAH;
            case -16:
            case 194:
              return E5c85h;
              I2jooF["o7UuCi"] = I2jooF["X1Me0Be"], y4WZFZE += UOhdtOb - 249, rknTMf += UOhdtOb - 130;
              break __p_uWAH;
            case 198:
            case UOhdtOb - -10:
              [I2jooF["_H0keXa"]["Xqndfy"]] = [-65];
              _H0keXa["_kHQvsT"] = function (...__p_lQvW) {
                return L9Hmk_(-238, 96, -2, -83, {
                  ["_H0keXa"]: I2jooF["_H0keXa"],
                  ["KpqOlUU"]: {}
                }, __p_lQvW)["next"]()["value"];
              };
              _H0keXa["SjWnru4"] = function (...__p_tmI7) {
                return L9Hmk_(303, -217, 230, -534, {
                  ["_H0keXa"]: I2jooF["_H0keXa"],
                  ["nvIdYR0"]: {}
                }, __p_tmI7)["next"]()["value"];
              };
              _H0keXa["qDscIjS"] = function (...__p_Skt3) {
                return L9Hmk_(185, 204, -717, 211, {
                  ["_H0keXa"]: I2jooF["_H0keXa"],
                  ["o2oUlS"]: {}
                }, __p_Skt3)["next"]()["value"];
              };
              _H0keXa["Gb9Abz"] = function (...__p_8FwN) {
                return L9Hmk_(-217, -117, -102, 199, {
                  ["_H0keXa"]: I2jooF["_H0keXa"],
                  ["X1Me0Be"]: {}
                }, __p_8FwN)["next"]()["value"];
              };
              _H0keXa["RFudaG"] = function (...__p_lFhg) {
                return L9Hmk_(18, -296, 172, -10, {
                  ["_H0keXa"]: I2jooF["_H0keXa"],
                  ["ZGIwnT"]: {}
                }, __p_lFhg)["next"]()["value"];
              };
              I2jooF["o7UuCi"] = I2jooF["_H0keXa"], vwSDGEv += y4WZFZE - -378, UOhdtOb += y4WZFZE - -522, y4WZFZE += UOhdtOb - -67, rknTMf += UOhdtOb - 357;
              break __p_uWAH;
            case -17:
            case 172:
              return undefined;
            case rknTMf - 96:
              return undefined;
            case vwSDGEv - 134:
              [ZGIwnT["GiFNZ0"]] = Dvws4H;
              ZGIwnT["LGHkouO"] = function* Bf3LsEJ(EjpZjo, EZG80k, cUYyE3A, CKGR_wY, GtQEKmU = {
                ["YVwDsf"]: {}
              }) {
                while (EjpZjo + EZG80k + cUYyE3A + CKGR_wY !== 46) {
                  with (GtQEKmU["mO2Tfx"] || GtQEKmU) {
                    __p_MTam: switch (EjpZjo + EZG80k + cUYyE3A + CKGR_wY) {
                      case -208:
                      case 182:
                      case EZG80k - -9:
                        GtQEKmU["YVwDsf"]["pMI4eC1"] = ZGIwnT["GiFNZ0"] % (EZG80k + -130) === cUYyE3A + 19 ? 'even' : 'odd';
                        if (ZGIwnT["GiFNZ0"] > EjpZjo + 226) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += EZG80k - -184, EZG80k += cUYyE3A - 325, cUYyE3A += EZG80k - -89;
                          break __p_MTam;
                        } else {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += cUYyE3A - -155, EZG80k += CKGR_wY - 157, cUYyE3A += EZG80k - 326, CKGR_wY += EjpZjo - 9;
                          break __p_MTam;
                        }
                      case GtQEKmU["YVwDsf"]["yBtHyP"] + 189:
                      case -99:
                      case 51:
                        return ZGIwnT["derHsc"] = true, 'zero';
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EZG80k += CKGR_wY - -292, cUYyE3A += CKGR_wY - 386, CKGR_wY += EZG80k - 26;
                        break __p_MTam;
                      case -60:
                      case -168:
                      case 202:
                        [GtQEKmU["YVwDsf"]["yBtHyP"]] = [16];
                        if (ZGIwnT["GiFNZ0"] > EjpZjo + 911) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += cUYyE3A - 119, EZG80k += CKGR_wY - -254, cUYyE3A += CKGR_wY - -20, CKGR_wY += EZG80k - 898;
                          break __p_MTam;
                        } else {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - 88, EZG80k += cUYyE3A - -563, cUYyE3A += EjpZjo - -60, CKGR_wY += cUYyE3A - 995;
                          break __p_MTam;
                        }
                      case GtQEKmU["YVwDsf"]["yBtHyP"] + 378:
                      case -144:
                      case 75:
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - 354, EZG80k += EjpZjo - -96, cUYyE3A += CKGR_wY - -10, CKGR_wY += cUYyE3A - -34;
                        break __p_MTam;
                        if (!(CKGR_wY != -156)) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["D4ORYt"], EZG80k += EjpZjo - 358, cUYyE3A += CKGR_wY - 62, CKGR_wY += EZG80k - -123;
                          break __p_MTam;
                        }
                      case GtQEKmU["YVwDsf"]["yBtHyP"] + 146:
                      case -18:
                        if (ZGIwnT["GiFNZ0"] > 1000) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EZG80k += CKGR_wY - -205, cUYyE3A += CKGR_wY - -191, CKGR_wY += cUYyE3A - 1145;
                          break __p_MTam;
                        } else {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += EZG80k - 14, EZG80k += cUYyE3A - -1067, cUYyE3A += CKGR_wY - -232, CKGR_wY += EZG80k - 1655;
                          break __p_MTam;
                        }
                      case 97:
                      case EjpZjo - -110:
                      case -176:
                        if (ZGIwnT["GiFNZ0"] === 0) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EZG80k += EjpZjo - 119, cUYyE3A += EZG80k - -444, CKGR_wY += EZG80k - -266;
                          break __p_MTam;
                        } else {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EZG80k += cUYyE3A - -12, cUYyE3A += EZG80k - 234, CKGR_wY += EjpZjo - -290;
                          break __p_MTam;
                        }
                      case 175:
                      case -27:
                      default:
                        return ZGIwnT["derHsc"] = true, 'negative';
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - -85, EZG80k += CKGR_wY - 84, CKGR_wY += cUYyE3A - 250;
                        break __p_MTam;
                      case GtQEKmU["YVwDsf"]["yBtHyP"] + 251:
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += EZG80k - -171, EZG80k += cUYyE3A - -372, cUYyE3A += CKGR_wY - -127, CKGR_wY += cUYyE3A - 1222;
                        break __p_MTam;
                      case 30:
                      case -127:
                      case 145:
                        [GtQEKmU["YVwDsf"]["yBtHyP"]] = [-156];
                        if (ZGIwnT["GiFNZ0"] < 0) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - 287, EZG80k += CKGR_wY - -87, cUYyE3A += EZG80k - -111, CKGR_wY += EZG80k - -262;
                          break __p_MTam;
                        } else {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - 45, EZG80k += cUYyE3A - -83, cUYyE3A += EjpZjo - -201, CKGR_wY += EZG80k - -22;
                          break __p_MTam;
                        }
                      case cUYyE3A - -82:
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - -44, EZG80k += cUYyE3A - -719, cUYyE3A += CKGR_wY - -581, CKGR_wY += EjpZjo - 583;
                        break __p_MTam;
                      case 52:
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += CKGR_wY - 688, EZG80k += EjpZjo - -170, cUYyE3A += CKGR_wY - -282, CKGR_wY += EZG80k - 38;
                        break __p_MTam;
                      case cUYyE3A - -294:
                      case 160:
                      case -70:
                        return ZGIwnT["derHsc"] = true, pMI4eC1;
                        GtQEKmU["mO2Tfx"] = GtQEKmU["vwn4R15"], EjpZjo += CKGR_wY - 76, EZG80k += EjpZjo - 325, cUYyE3A += CKGR_wY - 30;
                        break __p_MTam;
                      case cUYyE3A - 142:
                      case -38:
                      case -140:
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += cUYyE3A - 576, EZG80k += EjpZjo - -328, cUYyE3A += CKGR_wY - 219, CKGR_wY += cUYyE3A - -334;
                        break __p_MTam;
                        if (!(CKGR_wY != -(EZG80k + 226))) {
                          GtQEKmU["mO2Tfx"] = GtQEKmU["FoDn_kj"], EZG80k += CKGR_wY - -124, cUYyE3A += EjpZjo - 541, CKGR_wY += EjpZjo - -227;
                          break __p_MTam;
                        }
                      case -248:
                      case -121:
                        return ZGIwnT["derHsc"] = true, 'huge ' + pMI4eC1;
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += EZG80k - 373, EZG80k += EjpZjo - -602, cUYyE3A += CKGR_wY - -829;
                        break __p_MTam;
                      case -212:
                      case CKGR_wY - -921:
                      case 110:
                        return ZGIwnT["derHsc"] = true, 'large ' + pMI4eC1;
                        GtQEKmU["mO2Tfx"] = GtQEKmU["YVwDsf"], EjpZjo += cUYyE3A - 198, EZG80k += cUYyE3A - 828, cUYyE3A += EZG80k - 589, CKGR_wY += EjpZjo - -933;
                        break __p_MTam;
                    }
                  }
                }
              };
              ZGIwnT["derHsc"] = undefined;
              ZGIwnT["DfHlyQ"] = (1, ZGIwnT["LGHkouO"])(-12, -54, UOhdtOb + 304, -(UOhdtOb + 365))["next"]()["value"];
              if (ZGIwnT["derHsc"]) {
                I2jooF["o7UuCi"] = I2jooF["ZGIwnT"], vwSDGEv += UOhdtOb - -61, y4WZFZE += vwSDGEv - -151, rknTMf += UOhdtOb - -918;
                break __p_uWAH;
              } else {
                I2jooF["o7UuCi"] = I2jooF["ZGIwnT"], vwSDGEv += y4WZFZE - 407, UOhdtOb += rknTMf - -217, y4WZFZE += vwSDGEv - 57, rknTMf += vwSDGEv - -431;
                break __p_uWAH;
              }
            default:
            case 202:
            case -104:
              I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += y4WZFZE - 219, UOhdtOb += rknTMf - -97, y4WZFZE += rknTMf - 145, rknTMf += vwSDGEv - 5;
              break __p_uWAH;
            case y4WZFZE - 119:
            case 213:
              return FGX08u;
              I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += rknTMf - -401, UOhdtOb += y4WZFZE - -4, rknTMf += vwSDGEv - 257;
              break __p_uWAH;
            case y4WZFZE - -14:
              return undefined;
            case -5:
            case 208:
            case 205:
              return DfHlyQ;
              I2jooF["o7UuCi"] = I2jooF["ZGIwnT"], UOhdtOb += vwSDGEv - -424, y4WZFZE += vwSDGEv - -9, rknTMf += y4WZFZE - 306;
              break __p_uWAH;
            case I2jooF["_H0keXa"]["Xqndfy"] + -172:
              [X1Me0Be["OjjfsM"], X1Me0Be["B_MNduh"]] = Dvws4H;
              X1Me0Be["Kk21ma"] = function* vUj6ZN4(ZiAr83, TBm7VAe, fA0mcu_ = {
                ["ZoOKfUY"]: {}
              }) {
                while (ZiAr83 + TBm7VAe !== 63) {
                  with (fA0mcu_["TMp5_dO"] || fA0mcu_) {
                    __p_geRJ: switch (ZiAr83 + TBm7VAe) {
                      default:
                      case -127:
                        [fA0mcu_["ZoOKfUY"]["dqxBc8T"], fA0mcu_["ZoOKfUY"]["fjpj4h"], fA0mcu_["ZoOKfUY"]["YLhwqoY"]] = [-59, 98, 201];
                        return X1Me0Be["uOForCl"] = true, -1;
                        fA0mcu_["TMp5_dO"] = fA0mcu_["vGs_ooh"], ZiAr83 += TBm7VAe - 121, TBm7VAe += ZiAr83 - 493;
                        break __p_geRJ;
                      case -22:
                      case -169:
                        [fA0mcu_["ZoOKfUY"]["dqxBc8T"], fA0mcu_["ZoOKfUY"]["fjpj4h"], fA0mcu_["ZoOKfUY"]["YLhwqoY"]] = [-179, -128, -77];
                        ZoOKfUY["hNiB2w"] = ZiAr83 + 11;
                        for (const item of X1Me0Be["OjjfsM"]) {
                          if ((1, X1Me0Be["B_MNduh"])(item)) {
                            return X1Me0Be["uOForCl"] = true, ZoOKfUY["hNiB2w"];
                          }
                          ZoOKfUY["hNiB2w"]++;
                        }
                        fA0mcu_["TMp5_dO"] = fA0mcu_["ZoOKfUY"], ZiAr83 += TBm7VAe - -287, TBm7VAe += ZiAr83 - 310;
                        break __p_geRJ;
                        if (ZiAr83 > -(ZiAr83 + 22)) {
    ;
                          break __p_geRJ;
                        }
                      case fA0mcu_["ZoOKfUY"]["dqxBc8T"] + 388:
                      case 87:
                        return X1Me0Be["uOForCl"] = true, -1;
                        fA0mcu_["TMp5_dO"] = fA0mcu_["l1BEPZk"], ZiAr83 += TBm7VAe - 90;
                        break __p_geRJ;
                      case 144:
                      case -32:
                      case 180:
                        fA0mcu_["TMp5_dO"] = fA0mcu_["ZoOKfUY"], ZiAr83 += TBm7VAe - -85, TBm7VAe += ZiAr83 - 656;
                        break __p_geRJ;
                      case fA0mcu_["ZoOKfUY"]["fjpj4h"] + 291:
                      case -166:
                      case 128:
                        return X1Me0Be["uOForCl"] = true, -1;
                        fA0mcu_["TMp5_dO"] = fA0mcu_["d6dgDj1"], ZiAr83 += TBm7VAe - 44, TBm7VAe += ZiAr83 - 493;
                        break __p_geRJ;
                      case ZiAr83 != -78 && ZiAr83 != -155 && ZiAr83 - -318:
                      case -40:
                      case -176:
                        return X1Me0Be["uOForCl"] = true, -1;
                        fA0mcu_["TMp5_dO"] = fA0mcu_["lgXuLLj"], ZiAr83 += TBm7VAe - -112, TBm7VAe += ZiAr83 - 493;
                        break __p_geRJ;
                    }
                  }
                }
              };
              X1Me0Be["uOForCl"] = undefined;
              X1Me0Be["E5c85h"] = (1, X1Me0Be["Kk21ma"])(-11, -11)["next"]()["value"];
              if (X1Me0Be["uOForCl"]) {
                I2jooF["o7UuCi"] = I2jooF["X1Me0Be"], vwSDGEv += y4WZFZE - -504, UOhdtOb += vwSDGEv - -136, rknTMf += y4WZFZE - 190;
                break __p_uWAH;
              } else {
                I2jooF["o7UuCi"] = I2jooF["X1Me0Be"], vwSDGEv += UOhdtOb - -519, UOhdtOb += rknTMf - -122, y4WZFZE += UOhdtOb - 249, rknTMf += y4WZFZE - 71;
                break __p_uWAH;
              }
            case y4WZFZE - -294:
              [I2jooF["_H0keXa"]["Xqndfy"]] = [197];
              I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += UOhdtOb - 41, UOhdtOb += y4WZFZE - -308, y4WZFZE += rknTMf - 427, rknTMf += UOhdtOb - 726;
              break __p_uWAH;
            case y4WZFZE - 448:
              [nvIdYR0["BLmGHN"], ...nvIdYR0["Kmjc_bL"]] = Dvws4H;
              nvIdYR0["lleLmjP"] = function* vKaZTM9(xrXSmh, swSZWGU, Q341Ei = {
                ["v3xVAFx"]: {}
              }) {
                while (xrXSmh + swSZWGU !== -12) {
                  with (Q341Ei["kMNdaz"] || Q341Ei) {
                    __p_nsB1: switch (xrXSmh + swSZWGU) {
                      case xrXSmh - 37:
                        [Q341Ei["v3xVAFx"]["PDIdjUc"], Q341Ei["v3xVAFx"]["WmXHjtq"]] = [58, 195];
                        v3xVAFx["GphWaC"] = nvIdYR0["BLmGHN"];
                        for (const value of nvIdYR0["Kmjc_bL"]) {
                          v3xVAFx["GphWaC"] += value;
                        }
                        if (v3xVAFx["GphWaC"] > xrXSmh + -199) {
                          Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - 184, swSZWGU += xrXSmh - -222;
                          break __p_nsB1;
                        } else {
                          Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - 395, swSZWGU += xrXSmh - -259;
                          break __p_nsB1;
                        }
                      case 139:
                      case 58:
                      default:
                        return nvIdYR0["aKXZL5N"] = true, 'big ' + GphWaC;
                        Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - 384, swSZWGU += xrXSmh - -465;
                        break __p_nsB1;
                      case Q341Ei["v3xVAFx"]["WmXHjtq"] + -444:
                      case 197:
                        Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - -26, swSZWGU += xrXSmh - -561;
                        break __p_nsB1;
                      case xrXSmh - -110:
                      case -165:
                      case -197:
                        Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - 405, swSZWGU += xrXSmh - -528;
                        break __p_nsB1;
                      case -49:
                      case Q341Ei["v3xVAFx"]["PDIdjUc"] + 134:
                        Q341Ei["kMNdaz"] = Q341Ei["YWzJfuI"], xrXSmh += swSZWGU - 619;
                        break __p_nsB1;
                      case Q341Ei["v3xVAFx"]["WmXHjtq"] + -419:
                      case -176:
                        return nvIdYR0["aKXZL5N"] = true, 'small ' + GphWaC;
                        Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], swSZWGU += xrXSmh - -639;
                        break __p_nsB1;
                      case xrXSmh - -35:
                        [Q341Ei["v3xVAFx"]["PDIdjUc"], Q341Ei["v3xVAFx"]["WmXHjtq"]] = [-162, 137];
                        return nvIdYR0["aKXZL5N"] = true, 'big ' + GphWaC;
                        Q341Ei["kMNdaz"] = Q341Ei["v3xVAFx"], xrXSmh += swSZWGU - 330, swSZWGU += xrXSmh - -603;
                        break __p_nsB1;
                    }
                  }
                }
              };
              nvIdYR0["aKXZL5N"] = undefined;
              I2jooF["o7UuCi"] = I2jooF["nvIdYR0"], vwSDGEv += y4WZFZE - 488, rknTMf += y4WZFZE - -298;
              break __p_uWAH;
            case -222:
            case -200:
            case vwSDGEv != 185 && vwSDGEv - 302:
              return hYKNtS_;
              I2jooF["o7UuCi"] = I2jooF["o2oUlS"], UOhdtOb += rknTMf - 632, y4WZFZE += vwSDGEv - -644, rknTMf += UOhdtOb - 236;
              break __p_uWAH;
            case 140:
              return TLQp9V;
              I2jooF["o7UuCi"] = I2jooF["nvIdYR0"], vwSDGEv += rknTMf - 277, UOhdtOb += y4WZFZE - -75;
              break __p_uWAH;
            case I2jooF["_H0keXa"]["Xqndfy"] + 139:
              return undefined;
            case I2jooF["_H0keXa"]["Xqndfy"] + 141:
              console["log"]((1, RFudaG)(-5), (1, RFudaG)(0), (1, RFudaG)(7), (1, RFudaG)(250), (1, RFudaG)(5000));
              console["log"]((1, Gb9Abz)([3, 8, 12], x => {
                return x > 5;
              }), (1, Gb9Abz)([1], x => {
                return x > 5;
              }));
              I2jooF["o7UuCi"] = I2jooF["_H0keXa"], vwSDGEv += y4WZFZE - 205, UOhdtOb += vwSDGEv - 67, y4WZFZE += UOhdtOb - -357, rknTMf += vwSDGEv - 234;
              break __p_uWAH;
            case 52:
              I2jooF["nvIdYR0"]["TLQp9V"] = (1, lleLmjP)(209, -37)["next"]()["value"];
              if (aKXZL5N) {
                I2jooF["o7UuCi"] = I2jooF["nvIdYR0"], UOhdtOb += vwSDGEv - -307, y4WZFZE += UOhdtOb - 399;
                break __p_uWAH;
              } else {
                I2jooF["o7UuCi"] = I2jooF["nvIdYR0"], vwSDGEv += UOhdtOb - 66, UOhdtOb += y4WZFZE - -163, y4WZFZE += UOhdtOb - 440;
                break __p_uWAH;
              }
            case -204:
              return undefined;
              if (rknTMf > 204) {
                I2jooF["o7UuCi"] = I2jooF["_H0keXa"], vwSDGEv += rknTMf - -46, UOhdtOb += vwSDGEv - -1, y4WZFZE += UOhdtOb - -130, rknTMf += y4WZFZE - 42;
                break __p_uWAH;
              }
            case UOhdtOb - -32:
            case -150:
            case -180:
              console["log"]((1, RFudaG)(-5), (1, RFudaG)(0), (1, RFudaG)(7), (1, RFudaG)(250), (1, RFudaG)(5000));
              console["log"]((1, Gb9Abz)([3, 8, 12], x => {
                return x > 5;
              }), (1, Gb9Abz)([1], x => {
                return x > 5;
              }));
              I2jooF["o7UuCi"] = I2jooF["_H0keXa"], UOhdtOb += rknTMf - 133, y4WZFZE += rknTMf - -319, rknTMf += vwSDGEv - 247;
              break __p_uWAH;
            case -117:
              [o2oUlS["vpKs618"], o2oUlS["uZRGvl"] = ', '] = Dvws4H;
              o2oUlS["KmqxwmC"] = function* XUqJBk0(CcFKsQ, w9Truk, gEC2Cb, jwGaSJQ, MQHwQL = {
                ["JvxhoX"]: {}
              }, IKEZOf) {
                while (CcFKsQ + w9Truk + gEC2Cb + jwGaSJQ !== 116) {
                  with (MQHwQL["rwjLsrL"] || MQHwQL) {
                    __p_X7Ug: switch (CcFKsQ + w9Truk + gEC2Cb + jwGaSJQ) {
                      case gEC2Cb - -265:
                        MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += jwGaSJQ - 158, w9Truk += CcFKsQ - -31, gEC2Cb += CcFKsQ - -17, jwGaSJQ += gEC2Cb - 609;
                        break __p_X7Ug;
                      case CcFKsQ - 114:
                        return Fkiv9Ni;
                        MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += gEC2Cb - 18, w9Truk += jwGaSJQ - -276, gEC2Cb += CcFKsQ - 403;
                        break __p_X7Ug;
                      case w9Truk - 158:
                        MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += jwGaSJQ - -319, w9Truk += jwGaSJQ - -263, gEC2Cb += jwGaSJQ - 100, jwGaSJQ += CcFKsQ - 202;
                        break __p_X7Ug;
                      case -237:
                      case gEC2Cb - -55:
                      case -17:
                        for (const entry of o2oUlS["vpKs618"]) {
                          FMyKiG["push"]((1, dgVoWM)(entry));
                        }
                        return o2oUlS["t_lm1wN"] = true, FMyKiG["join"](o2oUlS["uZRGvl"]);
                        MQHwQL["rwjLsrL"] = MQHwQL["Yyh9Oe"], CcFKsQ += gEC2Cb - -334, w9Truk += jwGaSJQ - 18, gEC2Cb += CcFKsQ - -148;
                        break __p_X7Ug;
                      case w9Truk - 51:
                        [MQHwQL["JvxhoX"]["BW25i9"]] = [-127];
                        MQHwQL["rwjLsrL"] = MQHwQL["scRteis"], CcFKsQ += w9Truk - 121, w9Truk += jwGaSJQ - 52, gEC2Cb += w9Truk - -246, jwGaSJQ += CcFKsQ - 64;
                        break __p_X7Ug;
                        if (CcFKsQ > -(w9Truk + 152)) {
                          MQHwQL["rwjLsrL"] = MQHwQL["JvxhoX"], CcFKsQ += w9Truk - 175, w9Truk += gEC2Cb - 125, gEC2Cb += jwGaSJQ - -8, jwGaSJQ += w9Truk - -231;
                          break __p_X7Ug;
                        }
                      case w9Truk - 363:
                      case 48:
                      case -247:
                        return undefined;
                      case 112:
                      case gEC2Cb - 205:
                        [MQHwQL["JvxhoX"]["BW25i9"]] = [124];
                        JvxhoX["dgVoWM"] = function (...__p_yxwK) {
                          return XUqJBk0(78, 7, -12, 4, {
                            ["JvxhoX"]: MQHwQL["JvxhoX"],
                            ["Si3i60"]: {}
                          }, __p_yxwK)["next"]()["value"];
                        };
                        JvxhoX["FMyKiG"] = [];
                        MQHwQL["rwjLsrL"] = MQHwQL["JvxhoX"], CcFKsQ += gEC2Cb - 66, w9Truk += gEC2Cb - -222, gEC2Cb += jwGaSJQ - 125, jwGaSJQ += w9Truk - -95;
                        break __p_X7Ug;
                      case CcFKsQ - -275:
                      case 101:
                      case -148:
                        MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += w9Truk - -27, w9Truk += CcFKsQ - 197, gEC2Cb += w9Truk - 569, jwGaSJQ += gEC2Cb - -105;
                        break __p_X7Ug;
                      case -159:
                      default:
                        MQHwQL["rwjLsrL"] = MQHwQL["nxeyUEl"], CcFKsQ += gEC2Cb - -359, w9Truk += CcFKsQ - 380, gEC2Cb += CcFKsQ - 276, jwGaSJQ += w9Truk - 111;
                        break __p_X7Ug;
                        if (CcFKsQ > -(CcFKsQ + 494)) {
                          MQHwQL["rwjLsrL"] = MQHwQL["JvxhoX"], CcFKsQ += gEC2Cb - -305, w9Truk += CcFKsQ - 92, gEC2Cb += CcFKsQ - 503, jwGaSJQ += CcFKsQ - 426;
                          break __p_X7Ug;
                        }
                      case -156:
                      case MQHwQL["JvxhoX"]["BW25i9"] + -47:
                      case -180:
                        [Si3i60["ZBiLRWQ"]] = IKEZOf;
                        Si3i60["CW7i03Q"] = function* HnibRHD(Oed4EX, YaynH0Y, JydwWG, aooxDp = {
                          ["hBFIb7"]: {}
                        }) {
                          while (Oed4EX + YaynH0Y + JydwWG !== -49) {
                            with (aooxDp["Tn01Vf"] || aooxDp) {
                              __p_6TDn: switch (Oed4EX + YaynH0Y + JydwWG) {
                                case aooxDp["hBFIb7"]["Z54vbQb"] + 241:
                                  aooxDp["Tn01Vf"] = aooxDp["hBFIb7"], Oed4EX += JydwWG - -522, YaynH0Y += Oed4EX - 549, JydwWG += Oed4EX - 850;
                                  break __p_6TDn;
                                case aooxDp["hBFIb7"]["z_vgav"] + 173:
                                  aooxDp["Tn01Vf"] = aooxDp["tB5TodY"], Oed4EX += JydwWG - -323, YaynH0Y += Oed4EX - 379;
                                  break __p_6TDn;
                                default:
                                  [aooxDp["hBFIb7"]["Z54vbQb"], aooxDp["hBFIb7"]["z_vgav"]] = [-247, 20];
                                  aooxDp["Tn01Vf"] = aooxDp["nL6wZoe"], Oed4EX += YaynH0Y - -374, YaynH0Y += JydwWG - 248, JydwWG += YaynH0Y - 446;
                                  break __p_6TDn;
                                case aooxDp["hBFIb7"]["Z54vbQb"] + -72:
                                  return Si3i60["qMtd_C5"] = true, VoLhCmv + rrJ0ZV + VoLhCmv;
                                  aooxDp["Tn01Vf"] = aooxDp["Rw6g5h"], Oed4EX += JydwWG - -499, YaynH0Y += Oed4EX - 253;
                                  break __p_6TDn;
                                case -170:
                                case YaynH0Y != 45 && YaynH0Y - -16:
                                  aooxDp["Tn01Vf"] = aooxDp["LaHp_Tv"], Oed4EX += JydwWG - -323, YaynH0Y += JydwWG - -568;
                                  break __p_6TDn;
                                case 193:
                                  [aooxDp["hBFIb7"]["Z54vbQb"], aooxDp["hBFIb7"]["z_vgav"]] = [-169, -112];
                                  hBFIb7["VoLhCmv"] = '"';
                                  hBFIb7["rrJ0ZV"] = String(Si3i60["ZBiLRWQ"]);
                                  aooxDp["Tn01Vf"] = aooxDp["hBFIb7"], Oed4EX += YaynH0Y - -249, YaynH0Y += JydwWG - 527, JydwWG += YaynH0Y - 521;
                                  break __p_6TDn;
                                case -216:
                                case aooxDp["hBFIb7"]["Z54vbQb"] + 397:
                                  aooxDp["Tn01Vf"] = aooxDp["hBFIb7"], Oed4EX += YaynH0Y - 341;
                                  break __p_6TDn;
                                case YaynH0Y - -186:
                                case 204:
                                case -200:
                                  aooxDp["Tn01Vf"] = aooxDp["hBFIb7"], Oed4EX += YaynH0Y - 39, YaynH0Y += Oed4EX - -414, JydwWG += YaynH0Y - 377;
                                  break __p_6TDn;
                              }
                            }
                          }
                        };
                        Si3i60["qMtd_C5"] = undefined;
                        Si3i60["Fkiv9Ni"] = (gEC2Cb + 13, Si3i60["CW7i03Q"])(-(w9Truk + 246), 237, gEC2Cb + 221)["next"]()["value"];
                        if (Si3i60["qMtd_C5"]) {
                          MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += w9Truk - -91, w9Truk += gEC2Cb - -143, jwGaSJQ += w9Truk - 382;
                          break __p_X7Ug;
                        } else {
                          MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += w9Truk - -61, w9Truk += gEC2Cb - -179, gEC2Cb += jwGaSJQ - 261, jwGaSJQ += CcFKsQ - 390;
                          break __p_X7Ug;
                        }
                        if (jwGaSJQ > w9Truk + -3) {
                          MQHwQL["rwjLsrL"] = MQHwQL["Si3i60"], CcFKsQ += gEC2Cb - -110, w9Truk += CcFKsQ - 45, jwGaSJQ += w9Truk - 382;
                          break __p_X7Ug;
                        }
                    }
                  }
                }
              };
              o2oUlS["t_lm1wN"] = undefined;
              o2oUlS["hYKNtS_"] = (1, o2oUlS["KmqxwmC"])(200, -249, 12, -156)["next"]()["value"];
              if (o2oUlS["t_lm1wN"]) {
                I2jooF["o7UuCi"] = I2jooF["o2oUlS"], vwSDGEv += UOhdtOb - 86;
                break __p_uWAH;
              } else {
                I2jooF["o7UuCi"] = I2jooF["o2oUlS"], vwSDGEv += UOhdtOb - 86, UOhdtOb += y4WZFZE - -296, y4WZFZE += rknTMf - -736, rknTMf += y4WZFZE - 683;
                break __p_uWAH;
              }
            case rknTMf - 144:
              [KpqOlUU["MktJ21"]] = Dvws4H;
              KpqOlUU["TQCfM5"] = function* nVNJIr(yXFZDK, yn4AUjy, wwVayk, glZC0Q8 = {
                ["DSiJjX"]: {}
              }, MKIOehK) {
                while (yXFZDK + yn4AUjy + wwVayk !== 64) {
                  with (glZC0Q8["zWknfR"] || glZC0Q8) {
                    __p_5fg8: switch (yXFZDK + yn4AUjy + wwVayk) {
                      case -105:
                        [glZC0Q8["DSiJjX"]["DGdHV_"], glZC0Q8["DSiJjX"]["DHOP_b"]] = [-72, -38];
                        DSiJjX["TaGsKW"] = 'none';
                        if (KpqOlUU["MktJ21"]) {
                          glZC0Q8["zWknfR"] = glZC0Q8["DSiJjX"], yXFZDK += yn4AUjy - 86, yn4AUjy += yXFZDK - 92, wwVayk += yXFZDK - 16;
                          break __p_5fg8;
                        } else {
                          glZC0Q8["zWknfR"] = glZC0Q8["DSiJjX"], yXFZDK += yn4AUjy - 202, yn4AUjy += wwVayk - 13, wwVayk += yXFZDK - -395;
                          break __p_5fg8;
                        }
                      case yn4AUjy - -141:
                        return WC7Xc6f;
                        glZC0Q8["zWknfR"] = glZC0Q8["UHBg4ET"], yXFZDK += wwVayk - 477, yn4AUjy += wwVayk - -349, wwVayk += yn4AUjy - 193;
                        break __p_5fg8;
                      case 138:
                        [glZC0Q8["DSiJjX"]["DGdHV_"], glZC0Q8["DSiJjX"]["DHOP_b"]] = [-218, 31];
                        glZC0Q8["zWknfR"] = glZC0Q8["x6Y821r"], yXFZDK += wwVayk - -121, yn4AUjy += wwVayk - 213, wwVayk += yn4AUjy - 488;
                        break __p_5fg8;
                      case glZC0Q8["DSiJjX"]["DHOP_b"] + -64:
                      case -52:
                        return undefined;
                      case -231:
                        glZC0Q8["DSiJjX"]["zjBuB2K"] = '!';
                        return KpqOlUU["BtNG7J"] = true, TaGsKW + zjBuB2K;
                        glZC0Q8["zWknfR"] = glZC0Q8["K85z4rj"], yXFZDK += yn4AUjy - -243, yn4AUjy += wwVayk - -531, wwVayk += yXFZDK - 160;
                        break __p_5fg8;
                      case yn4AUjy - 79:
                      case 34:
                      default:
                        glZC0Q8["XYtgwdz"] = {};
                        glZC0Q8["XYtgwdz"]["UzxcTG"] = function (...__p_Wmjg) {
                          return nVNJIr(27, -338, 133, {
                            ["XYtgwdz"]: glZC0Q8["XYtgwdz"],
                            ["DSiJjX"]: glZC0Q8["DSiJjX"],
                            ["UHBg4ET"]: {}
                          }, __p_Wmjg)["next"]()["value"];
                        };
                        TaGsKW = (1, glZC0Q8["XYtgwdz"]["UzxcTG"])(yXFZDK + -125);
                        glZC0Q8["zWknfR"] = glZC0Q8["DSiJjX"], yXFZDK += wwVayk - -91, yn4AUjy += yXFZDK - 380, wwVayk += yXFZDK - -283;
                        break __p_5fg8;
                      case wwVayk - 226:
                      case -168:
                      case 170:
                        glZC0Q8["zWknfR"] = glZC0Q8["O3cj5cJ"], yXFZDK += yn4AUjy - -439, yn4AUjy += wwVayk - 213, wwVayk += yXFZDK - 700;
                        break __p_5fg8;
                      case -178:
                      case -214:
                        [UHBg4ET["w7WZ2zl"]] = MKIOehK;
                        UHBg4ET["JNIAwV"] = function* A5CxnT(RtgbGU_, NsdxI_, zQq62mA, WpBu1Y, Dv6zj5 = {
                          ["HCHydC4"]: {}
                        }) {
                          while (RtgbGU_ + NsdxI_ + zQq62mA + WpBu1Y !== -208) {
                            with (Dv6zj5["Rc_X8N"] || Dv6zj5) {
                              __p_rayw: switch (RtgbGU_ + NsdxI_ + zQq62mA + WpBu1Y) {
                                case WpBu1Y - -127:
                                case 97:
                                default:
                                  [Dv6zj5["HCHydC4"]["W4WtEr"], Dv6zj5["HCHydC4"]["qv3Laj0"], Dv6zj5["HCHydC4"]["DZ_gq5B"]] = [-139, -10, -220];
                                  HCHydC4["fRIB7n"] = UHBg4ET["w7WZ2zl"] * 2;
                                  HCHydC4["ttVx2nc"] = HCHydC4["fRIB7n"] + '';
                                  return UHBg4ET["eAAvv7"] = true, HCHydC4["ttVx2nc"];
                                  RtgbGU_ += zQq62mA - 404, NsdxI_ += WpBu1Y - -257, zQq62mA += WpBu1Y - 679, WpBu1Y += RtgbGU_ - -63;
                                  break __p_rayw;
                                case -54:
                                  Dv6zj5["Rc_X8N"] = Dv6zj5["os7g8pC"], RtgbGU_ += zQq62mA - 226, NsdxI_ += WpBu1Y - 87, zQq62mA += NsdxI_ - -712, WpBu1Y += zQq62mA - 669;
                                  break __p_rayw;
                                case -198:
                                  Dv6zj5["Rc_X8N"] = Dv6zj5["F0Tu4I"], RtgbGU_ += zQq62mA - 347, NsdxI_ += zQq62mA - 65, zQq62mA += NsdxI_ - -436, WpBu1Y += zQq62mA - 404;
                                  break __p_rayw;
                                case WpBu1Y - -27:
                                case 220:
                                  if (!(NsdxI_ == NsdxI_ + 292)) {
                                    Dv6zj5["Rc_X8N"] = Dv6zj5["HCHydC4"], NsdxI_ += zQq62mA - -89, WpBu1Y += NsdxI_ - 552;
                                    break __p_rayw;
                                  }
                                case zQq62mA - 298:
                                  Dv6zj5["Rc_X8N"] = Dv6zj5["QygEv7"], RtgbGU_ += zQq62mA - 400, NsdxI_ += RtgbGU_ - -80, zQq62mA += WpBu1Y - -828, WpBu1Y += NsdxI_ - -567;
                                  break __p_rayw;
                                case 147:
                                case -226:
                                  [Dv6zj5["HCHydC4"]["W4WtEr"], Dv6zj5["HCHydC4"]["qv3Laj0"], Dv6zj5["HCHydC4"]["DZ_gq5B"]] = [90, -126, 2];
                                  Dv6zj5["Rc_X8N"] = Dv6zj5["b4Ep2Y"], RtgbGU_ += NsdxI_ - 607, NsdxI_ += RtgbGU_ - -61, zQq62mA += NsdxI_ - -774, WpBu1Y += RtgbGU_ - -333;
                                  break __p_rayw;
                              }
                            }
                          }
                        };
                        UHBg4ET["eAAvv7"] = undefined;
                        UHBg4ET["WC7Xc6f"] = (1, UHBg4ET["JNIAwV"])(-(yXFZDK + 216), -124, yXFZDK + 467, yXFZDK + 2)["next"]()["value"];
                        if (UHBg4ET["eAAvv7"]) {
                          glZC0Q8["zWknfR"] = glZC0Q8["UHBg4ET"], yXFZDK += yn4AUjy - -317, wwVayk += yn4AUjy - -340;
                          break __p_5fg8;
                        } else {
                          glZC0Q8["zWknfR"] = glZC0Q8["UHBg4ET"], yXFZDK += yn4AUjy - 25, yn4AUjy += wwVayk - -351, wwVayk += yn4AUjy - 191;
                          break __p_5fg8;
                        }
                        if (yXFZDK > 27) {
                          glZC0Q8["zWknfR"] = glZC0Q8["DSiJjX"], yXFZDK += wwVayk - 32, yn4AUjy += yXFZDK - -247, wwVayk += yn4AUjy - 377;
                          break __p_5fg8;
                        }
                      case yXFZDK - -391:
                        return WC7Xc6f;
                        glZC0Q8["zWknfR"] = glZC0Q8["UHBg4ET"], yXFZDK += wwVayk - 232, yn4AUjy += yXFZDK - -259, wwVayk += yn4AUjy - 226;
                        break __p_5fg8;
                    }
                  }
                }
              };
              KpqOlUU["BtNG7J"] = undefined;
              KpqOlUU["FGX08u"] = (1, KpqOlUU["TQCfM5"])(213, 1, -319)["next"]()["value"];
              if (KpqOlUU["BtNG7J"]) {
                I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += y4WZFZE - -27, UOhdtOb += y4WZFZE - -83, y4WZFZE += rknTMf - -48;
                break __p_uWAH;
              } else {
                I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += rknTMf - -426, UOhdtOb += vwSDGEv - 57, y4WZFZE += UOhdtOb - 179, rknTMf += vwSDGEv - 257;
                break __p_uWAH;
              }
            case 106:
            case 235:
            case -134:
              console["log"]((1, qDscIjS)(['a', 'b']), (1, qDscIjS)([1, y4WZFZE + -164, 3], '/'));
              console["log"]((1, SjWnru4)(1, 2, 3), (1, SjWnru4)(5, 6));
              return console["log"]((1, _kHQvsT)(true), (1, _kHQvsT)(false));
              I2jooF["o7UuCi"] = I2jooF["yDeBXwn"], vwSDGEv += y4WZFZE - 246, y4WZFZE += UOhdtOb - -20;
              break __p_uWAH;
            case -82:
              I2jooF["o7UuCi"] = I2jooF["VBs_hSC"], vwSDGEv += rknTMf - -393, UOhdtOb += y4WZFZE - -78, y4WZFZE += rknTMf - 447, rknTMf += UOhdtOb - -137;
              break __p_uWAH;
              if (!(UOhdtOb != -221)) {
                I2jooF["o7UuCi"] = I2jooF["KpqOlUU"], vwSDGEv += rknTMf - 5, UOhdtOb += rknTMf - -41, y4WZFZE += vwSDGEv - -316, rknTMf += vwSDGEv - -260;
                break __p_uWAH;
              }
            case UOhdtOb - -294:
            case 10:
            case -94:
              console["log"]((1, qDscIjS)(['a', 'b']), (1, qDscIjS)([1, 2, 3], '/'));
              console["log"]((1, SjWnru4)(1, 2, 3), (1, SjWnru4)(5, 6));
              return console["log"]((1, _kHQvsT)(true), (1, _kHQvsT)(false));
              I2jooF["o7UuCi"] = I2jooF["tjOUm4"], vwSDGEv += UOhdtOb - -157, UOhdtOb += vwSDGEv - -13, y4WZFZE += rknTMf - 42, rknTMf += y4WZFZE - 390;
              break __p_uWAH;
          }
        }
      }
    }
    L9Hmk_(45, -198, -238, 203)["next"]()["value"];
    """
)

FLATTENED_TWICE_AGAIN_DEOBFUSCATED = inspect.cleandoc(
    """
    function qDscIjS(...__p_Skt3) {
      function dgVoWM(ZBiLRWQ) {
        var rrJ0ZV;
        rrJ0ZV = String(ZBiLRWQ);
        return '"' + rrJ0ZV + '"';
      }
      var FMyKiG;
      var uZRGvl, vpKs618;
      [vpKs618, uZRGvl = ', '] = __p_Skt3;
      FMyKiG = [];
      for (const entry of vpKs618) {
        FMyKiG.push(dgVoWM(entry));
      }
      return FMyKiG.join(uZRGvl);
    }
    function _kHQvsT(MktJ21) {
      var TaGsKW;
      var XYtgwdz;
      TaGsKW = 'none';
      if (MktJ21) {
        XYtgwdz = {};
        XYtgwdz.UzxcTG = function(w7WZ2zl) {
          w7WZ2zl * 2;
          w7WZ2zl * 2 + '';
          return w7WZ2zl * 2 + '';
        };
        TaGsKW = (1, XYtgwdz.UzxcTG)(3);
      }
      return TaGsKW + '!';
    }
    function SjWnru4(BLmGHN, ...Kmjc_bL) {
      var GphWaC;
      GphWaC = BLmGHN;
      for (const value of Kmjc_bL) {
        GphWaC += value;
      }
      if (GphWaC > 10) {
        return 'big ' + GphWaC;
      }
      return 'small ' + GphWaC;
    }
    function Gb9Abz(OjjfsM, B_MNduh) {
      var hNiB2w;
      hNiB2w = 0;
      for (const item of OjjfsM) {
        if (B_MNduh(item)) {
          return hNiB2w;
        }
        hNiB2w++;
      }
      return -1;
    }
    console.log('negative', 'zero', 'odd', 'large even', 'huge even');
    console.log(Gb9Abz([3, 8, 12], x => {
      return x > 5;
    }), Gb9Abz([1], x => {
      return x > 5;
    }));
    console.log(qDscIjS(['a', 'b']), qDscIjS([1, 2, 3], '/'));
    console.log(SjWnru4(1, 2, 3), SjWnru4(5, 6));
    console.log(_kHQvsT(true), _kHQvsT(false));
    """
)


class TestTheFilesTheObfuscationWrote(TestBase):

    def test_the_file_of_the_first_version_reads_as_pinned(self):
        self.assertEqual(deobfuscated(FLATTENED_TWICE), FLATTENED_TWICE_DEOBFUSCATED)

    def test_the_file_of_the_later_version_reads_as_pinned(self):
        self.assertEqual(deobfuscated(FLATTENED_TWICE_AGAIN), FLATTENED_TWICE_AGAIN_DEOBFUSCATED)
