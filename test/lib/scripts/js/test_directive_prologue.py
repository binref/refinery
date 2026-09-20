"""
Where strict mode comes from, and whether a deobfuscation leaves it where it was.

A `'use strict'` is the Use Strict Directive only by virtue of its position: it must be a string
literal standing in the run of string-literal statements that a Script, a function body or a class
static block opens with. A body that merely holds a statement list — a plain block, the body of a
`try`, a `catch` or a loop, a labelled statement, a `switch` case — reads no Directive Prologue at
all, and a `'use strict'` written at the head of one is an ordinary statement that computes a string
and discards it. Everything a strict body encloses is strict in turn, and every part of a class
definition is strict whatever encloses it.

Node decides all of it, through four probes and no reading of the specification.

The first is an octal literal. It is a number where the code around it is sloppy and a SyntaxError
where that code is strict, so writing one below a `'use strict'` asks the engine which mode it
compiled that position in: a program Node refuses is one where the directive was read as such, and a
program it reads is one where the directive was an ordinary statement. The probe is a fact about
where a piece of code stands, so it is the same question
`refinery.lib.scripts.js.strict.strict_mode_at` answers of the node standing there.

The second is a parameter list. A function whose parameters are anything but plain identifiers may
hold no Use Strict Directive at all, so `function f(a = 1) { 'use strict'; }` is a SyntaxError while
`function f(a) { 'use strict'; }` is a program. That is the one place the language says out loud
where a directive is permitted, and it is what
`refinery.lib.scripts.js.strict.has_simple_parameters` is asked for.

The third is the name `eval`, which strict code may not bind. An octal literal has to be written
where an expression goes, and the region a function body's directive governs reaches two places that
are not expression positions at all: the name the function binds and its parameter list. Node
refuses to read a program that binds `eval` in either, so writing the name there asks the same
question of a position no number can stand in.

The fourth is what a running program says about itself. The three above ask whether a text is a
program at all, which decides nothing about a file that stays a program and changes what it does. A
plain call passes no receiver, so `this` in the callee is `undefined` where the call stands in
strict code and the global object where it stands in sloppy code, and a rewrite that moves the mode
of a body is a rewrite that moves what that expression answers. Every before-and-after comparison
here is written around it, since a file handed back to an analyst has to run the way the file
handed over ran, and not merely parse.

A class static block is the one body no probe of the first three reaches: class code is strict
whatever stands at the head of it, so the directive there decides nothing and both spellings of the
program are refused alike. It is recorded with that control beside it, and the fourth probe answers
`true` there whatever a rewrite does to its prologue.

SECURITY: every snippet here is hand-authored and benign, and running it is what makes the engine
the oracle. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import unittest

from typing import Sequence

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    behavior,
    completion_values,
    deobfuscate_source,
    host_behavior,
    node_executable,
)
from test.lib.scripts.js.analysis.test_differential import (
    SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING,
    SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE,
    a_file_holding_an_octal_literal_opening_with,
    a_function_body_opening_with,
    a_script_opening_with,
    a_script_whose_directive_stands_below,
)

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsNumericLiteral,
    JsScript,
    JsStringLiteral,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import (
    declares_use_strict,
    directive_prologue,
    has_simple_parameters,
    is_prologue_host,
    is_use_strict_directive,
    joins_directive_prologue,
    strict_mode_at,
)
from refinery.units.scripting.js import js

#: What `test.lib.scripts.js.analysis.differential.completion_values` reports for a text Node does
#: not read as a program at all.
NOT_A_PROGRAM = 'throw SyntaxError'

#: The Use Strict Directive as it is written into each program below, so that the same program
#: without it is the one this text is taken back out of.
THE_DIRECTIVE = "'use strict'; "

#: A program that writes the directive at the head of a body a Directive Prologue opens, with an
#: octal literal below it. Node refuses every one of them, and reads every one of them once the
#: directive is removed.
A_BODY_A_PROLOGUE_OPENS = {
    'a script'               : "'use strict'; 010;",
    'a function declaration' : "function f() { 'use strict'; 010; }",
    'a function expression'  : "var f = function () { 'use strict'; 010; };",
    'an arrow with a block'  : "var f = () => { 'use strict'; 010; };",
    'a method'               : "var o = { m() { 'use strict'; 010; } };",
    'a getter'               : "var o = { get g() { 'use strict'; 010; } };",
    'a setter'               : "var o = { set s(v) { 'use strict'; 010; } };",
    'a generator'            : "function* g() { 'use strict'; 010; }",
    'an async function'      : "async function h() { 'use strict'; 010; }",
    'a nested function'      : "function f() { function g() { 'use strict'; 010; } }",
}

#: A program that writes the directive at the head of a statement list no Directive Prologue opens.
#: Node reads every one of them, with and without the directive: the statement is a string that is
#: computed and discarded, and the octal literal below it stands in sloppy code.
A_BODY_NO_PROLOGUE_OPENS = {
    'a plain block'          : "{ 'use strict'; 010; }",
    'an if branch'           : "if (1) { 'use strict'; 010; }",
    'an else branch'         : "if (0) ; else { 'use strict'; 010; }",
    'a try block'            : "try { 'use strict'; 010; } catch (e) {}",
    'a catch block'          : "try {} catch (e) { 'use strict'; 010; }",
    'a finally block'        : "try {} finally { 'use strict'; 010; }",
    'a for body'             : "for (;;) { 'use strict'; 010; break; }",
    'a for-in body'          : "for (var k in {}) { 'use strict'; 010; }",
    'a for-of body'          : "for (var v of []) { 'use strict'; 010; }",
    'a while body'           : "while (0) { 'use strict'; 010; }",
    'a do-while body'        : "do { 'use strict'; 010; } while (0);",
    'a switch case'          : "switch (1) { case 1: 'use strict'; 010; }",
    'a switch default'       : "switch (1) { default: 'use strict'; 010; }",
    'a labelled block'       : "L: { 'use strict'; 010; }",
    'a with block'           : "with ({}) { 'use strict'; 010; }",
    'a block inside a body'  : "function f() { { 'use strict'; 010; } }",
}

#: The one body whose directive neither probe reaches. A class static block opens a Directive
#: Prologue, and every part of a class definition is strict already, so Node refuses this program
#: and refuses it just the same with the directive taken back out.
A_CLASS_STATIC_BLOCK = "class C { static { 'use strict'; 010; } }"

#: A position an octal literal is written at, mapped to whether the code there is strict. Nothing
#: below declares a mode: each of these is a class, whose every part is strict however sloppy the
#: file around it is, or a body nested inside one that declares it.
AN_OCTAL_LITERAL_STANDING_IN = {
    'a sloppy script'                    : ('010;', False),
    'a sloppy function body'             : ('function f() { 010; }', False),
    'a strict script'                    : ("'use strict'; 010;", True),
    'a function inside a strict script'  : ("'use strict'; function f() { 010; }", True),
    'an arrow inside a strict script'    : ("'use strict'; var f = () => 010;", True),
    'a block inside a strict script'     : ("'use strict'; { 010; }", True),
    'a function inside a strict body'    : (
        "function f() { 'use strict'; function g() { 010; } }", True),
    'a catch inside a strict body'       : (
        "function f() { 'use strict'; try {} catch (e) { 010; } }", True),
    'a class method'                     : ('class C { m() { 010; } }', True),
    'a class field initializer'          : ('class C { p = 010; }', True),
    'a class static block'               : ('class C { static { 010; } }', True),
    'a class heritage clause'            : ('class C extends (010, Object) {}', True),
    'a class computed key'               : ('class C { [010]() {} }', True),
    'a function inside a class method'   : ('class C { m() { function g() { 010; } } }', True),
    'a class expression method'          : ('var C = class { m() { 010; } };', True),
    'a script below a strict function'   : ("function f() { 'use strict'; } 010;", False),
    'a script below a block holding one' : ("{ 'use strict'; } 010;", False),
    'a body below a block holding one'   : ("function f() { { 'use strict'; } 010; }", False),
}

#: A program that binds the name `eval` inside the code a function body's Use Strict Directive
#: governs. Strict code may bind neither `eval` nor `arguments`, so Node refuses every one of these,
#: and reads every one of them once the directive is taken back out.
A_BINDING_THE_DIRECTIVE_GOVERNS = {
    'the name of a declaration'      : "function eval() { 'use strict'; }",
    'the name of an expression'      : "var f = function eval() { 'use strict'; };",
    'the name of a generator'        : "function* eval() { 'use strict'; }",
    'the name of an async function'  : "async function eval() { 'use strict'; }",
    'the name of a nested function'  : "function f() { function eval() { 'use strict'; } }",
    'the parameter of a declaration' : "function f(eval) { 'use strict'; }",
    'a later parameter'              : "function f(a, eval) { 'use strict'; }",
    'the parameter of an expression' : "var f = function (eval) { 'use strict'; };",
    'the parameter of a named one'   : "var f = function g(eval) { 'use strict'; };",
    'the parameter of an arrow'      : "var f = (eval) => { 'use strict'; };",
    'the parameter of a method'      : "var o = { m(eval) { 'use strict'; } };",
    'the parameter of a setter'      : "var o = { set s(eval) { 'use strict'; } };",
    'the parameter of a generator'   : "function* g(eval) { 'use strict'; }",
    'the parameter of an async one'  : "async function h(eval) { 'use strict'; }",
    'a binding inside the body'      : "function f() { 'use strict'; var eval = 1; }",
}

#: A program that binds the same name outside that code, which Node reads. A directive governs the
#: one function it was written in and nothing around it, and two of these bind the name in a place
#: that only looks as though it belongs to that function: a property key is a name and not a
#: binding, and the variable a function expression is stored in belongs to the statement that
#: declares it.
A_BINDING_OUTSIDE_WHAT_IT_GOVERNS = {
    'a binding above the function'       : "var eval = 1; function f() { 'use strict'; }",
    'a binding below the function'       : "function f() { 'use strict'; } var eval = 1;",
    'the name of a sibling function'     : "function eval() {} function f() { 'use strict'; }",
    'the key of a method'                : "var o = { eval() { 'use strict'; } };",
    'the key of a getter'                : "var o = { get eval() { 'use strict'; } };",
    'the variable an arrow is put in'    : "var eval = () => { 'use strict'; };",
    'the variable a function is put in'  : "var eval = function () { 'use strict'; };",
    'the name of the function around'    : "function eval() { function g() { 'use strict'; } }",
    'a parameter of the function around' : "function f(eval) { function g() { 'use strict'; } }",
}

#: A statement standing between the head of a body and a `'use strict'` written below it, mapped to
#: whether the prologue still reaches that directive. The empty key is the directive standing first.
A_STATEMENT_ABOVE_THE_DIRECTIVE = {
    ''                    : True,
    "'other';"            : True,
    '"another";'          : True,
    "'a'; 'b';"           : True,
    R"'use\u0020strict';" : True,
    ';'                   : False,
    '0;'                  : False,
    'var x;'              : False,
    "('paren');"          : False,
    "'a' + 'b';"          : False,
    "'a', 'b';"           : False,
    'x = 1;'              : False,
    "{ 'x'; }"            : False,
    "if (0) 'x';"         : False,
    'function g() {}'     : False,
    "'a'.length;"         : False,
}

#: The statements a body is written with. Its Directive Prologue is the run of string literals it
#: opens with, which is the first two, and a directive inserted at any index from zero up to and
#: including two is read as one.
A_BODY_WRITTEN_AS = ["'alpha';", "'beta';", '0;', "'gamma';"]

#: A statement that is no string literal and that a fold would write as one, placed at a position,
#: mapped to whether respelling it hands a `'use strict'` below it the Directive Prologue.
A_STATEMENT_STANDING_AT = {
    'the head of a script'           : ("{stmt} 'use strict'; 010;", True),
    'the second statement'           : ("'lead'; {stmt} 'use strict'; 010;", True),
    'below a statement that is none' : ("0; {stmt} 'use strict'; 010;", False),
    'the head of a function body'    : ("function f() {{ {stmt} 'use strict'; 010; }}", True),
    'the head of a plain block'      : ("{{ {stmt} 'use strict'; 010; }}", False),
    'the head of a switch case'      : (
        "switch (1) {{ case 1: {stmt} 'use strict'; 010; }}", False),
    'the head of a catch block'      : (
        "try {{}} catch (e) {{ {stmt} 'use strict'; 010; }}", False),
    'the head of a nested block'     : (
        "function f() {{ {{ {stmt} 'use strict'; 010; }} }}", False),
}

#: The statement `A_STATEMENT_STANDING_AT` places. It is no string literal, so it ends whatever
#: Directive Prologue it stands in, and it denotes a string, so a fold writes one where it stood.
A_COMPUTED_STRING = "'a' + 'b';"

#: The string literal that fold writes. It does not denote `use strict`, so it is never the
#: directive itself; what it can do is hand the position of one to a statement below it.
A_PLAIN_STRING = "'ab';"

#: A parameter list, mapped to whether it is a simple one. Every parameter of a simple list is a
#: plain identifier; a default, a rest element and a destructuring pattern are each something else.
#: The empty list is simple, nothing in it being anything but an identifier.
A_PARAMETER_LIST = {
    ''          : True,
    'a'         : True,
    'a, b'      : True,
    'a, b, c'   : True,
    'a,'        : True,
    'a = 1'     : False,
    'a, b = 2'  : False,
    '...a'      : False,
    'a, ...b'   : False,
    '[a]'       : False,
    '[a, b]'    : False,
    '{a}'       : False,
    '{a: b}'    : False,
    '{a} = {}'  : False,
    'a, [b]'    : False,
}

#: Each way of writing a function that takes a parameter list and holds a body.
A_FUNCTION_WRITTEN_AS = {
    'a function declaration' : 'function f({params}) {{ {body} }}',
    'a function expression'  : 'var f = function ({params}) {{ {body} }};',
    'an arrow'               : 'var f = ({params}) => {{ {body} }};',
    'a method'               : 'var o = {{ m({params}) {{ {body} }} }};',
    'a generator'            : 'function* g({params}) {{ {body} }}',
    'an async function'      : 'async function h({params}) {{ {body} }}',
}

#: An expression that is `true` where it stands in strict code and `false` where it stands in
#: sloppy code. A plain call passes no receiver, so `this` in the callee is `undefined` under strict
#: and the global object under sloppy, and a function written inside a body runs in that body's
#: mode.
_THE_MODE_IT_STANDS_IN = '(function () { return this; })() === undefined'

#: The same probe as a statement, for a position that takes one.
_REPORTS_THE_MODE_IT_STANDS_IN = F'console.log({_THE_MODE_IT_STANDS_IN});'

#: A program that says which mode each part of it runs in, mapped to what Node prints for it.
A_PROGRAM_REPORTING_ITS_MODE = {
    F"'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'true\n',
    F"'use strict';\nfunction f() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();":
        'true\n',
    F"function f() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();":
        'true\n',
    F"var o = {{ m() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }} }};\no.m();":
        'true\n',
    F"var f = () => {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }};\nf();":
        'true\n',
    F"function* g() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\ng().next();":
        'true\n',
    F"var o = {{ get p() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }} }};\no.p;":
        'true\n',
    F'class C {{ m() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }} }}\nnew C().m();':
        'true\n',
    F'class C {{ static {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }} }}':
        'true\n',
    F'class C {{ p = (function () {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }})(); }}\nnew C();':
        'true\n',
    F"function f() {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}\n"
    F'function g() {{ {_REPORTS_THE_MODE_IT_STANDS_IN} }}\nf();\ng();':
        'true\nfalse\n',
    F"{_REPORTS_THE_MODE_IT_STANDS_IN}\n"
    F"(function () {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }})();":
        'false\ntrue\n',
    F"switch (1) {{ case 1: 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"try {{ throw 1; }} catch (e) {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"for (var i = 0; i < 1; i++) {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"L: {{ 'use strict'; {_REPORTS_THE_MODE_IT_STANDS_IN} }}":
        'false\n',
    F"console.log('x');\n'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'x\nfalse\n',
    F"'note';\n'use strict';\n{_REPORTS_THE_MODE_IT_STANDS_IN}":
        'true\n',
    "function f(a) { 'use strict'; a = 2; return arguments[0]; }\nconsole.log(f(1));":
        '1\n',
    "'use strict';\nvar s = ['con', 'sole'];\nconsole.log(s[0] + s[1]);\n"
    + _REPORTS_THE_MODE_IT_STANDS_IN:
        'console\ntrue\n',
}

#: A read a constant string decides, standing at the head of a body that reads no Directive
#: Prologue, mapped to the text `refinery.js` writes for the whole program. The read answers a
#: string, so folding it writes a string literal where the read stood; no directive is ever read
#: there, so no mode turns on the rewrite and nothing licenses declining it.
A_READ_WHERE_NO_PROLOGUE_IS_READ = {
    "{ 'abc'[0]; }":
        "{\n  'a';\n}",
    "switch (1) { case 1: 'abc'[0]; }":
        "switch (1) {\n  case 1:\n    'a';\n}",
    "try {} catch (e) { 'abc'[0]; }":
        "try {} catch (e) {\n  'a';\n}",
    "L: { 'abc'[0]; }":
        "L: {\n  'a';\n}",
    "function f() { { 'abc'[0]; } }":
        "function f() {\n  {\n    'a';\n  }\n}",
}

#: The same read standing where a string literal would join a Directive Prologue, mapped to the text
#: `refinery.js` writes for it. Folding it there hands the prologue a statement that had ended one.
A_READ_WHERE_A_PROLOGUE_IS_READ = {
    "'abc'[0];":
        "'abc'[0];",
    "function f() { 'abc'[0]; }":
        "function f() {\n  'abc'[0];\n}",
}


def _a_function_whose_body_opens_with(head: str, parameters: str, call: str, read: str) -> str:
    """
    A program calling a function written with *parameters* as *call*, whose body opens with *head*
    and reads *read* below it.
    """
    return (
        F'function f({parameters}) {{ {head} return {read}; }}\n'
        F'console.log({call});\n'
    )


#: A parameter list that holds a default value, a rest element, or a destructuring pattern, mapped
#: to a call that reaches a body reading it, the expression such a body returns, and what Node
#: prints for that call. A parameter list written any of those ways is not a simple one, and a
#: function with such a list may hold no Use Strict Directive at all, so a rewrite that writes one
#: into such a body costs the file its reading rather than merely its mode.
_A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER = {
    'a = 1' : ('f()', 'a', '1\n'),
    '...a'  : ('f(1, 2)', 'a.length', '2\n'),
    '{a}'   : ('f({a: 5})', 'a', '5\n'),
}

#: A function whose parameter list forbids a directive, whose body holds a `'use strict'` one
#: statement in, mapped to what Node prints for it. The statement above the directive is the `atob`
#: call of
#: `test.lib.scripts.js.analysis.test_differential.SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING`, which
#: is not a string literal and therefore ends the prologue in front of the directive.
A_FUNCTION_WHOSE_PARAMETER_LIST_FORBIDS_A_DIRECTIVE = {
    _a_function_whose_body_opens_with(
        "atob('YQ=='); 'use strict';", parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
}

#: A function whose parameter list forbids a directive, whose body opens with a statement that is
#: none but that a fold writes as the plain spelling of one, mapped to what Node prints for it.
A_FUNCTION_WHOSE_BODY_OPENS_WITH_A_FOLD_TO_THE_DIRECTIVE = {
    _a_function_whose_body_opens_with(head, parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
    for head in SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
}

#: A body opening that promotes the statement standing below it once a pass is done with it: a block
#: whose contents are lifted into the body around it, and a binding nothing reads that is dropped
#: out of it. Neither writes a character of text; each only changes which statement the body opens
#: with.
A_HEAD_A_MOVE_PROMOTES_THE_STATEMENT_BELOW = [
    "if (1) { 'use strict'; }",
    "var dead = 1; 'use strict';",
]

#: A function whose parameter list forbids a directive, holding a `'use strict'` that one of those
#: moves would promote to the head of its body, mapped to what Node prints for it.
A_FUNCTION_A_MOVE_WOULD_WRITE_A_DIRECTIVE_INTO = {
    _a_function_whose_body_opens_with(head, parameters, call, read): prints
    for parameters, (call, read, prints) in _A_PARAMETER_LIST_NO_DIRECTIVE_MAY_STAND_UNDER.items()
    for head in A_HEAD_A_MOVE_PROMOTES_THE_STATEMENT_BELOW
}


def _a_strict_body_holding(statements: str, installs: str = '') -> str:
    """
    A program that runs *installs*, then prints whether the body of `f` runs strict, with
    *statements* standing between the directive that opens that body and the report.
    """
    body = (
        F'function f(a) {{ {THE_DIRECTIVE}{statements}'
        F' return {_THE_MODE_IT_STANDS_IN}; }}\n'
        'console.log(f(1));\n'
    )
    return F'{installs}\n{body}' if installs else body


def _a_strict_script_holding(statements: str) -> str:
    """
    A program printing whether the script runs strict, with *statements* standing between the
    directive that opens the file and the report.
    """
    return F"{THE_DIRECTIVE}{statements}\n{_REPORTS_THE_MODE_IT_STANDS_IN}\n"


#: A body that opens with a directive and holds a binding nothing reads back, mapped to what Node
#: prints for it. Two of them are function bodies and two are whole scripts, and the binding is
#: written two ways: as a variable a single assignment stores into, and as a namespace object whose
#: one property is read straight back.
A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS = {
    _a_strict_body_holding('q = a;', 'var q;'): 'true\n',
    _a_strict_script_holding('var q;\nq = 1;'): 'true\n',
    _a_strict_body_holding('var NS = {}; NS.p = 1; console.log(NS.p);'): '1\ntrue\n',
    _a_strict_script_holding('var NS = {};\nNS.p = 1;\nconsole.log(NS.p);'): '1\ntrue\n',
}


def _an_accessor_returning_a_strict_function(body: str, run: str) -> str:
    """
    A program building an accessor with an immediately invoked function that holds one local, whose
    returned function opens with the directive and closes with *body*, and that then runs *run*.
    Promoting the accessor is what writes the local of the outer function into the body that the
    directive opens.
    """
    return (
        'var acc = (function () {\n'
        "  var t = ['a', 'b'];\n"
        F"  return function (i) {{ 'use strict'; {body} }};\n"
        '})();\n'
        F'{run}\n'
    )


#: An accessor whose returned function opens with a directive, mapped to what Node prints for it.
#: The first reports the mode that function runs in and the second assigns to a name nothing
#: declares, which strict code refuses and sloppy code answers with a new global. The third writes
#: two statements into the prologue the source gave that body, only one of which declares a mode.
AN_ACCESSOR_WHOSE_RETURNED_BODY_OPENS_WITH_A_DIRECTIVE = {
    _an_accessor_returning_a_strict_function(
        F"return t[i] + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');",
        'console.log(acc(1));',
    ): 'bS\n',
    _an_accessor_returning_a_strict_function(
        'undeclared = i; return t[i] + undeclared;',
        'try { console.log(acc(1)); } catch (e) { console.log(e.constructor.name); }',
    ): 'ReferenceError\n',
    _an_accessor_returning_a_strict_function(
        F"'note'; return t[i] + ({_THE_MODE_IT_STANDS_IN} ? 'S' : 'L');",
        'console.log(acc(1));',
    ): 'bS\n',
}

#: A body a Directive Prologue opens, as a template that places statements at the head of that body
#: and reports the mode the body runs in, mapped to what Node prints for the whole program. Only the
#: two bodies belonging to a class report `true`: every part of a class definition is strict whatever
#: opens it, which makes those the bodies here whose mode nothing written into a prologue can move.
A_BODY_REPORTING_THE_MODE_ITS_PROLOGUE_DECIDES = {
    'a script'               : ('{head} console.log({mode});', 'false\n'),
    'a function declaration' : (
        'function f() {{ {head} return {mode}; }} console.log(f());', 'false\n'),
    'a function expression'  : (
        'var f = function () {{ {head} return {mode}; }}; console.log(f());', 'false\n'),
    'an arrow with a block'  : (
        'var f = () => {{ {head} return {mode}; }}; console.log(f());', 'false\n'),
    'a method'               : (
        'var o = {{ m() {{ {head} return {mode}; }} }}; console.log(o.m());', 'false\n'),
    'a getter'               : (
        'var o = {{ get g() {{ {head} return {mode}; }} }}; console.log(o.g);', 'false\n'),
    'a setter'               : (
        'var o = {{ set s(v) {{ {head} console.log({mode}); }} }}; o.s = 1;', 'false\n'),
    'a generator'            : (
        'function* g() {{ {head} yield {mode}; }} console.log(g().next().value);', 'false\n'),
    'an async function'      : (
        'async function h() {{ {head} return {mode}; }}'
        ' h().then(function (v) {{ console.log(v); }});', 'false\n'),
    'a class method'         : (
        'class C {{ m() {{ {head} console.log({mode}); }} }} new C().m();', 'true\n'),
    'a class static block'   : (
        'class C {{ static {{ {head} console.log({mode}); }} }}', 'true\n'),
}

#: A route by which a `'use strict'` the source never wrote as a directive comes to stand at the
#: head of a body, written as the statements the report stands below. The first three are rewritten
#: in place — a fold, a decode, and the substitution of a name by the string it holds — and each
#: ends the Directive Prologue where the source wrote it, so the `'use strict'` they arrive at was
#: an ordinary statement. The fourth writes nothing at all: a declaration nothing reads is dropped
#: and the string that stood below it moves up into the position a directive is read in.
A_ROUTE_A_STRING_ARRIVES_AT_THE_HEAD_BY = {
    'a fold'      : "'use ' + 'strict';",
    'a decode'    : "atob('dXNlIHN0cmljdA==');",
    'an inlining' : "var m = 'use strict'; m;",
    'a removal'   : "var dead = 1; 'use strict';",
}

#: A statement standing at the head of a function body, mapped to the text `refinery.js` writes for
#: the whole program. A `'use strict'` an edit moved into the prologue is written inside a bracket,
#: which computes the same string and declares nothing; one the source wrote there is left alone;
#: and a promoted string that is not `use strict` is left alone too, since parenthesizing it would
#: end the run for a statement that declares no mode either way. The body ends in a declaration
#: rather than a call: the string statement computes nothing, and the sweep would take it before
#: the printer ever got to say how it is spelled.
A_HEAD_THE_PRINTER_ANSWERS_WITH = {
    "'use ' + 'strict';":
        "function f(a) {\n  ('use strict');\n  var b = g(a);\n}\nf(1);",
    "var dead = 1; 'use strict';":
        "function f(a) {\n  ('use strict');\n  var b = g(a);\n}\nf(1);",
    "'use ' + 'strict'; 'use strict';":
        "function f(a) {\n  ('use strict');\n  var b = g(a);\n}\nf(1);",
    "'use strict';":
        "function f(a) {\n  'use strict';\n  var b = g(a);\n}\nf(1);",
    "'use strict'; var dead = 1; 'other';":
        "function f(a) {\n  'use strict';\n  'other';\n  var b = g(a);\n}\nf(1);",
    "var dead = 1; 'other';":
        "function f(a) {\n  'other';\n  var b = g(a);\n}\nf(1);",
}


def _refused(programs: Sequence[str]) -> list[bool]:
    """
    Whether Node refuses to read each of *programs* as a program at all. Each is compiled and run in
    a context of its own, so a refusal is a fact about that one text.
    """
    return [
        value == NOT_A_PROGRAM
        for value in completion_values(programs, JsEvaluation.SCRIPT)
    ]


def _without_the_directive(source: str) -> str:
    return source.replace(THE_DIRECTIVE, '', 1)


def _the_directive_statement(root: Node) -> JsExpressionStatement:
    """
    The statement of *root* that is written as the Use Strict Directive.
    """
    statement, = (
        node for node in root.walk()
        if isinstance(node, JsExpressionStatement)
        and isinstance(node.expression, JsStringLiteral)
        and node.expression.body == 'use strict'
    )
    return statement


def _the_binding_named_eval(root: Node) -> JsIdentifier:
    name, = (
        node for node in root.walk()
        if isinstance(node, JsIdentifier) and node.name == 'eval'
    )
    return name


def _the_octal_literal(root: Node) -> JsNumericLiteral:
    literal, = (
        node for node in root.walk()
        if isinstance(node, JsNumericLiteral) and node.raw == '010'
    )
    return literal


def _the_computed_string_statement(root: Node) -> JsExpressionStatement:
    """
    The statement `A_STATEMENT_STANDING_AT` places, found through the literal it is written with
    rather than through its position, which is what each row varies.
    """
    statement, = (
        node for node in root.walk()
        if isinstance(node, JsExpressionStatement)
        and any(
            isinstance(inner, JsStringLiteral) and inner.body == 'a'
            for inner in node.walk()
        )
    )
    return statement


def _the_function(
    root: Node,
) -> JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression:
    function, = (
        node for node in root.walk()
        if isinstance(
            node,
            (JsFunctionDeclaration, JsFunctionExpression, JsArrowFunctionExpression),
        )
    )
    return function


def _prologue_spellings(host: Node) -> list[str]:
    """
    What each statement of the Directive Prologue of *host* is spelled with.
    """
    return [
        statement.expression.body
        for statement in directive_prologue(host)
        if isinstance(statement.expression, JsStringLiteral)
    ]


def _marked_spellings(script: JsScript) -> list[str]:
    """
    What each statement of *script* that the parser recorded as written into a Directive Prologue is
    spelled with, in the order the source wrote them.
    """
    return [
        statement.expression.body
        for statement in script.body
        if isinstance(statement, JsExpressionStatement)
        and statement.directive
        and isinstance(statement.expression, JsStringLiteral)
    ]


def _a_script_whose_directive_stands_below(head: str) -> str:
    return F"{head} 'use strict'; 010;"


def _a_function_body_whose_directive_stands_below(head: str) -> str:
    return F"function f() {{ {head} 'use strict'; 010; }}"


def _a_body_with_the_directive_at(index: int) -> str:
    statements = list(A_BODY_WRITTEN_AS)
    statements.insert(index, "'use strict';")
    return F'{" ".join(statements)} 010;'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | js(strict=True) | str


def _before_and_after(source: str) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    What Node makes of *source* and what it makes of the text `refinery.js` deobfuscates it to,
    reported together because the law is that the two agree.
    """
    return behavior(source), behavior(deobfuscate_source(source))


def _before_and_after_as_a_script(
    source: str,
) -> tuple[tuple[str, str | None], tuple[str, str | None]]:
    """
    The same pair as `_before_and_after`, with both programs run as classic global scripts.

    `behavior` runs a file as a CommonJS module, which wraps the whole of it in a function, so the
    top of the file is the top of a function body there and never the top of a script. A law about
    what the first statement of a script is has to be witnessed where the file has one.
    """
    return host_behavior(source), host_behavior(deobfuscate_source(source))


def _each_program_still_prints(
    programs: dict[str, str],
) -> dict[str, tuple[tuple[str, str | None], tuple[str, str | None]]]:
    """
    The pair `_before_and_after` has to give for each program in *programs*: the text the program
    prints, printed by the deobfuscation too, with neither of the two throwing.
    """
    return {
        source: ((prints, None), (prints, None))
        for source, prints in programs.items()
    }


def _a_body_opened_by(head: str, template: str) -> str:
    return template.format(head=head, mode=_THE_MODE_IT_STANDS_IN)


def _a_function_body_opening_with_and_calling_g(head: str) -> str:
    """
    A program whose one function opens with *head* and then calls `g`, keeping what it answers in a
    declaration so that a statement computing nothing ahead of it is never the shadow of an effect
    the sweep would sooner remove it than print.
    """
    return F'function f(a) {{ {head} var b = g(a); }}\nf(1);'


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichBodiesReadADirectivePrologue(TestBase):

    def test_a_directive_at_the_head_of_a_prologue_host_makes_the_code_below_it_strict(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values())
        self.assertEqual(_refused(sources), [True] * len(sources))

    def test_the_same_body_without_the_directive_is_sloppy(self):
        sources = [_without_the_directive(s) for s in A_BODY_A_PROLOGUE_OPENS.values()]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_a_directive_at_the_head_of_any_other_statement_list_changes_no_mode(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_those_bodies_are_sloppy_without_the_directive_too(self):
        sources = [_without_the_directive(s) for s in A_BODY_NO_PROLOGUE_OPENS.values()]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_a_class_static_block_is_strict_whatever_stands_at_its_head(self):
        self.assertEqual(
            _refused([A_CLASS_STATIC_BLOCK, _without_the_directive(A_CLASS_STATIC_BLOCK)]),
            [True, True],
        )


class TestIsPrologueHostAnswersForTheBodiesTheEngineReadsOneIn(TestBase):

    def _hosts(self, sources: Sequence[str]) -> list[bool]:
        return [
            is_prologue_host(_the_directive_statement(JsParser(source).parse()).parent)
            for source in sources
        ]

    def test_a_body_the_engine_compiled_strict_holds_a_prologue(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._hosts(sources), [True] * len(sources))

    def test_a_body_the_engine_left_sloppy_holds_none(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._hosts(sources), [False] * len(sources))


class TestStrictModeAtAnswersTheModeTheEngineCompiled(TestBase):

    def _modes(self, sources: Sequence[str]) -> list[bool]:
        return [
            strict_mode_at(_the_octal_literal(JsParser(source).parse()))
            for source in sources
        ]

    def test_the_octal_literal_below_a_directive_a_body_reads_stands_in_strict_code(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._modes(sources), [True] * len(sources))

    def test_the_octal_literal_below_a_directive_no_body_reads_stands_in_sloppy_code(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._modes(sources), [False] * len(sources))

    def test_a_position_a_strict_body_encloses_inherits_the_mode_of_that_body(self):
        rows = AN_OCTAL_LITERAL_STANDING_IN
        self.assertEqual(
            self._modes([source for source, _ in rows.values()]),
            [strict for _, strict in rows.values()],
        )

    def _eval_modes(self, sources: Sequence[str]) -> list[bool]:
        return [
            strict_mode_at(_the_binding_named_eval(JsParser(source).parse()))
            for source in sources
        ]

    def test_the_name_and_the_parameters_of_a_function_stand_in_the_mode_of_its_body(self):
        sources = list(A_BINDING_THE_DIRECTIVE_GOVERNS.values())
        self.assertEqual(self._eval_modes(sources), [True] * len(sources))

    def test_a_binding_the_directive_does_not_govern_stands_in_sloppy_code(self):
        sources = list(A_BINDING_OUTSIDE_WHAT_IT_GOVERNS.values())
        self.assertEqual(self._eval_modes(sources), [False] * len(sources))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestModeIsInheritedByEverythingAStrictBodyEncloses(TestBase):

    def test_node_compiles_each_position_in_the_mode_the_corpus_records(self):
        rows = AN_OCTAL_LITERAL_STANDING_IN
        self.assertEqual(
            _refused([source for source, _ in rows.values()]),
            [strict for _, strict in rows.values()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatAFunctionBodysDirectiveGovernsBesidesThatBody(TestBase):
    """
    A function body's directive governs the function and not the body alone. The name the function
    binds and its parameter list stand outside the braces the directive opens and are strict code
    all the same, which is what makes `function eval() { 'use strict'; }` and
    `function f(eval) { 'use strict'; }` two texts Node will not read.

    It reaches no further than that one function. The code around it stays sloppy, and so does
    anything that only looks as though it belongs to the function: the property key a method is
    written under is a name and not a binding, and the variable a function expression is assigned to
    belongs to the statement that declares it.
    """

    def test_node_refuses_the_name_bound_in_the_code_the_directive_governs(self):
        sources = list(A_BINDING_THE_DIRECTIVE_GOVERNS.values())
        self.assertEqual(_refused(sources), [True] * len(sources))

    def test_node_reads_the_same_name_bound_anywhere_else(self):
        sources = list(A_BINDING_OUTSIDE_WHAT_IT_GOVERNS.values())
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_it_is_the_directive_and_not_the_name_that_costs_the_program(self):
        sources = [
            _without_the_directive(source)
            for source in A_BINDING_THE_DIRECTIVE_GOVERNS.values()
        ]
        self.assertEqual(_refused(sources), [False] * len(sources))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHowFarADirectivePrologueReaches(TestBase):

    def test_a_directive_is_read_below_string_literal_statements_and_below_nothing_else(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            _refused([_a_script_whose_directive_stands_below(head) for head in rows]),
            list(rows.values()),
        )

    def test_a_function_body_reads_its_prologue_the_same_way_a_script_does(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            _refused([_a_function_body_whose_directive_stands_below(head) for head in rows]),
            list(rows.values()),
        )

    def test_a_directive_stands_anywhere_from_the_head_up_to_the_end_of_the_prologue(self):
        indices = range(len(A_BODY_WRITTEN_AS) + 1)
        self.assertEqual(
            _refused([_a_body_with_the_directive_at(index) for index in indices]),
            [True, True, True, False, False],
        )


class TestTheDirectivePrologueTheToolReads(TestBase):

    def test_declares_use_strict_answers_what_the_engine_compiled(self):
        rows = A_STATEMENT_ABOVE_THE_DIRECTIVE
        self.assertEqual(
            [
                declares_use_strict(JsParser(_a_script_whose_directive_stands_below(head)).parse())
                for head in rows
            ],
            list(rows.values()),
        )

    def test_the_prologue_is_the_run_of_string_literal_statements_a_body_opens_with(self):
        script = JsParser(F'{" ".join(A_BODY_WRITTEN_AS)} 010;').parse()
        self.assertEqual(_prologue_spellings(script), ['alpha', 'beta'])

    def test_a_body_that_opens_with_no_string_literal_has_an_empty_prologue(self):
        script = JsParser("0; 'alpha'; 'beta';").parse()
        self.assertEqual(_prologue_spellings(script), [])


class TestWhichStatementsTheParserRecordsAsWrittenIntoAPrologue(TestBase):
    """
    Which statements the source wrote into a Directive Prologue is recorded once, when the file is
    parsed, and it can be answered at no other time: a statement is a directive by virtue of the
    list it sits in and the statements ahead of it, neither of which is known while it is being
    built. The mark
    is provenance and never a conclusion — a statement an edit later moves to the head of a body
    carries none, which is the whole of what tells the two apart.
    """

    def _marked(self, sources: Sequence[str]) -> list[bool]:
        return [
            _the_directive_statement(JsParser(source).parse()).directive
            for source in sources
        ]

    def test_the_directive_of_a_body_the_engine_compiled_strict_is_marked(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._marked(sources), [True] * len(sources))

    def test_the_same_statement_in_a_body_the_engine_left_sloppy_is_not(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._marked(sources), [False] * len(sources))

    def test_the_mark_is_on_the_run_of_string_literals_a_body_opens_with(self):
        script = JsParser(F'{" ".join(A_BODY_WRITTEN_AS)} 010;').parse()
        self.assertEqual(_marked_spellings(script), ['alpha', 'beta'])

    def test_a_body_opening_with_no_string_literal_marks_nothing(self):
        script = JsParser("0; 'alpha'; 'beta';").parse()
        self.assertEqual(_marked_spellings(script), [])


class TestWhichStatementIsTheOneThatDeclaresTheMode(TestBase):
    """
    `refinery.lib.scripts.js.strict.is_use_strict_directive` is the one predicate a removal asks
    before dropping a statement and an insertion asks before stepping over one, so that the two
    cannot disagree about which statement is at stake. It holds for a statement the source wrote
    into a prologue, that still stands in one, and that spells `use strict`.
    """

    def _declares(self, sources: Sequence[str]) -> list[bool]:
        return [
            is_use_strict_directive(_the_directive_statement(JsParser(source).parse()))
            for source in sources
        ]

    def test_it_holds_for_the_directive_of_every_body_the_engine_compiled_strict(self):
        sources = list(A_BODY_A_PROLOGUE_OPENS.values()) + [A_CLASS_STATIC_BLOCK]
        self.assertEqual(self._declares(sources), [True] * len(sources))

    def test_it_holds_for_no_statement_of_a_body_the_engine_left_sloppy(self):
        sources = list(A_BODY_NO_PROLOGUE_OPENS.values())
        self.assertEqual(self._declares(sources), [False] * len(sources))

    def test_it_holds_for_no_string_that_declares_another_mode(self):
        sources = [
            "'use loose'; 010;",
            "function f() { 'use loose'; 010; }",
            "'use loose'; 'use strict';",
        ]
        answers = [
            [
                is_use_strict_directive(statement)
                for statement in directive_prologue(JsParser(source).parse())
                if isinstance(statement.expression, JsStringLiteral)
                and statement.expression.body == 'use loose'
            ]
            for source in sources
        ]
        self.assertEqual(answers, [[False], [], [False]])


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichStatementsWouldJoinADirectivePrologue(TestBase):

    def test_a_statement_that_is_no_string_literal_hands_no_directive_position_away(self):
        sources = [
            template.format(stmt=A_COMPUTED_STRING)
            for template, _ in A_STATEMENT_STANDING_AT.values()
        ]
        self.assertEqual(_refused(sources), [False] * len(sources))

    def test_respelling_it_as_a_string_literal_extends_the_prologue_over_what_follows(self):
        rows = A_STATEMENT_STANDING_AT
        self.assertEqual(
            _refused([template.format(stmt=A_PLAIN_STRING) for template, _ in rows.values()]),
            [joins for _, joins in rows.values()],
        )

    def test_joins_directive_prologue_answers_what_the_respelling_costs(self):
        rows = A_STATEMENT_STANDING_AT
        self.assertEqual(
            [
                joins_directive_prologue(
                    _the_computed_string_statement(
                        JsParser(template.format(stmt=A_COMPUTED_STRING)).parse()))
                for template, _ in rows.values()
            ],
            [joins for _, joins in rows.values()],
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichParameterListsADirectiveMayStandUnder(TestBase):

    def test_node_refuses_a_directive_under_every_list_that_is_not_simple(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            sources = [
                template.format(params=params, body="'use strict';")
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(
                    _refused(sources),
                    [not simple for simple in A_PARAMETER_LIST.values()],
                )

    def test_node_reads_every_one_of_those_lists_with_an_empty_body(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            sources = [
                template.format(params=params, body='')
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(_refused(sources), [False] * len(sources))


class TestHasSimpleParametersAnswersWhereADirectiveIsPermitted(TestBase):

    def test_a_list_is_simple_exactly_where_the_engine_permits_a_directive_under_it(self):
        for shape, template in A_FUNCTION_WRITTEN_AS.items():
            answers = [
                has_simple_parameters(
                    _the_function(JsParser(template.format(params=params, body='')).parse()))
                for params in A_PARAMETER_LIST
            ]
            with self.subTest(shape=shape):
                self.assertEqual(answers, list(A_PARAMETER_LIST.values()))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationLeavesEveryModeWhereItWas(TestBase):

    def test_node_prints_what_the_corpus_records_for_each_program(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: host_behavior(source) for source in rows},
            {source: (printed, None) for source, printed in rows.items()},
        )

    def test_the_deobfuscation_of_each_program_prints_the_same(self):
        rows = A_PROGRAM_REPORTING_ITS_MODE
        self.assertEqual(
            {source: host_behavior(_deobfuscated(source)) for source in rows},
            {source: (printed, None) for source, printed in rows.items()},
        )


class TestAFoldDeclinesOnlyWhereADirectiveCouldBeRead(TestBase):

    def test_a_read_in_a_body_that_opens_no_prologue_is_folded(self):
        rows = A_READ_WHERE_NO_PROLOGUE_IS_READ
        self.assertEqual({s: _deobfuscated(s) for s in rows}, dict(rows))

    def test_a_read_that_would_join_a_prologue_is_left_standing(self):
        rows = A_READ_WHERE_A_PROLOGUE_IS_READ
        self.assertEqual({s: _deobfuscated(s) for s in rows}, dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFoldWritesNoDirectiveWhereNoneWasWritten(TestBase):
    """
    A directive is a string literal written plainly at the top of a script or of a function body,
    and nothing else is one: a bracket around the literal, an operator beside it, or a call that
    computes the same text each leaves a statement that is merely evaluated. Folding one of those to
    the text it denotes puts the plain spelling where a directive is read, and the mode of the whole
    script or body around it is what the spelling would otherwise decide.
    """

    def test_a_statement_that_only_denotes_the_text_leaves_the_script_sloppy(self):
        """
        Node prints `false` for each of these programs: the probe is called with no receiver, so
        `this` in its body is the global object, which is what sloppy code gives. The fold arrives
        at the text of the directive as the first statement of the file, and the file that comes
        back has to print `false` all the same.
        """
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [_before_and_after(a_script_opening_with(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_statement_that_only_denotes_the_text_leaves_the_function_body_sloppy(self):
        """
        Node prints `false` for each of these too, the statement standing at the top of the probe's
        own body rather than of the file. A directive there governs the body it opens, so a fold
        that wrote one would turn that one function strict while the file around it stayed as it
        was.
        """
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [_before_and_after(a_function_body_opening_with(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_file_that_holds_an_octal_literal_still_parses(self):
        """
        Node prints `8` for each of these, an octal literal being a number in sloppy code and one of
        the spellings strict mode forbids outright. A directive appearing where none was written
        would cost the file its ability to parse at all, so what comes back has to be a program.
        """
        eight = ('8\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_THE_DIRECTIVE
        self.assertEqual(
            [
                _before_and_after(a_file_holding_an_octal_literal_opening_with(head))
                for head in spellings
            ],
            [(eight, eight)] * len(spellings),
        )

    def test_a_statement_folded_to_a_plain_string_does_not_extend_the_prologue(self):
        """
        Node prints `false` for each of the files
        `test.lib.scripts.js.analysis.test_differential.SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING`
        builds: none of the heads is a string literal, so the prologue ends at it and the
        `'use strict'` below it governs nothing. Each fold writes a string literal there, and a
        prologue extended over the line below would hand that statement a position it never had.
        """
        sloppy = ('false\n', None)
        spellings = SPELLINGS_A_FOLD_WRITES_AS_A_PLAIN_STRING
        self.assertEqual(
            [_before_and_after(a_script_whose_directive_stands_below(head)) for head in spellings],
            [(sloppy, sloppy)] * len(spellings),
        )

    def test_a_fold_writes_no_prologue_into_a_function_that_can_hold_none(self):
        """
        Node prints `1`, `2`, and `5` for the three programs of
        `A_FUNCTION_WHOSE_PARAMETER_LIST_FORBIDS_A_DIRECTIVE`, each of which runs a body holding a
        `'use strict'` that governs nothing, one statement below a call. The fold writes a string
        literal where that call stood, and a function whose parameter list is not simple may not
        open with that directive under any circumstances: what is at stake here is not a body that
        reports the wrong mode but a file that would no longer be a program at all.
        """
        rows = A_FUNCTION_WHOSE_PARAMETER_LIST_FORBIDS_A_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_a_fold_writes_no_directive_into_a_function_that_can_hold_none(self):
        """
        Node prints `1`, `2`, and `5` for the programs of
        `A_FUNCTION_WHOSE_BODY_OPENS_WITH_A_FOLD_TO_THE_DIRECTIVE`, one for each way of writing a
        parameter list that is not simple, crossed with every spelling that denotes the text of the
        directive without being one. Each body opens with a statement that is evaluated and
        discarded, so each function is sloppy code that a parameter list of that shape is welcome
        in, and each has to stay a program once the fold has written the plain spelling there.
        """
        rows = A_FUNCTION_WHOSE_BODY_OPENS_WITH_A_FOLD_TO_THE_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestMovingAStatementDoesNotChangeWhichStatementsAreDirectives(TestBase):
    """
    Whether a statement is a directive is decided by where it stands. A string literal written
    plainly in the run of statements a script or a function body opens with is one; the same
    statement a single position lower is an expression that computes a string and discards it. A
    pass that lifts the contents of a block into the body around it, one that drops a statement it
    found dead, and one that writes a declaration into a body each change which statements a body
    opens with, and the mode of that body may not follow.

    It may not follow in either direction: below a statement that is dropped, a string nobody wrote
    as a directive would otherwise become one and turn sloppy code strict, and below a declaration
    written in, a directive that was written would stop being one and turn strict code sloppy. What
    a fold does to the same run is law in `TestAFoldWritesNoDirectiveWhereNoneWasWritten`; these
    move no statement's text at all.
    """

    def test_lifting_a_block_into_the_body_around_it_writes_no_directive(self):
        """
        Node prints `false` for both of these. A block is not a prologue and a statement inside one
        is never a directive, so the script and the probe's body are sloppy code however certainly
        the branch around that block is taken. The branch is replaced by the statements it holds,
        which is a rewrite of the block and nothing more.
        """
        sloppy = ('false\n', None)
        sources = [
            a_script_opening_with("if (1) { 'use strict'; }"),
            a_function_body_opening_with("if (1) { 'use strict'; }"),
        ]
        self.assertEqual(
            [_before_and_after_as_a_script(source) for source in sources],
            [(sloppy, sloppy)] * len(sources),
        )

    def test_dropping_a_statement_writes_no_directive_below_it(self):
        """
        Node prints `false` for both of these. The prologue ends at the declaration, which is no
        string literal, so the `'use strict'` standing below it computes a string and discards it.
        Nothing reads `dead`, so the declaration is dropped, which moves every statement below it up
        one place: a statement removed from a list is one the statements below it move up past.
        """
        sloppy = ('false\n', None)
        sources = [
            a_script_opening_with("var dead = 1; 'use strict';"),
            a_function_body_opening_with("var dead = 1; 'use strict';"),
        ]
        self.assertEqual(
            [_before_and_after_as_a_script(source) for source in sources],
            [(sloppy, sloppy)] * len(sources),
        )

    def test_writing_a_declaration_into_a_body_leaves_its_directive_first(self):
        """
        Node prints `bS`, `ReferenceError`, and `bS` for the three programs of
        `AN_ACCESSOR_WHOSE_RETURNED_BODY_OPENS_WITH_A_DIRECTIVE`. Each returns a function that opens
        with the directive, so that function is strict: it reports the strict mode in the first and
        the third, and in the second its assignment to a name nothing declares throws, which the
        file catches and names. Promoting the accessor writes the local of the outer function into
        that body, and above the directive is a position no directive survives.
        """
        rows = AN_ACCESSOR_WHOSE_RETURNED_BODY_OPENS_WITH_A_DIRECTIVE
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_a_move_writes_no_directive_into_a_function_that_can_hold_none(self):
        """
        Node prints `1`, `2`, and `5` for the six programs of
        `A_FUNCTION_A_MOVE_WOULD_WRITE_A_DIRECTIVE_INTO`, one pair for each way of writing a
        parameter list that is not simple. In each, the `'use strict'` stands inside a block or one
        statement below a binding, so it governs nothing and the function is sloppy code that such a
        list is welcome in. Lifting the block, and dropping the binding, each leave that string at
        the head of a body which may hold no directive at all.
        """
        rows = A_FUNCTION_A_MOVE_WOULD_WRITE_A_DIRECTIVE_INTO
        self.assertEqual(
            {source: _before_and_after(source) for source in rows},
            _each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADirectiveIsNotAStatementThatCanBeDiscarded(TestBase):
    """
    A directive is written in the shape of an expression statement and is not one. Evaluating the
    literal is the least of what it does: it states the mode the body it opens runs in, and that
    body keeps the mode for as long as the statement stands there. A statement whose value nothing
    reads may be discarded, and this one may not, so the shape it is written in is not enough to
    decide it by.

    The sweep that drops a variable nothing reads back also drops the statements of that body which
    only evaluate a literal, and a directive is one of those by its shape alone. What removed the
    variable does not matter — an assignment nothing reads and a namespace object flattened into
    bare names each put the sweep over the same body — and neither does whether the body is a
    function or the file.
    """

    def test_a_directive_survives_the_removal_of_a_binding_beside_it(self):
        """
        Node prints `true` for all four programs of
        `A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS`, the two that read a property
        back printing the property first: each body opens with the directive and is strict for it.
        The same programs with the directive left out print `false`, which is what makes the
        directive and not the binding the statement these measure.
        """
        rows = A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in rows},
            _each_program_still_prints(rows),
        )

    def test_the_same_bodies_report_sloppy_once_the_directive_is_taken_out(self):
        rows = A_BODY_WHOSE_DIRECTIVE_STANDS_BESIDE_A_BINDING_NOTHING_READS
        sloppy = {
            _without_the_directive(source): prints.replace('true', 'false')
            for source, prints in rows.items()
        }
        self.assertEqual(
            {source: _before_and_after_as_a_script(source) for source in sloppy},
            _each_program_still_prints(sloppy),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStringPromotedIntoAPrologueGovernsNothing(TestBase):
    """
    A `'use strict'` can reach the head of a body by four routes that write no directive: a fold, a
    decode, and the substitution of a name each rewrite the statement that had ended the Directive
    Prologue, and the removal of a statement above one moves it up into the run. Every kind of body
    a prologue opens is crossed with every route, and the mode each body runs in is the same before
    and after.
    """

    def _programs(self) -> dict[str, str]:
        return {
            _a_body_opened_by(head, template): prints
            for template, prints in A_BODY_REPORTING_THE_MODE_ITS_PROLOGUE_DECIDES.values()
            for head in A_ROUTE_A_STRING_ARRIVES_AT_THE_HEAD_BY.values()
        }

    def test_node_prints_what_the_corpus_records_for_each_body(self):
        rows = self._programs()
        self.assertEqual(
            {source: host_behavior(source) for source in rows},
            {source: (prints, None) for source, prints in rows.items()},
        )

    def test_the_deobfuscation_of_each_body_prints_the_same(self):
        rows = self._programs()
        self.assertEqual(
            {source: host_behavior(deobfuscate_source(source)) for source in rows},
            {source: (prints, None) for source, prints in rows.items()},
        )


class TestThePrinterWritesOnlyADirectiveTheSourceWrote(TestBase):
    """
    Which statements the source wrote as directives is recorded when the file is parsed, and the
    printer is what keeps a statement that arrived later from being read as one. The bracket it
    writes is the whole mechanism: `('use strict');` computes the same string, declares nothing, and
    ends the run it stands in.

    That last part is why only a promoted `use strict` is written this way. Ending the run would
    eject every directive standing behind it, and for a string that declares no mode wherever it
    lands that is a cost paid for nothing.
    """

    def test_the_printer_answers_each_head_with_the_text_the_corpus_records(self):
        rows = A_HEAD_THE_PRINTER_ANSWERS_WITH
        self.assertEqual(
            {
                head: _deobfuscated(_a_function_body_opening_with_and_calling_g(head))
                for head in rows
            },
            dict(rows),
        )
