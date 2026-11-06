"""
Every snippet is written by hand and is a program a JavaScript engine compiles, not merely one the
parser accepts; the one exception is `JsDecorator`, since decorators are a proposal that has not
shipped. Nothing here may be read from disk, downloaded or derived from a sample, and nothing here
is ever run.
"""
from __future__ import annotations

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import JsTemplateLiteral

#: One minimal program per node class. Where the node has a child list, its snippet fills the list
#: with two entries, which the fidelity test cuts to each shorter length.
SNIPPETS: dict[str, str] = {
    'JsArrayExpression'          : '[1, 2];',
    'JsArrayPattern'             : 'var [a, b] = c;',
    'JsArrowFunctionExpression'  : 'var f = (a, b) => a + b;',
    'JsAssignmentExpression'     : 'a = 1;',
    'JsAssignmentPattern'        : 'function f(a = 1, b = 2) { return a; }',
    'JsAwaitExpression'          : 'async function f(p) { return await p; }',
    'JsBigIntLiteral'            : 'var x = 10n;',
    'JsBinaryExpression'         : '1 + 2;',
    'JsBlockStatement'           : '{ a; b; }',
    'JsBooleanLiteral'           : 'var x = true;',
    'JsBreakStatement'           : 'while (a) { break; }',
    'JsCallExpression'           : 'f(1, 2);',
    'JsCatchClause'              : 'try { a; } catch (e) { b; }',
    'JsClassBody'                : 'class C { m() {} n() {} }',
    'JsClassDeclaration'         : 'class C extends B { m() {} }',
    'JsClassExpression'          : 'var C = class extends B { m() {} };',
    'JsConditionalExpression'    : 'a ? b : c;',
    'JsContinueStatement'        : 'while (a) { continue; }',
    'JsDebuggerStatement'        : 'debugger;',
    'JsDecorator'                : 'class C { @a @b m() {} }',
    'JsDoWhileStatement'         : 'do { a; } while (b);',
    'JsEmptyStatement'           : ';',
    'JsExportAllDeclaration'     : "export * as ns from 'm';",
    'JsExportDefaultDeclaration' : 'export default 1;',
    'JsExportNamedDeclaration'   : 'var a, c; export { a as b, c };',
    'JsExportSpecifier'          : 'var a, c; export { a as b, c };',
    'JsExpressionStatement'      : 'a;',
    'JsForInStatement'           : 'for (var k in o) { a; }',
    'JsForOfStatement'           : 'for (var v of o) { a; }',
    'JsForStatement'             : 'for (var i = 0; i < 2; i++) { a; }',
    'JsFunctionDeclaration'      : 'function f(a, b) { return a; }',
    'JsFunctionExpression'       : 'var f = function (a, b) { return a; };',
    'JsIdentifier'               : 'a;',
    'JsIfStatement'              : 'if (a) { b; } else { c; }',
    'JsImportAttribute'          : "import a from 'm' with { type: 'json', x: 'y' };",
    'JsImportDeclaration'        : "import a, { b as c } from 'm';",
    'JsImportDefaultSpecifier'   : "import a, { b as c } from 'm';",
    'JsImportExpression'         : "import('m', { with: { type: 'json' } });",
    'JsImportNamespaceSpecifier' : "import * as ns from 'm';",
    'JsImportSpecifier'          : "import { a as b, c } from 'm';",
    'JsLabeledStatement'         : 'outer: while (a) { break outer; }',
    'JsLogicalExpression'        : 'a && b;',
    'JsMemberExpression'         : 'a.b;',
    'JsMetaProperty'             : 'import.meta;',
    'JsMethodDefinition'         : 'class C { m() {} static n() {} }',
    'JsNewExpression'            : 'new C(1, 2);',
    'JsNullLiteral'              : 'var x = null;',
    'JsNumericLiteral'           : 'var x = 1;',
    'JsObjectExpression'         : 'var o = { a: 1, b: 2 };',
    'JsObjectPattern'            : 'var { a, b } = o;',
    'JsParenthesizedExpression'  : '(a);',
    'JsPrivateIdentifier'        : 'class C { #x = 1; m() { return this.#x; } }',
    'JsProperty'                 : 'var o = { a: 1, b: 2 };',
    'JsPropertyDefinition'       : 'class C { x = 1; static y = 2; }',
    'JsRegExpLiteral'            : 'var r = /ab+c/gi;',
    'JsRestElement'              : 'function f(a, ...rest) { return rest; }',
    'JsReturnStatement'          : 'function f() { return 1; }',
    'JsScript'                   : 'a; b;',
    'JsSequenceExpression'       : 'a, b;',
    'JsSpreadElement'            : 'f(...a, ...b);',
    'JsStaticBlock'              : 'class C { static { a; b; } }',
    'JsStringLiteral'            : "var s = 'a';",
    'JsSwitchCase'               : 'switch (a) { case 1: b; break; default: c; }',
    'JsSwitchStatement'          : 'switch (a) { case 1: b; break; default: c; }',
    'JsTaggedTemplateExpression' : 'tag`a${b}c${d}e`;',
    'JsTemplateElement'          : '`a${b}c${d}e`;',
    'JsTemplateLiteral'          : '`a${b}c${d}e`;',
    'JsThisExpression'           : 'this;',
    'JsThrowStatement'           : 'throw a;',
    'JsTryStatement'             : 'try { a; } catch (e) { b; } finally { c; }',
    'JsUnaryExpression'          : 'typeof a;',
    'JsUpdateExpression'         : 'a++;',
    'JsVariableDeclaration'      : 'var a = 1, b = 2;',
    'JsVariableDeclarator'       : 'var a = 1, b = 2;',
    'JsWhileStatement'           : 'while (a) { b; }',
    'JsWithStatement'            : 'with (o) { a; }',
    'JsYieldExpression'          : 'function* g(h) { yield 1; yield* h(); }',
}

#: The fewest entries a child list must hold for the tree to spell a program. A child list not named
#: here may be empty.
SHORTEST_LIST: dict[str, dict[str, int]] = {
    'JsSequenceExpression'  : {'expressions': 2},
    'JsVariableDeclaration' : {'declarations': 1},
}


def shapes_the_grammar_forbids(root: Node) -> list[str]:
    found: list[str] = []
    for node in root.walk():
        name = type(node).__name__
        if getattr(node, 'name', None) == '':
            found.append(F'{name} has no name')
        if isinstance(node, JsTemplateLiteral):
            runs, holes = len(node.quasis), len(node.expressions)
            if runs != holes + 1:
                found.append(F'JsTemplateLiteral has {runs} runs around {holes} holes')
        for attribute, shortest in SHORTEST_LIST.get(name, {}).items():
            held = len(getattr(node, attribute))
            if held < shortest:
                found.append(F'{name} holds {held} of {attribute}, fewer than {shortest}')
    return found
