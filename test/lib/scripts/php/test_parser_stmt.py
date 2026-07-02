from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.php.model import (
    PhpBlock,
    PhpBreak,
    PhpClass,
    PhpClassConst,
    PhpClassKind,
    PhpClassMethod,
    PhpConst,
    PhpContinue,
    PhpDeclare,
    PhpDoWhile,
    PhpEcho,
    PhpEchoTagStatement,
    PhpEnumCase,
    PhpExpressionStatement,
    PhpFor,
    PhpForeach,
    PhpFunctionDeclaration,
    PhpGlobal,
    PhpGoto,
    PhpIf,
    PhpInlineHTML,
    PhpLabel,
    PhpNamespace,
    PhpNop,
    PhpProperty,
    PhpReturn,
    PhpStaticVar,
    PhpSwitch,
    PhpThrowStatement,
    PhpTraitUse,
    PhpTry,
    PhpUnset,
    PhpUse,
    PhpWhile,
)
from refinery.lib.scripts.php.parser import PhpParser


class TestPhpParserStmt(TestBase):

    def _parse(self, code: str):
        return PhpParser(code).parse().body

    def _one(self, code: str):
        body = self._parse(F'<?php {code}')
        self.assertEqual(len(body), 1)
        return body[0]

    def test_inline_html(self):
        body = self._parse('<p>text</p>')
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], PhpInlineHTML)
        self.assertEqual(body[0].value, '<p>text</p>')

    def test_echo_tag(self):
        body = self._parse('<?= $x ?>')
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], PhpEchoTagStatement)

    def test_expression_statement(self):
        node = self._one('$x = 1;')
        self.assertIsInstance(node, PhpExpressionStatement)

    def test_empty_statement(self):
        node = self._one(';')
        self.assertIsInstance(node, PhpNop)

    def test_echo(self):
        node = self._one('echo $a, $b;')
        self.assertIsInstance(node, PhpEcho)
        self.assertEqual(len(node.expressions), 2)

    def test_block(self):
        node = self._one('{ $a; $b; }')
        self.assertIsInstance(node, PhpBlock)
        self.assertEqual(len(node.body), 2)

    def test_if(self):
        node = self._one('if ($a) { echo 1; }')
        self.assertIsInstance(node, PhpIf)
        self.assertEqual(node.alternative_syntax, False)

    def test_if_elseif_else(self):
        node = self._one('if ($a) {} elseif ($b) {} else {}')
        self.assertIsInstance(node, PhpIf)
        self.assertEqual(len(node.elseifs), 1)
        self.assertEqual(node.alternate, [])

    def test_if_alternative_syntax(self):
        node = self._one('if ($a): echo 1; endif;')
        self.assertIsInstance(node, PhpIf)
        self.assertEqual(node.alternative_syntax, True)

    def test_while(self):
        node = self._one('while ($a) { $a--; }')
        self.assertIsInstance(node, PhpWhile)

    def test_while_alternative(self):
        node = self._one('while ($a): $a--; endwhile;')
        self.assertIsInstance(node, PhpWhile)
        self.assertEqual(node.alternative_syntax, True)

    def test_do_while(self):
        node = self._one('do { $a--; } while ($a);')
        self.assertIsInstance(node, PhpDoWhile)

    def test_for(self):
        node = self._one('for ($i = 0; $i < 10; $i++) {}')
        self.assertIsInstance(node, PhpFor)
        self.assertEqual(len(node.init), 1)
        self.assertEqual(len(node.condition), 1)
        self.assertEqual(len(node.update), 1)

    def test_foreach(self):
        node = self._one('foreach ($arr as $v) {}')
        self.assertIsInstance(node, PhpForeach)
        self.assertEqual(node.key, None)

    def test_foreach_key_value(self):
        node = self._one('foreach ($arr as $k => $v) {}')
        self.assertIsInstance(node, PhpForeach)
        self.assertIsNotNone(node.key)

    def test_foreach_by_ref(self):
        node = self._one('foreach ($arr as &$v) {}')
        self.assertIsInstance(node, PhpForeach)
        self.assertEqual(node.by_ref, True)

    def test_switch(self):
        node = self._one('switch ($x) { case 1: break; default: return; }')
        self.assertIsInstance(node, PhpSwitch)
        self.assertEqual(len(node.cases), 2)

    def test_break(self):
        node = self._one('while (1) { break; }')
        self.assertIsInstance(node.body[0], PhpBreak)

    def test_break_level(self):
        node = self._one('while (1) { break 2; }')
        self.assertIsNotNone(node.body[0].level)

    def test_continue(self):
        node = self._one('while (1) { continue; }')
        self.assertIsInstance(node.body[0], PhpContinue)

    def test_return(self):
        node = self._one('return $x;')
        self.assertIsInstance(node, PhpReturn)
        self.assertIsNotNone(node.value)

    def test_return_void(self):
        node = self._one('return;')
        self.assertIsInstance(node, PhpReturn)
        self.assertEqual(node.value, None)

    def test_throw_statement(self):
        node = self._one('throw $e;')
        self.assertIsInstance(node, PhpThrowStatement)

    def test_try_catch_finally(self):
        node = self._one('try {} catch (A | B $e) {} finally {}')
        self.assertIsInstance(node, PhpTry)
        self.assertEqual(len(node.catches), 1)
        self.assertEqual(len(node.catches[0].types), 2)
        self.assertIsNotNone(node.finally_body)

    def test_unset(self):
        node = self._one('unset($a, $b);')
        self.assertIsInstance(node, PhpUnset)
        self.assertEqual(len(node.variables), 2)

    def test_global(self):
        node = self._one('global $a, $b;')
        self.assertIsInstance(node, PhpGlobal)
        self.assertEqual(len(node.variables), 2)

    def test_static_var(self):
        node = self._one('static $a = 1;')
        self.assertIsInstance(node, PhpStaticVar)
        self.assertEqual(len(node.declarations), 1)

    def test_goto_and_label(self):
        body = self._parse('<?php goto end; end: ;')
        self.assertIsInstance(body[0], PhpGoto)
        self.assertIsInstance(body[1], PhpLabel)

    def test_function_declaration(self):
        node = self._one('function f(int $x): string { return ""; }')
        self.assertIsInstance(node, PhpFunctionDeclaration)
        self.assertEqual(node.name, 'f')
        self.assertEqual(len(node.params), 1)

    def test_function_by_ref(self):
        node = self._one('function &f() {}')
        self.assertIsInstance(node, PhpFunctionDeclaration)
        self.assertEqual(node.by_ref, True)

    def test_class(self):
        node = self._one('class C extends B implements I {}')
        self.assertIsInstance(node, PhpClass)
        self.assertEqual(node.kind, PhpClassKind.CLASS)
        self.assertEqual(len(node.extends), 1)
        self.assertEqual(len(node.implements), 1)

    def test_abstract_class(self):
        node = self._one('abstract class C {}')
        self.assertIsInstance(node, PhpClass)
        self.assertEqual(node.modifiers, ['abstract'])

    def test_interface(self):
        node = self._one('interface I {}')
        self.assertIsInstance(node, PhpClass)
        self.assertEqual(node.kind, PhpClassKind.INTERFACE)

    def test_trait(self):
        node = self._one('trait T {}')
        self.assertIsInstance(node, PhpClass)
        self.assertEqual(node.kind, PhpClassKind.TRAIT)

    def test_enum(self):
        node = self._one('enum Suit: string { case Hearts = "H"; }')
        self.assertIsInstance(node, PhpClass)
        self.assertEqual(node.kind, PhpClassKind.ENUM)
        self.assertIsInstance(node.members[0], PhpEnumCase)

    def test_class_members(self):
        node = self._one(
            'class C { public int $n = 0; const X = 1; public function m() {} }')
        self.assertIsInstance(node.members[0], PhpProperty)
        self.assertIsInstance(node.members[1], PhpClassConst)
        self.assertIsInstance(node.members[2], PhpClassMethod)

    def test_trait_use(self):
        node = self._one('class C { use T; }')
        self.assertIsInstance(node.members[0], PhpTraitUse)

    def test_namespace(self):
        node = self._one('namespace A\\B;')
        self.assertIsInstance(node, PhpNamespace)

    def test_use(self):
        node = self._one('use A\\B as C;')
        self.assertIsInstance(node, PhpUse)
        self.assertEqual(node.uses[0].alias, 'C')

    def test_const(self):
        node = self._one('const X = 1, Y = 2;')
        self.assertIsInstance(node, PhpConst)
        self.assertEqual(len(node.consts), 2)

    def test_declare(self):
        node = self._one('declare(strict_types=1);')
        self.assertIsInstance(node, PhpDeclare)
        self.assertEqual(len(node.directives), 1)

    def test_promoted_constructor_params(self):
        node = self._one(
            'class C { public function __construct(private readonly int $x) {} }')
        method = node.members[0]
        self.assertIsInstance(method, PhpClassMethod)
        self.assertEqual(method.params[0].readonly, True)
