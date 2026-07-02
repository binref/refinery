from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.php.model import PhpErrorNode
from refinery.lib.scripts.php.parser import PhpParser
from refinery.lib.scripts.php.synth import PhpSynthesizer


class TestPhpSynthesizer(TestBase):

    def _round_trip(self, source: str) -> str:
        synth = PhpSynthesizer()
        ast1 = PhpParser(source).parse()
        errors = [n for n in ast1.walk() if isinstance(n, PhpErrorNode)]
        self.assertEqual(
            errors, [],
            F'Parse produced error nodes for {source!r}: '
            F'{[e.text for e in errors]}',
        )
        out1 = synth.convert(ast1)
        ast2 = PhpParser(out1).parse()
        out2 = synth.convert(ast2)
        self.assertEqual(
            out1, out2,
            F'Round-trip not a fixpoint:\nInput: {source!r}\n'
            F'First: {out1!r}\nSecond: {out2!r}',
        )
        return out1

    def test_int_literal(self):
        self._round_trip('<?php 42;')

    def test_float_literal(self):
        self._round_trip('<?php 3.14;')

    def test_string_single(self):
        self._round_trip("<?php 'hello';")

    def test_string_double(self):
        self._round_trip('<?php "hello";')

    def test_interpolated_string(self):
        self._round_trip('<?php $s = "hello $world and {$obj->x}";')

    def test_heredoc(self):
        self._round_trip('<?php $h = <<<EOT\nline $x\nEOT;\n')

    def test_arithmetic_precedence(self):
        self._round_trip('<?php $x = 1 + 2 * 3;')

    def test_concat_precedence(self):
        self._round_trip('<?php $x = "a" . 1 + 2;')

    def test_parenthesized(self):
        self._round_trip('<?php $x = (1 + 2) * 3;')

    def test_pow_right_assoc(self):
        self._round_trip('<?php $x = 2 ** 3 ** 2;')

    def test_coalesce_and_short_ternary(self):
        self._round_trip('<?php $z = $a ?? $b ?: $c;')

    def test_nested_unary(self):
        self._round_trip('<?php $u = -(-$x);')

    def test_not_of_and(self):
        self._round_trip('<?php $v = !($a && $b);')

    def test_cast(self):
        self._round_trip('<?php $x = (string) $y;')

    def test_instanceof_ternary(self):
        self._round_trip('<?php echo $a instanceof Foo ? -$b ** 2 : ~$c;')

    def test_assignment_by_ref(self):
        self._round_trip('<?php $x = &$y;')

    def test_function_declaration(self):
        self._round_trip(
            '<?php function f(int $x, ...$rest): string { return (string) $x; }')

    def test_closure_with_use(self):
        self._round_trip('<?php $d = static function () use (&$y) { return $y; };')

    def test_arrow_function(self):
        self._round_trip('<?php $c = fn($x) => $x * 2;')

    def test_match(self):
        self._round_trip('<?php $r = match ($x) { 1, 2 => "a", default => "b" };')

    def test_class_with_attribute(self):
        self._round_trip(
            '<?php #[Attr(1)] class C extends B implements I '
            '{ public int $n = 0; const X = 1; function m() {} }')

    def test_enum(self):
        self._round_trip(
            '<?php enum Suit: string { case Hearts = "H"; case Spades = "S"; }')

    def test_if_alternative_syntax(self):
        self._round_trip('<?php if ($a): echo 1; elseif ($b): echo 2; else: echo 3; endif;')

    def test_while_alternative_syntax(self):
        self._round_trip('<?php while ($i < 10): $i++; endwhile;')

    def test_foreach_by_ref(self):
        self._round_trip('<?php foreach ($arr as $k => &$v) { $v++; }')

    def test_for(self):
        self._round_trip('<?php for ($i = 0; $i < 10; $i++) { echo $i; }')

    def test_switch(self):
        self._round_trip('<?php switch ($x) { case 1: break; default: return; }')

    def test_try_catch_finally(self):
        self._round_trip(
            '<?php try { risky(); } catch (A | B $e) { log($e); } finally { cleanup(); }')

    def test_new_and_anonymous_class(self):
        self._round_trip('<?php $o = new Foo($a, name: $b); $p = new class extends Bar {};')

    def test_nullsafe_chain(self):
        self._round_trip('<?php $q = $obj?->prop->method()::CONST;')

    def test_namespace_and_use(self):
        self._round_trip('<?php namespace A\\B; use C\\D as E; use function F\\{g, h};')

    def test_array_spread_and_destructuring(self):
        self._round_trip('<?php $arr = [1, 2, ...$more, "k" => $v]; [$a, $b] = $arr;')

    def test_first_class_callable(self):
        self._round_trip('<?php $g = strlen(...); $h = $obj->method(...);')

    def test_global_static_goto(self):
        self._round_trip('<?php global $a, $b; static $c = 1; goto end; end: ;')

    def test_declare_and_trait(self):
        self._round_trip('<?php declare(strict_types=1); trait T { public function h() {} }')

    def test_html_islands(self):
        self._round_trip('<html><?php echo "hi", $x; ?></html>')

    def test_echo_tag(self):
        self._round_trip('<div><?= $name ?></div>')

    def test_yield(self):
        self._round_trip('<?php function g() { yield $k => $v; yield from $other; }')
