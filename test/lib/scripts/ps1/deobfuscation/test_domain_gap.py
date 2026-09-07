from __future__ import annotations

import collections
import unittest

from refinery.lib.scripts.ps1.analysis.values import NOTHING, UNKNOWN, apply, read, render
from refinery.lib.scripts.ps1.data import binary_operators, operand_witnesses
from refinery.lib.scripts.ps1.deobfuscation.emulator import _Ps1Interpreter
from refinery.lib.scripts.ps1.model import Ps1BinaryExpression, Ps1ExpressionStatement
from refinery.lib.scripts.ps1.parser import Ps1Parser

#: How many applications the interpreter answers and the value domain declines to, by the type of
#: the left operand. The interpreter cannot be pointed at the domain while this is not empty: every
#: one of these is a fold the deobfuscator takes today and would stop taking.
#:
#: The four largest rows are the four types the domain refuses to read a grid cell over, and they
#: are the migration's work in the order it is worth doing. This is a ratchet — the numbers come
#: down as the domain learns to answer, and a commit that raises one has removed a fold.
#:
#: The `String` and `Char` rows were raised once, by 25 and 15, and what was withdrawn there was a
#: wrong answer rather than a fold: `+` over a String or a Char on its left joins text, and a Double
#: on the right is a text `_rendered` refuses because the spelling is .NET's. Those pairs were
#: falling through to the arithmetic and answering `'5' + 1.5` with the number 6.5 where a host
#: writes `51.5`. They come back down by teaching the domain to spell a Double, not by computing.
#:
#: The `String` row was raised a second time, by 160, and again what was withdrawn was a wrong
#: answer: 5.1 *orders* two texts by `CompareInfo.Compare`, so a String on the left of `-lt`, `-le`,
#: `-gt` or `-ge` is not the numerals its operands spell — measured, `'10' -lt '9'` is `$True` and
#: `'2' -lt '10'` is `$False`, both of which reading them as numbers answers the other way. This row
#: comes back down by a collation and not by an arithmetic.
#:
#: All nine rows were then raised together, by 408 in total, and what was added was a fold rather
#: than a wrong answer: `-and` and `-or` short circuit, so the interpreter now answers them from the
#: left operand alone and never evaluates the operand it skips. The domain's `apply` still reads both
#: operands, so every pair whose skipped operand is one the interpreter cannot fold is new gap. These
#: rows come back down by teaching `apply` to short circuit as well, not by computing the operand
#: neither engine needs.
#:
#: The eight scalar rows were raised once more, by 168 in total, and again a fold was added rather
#: than a wrong answer withdrawn: the interpreter now reads the `-split` max-substrings argument.
#: `<string> -split <delimiter>, <n>` hands the operator a collection right operand the interpreter
#: used to refuse because stringifying it needs `$OFS`; it now caps the result at `n` elements and
#: answers, where `apply` still declines the split operators outright. `System.Object[]` alone does
#: not move, because a split reads its left operand as text and an array left is the one `$OFS`
#: refusal that survives. These rows come back down by teaching `apply` to split, not by computing.
#:
#: The eight scalar-and-array rows then fell, by 400 in total, and `System.Void` alone held. What was
#: withdrawn is not a fold the domain will come to need but a wrong answer the interpreter gave:
#: `-contains`, `-in` and their negations now test membership with 5.1's `LanguagePrimitives.Equals`,
#: which converts the item to each element's type, where they used to compare with Python's `==`. So
#: they refuse a membership test they cannot reproduce — an element or an item that is a `Double`
#: written as text, a `String` read as a `Double`, or an array compared by reference — rather than
#: answer it. `System.Object[]` falls furthest because it is the collection `-contains` enumerates,
#: and one element the equality cannot read refuses the whole test; the scalar rows fall through
#: `-in`, whose left operand keys them, when its right operand is such an array. These do not come
#: back by the domain learning to answer; the gap is smaller because the interpreter stopped
#: answering where it should not.
#:
#: The `String` and `Char` rows then came back down, by 25 and 15, reversing the first raise above.
#: The domain now spells a `Double` the way the .NET-Framework host writes it — `[string]0.5` is
#: `0.5` and `'5' + 1.5` is `51.5` — so `+` over a String or a Char on its left joins the two texts
#: where it used to fall through, and the pairs that were the raise are folds again rather than the
#: arithmetic `6.5` they once misread. Only these two rows move: a Double on the *left* of `+` is an
#: addition and never had this gap.
#:
#: The `Char` row then fell again, by 36, and what was withdrawn was a wrong answer rather than a
#: fold: `*` on a Char's left has no multiplication on 5.1, which throws `NotADefinedOperationForType`
#: there, where the interpreter held the Char as a one-character string and repeated it. The
#: interpreter now carries a Char apart from a String and refuses the repeat, so the pairs that were
#: `[char]65 * 2` folding to `AA` leave the gap. This does not come back by the domain learning to
#: answer; the gap is smaller because the interpreter stopped answering where it should not.
#:
#: Six rows then moved on one change, in opposite directions. The `Byte`, `Int32`, `Int64`, `String`
#: and `Void` rows rose together, by 64 in total, and what was added was a fold: `-shl` and `-shr`
#: read a `System.Char` on the *right* as the code point that is the shift count, where the
#: interpreter used to read the one-character string the Char spells and throw on a letter that is
#: no numeral. The `Char` row fell, by 43, and what was withdrawn was a wrong answer: a Char on the
#: *left* of `-shl` or `-shr` has no method on 5.1 — the `not defined` that `*` already throws — so
#: the interpreter now refuses it where it used to read the Char as a string and fold a shift the
#: host never runs. The five rises come back down by teaching `apply` the code point of a shift
#: count; the fall does not come back, the gap is smaller because the interpreter stopped answering
#: where it should not.
#:
#: Eight rows then rose together, by 616 in total, and `System.Object[]` alone held. What was added
#: is not a fold the domain lost but a false throw it stopped claiming: `-and`, `-or`, `-xor`, the
#: pattern and `-like` operators, `-contains`/`-in`, `-split` and `-f` all fell through `_kernel` to
#: `_numeric_pair`, whose refusal of a String no number reads was raised as a *certain* throw — an
#: answer that is neither a value nor the clean decline this census counts, so the gap went unseen.
#: `_kernel` now declines an operator that reads no number from its operands before it reaches the
#: pair, so each is the honest decline it always was. `System.Object[]` does not move because an
#: array left reaches these operators by a path that already declined without the pair.
GAP: dict[str, int] = {
    'System.String': 2133,
    'System.Object[]': 1317,
    'System.Char': 1125,
    'System.Int64': 1132,
    'System.Int32': 750,
    'System.Double': 640,
    'System.Byte': 450,
    'System.Boolean': 260,
    'System.Void': 170,
}

#: The witness spellings the reader cannot make a fact of, so the census is quantified over the
#: rest. Three are a `Single`, which no fact carries because `render` cannot spell one, and two read
#: a static member rather than writing a value. Pinned because a census whose population shrinks
#: silently reports an improvement it did not make.
UNREADABLE_WITNESSES: tuple[str, ...] = (
    '[decimal]::MaxValue',
    '[double]::MaxValue',
    '[single]-1.5',
    '[single]0',
    '[single]1.5',
)


def _witnesses() -> dict[str, tuple]:
    """
    The shipped operand witnesses as facts, keyed by the row they were captured for. Read out of
    the resource through the ordinary reader rather than written out again here, so that the census
    cannot come to be quantified over values the capture never used.
    """
    found = {}
    for name, spellings in operand_witnesses().items():
        facts = []
        for spelling in spellings:
            statement = next(
                node for node in Ps1Parser(spelling).parse().walk()
                if isinstance(node, Ps1ExpressionStatement)
            )
            fact = read(statement.expression)
            if fact is not UNKNOWN:
                facts.append(fact)
        if facts:
            found[name] = tuple(facts)
    return found


def _unreadable() -> list[str]:
    refused = []
    for spellings in operand_witnesses().values():
        for spelling in spellings:
            statement = next(
                node for node in Ps1Parser(spelling).parse().walk()
                if isinstance(node, Ps1ExpressionStatement)
            )
            if read(statement.expression) is UNKNOWN:
                refused.append(spelling)
    return sorted(refused)


def _gap() -> collections.Counter:
    interpreter = _Ps1Interpreter()
    counted: collections.Counter = collections.Counter()
    for operator in sorted(binary_operators()):
        for name, lefts in _witnesses().items():
            for rights in _witnesses().values():
                for left in lefts:
                    for right in rights:
                        spelled_left, spelled_right = render(left), render(right)
                        if spelled_left is None or spelled_right is None:
                            continue
                        node = Ps1BinaryExpression(
                            operator=operator, left=spelled_left, right=spelled_right)
                        try:
                            interpreter._eval_binary(node)
                        except Exception:
                            continue
                        if apply(operator, left, right) is NOTHING:
                            counted[name] += 1
    return counted


class TestPs1DomainAnswersWhereTheInterpreterDoes(unittest.TestCase):
    """
    What stands between the interpreter and the value domain, counted rather than described.

    The interpreter computes in Python values that carry no .NET type; the domain computes in facts
    that do. Pointing the first at the second is only sound once the domain answers wherever the
    interpreter answers, and this is the measurement of how far that is from true.
    """

    def test_the_applications_only_the_interpreter_answers_are_the_ones_recorded(self):
        self.assertEqual(dict(_gap()), GAP)

    def test_the_witnesses_the_census_cannot_read_are_the_ones_recorded(self):
        self.assertEqual(_unreadable(), sorted(UNREADABLE_WITNESSES))
