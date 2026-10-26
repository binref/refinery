"""
A comparison of the host's clock with a time. A run is assumed to read the clock inside a window of
dates (`refinery.lib.scripts.js.analysis.environment.ASSUMED_CLOCK`), so a comparison with a time
outside the window answers the same for every run and folds wherever the clock is the built-in's;
a time inside it is the program's own, an expiry or a time the program waits for, and stays.

SECURITY: every program here is hand-authored and benign. No sample and no stored obfuscator fixture
may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from datetime import date, datetime, timezone

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints

from refinery.lib.scripts.js.analysis.environment import ASSUMED_CLOCK, ClockWindow
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

_COMPARISONS = ('<', '<=', '>', '>=', '==', '===', '!=', '!==')


def _deobfuscated(source: str, clock: ClockWindow | None = ASSUMED_CLOCK) -> str:
    ast = JsParser(source).parse()
    deobfuscate(ast, execution=ExecutionModel.module, clock=clock)
    return JsSynthesizer().convert(ast)


class TestTheWindowDecidesOnlyATimeOutsideIt(TestBase):

    def test_the_window_holds_the_second_day_of_2000_to_the_last_day_of_2099(self):
        days = [datetime.fromtimestamp(time / 1000, timezone.utc).date() for time in ASSUMED_CLOCK]
        self.assertEqual(days, [date(2000, 1, 2), date(2099, 12, 31)])

    def test_a_time_inside_the_window_its_ends_included_is_undecided(self):
        earliest, latest = ASSUMED_CLOCK
        for time in (earliest, latest, (earliest + latest) // 2):
            for comparison in _COMPARISONS:
                with self.subTest(time=time, comparison=comparison):
                    self.assertIsNone(ASSUMED_CLOCK.comparison(comparison, time))

    def test_a_time_one_millisecond_before_the_window_is_decided(self):
        earliest, _ = ASSUMED_CLOCK
        self.assertEqual(
            {comparison: ASSUMED_CLOCK.comparison(comparison, earliest - 1) for comparison in _COMPARISONS},
            {
                '<'   : False,
                '<='  : False,
                '>'   : True,
                '>='  : True,
                '=='  : False,
                '===' : False,
                '!='  : True,
                '!==' : True,
            },
        )

    def test_a_time_one_millisecond_after_the_window_is_decided(self):
        _, latest = ASSUMED_CLOCK
        self.assertEqual(
            {comparison: ASSUMED_CLOCK.comparison(comparison, latest + 1) for comparison in _COMPARISONS},
            {
                '<'   : True,
                '<='  : True,
                '>'   : False,
                '>='  : False,
                '=='  : False,
                '===' : False,
                '!='  : True,
                '!==' : True,
            },
        )

    def test_nan_and_an_operator_that_compares_nothing_are_undecided(self):
        self.assertIsNone(ASSUMED_CLOCK.comparison('<', float('nan')))
        self.assertIsNone(ASSUMED_CLOCK.comparison('+', 0))
        self.assertIsNone(ASSUMED_CLOCK.comparison('in', 0))


class TestAComparisonOfTheClockFolds(TestBase):

    def test_a_check_against_the_end_or_the_start_of_the_window_goes(self):
        for source in (
            "if (Date.now() > 4102444800000) { while (true) {} }\nconsole.log('ran');",
            "if ((new Date()).getTime() > 4102444800000) { while (true) {} }\nconsole.log('ran');",
            "if (Date.now() < 946684800000) { while (true) {} }\nconsole.log('ran');",
            "if (Date.prototype.getTime.call(new Date()) > 4102444800000) { while (true) {} }\nconsole.log('ran');",
        ):
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source), "console.log('ran');")

    def test_each_form_of_the_comparison_folds(self):
        for source, folded in {
            'console.log(4102444800000 < Date.now(), 946684800000 <= Date.now());': 'console.log(false, true);',
            'console.log(Date.now() == 0, Date.now() !== 4102444800000);': 'console.log(false, true);',
            "console.log(Date['now']() > 4102444800000, new Date()['getTime']() < 946684800000);": (
                'console.log(false, false);'
            ),
            "console.log(Date['prototype']['getTime']['call'](new Date()) < 946684800000);": (
                'console.log(false);'
            ),
            'console.log(Date.now() < 946684804000, Date.now() > 4102444796000);': 'console.log(false, false);',
        }.items():
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source), folded)

    def test_no_window_decides_nothing(self):
        source = "if (Date.now() > 4102444800000) { while (true) {} }\nconsole.log('ran');"
        self.assertIn('Date.now() > 4102444800000', _deobfuscated(source, clock=None))


class TestAComparisonTheWindowDoesNotDecideStays(TestBase):

    def test_a_comparison_stays_where_the_time_is_inside_the_window_or_the_clock_may_be_replaced(self):
        for source, kept in {
            "if (Date.now() > 4000000000000) { console.log('late'); } else { console.log('early'); }": (
                'Date.now() > 4000000000000'
            ),
            'console.log(Date.now() > 946771200000);': 'Date.now() > 946771200000',
            inspect.cleandoc("""
                function payload() { console.log('payload ran'); }
                if (Date.now() > 1735689600000) { console.log('expired'); } else { payload(); }
            """): 'Date.now() > 1735689600000',
            inspect.cleandoc("""
                Date.now = function () { return 5000000000000; };
                if (Date.now() > 4102444800000) { console.log('late'); }
            """): 'Date.now() > 4102444800000',
            inspect.cleandoc("""
                Date.prototype.getTime = function () { return 5000000000000; };
                if (new Date().getTime() > 4102444800000) { console.log('late'); }
            """): 'new Date().getTime() > 4102444800000',
            'console.log(new Date(0).getTime() > 4102444800000);': 'new Date(0).getTime() > 4102444800000',
            'console.log(Date.now() > NaN);': 'Date.now() > NaN',
            'var n = 0;\nconsole.log(Date.now(n++) > 4102444800000, n);': 'Date.now(n++) > 4102444800000',
            inspect.cleandoc("""
                Function.prototype.call = function () { return 5000000000000; };
                console.log(Date.prototype.getTime.call(new Date()) > 4102444800000);
            """): 'Date.prototype.getTime.call(new Date()) > 4102444800000',
            inspect.cleandoc("""
                (0, Date).now = function () { return 5000000000000; };
                console.log(Date.now() > 4102444800000);
            """): 'Date.now() > 4102444800000',
        }.items():
            with self.subTest(source=source):
                self.assertIn(kept, _deobfuscated(source))


#: Programs comparing the host's clock with a time, in the three forms a read of the clock takes,
#: with the built-in `Date` and with every way a program replaces what it answers, mapped to what
#: Node prints for them.
A_COMPARISON_OF_THE_CLOCK = {
    "if (Date.now() > 4102444800000) { while (true) {} }\nconsole.log('ran');": 'ran\n',
    "if ((new Date()).getTime() > 4102444800000) { while (true) {} }\nconsole.log('ran');": 'ran\n',
    "if (Date.now() < 946684800000) { while (true) {} }\nconsole.log('ran');": 'ran\n',
    "if (Date.now() > 4000000000000) { console.log('late'); } else { console.log('early'); }": 'early\n',
    inspect.cleandoc("""
        Date.now = function () { return 5000000000000; };
        if (Date.now() > 4102444800000) { console.log('late'); }
    """): 'late\n',
    inspect.cleandoc("""
        Date.prototype.getTime = function () { return 5000000000000; };
        if (new Date().getTime() > 4102444800000) { console.log('late'); }
    """): 'late\n',
    inspect.cleandoc("""
        function f() {
          var Date = { now: function () { return 5000000000000; } };
          return Date.now() > 4102444800000;
        }
        console.log(f());
    """): 'true\n',
    inspect.cleandoc("""
        globalThis.Date = { now: function () { return 5000000000000; } };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        Object.defineProperty(Date, 'now', { value: function () { return 5000000000000; } });
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        var D = Date;
        D.now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    'console.log(4102444800000 < Date.now(), 946684800000 <= Date.now());': 'false true\n',
    'console.log(Date.now() == 0, Date.now() !== 4102444800000);': 'false true\n',
    'console.log(new Date(0).getTime() > 4102444800000, new Date(0).getTime() < 946684800000);': 'false true\n',
    'console.log(Date.now() > NaN, Date.now() < NaN);': 'false false\n',
    inspect.cleandoc("""
        with ({ Date: { now: function () { return 5000000000000; } } }) {
          console.log(Date.now() > 4102444800000);
        }
    """): 'true\n',
    'console.log(Date.now() < Infinity, Date.now() > -Infinity);': 'true true\n',
    "console.log(Date['now']() > 4102444800000, new Date()['getTime']() < 946684800000);": 'false false\n',
    inspect.cleandoc("""
        Object.setPrototypeOf(Date, { now: function () { return 5000000000000; } });
        delete Date.now;
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        Reflect.set(Date, 'now', function () { return 5000000000000; });
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function late() { return Date.now() > 4102444800000; }
        console.log(late());
        Date.now = function () { return 5000000000000; };
        console.log(late());
    """): 'false\ntrue\n',
    'var n = 0;\nconsole.log(Date.now(n++) > 4102444800000, n);': 'false 1\n',
    inspect.cleandoc("""
        function patch(d) { d.now = function () { return 5000000000000; }; }
        patch(Date);
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        eval('Date.now = function () { return 5000000000000; }');
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    'var a = [0];\nconsole.log(new Date(...a).getTime() > 4102444800000);': 'false\n',
    inspect.cleandoc("""
        class Clock { static now() { return 5000000000000; } }
        var Date2 = Clock;
        console.log(Date2.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function patch(p) { p.getTime = function () { return 5000000000000; }; }
        patch(Date.prototype);
        console.log(new Date().getTime() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        Object.assign(Date, { now: function () { return 5000000000000; } });
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        var holder = { d: Date };
        holder.d.now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function get() { return Date; }
        get().now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        function payload() { console.log('payload ran'); }
        if (Date.now() > 1735689600000) { console.log('expired'); } else { payload(); }
    """): 'expired\n',
    inspect.cleandoc("""
        if (Date.prototype.getTime.call(new Date()) > 4102444800000) { while (true) {} }
        console.log(Date['prototype']['getTime']['call'](new Date()) < 946684800000);
    """): 'false\n',
    inspect.cleandoc("""
        Function.prototype.call = function () { return 5000000000000; };
        console.log(Date.prototype.getTime.call(new Date()) > 4102444800000);
    """): '',
    'console.log(Date.now() < 946684804000, Date.now() > 4102444796000);': 'false false\n',
    'console.log(Date.now() > 946771200000);': 'true\n',
    inspect.cleandoc("""
        (0, Date).now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        (Date || null).now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
    inspect.cleandoc("""
        (process.argv.length ? Date : Math).now = function () { return 5000000000000; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAComparisonOfTheClock(TestBase):

    def test_a_comparison_folds_only_where_the_clock_is_the_built_in(self):
        rows = A_COMPARISON_OF_THE_CLOCK
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
