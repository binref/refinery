from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import inspect
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock

from pathlib import Path

from test import TestBase

from test.lib.scripts.js.analysis import node_answers, nodejs
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.analysis.node_answers import KeptAnswers, answers_kept_in

A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN = 'console.log(Math.random());'

THE_HOUR_AT_THE_START_OF_1970 = 'console.log(new Date(0).getHours());'

AN_IMPOSTORS_REPORT = '["not a version",{},"win32","x64","en-US","UTC"]'

ONE = hashlib.sha256(B'one').digest()
TWO = hashlib.sha256(B'two').digest()

ROOT = Path(__file__).resolve().parents[5]


def an_impostor(folder: str) -> str:
    """
    A program in *folder* that prints `AN_IMPOSTORS_REPORT` whatever it is asked, as a program in
    the place of Node would print something that is not Node's answer.
    """
    impostor = os.path.join(folder, 'impostor.cmd' if os.name == 'nt' else 'impostor')
    with open(impostor, 'w') as script:
        if os.name == 'nt':
            script.write(F'@echo {AN_IMPOSTORS_REPORT}\n')
        else:
            script.write(inspect.cleandoc(F'''
                #!/bin/sh
                echo '{AN_IMPOSTORS_REPORT}'
            '''))
    os.chmod(impostor, 0o755)
    return impostor


def a_wrapper_around_node(path: Path, *options: str) -> None:
    """
    Write a program at *path* that runs the real Node with *options* and whatever it is given.
    """
    arguments = ' '.join([F'"{node_executable()}"', *options])
    if os.name == 'nt':
        path.write_text(F'@{arguments} %*\n')
    else:
        path.write_text(inspect.cleandoc(F'''
            #!/bin/sh
            exec {arguments} "$@"
        '''))
        path.chmod(0o755)


@contextlib.contextmanager
def a_store_opened_on(folder: str, day: int):
    with unittest.mock.patch.object(node_answers, 'time') as clock:
        clock.time.return_value = day * 24 * 60 * 60
        store = KeptAnswers(Path(folder))
    try:
        yield store
    finally:
        store.close()


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARunRemembersWhatNodeAnswered(TestBase):

    def test_a_program_asked_about_twice_is_given_the_same_answer(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with answers_kept_in(None):
            self.assertEqual(behavior(program), behavior(program))

    def test_a_fresh_run_runs_the_program_again(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with answers_kept_in(None):
            self.assertNotEqual(behavior(program), behavior(program, fresh=True))

    def test_a_program_asked_about_in_two_time_zones_is_given_the_answer_of_each(self):
        answers = []
        with answers_kept_in(None):
            for time_zone in ['UTC', 'Asia/Tokyo']:
                with unittest.mock.patch.dict(os.environ, {'TZ': time_zone}):
                    answers.append(behavior(THE_HOUR_AT_THE_START_OF_1970))
        self.assertEqual(answers, [('0\n', None), ('9\n', None)])

    def test_a_run_inside_another_remembers_nothing_of_it_and_the_outer_run_goes_on_after_it(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with answers_kept_in(None):
            outer = behavior(program)
            with answers_kept_in(None):
                inner = behavior(program)
            again = behavior(program)
        self.assertNotEqual(outer, inner)
        self.assertEqual(outer, again)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAnswerWithoutAnErrorIsKeptForTheNextRun(TestBase):

    def test_a_later_run_is_given_the_answer_an_earlier_run_kept(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as folder:
            with answers_kept_in(lambda: Path(folder)):
                first = behavior(program)
            with answers_kept_in(lambda: Path(folder)):
                again = behavior(program)
        self.assertEqual(first, again)

    def test_an_answer_that_ends_in_an_error_is_not_kept(self):
        program = 'console.log(Math.random()); throw new TypeError("after printing");'
        with tempfile.TemporaryDirectory() as folder:
            with answers_kept_in(lambda: Path(folder)):
                first = behavior(program)
            with answers_kept_in(lambda: Path(folder)):
                again = behavior(program)
        self.assertEqual((first[1], again[1]), ('TypeError', 'TypeError'))
        self.assertNotEqual(first[0], again[0])

    def test_an_answer_with_any_character_is_given_exactly_as_node_gave_it(self):
        program = R'console.log(Math.random() + "\u0000\u00e4\u4e2d\ud83d\ude00\ud83d");'
        with tempfile.TemporaryDirectory() as folder:
            with answers_kept_in(lambda: Path(folder)):
                first = behavior(program)
            with answers_kept_in(lambda: Path(folder)):
                again = behavior(program)
        self.assertEqual(first, again)
        self.assertIn('\x00\xe4\u4e2d\U0001F600\ufffd', first[0])

    def test_answers_kept_in_one_time_zone_are_given_in_it_and_not_in_another(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        answers = []
        with tempfile.TemporaryDirectory() as folder:
            for time_zone in ['UTC', 'Asia/Tokyo', 'UTC']:
                with unittest.mock.patch.dict(os.environ, {'TZ': time_zone}):
                    with answers_kept_in(lambda: Path(folder)):
                        answers.append(behavior(program))
        utc, tokyo, utc_again = answers
        self.assertEqual(utc, utc_again)
        self.assertNotEqual(utc, tokyo)

    def test_two_spellings_of_the_time_zone_that_node_reads_as_one_share_their_answers(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        answers = []
        with tempfile.TemporaryDirectory() as folder:
            for time_zone in ['UTC', 'Etc/UTC']:
                with unittest.mock.patch.dict(os.environ, {'TZ': time_zone}):
                    with answers_kept_in(lambda: Path(folder)):
                        answers.append(behavior(program))
        utc, etc_utc = answers
        self.assertEqual(utc, etc_utc)

    def test_a_node_in_the_same_place_that_reports_another_version_is_not_given_the_answers(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        answers = []
        with tempfile.TemporaryDirectory() as programs, tempfile.TemporaryDirectory() as folder:
            older = Path(programs, 'older.js')
            older.write_text('Object.defineProperty(process, "version", { value: "v0.0.1" });\n')
            node = Path(programs, 'node.cmd' if os.name == 'nt' else 'node')
            for options in [(), ('-r', F'"{older}"'), ()]:
                a_wrapper_around_node(node, *options)
                with unittest.mock.patch.object(nodejs, 'node_executable', return_value=str(node)):
                    with answers_kept_in(lambda: Path(folder)):
                        answers.append(behavior(program))
        first, older_node, first_again = answers
        self.assertEqual(first, first_again)
        self.assertNotEqual(first, older_node)

    def test_a_node_that_cannot_say_what_it_is_keeps_nothing(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as programs, tempfile.TemporaryDirectory() as folder:
            impostor = an_impostor(programs)
            for name, executable in [
                ('missing', os.path.join(programs, 'missing')),
                ('python', sys.executable),
                ('impostor', impostor),
            ]:
                with self.subTest(node=name):
                    self.assertIsNone(nodejs.identity(executable))
            with unittest.mock.patch.object(nodejs, 'node_executable', return_value=impostor):
                with answers_kept_in(lambda: Path(folder)):
                    stdout, error = behavior(program)
            self.assertEqual((stdout.strip(), error), (AN_IMPOSTORS_REPORT, None))
            self.assertEqual(os.listdir(folder), [])

    def test_a_copy_of_how_node_is_asked_gives_node_the_same_identity_and_an_edited_copy_another(self):
        node = node_executable()
        assert node is not None
        identities = []
        with tempfile.TemporaryDirectory() as folder:
            for name, edit in [('copy', B''), ('edited', B'#\n')]:
                copy = Path(folder, F'{name}.py')
                copy.write_bytes(Path(nodejs.__file__).read_bytes() + edit)
                spec = importlib.util.spec_from_file_location(F'nodejs_{name}', copy)
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                identities.append(module.identity(node))
        copied, edited = identities
        self.assertNotIn(None, identities)
        self.assertEqual(copied, nodejs.identity(node))
        self.assertNotEqual(edited, copied)


class TestNodeIsAskedWhatItIsOncePerRunAndLocaleAndTimeZone(TestBase):

    def test_another_test_or_variable_changes_nothing_but_the_locale_data_or_time_zone_does(self):
        with unittest.mock.patch.dict(os.environ, {'TZ': 'UTC', 'PYTEST_CURRENT_TEST': 'one'}):
            first = nodejs.surroundings()
            os.environ['PYTEST_CURRENT_TEST'] = 'two'
            os.environ['REFINERY_UNRELATED'] = 'set'
            self.assertEqual(nodejs.surroundings(), first)
            for variable, value in [('NODE_ICU_DATA', 'icu'), ('TZ', 'Asia/Tokyo'), ('LC_ALL', 'C')]:
                with self.subTest(variable=variable):
                    with unittest.mock.patch.dict(os.environ, {variable: value}):
                        self.assertNotEqual(nodejs.surroundings(), first)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_starts_once_for_each_program_and_once_for_each_time_zone_of_a_run(self):
        node = node_executable()
        with tempfile.TemporaryDirectory() as folder, answers_kept_in(lambda: Path(folder)):
            with unittest.mock.patch.object(subprocess, 'run', wraps=subprocess.run) as started:
                for test, time_zone, program in [
                    ('one', 'UTC', 'console.log(1);'),
                    ('two', 'UTC', 'console.log(2);'),
                    ('three', 'Asia/Tokyo', 'console.log(3);'),
                    ('four', 'UTC', 'console.log(4);'),
                ]:
                    with unittest.mock.patch.dict(os.environ, {'PYTEST_CURRENT_TEST': test, 'TZ': time_zone}):
                        behavior(program)
        nodes = [call.args[0][0] for call in started.call_args_list]
        self.assertEqual(nodes, [node] * 6)


class TestTheFileOfKeptAnswers(TestBase):

    def test_an_answer_no_run_used_for_more_than_thirty_days_is_dropped_and_one_used_since_is_not(self):
        with tempfile.TemporaryDirectory() as folder:
            with a_store_opened_on(folder, 20_000) as store:
                store.keep(ONE, '1\n')
                store.keep(TWO, '2\n')
            with a_store_opened_on(folder, 20_020) as store:
                self.assertEqual(store.answer(TWO), '2\n')
            with a_store_opened_on(folder, 20_031) as store:
                self.assertEqual((store.answer(ONE), store.answer(TWO)), (None, '2\n'))

    def test_an_answer_whose_row_was_changed_is_not_given(self):
        for name, change, parameters in [
            ('garbled', 'UPDATE answers SET answer = ? WHERE key = ?', (B'1\x00', ONE)),
            ('emptied', 'UPDATE answers SET answer = zeroblob(0) WHERE key = ?', (ONE,)),
            ('swapped', 'UPDATE answers SET answer = (SELECT answer FROM answers WHERE key = ?) WHERE key = ?', (TWO, ONE)),
            ('answer made text', 'UPDATE answers SET answer = CAST(answer AS TEXT) WHERE key = ?', (ONE,)),
            ('last use made text', 'UPDATE answers SET used = ? WHERE key = ?', ('a day', ONE)),
        ]:
            with self.subTest(change=name), tempfile.TemporaryDirectory() as folder:
                with a_store_opened_on(folder, 20_000) as store:
                    store.keep(ONE, '1\n')
                    store.keep(TWO, '2\n')
                with contextlib.closing(sqlite3.connect(Path(folder, 'answers.sqlite'))) as db, db:
                    db.execute(change, parameters)
                with a_store_opened_on(folder, 20_000) as store:
                    self.assertEqual((store.answer(ONE), store.answer(TWO)), (None, '2\n'))

    def test_a_file_sqlite_rejects_or_of_another_format_gives_no_answer_and_keeps_them_again(self):
        def truncated(path: Path):
            path.write_bytes(path.read_bytes()[:4096])

        def header_zeroed(path: Path):
            path.write_bytes(bytes(100) + path.read_bytes()[100:])

        def not_a_database(path: Path):
            path.write_text('kept answers\n')

        def another_format(path: Path):
            with contextlib.closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA user_version = 7')

        for damage in [truncated, header_zeroed, not_a_database, another_format]:
            with self.subTest(damage=damage.__name__), tempfile.TemporaryDirectory() as folder:
                with a_store_opened_on(folder, 20_000) as store:
                    store.keep(ONE, '1\n')
                damage(Path(folder, 'answers.sqlite'))
                with a_store_opened_on(folder, 20_000) as store:
                    self.assertIsNone(store.answer(ONE))
                    store.keep(ONE, 'again\n')
                with a_store_opened_on(folder, 20_000) as store:
                    self.assertEqual(store.answer(ONE), 'again\n')

    def test_a_file_that_another_format_took_over_during_a_run_is_left_as_it_is(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'answers.sqlite')
            with a_store_opened_on(folder, 20_000) as store:
                store.keep(ONE, '1\n')
            with a_store_opened_on(folder, 20_000) as store:
                self.assertEqual(store.answer(ONE), '1\n')
                store.keep(TWO, '2\n')
                with contextlib.closing(sqlite3.connect(path)) as db:
                    db.execute('PRAGMA user_version = 7')
                taken_over = path.read_bytes()
            self.assertEqual(path.read_bytes(), taken_over)

    def test_a_store_that_can_be_read_but_not_written_still_gives_its_answers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'answers.sqlite')
            with a_store_opened_on(folder, 20_000) as store:
                store.keep(ONE, '1\n')
            path.chmod(stat.S_IREAD)
            try:
                with a_store_opened_on(folder, 20_000) as store:
                    self.assertEqual(store.answer(ONE), '1\n')
            finally:
                path.chmod(stat.S_IREAD | stat.S_IWRITE)

    @unittest.skipUnless(os.name == 'nt', 'a UNC path names a folder only on Windows')
    def test_a_store_in_a_folder_named_by_a_unc_path_keeps_its_answers_in_that_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            drive, rest = os.path.splitdrive(os.path.abspath(folder))
            shared = Path(F'//localhost/{drive[0]}$') / rest
            if not shared.is_dir():
                self.skipTest(F'the administrative share of {drive} cannot be reached')
            with a_store_opened_on(str(shared), 20_000) as store:
                store.keep(ONE, '1\n')
            with a_store_opened_on(str(shared), 20_000) as store:
                self.assertEqual(store.answer(ONE), '1\n')
            self.assertTrue(Path(folder, 'answers.sqlite').is_file())

    def test_the_journal_of_a_killed_writer_applied_to_another_store_gives_no_wrong_answer(self):
        killed_writer = inspect.cleandoc('''
            import hashlib, os, sqlite3, sys
            db = sqlite3.connect(sys.argv[1], isolation_level=None)
            db.execute('PRAGMA cache_size = 1')
            db.execute('BEGIN IMMEDIATE')
            for n in range(3):
                key = hashlib.sha256(F'A-{n}'.encode()).digest()
                db.execute('UPDATE answers SET used = used + 1 WHERE key = ?', (key,))
            db.execute('SELECT count(*), sum(length(answer)) FROM answers').fetchall()
            os._exit(1)
        ''')

        def key(store: str, n: int):
            return hashlib.sha256(F'{store}-{n}'.encode()).digest()

        def answer(store: str, n: int):
            text = (F'{store}{n:04d} ' * 1000)[:5000]
            return F'{text}\n'

        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            for folder, store in [(a, 'A'), (b, 'B')]:
                with a_store_opened_on(folder, 20_000) as kept:
                    for n in range(400):
                        kept.keep(key(store, n), answer(store, n))
            path = Path(a, 'answers.sqlite')
            subprocess.run([sys.executable, '-c', killed_writer, str(path)])
            self.assertTrue(path.with_name('answers.sqlite-journal').exists())
            path.unlink()
            shutil.copy(Path(b, 'answers.sqlite'), path)
            with contextlib.closing(sqlite3.connect(path)) as db:
                stored = [
                    db.execute('SELECT answer FROM answers WHERE key = ?', (key('B', n),)).fetchone()
                    for n in range(400)
                ]
            mixed = [n for n, row in enumerate(stored) if row is not None and row[0] != answer('B', n).encode()]
            self.assertNotEqual(mixed, [])
            with a_store_opened_on(a, 20_000) as kept:
                given = [kept.answer(key('B', n)) for n in range(400)]
        self.assertEqual([n for n, text in enumerate(given) if text not in (None, answer('B', n))], [])

    def test_four_processes_keeping_answers_in_one_folder_at_once_keep_all_of_them(self):
        writer = inspect.cleandoc('''
            import hashlib, sys
            from pathlib import Path
            sys.path.insert(0, sys.argv[1])
            from test.lib.scripts.js.analysis.node_answers import KeptAnswers
            store = KeptAnswers(Path(sys.argv[2]))
            for n in range(200):
                store.keep(hashlib.sha256(F'{sys.argv[3]}-{n}'.encode()).digest(), F'{sys.argv[3]} {n}')
            print('ready', flush=True)
            sys.stdin.read()
            store.close()
        ''')
        with tempfile.TemporaryDirectory() as folder:
            with contextlib.ExitStack() as running:
                writers = [
                    running.enter_context(subprocess.Popen(
                        [sys.executable, '-c', writer, str(ROOT), folder, str(w)],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        text=True,
                    ))
                    for w in range(4)
                ]
                for process in writers:
                    assert process.stdout is not None
                    self.assertEqual(process.stdout.readline(), 'ready\n')
                for process in writers:
                    assert process.stdin is not None
                    process.stdin.close()
            with a_store_opened_on(folder, 20_000) as store:
                lost = [
                    (w, n) for w in range(4) for n in range(200)
                    if store.answer(hashlib.sha256(F'{w}-{n}'.encode()).digest()) != F'{w} {n}'
                ]
        self.assertEqual(lost, [])


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARunOfTheTestsWithKeptAnswers(TestBase):

    def test_a_run_reads_nothing_before_its_first_question_and_holds_nothing_open_after_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'answers.sqlite')
            path.write_text('kept answers\n')
            with answers_kept_in(lambda: Path(folder)):
                self.assertEqual(path.read_text(), 'kept answers\n')
                behavior('console.log(1);')
                self.assertFalse(path.exists())
            with answers_kept_in(lambda: Path(folder)):
                self.assertEqual(behavior('console.log(1);'), ('1\n', None))
                path.unlink()

    def test_a_run_asks_where_to_keep_its_answers_at_its_first_question_and_not_again(self):
        with tempfile.TemporaryDirectory() as folder:
            unasked = unittest.mock.Mock(return_value=Path(folder))
            with answers_kept_in(unasked):
                pass
            where = unittest.mock.Mock(return_value=Path(folder))
            with answers_kept_in(where):
                where.assert_not_called()
                behavior('console.log(1);')
                behavior('console.log(2);')
        unasked.assert_not_called()
        where.assert_called_once_with()

    def test_a_damaged_store_that_is_held_open_still_gives_nodes_answers(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'answers.sqlite')
            path.write_text('kept answers\n')
            with path.open('rb'), answers_kept_in(lambda: Path(folder)):
                self.assertEqual(behavior('console.log(1);'), ('1\n', None))

    def test_a_store_that_cannot_be_written_still_gives_nodes_answers(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as folder:
            store = Path(folder, 'node')
            store.write_text('a file where the folder was\n')
            with answers_kept_in(lambda: store):
                first = behavior(program)
            with answers_kept_in(lambda: store):
                again = behavior(program)
        self.assertIsNone(first[1])
        self.assertNotEqual(first, again)

    def test_a_folder_removed_during_a_run_is_made_again_when_the_run_ends(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as folder:
            store = Path(folder, 'node')
            store.mkdir()
            with answers_kept_in(lambda: store):
                first = behavior(program)
                shutil.rmtree(store)
            with answers_kept_in(lambda: store):
                again = behavior(program)
        self.assertEqual(first, again)

    def test_a_question_asked_from_another_thread_is_answered_and_kept(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        answers = []
        with tempfile.TemporaryDirectory() as folder:
            with answers_kept_in(lambda: Path(folder)):
                thread = threading.Thread(target=lambda: answers.append(behavior(program)))
                thread.start()
                thread.join()
            with answers_kept_in(lambda: Path(folder)):
                again = behavior(program)
        self.assertEqual(answers, [again])
