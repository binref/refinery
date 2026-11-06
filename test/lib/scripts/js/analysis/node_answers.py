"""
Node's answers, remembered within a run of the test suite and kept between runs, so that a later run
starts Node only for the programs it has not seen. The configuration of the test suite makes a run
active in each process with `answers_kept_in`; a process that makes none, such as a script,
remembers answers and keeps none.

Answers are remembered per locale and time zone, because a program can print something else in
another one.

An answer that ends in an error is never kept: a failure unrelated to the program, such as a machine
that ran out of memory, must never be given again as what the program does.
"""
from __future__ import annotations

import functools
import hashlib
import json
import sqlite3
import threading
import time
import zlib

from contextlib import closing, contextmanager, suppress
from pathlib import Path
from typing import Callable, Generator
from urllib.parse import quote

from samples import refuse_script_host_near_a_sample
from test.lib.scripts.js.analysis import nodejs

_DEFINITION = (
    'CREATE TABLE answers ('
    'key BLOB PRIMARY KEY, '
    'answer BLOB NOT NULL, '
    'digest BLOB NOT NULL, '
    'used INTEGER NOT NULL'
    ') WITHOUT ROWID'
)

#: The format of a store, which is the definition of its table, as the number that `PRAGMA
#: user_version` holds. SQLite stores a number of 2^31 or more there as 0, which is the number of a
#: file without a table, hence 31 bits and never 0.
_FORMAT = zlib.crc32(_DEFINITION.encode('ascii')) & 0x7FFFFFFF or 1

_UNUSED_DAYS = 30

_BUSY_SECONDS = 30

_REMEMBERED = 1024


def _today() -> int:
    return int(time.time() // 86400)


def _digest(key: bytes, answer: bytes) -> bytes:
    return hashlib.sha256(key + answer).digest()


def _rejected(error: sqlite3.Error) -> bool:
    code = getattr(error, 'sqlite_errorcode', None)
    return code is not None and (code & 0xFF) in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)


class KeptAnswers:
    """
    What Node printed for programs that ran without an error, kept in the file `answers.sqlite` of a
    folder.

    No process holds the file open while its tests run: it is read whole at the first question and
    written once, by `close`. On Windows, a file held open would keep pytest from emptying its cache
    folder.

    Each row holds a digest of its key and answer, checked every time the answer is given: the
    journal of a killed writer, applied to the file that took the place of its own, mixes the rows
    of two files without SQLite reporting damage. A row whose fields are not of the types its table
    declares is skipped, because SQLite does not enforce them.

    A store that cannot be read or written keeps nothing: every `OSError` and `sqlite3.Error` means
    that an answer is not kept, and Node is asked.
    """

    def __init__(self, folder: Path):
        self.path = folder.absolute() / 'answers.sqlite'
        self.lock = threading.Lock()
        self.today = _today()
        self.known: dict[bytes, tuple[bytes, bytes, int]] | None = None
        self.new: dict[bytes, bytes] = {}
        self.used: set[bytes] = set()

    def _connect(self, *, create: bool) -> sqlite3.Connection:
        mode = 'rwc' if create else 'rw'
        return sqlite3.connect(
            F'file:{quote(str(self.path))}?mode={mode}',
            uri=True,
            timeout=_BUSY_SECONDS,
            isolation_level=None,
        )

    def _read(self) -> dict[bytes, tuple[bytes, bytes, int]]:
        try:
            with closing(self._connect(create=False)) as db:
                if db.execute('PRAGMA quick_check').fetchall() == [('ok',)]:
                    return self._tidied_rows(db)
        except sqlite3.Error as error:
            if not _rejected(error):
                return {}
        for leftover in (self.path.with_name(F'{self.path.name}-journal'), self.path):
            with suppress(OSError):
                leftover.unlink(missing_ok=True)
        return {}

    def _tidied_rows(self, db: sqlite3.Connection) -> dict[bytes, tuple[bytes, bytes, int]]:
        if db.execute('PRAGMA user_version').fetchone()[0] != _FORMAT:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('PRAGMA user_version').fetchone()[0] != _FORMAT:
                db.execute('DROP TABLE IF EXISTS answers')
                db.execute(_DEFINITION)
                db.execute(F'PRAGMA user_version = {_FORMAT}')
            db.execute('COMMIT')
            return {}
        oldest = self.today - _UNUSED_DAYS
        rows = db.execute(
            'SELECT key, answer, digest, used FROM answers WHERE used >= ?'
            ' AND typeof(answer) = ? AND typeof(digest) = ? AND typeof(used) = ?',
            (oldest, 'blob', 'blob', 'integer'),
        ).fetchall()
        with suppress(sqlite3.OperationalError):
            db.execute('DELETE FROM answers WHERE used < ?', (oldest,))
        return {key: (answer, digest, used) for key, answer, digest, used in rows}

    def answer(self, key: bytes) -> str | None:
        with self.lock:
            if (new := self.new.get(key)) is not None:
                return new.decode('utf-8')
            if self.known is None:
                self.known = self._read()
            if (row := self.known.get(key)) is None:
                return None
            answer, digest, used = row
            if _digest(key, answer) != digest:
                return None
            if used < self.today:
                self.used.add(key)
            return answer.decode('utf-8')

    def keep(self, key: bytes, stdout: str) -> None:
        with self.lock:
            self.new[key] = stdout.encode('utf-8')

    def close(self) -> None:
        with self.lock:
            if self.new or self.used:
                with suppress(OSError, sqlite3.Error):
                    self._write()
            self.new.clear()
            self.used.clear()

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect(create=True)) as db:
            db.execute('BEGIN IMMEDIATE')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version == 0:
                db.execute(_DEFINITION)
                db.execute(F'PRAGMA user_version = {_FORMAT}')
            elif version != _FORMAT:
                return
            db.executemany(
                'INSERT OR REPLACE INTO answers VALUES (?, ?, ?, ?)',
                [(key, answer, _digest(key, answer), self.today) for key, answer in self.new.items()],
            )
            db.executemany(
                'UPDATE answers SET used = ? WHERE key = ?',
                [(self.today, key) for key in self.used],
            )
            db.execute('COMMIT')


class _Run:
    """
    The store's folder is asked of *where* at the run's first question, never before: under
    `--cache-clear`, each xdist worker empties pytest's cache folder as it starts, and a folder that
    one worker makes while another empties it can fail to be made or to be emptied. No test runs
    before every worker has started.
    """

    def __init__(self, where: Callable[[], Path | None] | None):
        self.where = where
        self.lock = threading.Lock()
        self.kept: KeptAnswers | None = None
        self.answer = functools.lru_cache(maxsize=_REMEMBERED)(self._kept_or_asked)
        self.identity = functools.cache(self._identity)

    def _store(self) -> KeptAnswers | None:
        with self.lock:
            if self.where is not None:
                folder, self.where = self.where(), None
                self.kept = None if folder is None else KeptAnswers(folder)
            return self.kept

    def _kept_or_asked(
        self,
        node: str,
        surroundings: tuple[tuple[str, str], ...],
        graph: tuple[tuple[str, str], ...],
        entry: str,
        timeout: float,
    ) -> tuple[str, str | None]:
        kept = self._store()
        if kept is None or (identity := self.identity(node, surroundings)) is None:
            return nodejs.run(node, graph, entry, timeout)
        key = hashlib.sha256(json.dumps([identity, graph, entry, timeout]).encode('ascii')).digest()
        if (stdout := kept.answer(key)) is not None:
            return stdout, None
        stdout, error = nodejs.run(node, graph, entry, timeout)
        if error is None:
            kept.keep(key, stdout)
        return stdout, error

    def _identity(self, node: str, surroundings: tuple[tuple[str, str], ...]) -> str | None:
        return nodejs.identity(node)

    def close(self) -> None:
        with self.lock:
            kept, self.where = self.kept, None
        if kept is not None:
            kept.close()


_active = _Run(None)


def ask(
    graph: tuple[tuple[str, str], ...],
    entry: str,
    timeout: float,
    *,
    fresh: bool = False,
) -> tuple[str, str | None]:
    """
    What Node prints when it runs *entry* with every file of *graph* written beside it, as names and
    sources, and the type of the error it ended in, or `None` when it ended without one. The answer
    is the one the active run remembers, else the one it keeps, else Node's. *fresh* asks Node even
    when an answer is remembered or kept, and keeps nothing.

    A test that decoded a sample is refused before anything else, so that whether it is refused
    never depends on what an earlier test asked.
    """
    refuse_script_host_near_a_sample('node')
    node = nodejs.node_executable()
    if node is None:
        raise RuntimeError('node.js is not available')
    if fresh:
        return nodejs.run(node, graph, entry, timeout)
    return _active.answer(node, nodejs.surroundings(), graph, entry, timeout)


@contextmanager
def answers_kept_in(where: Callable[[], Path | None] | None) -> Generator[None, None, None]:
    """
    Make a new run active for as long as the context lasts: it remembers no answer yet, and it keeps
    answers in the folder that *where* gives at its first question, or nowhere when *where* is or
    gives `None`. On exit, the run writes what it kept, and the run that was active before is active
    again.
    """
    global _active
    previous = _active
    _active = run = _Run(where)
    try:
        yield
    finally:
        _active = previous
        run.close()
