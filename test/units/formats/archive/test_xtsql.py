import sys
import sqlite3
import unittest
from ... import TestUnitBase


@unittest.skipIf(sys.version_info[:2] < (3, 11), 'requires python 3.11+')
class TestExtractSQLite(TestUnitBase):

    @staticmethod
    def _make_test_db() -> bytes:
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE users (name TEXT, age INTEGER)')
        db.execute("INSERT INTO users VALUES ('Alice', 30)")
        db.execute("INSERT INTO users VALUES ('Bob', 25)")
        db.commit()
        return db.serialize()

    def test_extract_sqlite(self):
        data = self._make_test_db()
        unit = self.load()
        results = data | unit | []
        # Should produce: db, db/users, db/users/0, db/users/1
        self.assertGreaterEqual(len(results), 3)

    def test_extract_contains_table_data(self):
        data = self._make_test_db()
        unit = self.load()
        results = data | unit | []
        found_alice = any(b'Alice' in bytes(r) for r in results)
        self.assertTrue(found_alice)

    def test_extract_simple_table(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE test (name TEXT, value TEXT)')
        db.execute("INSERT INTO test VALUES ('key', 'data')")
        db.commit()
        data = bytearray(db.serialize())
        db.close()
        unit = self.load()
        results = data | unit | []
        self.assertTrue(len(results) > 0)
        found = any(bytes(r) == b'data' for r in results)
        self.assertTrue(found)

    def test_handles_method(self):
        from refinery.units.formats.archive.xtsql import xtsql
        self.assertTrue(xtsql.handles(b'SQLite format 3\x00' + b'\x00' * 84))
        self.assertFalse(xtsql.handles(b'not sqlite'))

    def test_column_names_are_those_of_the_database(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE t ("my a" TEXT, "my b" TEXT, price NUMERIC(10, 2), qty INTEGER)')
        db.execute("INSERT INTO t VALUES ('first', 'second', 9.5, 3)")
        db.commit()
        data = db.serialize()
        db.close()
        test = data | self.load('db/t/0/*') | {'path': bytes}
        self.assertEqual(test, {
            'db/t/0/my a': b'first',
            'db/t/0/my b': b'second',
            'db/t/0/price': b'9.5',
            'db/t/0/qty': b'3',
        })

    def test_a_virtual_table_is_skipped_and_the_tables_next_to_it_are_read(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE users (name TEXT)')
        db.execute("INSERT INTO users VALUES ('Alice')")
        db.execute('CREATE VIRTUAL TABLE docs USING fts5(body)')
        db.execute("INSERT INTO docs (body) VALUES ('hello world')")
        db.commit()
        data = db.serialize()
        db.close()
        test = data | self.load() | {'path': bytes}
        self.assertEqual(test['db/users/0/name'], B'Alice')
        self.assertEqual(test['db/docs_content/0/c0'], B'hello world')
        self.assertFalse([path for path in test if str(path).startswith('db/docs/')])

    def test_a_table_that_cannot_be_read_is_skipped_with_a_warning(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE users (name TEXT)')
        db.execute("INSERT INTO users VALUES ('Alice')")
        db.execute('CREATE TABLE broken (a INTEGER)')
        db.execute('INSERT INTO broken (a) VALUES (1)')
        db.execute('ALTER TABLE broken ADD COLUMN b INTEGER GENERATED ALWAYS AS (abs(-9223372036854775807 - a)) VIRTUAL')
        db.commit()
        data = db.serialize()
        db.close()
        with self.load_logged() as (unit, log):
            test = data | unit | {'path': bytes}
        self.assertEqual(test['db/users/0/name'], B'Alice')
        self.assertFalse([path for path in test if str(path).startswith('db/broken')])
        self.assertTrue(any('broken' in message for message in log), log)

    def test_a_computed_value_longer_than_the_database_is_not_read(self):
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE users (name TEXT)')
        db.execute("INSERT INTO users VALUES ('Alice')")
        db.execute('CREATE TABLE big (a INTEGER, b BLOB GENERATED ALWAYS AS (zeroblob(10000000)) VIRTUAL)')
        db.execute('INSERT INTO big (a) VALUES (1)')
        db.commit()
        data = db.serialize()
        db.close()
        self.assertLess(len(data), 10000000)
        with self.load_logged() as (unit, log):
            test = data | unit | {'path': bytes}
        self.assertEqual(test['db/users/0/name'], B'Alice')
        self.assertFalse([path for path in test if str(path).startswith('db/big')])
        self.assertTrue(any('big' in message for message in log), log)
