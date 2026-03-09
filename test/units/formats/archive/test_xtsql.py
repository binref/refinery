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
