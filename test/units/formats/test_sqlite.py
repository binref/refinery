import json
import os
import sqlite3
import tempfile

from .. import TestUnitBase


class TestSQLiteExtractor(TestUnitBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sample_data = self._create_sample_database()

    def test_basic_query(self):
        unit = self.load(query="SELECT * FROM users ORDER BY id")
        result = [json.loads(r.decode()) for r in self.sample_data | unit]
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["id"], 1)
        self.assertEqual(result[0]["name"], "Alice")
        self.assertEqual(result[0]["email"], "alice@example.com")
        self.assertEqual(result[1]["name"], "Bob")
        self.assertEqual(result[2]["name"], "Charlie")

    def test_filtered_query(self):
        unit = self.load(query="SELECT name, email FROM users WHERE age > 25")
        result = [json.loads(t.decode()) for t in self.sample_data | unit]

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "Bob")
        self.assertEqual(result[1]["name"], "Charlie")

    def test_table_listing(self):
        unit = self.load()
        result = [json.loads(t.decode()) for t in self.sample_data | unit]

        self.assertTrue(len(result) > 0)
        table_names = [row["name"] for row in result if row["type"] == "table"]
        self.assertIn("users", table_names)

    def test_empty_result(self):
        unit = self.load(query="SELECT * FROM users WHERE age > 100")
        result = list(self.sample_data | unit)

        self.assertEqual(len(result), 0)

    def _create_sample_database(self):
        with sqlite3.connect(":memory:") as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE,
                    age INTEGER
                )
            """
            )
            sample_users = [
                (1, "Alice", "alice@example.com", 25),
                (2, "Bob", "bob@example.com", 30),
                (3, "Charlie", "charlie@example.com", 35),
            ]
            cursor.executemany(
                "INSERT INTO users (id, name, email, age) VALUES (?, ?, ?, ?)",
                sample_users,
            )
            conn.commit()

            with tempfile.NamedTemporaryFile(
                dir=os.getcwd(), delete=False
            ) as temp_file:
                temp_path = temp_file.name

            try:
                backup_conn = sqlite3.connect(temp_path)
                conn.backup(backup_conn)
                backup_conn.close()

                with open(temp_path, "rb") as f:
                    data = f.read()
            finally:
                try:
                    os.unlink(temp_path)
                except (PermissionError, FileNotFoundError):
                    pass
        return data
