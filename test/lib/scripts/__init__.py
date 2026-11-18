from __future__ import annotations

import inspect


def a_program(text: str, indent: int = 0, tablen: int = 2) -> str:
    code = inspect.cleandoc(text)
    if indent > 0:
        padding = indent * tablen * ' '
        code = ''.join(
            F'{padding}{line}' for line in code.splitlines(True)
        )
    return F'{code}\n'


def on_separate_lines(*texts: str) -> str:
    return '\n'.join(texts)
