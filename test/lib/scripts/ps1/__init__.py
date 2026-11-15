from __future__ import annotations

import inspect


def a_program(text: str) -> str:
    return F'{inspect.cleandoc(text)}\n'
