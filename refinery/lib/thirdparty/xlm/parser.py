from __future__ import annotations

import re

from typing import Any, List


class Token:
    """
    A leaf node in the parse tree, mimicking lark.lexer.Token.
    """
    __slots__ = ('type', 'value')

    def __init__(self, type: str, value: str):
        self.type = type
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f'Token({self.type!r}, {self.value!r})'

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.value == other
        if isinstance(other, Token):
            return self.type == other.type and self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    def lower(self) -> str:
        return self.value.lower()

    def upper(self) -> str:
        return self.value.upper()

    def startswith(self, prefix: str) -> bool:
        return self.value.startswith(prefix)

    def endswith(self, suffix: str) -> bool:
        return self.value.endswith(suffix)

    def strip(self, chars: str | None = None) -> str:
        return self.value.strip(chars)

    def update(self, type: str | None, value: str) -> Token:
        return Token(type or self.type, value)


class Tree:
    """
    An interior node in the parse tree, mimicking lark.tree.Tree.
    """
    __slots__ = ('data', 'children')

    def __init__(self, data: str, children: List[Any]):
        self.data = data
        self.children = children

    def __repr__(self) -> str:
        return f'Tree({self.data!r}, {self.children!r})'


class ParseError(Exception):
    pass


_RE_STRING = re.compile(r'"([^"]|"")*"', re.IGNORECASE)
_RE_BOOLEAN = re.compile(r'TRUE|FALSE', re.IGNORECASE)
_RE_ERROR = re.compile(
    r'#REF!|#DIV/0!|#N/A|#NAME\?|#NULL!|#NUM!|#VALUE!|#GETTING_DATA'
)
_RE_NUMBER = re.compile(r'[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?')

_RE_NAME = re.compile(
    r'[a-zA-Z_\\][a-zA-Z0-9_.\\?]*'
)

_CMP_OPS = {'>=', '<=', '<>', '<', '>', '='}


class XLMParser:
    def __init__(
        self,
        left_bracket: str = '[',
        list_separator: str = ',',
        right_bracket: str = ']',
    ):
        self.left_bracket = left_bracket
        self.list_separator = list_separator
        self.right_bracket = right_bracket

    def parse(self, formula: str) -> Tree:
        formula = formula.strip()
        if not formula.startswith('='):
            raise ParseError(f'Formula must start with =: {formula!r}')
        self._src = formula
        self._pos = 1
        self._skip_spaces()
        expr = self._parse_expression()
        return Tree('start', [expr])

    def _peek(self, n: int = 1) -> str:
        return self._src[self._pos:self._pos + n]

    def _at_end(self) -> bool:
        return self._pos >= len(self._src)

    def _skip_spaces(self) -> None:
        while self._pos < len(self._src) and self._src[self._pos] == ' ':
            self._pos += 1

    def _expect(self, char: str) -> None:
        if self._pos >= len(self._src) or self._src[self._pos] != char:
            ctx = self._src[max(0, self._pos - 10):self._pos + 10]
            raise ParseError(
                f'Expected {char!r} at position {self._pos} in {ctx!r}'
            )
        self._pos += 1
        self._skip_spaces()

    def _parse_expression(self) -> Any:
        left = self._parse_concat_expression()
        children: list[Any] = [left]
        while not self._at_end():
            op = self._try_cmp_op()
            if op is None:
                break
            children.append(Token('CMPOP', op))
            children.append(self._parse_concat_expression())
        if len(children) == 1:
            return children[0]
        return Tree('expression', children)

    def _try_cmp_op(self) -> str | None:
        for length in (2, 1):
            candidate = self._src[self._pos:self._pos + length]
            if candidate in _CMP_OPS:
                self._pos += length
                self._skip_spaces()
                return candidate
        return None

    def _parse_concat_expression(self) -> Any:
        left = self._parse_additive_expression()
        children: list[Any] = [left]
        while not self._at_end() and self._peek() == '&':
            self._pos += 1
            self._skip_spaces()
            children.append(Token('CONCATOP', '&'))
            children.append(self._parse_additive_expression())
        if len(children) == 1:
            return children[0]
        return Tree('concat_expression', children)

    def _parse_additive_expression(self) -> Any:
        left = self._parse_multiplicative_expression()
        children: list[Any] = [left]
        while not self._at_end() and self._peek() in ('+', '-'):
            op = self._src[self._pos]
            self._pos += 1
            self._skip_spaces()
            children.append(Token('ADDITIVEOP', op))
            children.append(self._parse_multiplicative_expression())
        if len(children) == 1:
            return children[0]
        return Tree('additive_expression', children)

    def _parse_multiplicative_expression(self) -> Any:
        left = self._parse_final()
        children: list[Any] = [left]
        while not self._at_end() and self._peek() in ('*', '/'):
            op = self._src[self._pos]
            self._pos += 1
            self._skip_spaces()
            children.append(Token('MULTIOP', op))
            children.append(self._parse_final())
        if len(children) == 1:
            return children[0]
        return Tree('multiplicative_expression', children)

    def _parse_final(self) -> Any:
        if self._at_end():
            return Token('NAME', '')
        ch = self._peek()
        if ch == '(':
            return self._parse_paren_or_func(None)
        if ch == '"':
            return self._parse_string()
        if ch == '{':
            return self._parse_array()
        if ch == '#':
            return self._parse_error()
        if ch == '-' or ch == '+':
            ahead = self._src[self._pos + 1:self._pos + 2]
            if ahead.isdigit() or ahead == '.':
                return self._parse_number()
        if ch.isdigit() or ch == '.':
            return self._parse_number()
        return self._parse_name_or_cell()

    def _parse_paren_or_func(self, name_node: Any) -> Any:
        self._expect('(')
        if name_node is not None:
            arglist = self._parse_arglist()
            self._expect(')')
            return Tree('function_call', [name_node, Token('L_PRA', '('), arglist, Token('R_PRA', ')')])
        inner = self._parse_expression()
        self._expect(')')
        return Tree('final', [Token('L_PRA', '('), inner, Token('R_PRA', ')')])

    def _parse_arglist(self) -> Tree:
        args: list[Any] = []
        args.append(self._parse_argument())
        while not self._at_end() and self._src[self._pos] == self.list_separator:
            self._pos += 1
            self._skip_spaces()
            args.append(self._parse_argument())
        return Tree('arglist', args)

    def _parse_argument(self) -> Tree:
        if self._at_end() or self._src[self._pos] in (self.list_separator, ')'):
            return Tree('argument', [])
        expr = self._parse_expression()
        return Tree('argument', [expr])

    def _parse_string(self) -> Token:
        m = _RE_STRING.match(self._src, self._pos)
        if m is None:
            raise ParseError(f'Invalid string at position {self._pos}')
        self._pos = m.end()
        self._skip_spaces()
        return Token('STRING', m.group())

    def _parse_number(self) -> Token:
        m = _RE_NUMBER.match(self._src, self._pos)
        if m is None:
            raise ParseError(f'Invalid number at position {self._pos}')
        self._pos = m.end()
        self._skip_spaces()
        return Token('NUMBER', m.group())

    def _parse_error(self) -> Token:
        m = _RE_ERROR.match(self._src, self._pos)
        if m is None:
            raise ParseError(f'Invalid error token at position {self._pos}')
        self._pos = m.end()
        self._skip_spaces()
        return Token('ERROR', m.group())

    def _parse_array(self) -> Tree:
        self._expect('{')
        items: list[Any] = []
        while not self._at_end() and self._peek() != '}':
            if self._peek() == '"':
                items.append(self._parse_string())
            else:
                items.append(self._parse_number())
            if not self._at_end() and self._peek() == ';':
                self._pos += 1
                self._skip_spaces()
        self._expect('}')
        return Tree('array', items)

    def _parse_name_or_cell(self) -> Any:
        start = self._pos
        src = self._src

        m_bool = _RE_BOOLEAN.match(src, self._pos)
        if m_bool:
            rest_start = m_bool.end()
            if rest_start >= len(src) or not src[rest_start].isalnum():
                self._pos = rest_start
                self._skip_spaces()
                return Token('BOOLEAN', m_bool.group())

        sheet_name = None
        has_excl = False

        if self._pos < len(src) and src[self._pos] == "'":
            end_q = src.index("'", self._pos + 1)
            sheet_name = src[self._pos + 1:end_q]
            self._pos = end_q + 1
            if self._pos < len(src) and src[self._pos] == '!':
                self._pos += 1
                has_excl = True
            self._skip_spaces()
        elif self._pos < len(src) and src[self._pos] == '!':
            self._pos += 1
            has_excl = True
            self._skip_spaces()
        else:
            m_name = _RE_NAME.match(src, self._pos)
            if m_name:
                after = m_name.end()
                if after < len(src) and src[after] == '!':
                    sheet_name = m_name.group()
                    self._pos = after + 1
                    has_excl = True
                    self._skip_spaces()

        if has_excl or sheet_name is not None:
            return self._parse_qualified_ref(sheet_name, start)

        self._pos = start
        return self._parse_unqualified_ref()

    def _parse_qualified_ref(self, sheet_name: str | None, fallback_pos: int) -> Any:
        src = self._src

        if self._pos < len(src) and src[self._pos].upper() == 'R':
            r1c1_node = self._try_parse_r1c1(sheet_name)
            if r1c1_node is not None:
                return r1c1_node

        m_a1 = re.match(r'\$?([a-zA-Z]+)\$?(\d+)', src[self._pos:])
        if m_a1:
            col_part = m_a1.group()
            self._pos += len(col_part)
            self._skip_spaces()
            a1_children: list[Any] = []
            if sheet_name is not None:
                a1_children.append(Token('NAME', sheet_name))
            a1_children.append(Token('A1_REF', col_part))
            cell_node = Tree('cell', [Tree('a1_notation_cell', a1_children)])
            return self._maybe_range_or_call(cell_node)

        m_name = _RE_NAME.match(src, self._pos)
        if m_name:
            name_token = m_name.group()
            self._pos = m_name.end()
            self._skip_spaces()
            children: list[Any] = []
            if sheet_name is not None:
                children.append(Token('NAME', sheet_name))
            children.append(Token('EXCLAMATION', '!'))
            children.append(Token('NAME', name_token))
            dn = Tree('defined_name', children)
            if not self._at_end() and self._peek() == '(':
                return self._parse_paren_or_func(dn)
            return dn

        self._pos = fallback_pos
        return self._parse_unqualified_ref()

    def _parse_unqualified_ref(self) -> Any:
        src = self._src

        if self._pos < len(src) and src[self._pos].upper() == 'R':
            r1c1_node = self._try_parse_r1c1(None)
            if r1c1_node is not None:
                return r1c1_node

        m_name = _RE_NAME.match(src, self._pos)
        if m_name is None:
            ch = src[self._pos] if self._pos < len(src) else '<EOF>'
            raise ParseError(f'Unexpected character {ch!r} at position {self._pos}')

        name = m_name.group()
        self._pos = m_name.end()
        self._skip_spaces()

        is_a1_cell = (
            len(name) >= 2
            and name.rstrip('0123456789').isalpha()
            and name.lstrip('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz$').isdigit()
        )

        if is_a1_cell:
            cell_node = Tree('cell', [Tree('a1_notation_cell', [Token('A1_REF', name)])])
            return self._maybe_range_or_call(cell_node)

        if not self._at_end() and self._peek() == '(':
            return self._parse_paren_or_func(Token('NAME', name))

        return Token('NAME', name)

    def _try_parse_r1c1(self, sheet_name: str | None) -> Tree | None:
        save = self._pos
        src = self._src

        if self._pos >= len(src) or src[self._pos].upper() != 'R':
            return None

        children: list[Any] = []
        if sheet_name is not None:
            children.append(Token('NAME', sheet_name))
        children.append(Token('ROW', src[self._pos]))
        self._pos += 1

        row_part = self._try_parse_ref_or_int()
        if row_part is not None:
            children.append(row_part)

        if self._pos < len(src) and src[self._pos].upper() == 'C':
            children.append(Token('COL', src[self._pos]))
            self._pos += 1
            col_part = self._try_parse_ref_or_int()
            if col_part is not None:
                children.append(col_part)
        else:
            self._pos = save
            return None

        if self._pos < len(src) and (src[self._pos].isalpha() or src[self._pos] == '_'):
            self._pos = save
            return None

        self._skip_spaces()
        cell_node = Tree('cell', [Tree('r1c1_notation_cell', children)])
        return self._maybe_range_or_call(cell_node)

    def _try_parse_ref_or_int(self) -> Token | None:
        src = self._src
        if self._pos < len(src) and src[self._pos] == self.left_bracket:
            end = src.index(self.right_bracket, self._pos)
            ref_text = src[self._pos:end + 1]
            self._pos = end + 1
            return Token('REF', ref_text)
        m = re.match(r'-?\d+', src[self._pos:])
        if m:
            self._pos += len(m.group())
            return Token('INT', m.group())
        return None

    def _maybe_range_or_call(self, cell_node: Tree) -> Any:
        if not self._at_end() and self._peek() == ':':
            self._pos += 1
            self._skip_spaces()
            second = self._parse_final()
            if not self._at_end() and self._peek() == ':':
                self._pos += 1
                self._skip_spaces()
                third = self._parse_final()
                return Tree('range', [cell_node, Token('COLON', ':'), second, Token('COLON', ':'), third])
            return Tree('range', [cell_node, Token('COLON', ':'), second])
        if not self._at_end() and self._peek() == '(':
            return self._parse_paren_or_func(cell_node)
        return cell_node
