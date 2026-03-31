"""
Evaluate user-defined PowerShell functions called with constant arguments.
"""
from __future__ import annotations

import re

from typing import Optional, Union

from refinery.lib.scripts import Block, Transformer
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _make_string_literal,
    _string_value,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1DoUntilLoop,
    Ps1DoWhileLoop,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RealLiteral,
    Ps1ReturnStatement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_Value = Optional[Union[str, int, float, bool, list]]


class _Ps1InterpreterError(Exception):
    pass


class _ReturnSignal(Exception):
    def __init__(self, value: _Value):
        self.value = value


class _Ps1Interpreter:

    def __init__(
        self,
        max_iterations: int = 100_000,
        max_string_length: int = 1_000_000,
    ):
        self.max_iterations = max_iterations
        self.max_string_length = max_string_length
        self._env: dict[str, _Value] = {}
        self._iterations = 0

    def execute(
        self,
        script_block: Ps1ScriptBlock,
        bindings: dict[str, _Value],
    ) -> _Value:
        if script_block.begin_block or script_block.process_block:
            raise _Ps1InterpreterError
        if script_block.end_block or script_block.dynamicparam_block:
            raise _Ps1InterpreterError
        self._env = dict(bindings)
        self._iterations = 0
        try:
            return self._exec_statements(script_block.body)
        except _ReturnSignal as r:
            return r.value

    def _exec_statements(self, stmts: list) -> _Value:
        result: _Value = None
        for stmt in stmts:
            result = self._exec_statement(stmt)
        return result

    def _exec_statement(self, stmt) -> _Value:
        if isinstance(stmt, Ps1Pipeline):
            return self._exec_pipeline(stmt)
        if isinstance(stmt, Ps1ExpressionStatement):
            return self._eval(stmt.expression)
        if isinstance(stmt, Ps1ForLoop):
            return self._exec_for(stmt)
        if isinstance(stmt, Ps1ForEachLoop):
            return self._exec_foreach(stmt)
        if isinstance(stmt, Ps1WhileLoop):
            return self._exec_while(stmt)
        if isinstance(stmt, Ps1DoWhileLoop):
            return self._exec_do_while(stmt)
        if isinstance(stmt, Ps1DoUntilLoop):
            return self._exec_do_until(stmt)
        if isinstance(stmt, Ps1IfStatement):
            return self._exec_if(stmt)
        if isinstance(stmt, Ps1ReturnStatement):
            value = self._eval(stmt.pipeline) if stmt.pipeline else None
            raise _ReturnSignal(value)
        raise _Ps1InterpreterError

    def _exec_pipeline(self, node: Ps1Pipeline) -> _Value:
        if len(node.elements) != 1:
            raise _Ps1InterpreterError
        elem = node.elements[0]
        if not isinstance(elem, Ps1PipelineElement):
            raise _Ps1InterpreterError
        if elem.redirections:
            raise _Ps1InterpreterError
        return self._eval(elem.expression)

    def _exec_for(self, node: Ps1ForLoop) -> _Value:
        if node.initializer:
            self._eval(node.initializer)
        result: _Value = None
        while True:
            self._tick()
            if node.condition:
                if not self._truthy(self._eval(node.condition)):
                    break
            result = self._exec_block(node.body)
            if node.iterator:
                self._eval(node.iterator)
        return result

    def _exec_foreach(self, node: Ps1ForEachLoop) -> _Value:
        if not isinstance(node.variable, Ps1Variable):
            raise _Ps1InterpreterError
        key = node.variable.name.lower()
        iterable = self._eval(node.iterable)
        if isinstance(iterable, str):
            items: list = list(iterable)
        elif isinstance(iterable, list):
            items = iterable
        else:
            raise _Ps1InterpreterError
        result: _Value = None
        for item in items:
            self._tick()
            self._env[key] = item
            result = self._exec_block(node.body)
        return result

    def _exec_while(self, node: Ps1WhileLoop) -> _Value:
        result: _Value = None
        while True:
            self._tick()
            if not self._truthy(self._eval(node.condition)):
                break
            result = self._exec_block(node.body)
        return result

    def _exec_do_while(self, node: Ps1DoWhileLoop) -> _Value:
        result: _Value = None
        while True:
            self._tick()
            result = self._exec_block(node.body)
            if not self._truthy(self._eval(node.condition)):
                break
        return result

    def _exec_do_until(self, node: Ps1DoUntilLoop) -> _Value:
        result: _Value = None
        while True:
            self._tick()
            result = self._exec_block(node.body)
            if self._truthy(self._eval(node.condition)):
                break
        return result

    def _exec_if(self, node: Ps1IfStatement) -> _Value:
        for condition, body in node.clauses:
            if self._truthy(self._eval(condition)):
                return self._exec_block(body)
        if node.else_block:
            return self._exec_block(node.else_block)
        return None

    def _exec_block(self, block) -> _Value:
        if block is None:
            return None
        if isinstance(block, Block):
            return self._exec_statements(block.body)
        raise _Ps1InterpreterError

    def _tick(self):
        self._iterations += 1
        if self._iterations > self.max_iterations:
            raise _Ps1InterpreterError

    def _eval(self, expr) -> _Value:
        if expr is None:
            return None
        if isinstance(expr, Ps1StringLiteral):
            return expr.value
        if isinstance(expr, Ps1IntegerLiteral):
            return expr.value
        if isinstance(expr, Ps1RealLiteral):
            return expr.value
        if isinstance(expr, Ps1Variable):
            return self._eval_variable(expr)
        if isinstance(expr, Ps1AssignmentExpression):
            return self._eval_assignment(expr)
        if isinstance(expr, Ps1BinaryExpression):
            return self._eval_binary(expr)
        if isinstance(expr, Ps1UnaryExpression):
            return self._eval_unary(expr)
        if isinstance(expr, Ps1ParenExpression):
            return self._eval(expr.expression)
        if isinstance(expr, Ps1MemberAccess):
            return self._eval_member_access(expr)
        if isinstance(expr, Ps1InvokeMember):
            return self._eval_invoke_member(expr)
        if isinstance(expr, Ps1IndexExpression):
            return self._eval_index(expr)
        if isinstance(expr, Ps1ArrayLiteral):
            return [self._eval(e) for e in expr.elements]
        if isinstance(expr, Ps1CastExpression):
            return self._eval_cast(expr)
        if isinstance(expr, Ps1Pipeline):
            return self._exec_pipeline(expr)
        if isinstance(expr, Ps1PipelineElement):
            if expr.redirections:
                raise _Ps1InterpreterError
            return self._eval(expr.expression)
        if isinstance(expr, Ps1CommandInvocation):
            return self._eval_command(expr)
        raise _Ps1InterpreterError

    def _eval_command(self, node: Ps1CommandInvocation) -> _Value:
        if not isinstance(node.name, Ps1StringLiteral):
            raise _Ps1InterpreterError
        cmd = node.name.value.lower().replace('-', '')
        if cmd != 'newobject':
            raise _Ps1InterpreterError
        positional: list[_Value] = []
        for arg in node.arguments:
            if isinstance(arg, Ps1CommandArgument):
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    continue
                expr = arg.value
            elif isinstance(arg, Expression):
                expr = arg
            else:
                raise _Ps1InterpreterError
            positional.append(self._eval(expr) if expr is not None else None)
        if len(positional) != 2:
            raise _Ps1InterpreterError
        type_name = positional[0]
        if not isinstance(type_name, str) or not type_name.lower().endswith('[]'):
            raise _Ps1InterpreterError
        size = self._to_int(positional[1])
        if size < 0 or size > self.max_string_length:
            raise _Ps1InterpreterError
        return [0] * size

    def _eval_variable(self, node: Ps1Variable) -> _Value:
        if node.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        name = node.name.lower()
        if name == 'true':
            return True
        if name == 'false':
            return False
        if name == 'null':
            return None
        return self._env.get(name)

    def _eval_assignment(self, node: Ps1AssignmentExpression) -> _Value:
        if isinstance(node.target, Ps1IndexExpression):
            return self._eval_index_assignment(node)
        if not isinstance(node.target, Ps1Variable):
            raise _Ps1InterpreterError
        if node.target.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        key = node.target.name.lower()
        value = self._eval(node.value)
        op = node.operator
        if op == '=':
            self._env[key] = value
        elif op == '+=':
            current = self._env.get(key)
            self._env[key] = self._add(current, value)
        elif op == '-=':
            current = self._env.get(key)
            self._env[key] = self._numeric_op(current, value, int.__sub__, float.__sub__)
        elif op == '*=':
            current = self._env.get(key)
            self._env[key] = self._numeric_op(current, value, int.__mul__, float.__mul__)
        else:
            raise _Ps1InterpreterError
        return self._env[key]

    def _eval_index_assignment(self, node: Ps1AssignmentExpression) -> _Value:
        target = node.target
        if not isinstance(target, Ps1IndexExpression):
            raise _Ps1InterpreterError
        if not isinstance(target.object, Ps1Variable):
            raise _Ps1InterpreterError
        if target.object.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
            raise _Ps1InterpreterError
        if node.operator != '=':
            raise _Ps1InterpreterError
        key = target.object.name.lower()
        lst = self._env.get(key)
        if not isinstance(lst, list):
            raise _Ps1InterpreterError
        idx = self._to_int(self._eval(target.index))
        value = self._eval(node.value)
        try:
            lst[idx] = value
        except IndexError:
            raise _Ps1InterpreterError
        return value

    def _eval_binary(self, node: Ps1BinaryExpression) -> _Value:
        op = node.operator.lower()
        left = self._eval(node.left)
        right = self._eval(node.right)
        if op == '+':
            return self._add(left, right)
        if op == '-':
            return self._numeric_op(left, right, int.__sub__, float.__sub__)
        if op == '*':
            return self._multiply(left, right)
        if op == '/':
            return self._numeric_op(left, right, int.__floordiv__, float.__truediv__)
        if op == '%':
            return self._numeric_op(left, right, int.__mod__, float.__mod__)
        if op == '-band':
            return self._int_op(left, right, int.__and__)
        if op == '-bor':
            return self._int_op(left, right, int.__or__)
        if op == '-bxor':
            return self._int_op(left, right, int.__xor__)
        if op == '-lt':
            return self._compare(left, right, lambda a, b: a < b)
        if op == '-le':
            return self._compare(left, right, lambda a, b: a <= b)
        if op == '-gt':
            return self._compare(left, right, lambda a, b: a > b)
        if op == '-ge':
            return self._compare(left, right, lambda a, b: a >= b)
        if op == '-eq':
            return self._compare(left, right, lambda a, b: a == b)
        if op == '-ne':
            return self._compare(left, right, lambda a, b: a != b)
        raise _Ps1InterpreterError

    def _eval_unary(self, node: Ps1UnaryExpression) -> _Value:
        op = node.operator
        if op in ('++', '--'):
            if not isinstance(node.operand, Ps1Variable):
                raise _Ps1InterpreterError
            key = node.operand.name.lower()
            current = self._env.get(key, 0)
            if not isinstance(current, (int, float)):
                current = 0
            delta = 1 if op == '++' else -1
            new_val = current + delta
            self._env[key] = new_val
            return current if not node.prefix else new_val
        if op.lower() == '-not':
            return not self._truthy(self._eval(node.operand))
        if op.lower() == '-bnot':
            val = self._eval(node.operand)
            if not isinstance(val, int):
                raise _Ps1InterpreterError
            return ~val
        if op == '-':
            val = self._eval(node.operand)
            if isinstance(val, int):
                return -val
            if isinstance(val, float):
                return -val
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    _MEMBER_ARITHMETIC = re.compile(r'^(\w+)([+\-])(\d+)$')

    def _eval_member_access(self, node: Ps1MemberAccess) -> _Value:
        obj = self._eval(node.object)
        member = node.member if isinstance(node.member, str) else None
        if member is None:
            if isinstance(node.member, Ps1StringLiteral):
                member = node.member.value
            else:
                raise _Ps1InterpreterError
        name = member.lower()
        result = self._resolve_property(obj, name)
        if result is not None:
            return result
        # Handle parser quirk: $obj.Length-1 is parsed as member 'Length-1'
        m = self._MEMBER_ARITHMETIC.match(name)
        if m:
            prop = m.group(1)
            op = m.group(2)
            offset = int(m.group(3))
            base = self._resolve_property(obj, prop)
            if isinstance(base, (int, float)):
                if op == '-':
                    return base - offset
                return base + offset
        raise _Ps1InterpreterError

    @staticmethod
    def _resolve_property(obj: _Value, name: str) -> _Value:
        if isinstance(obj, str):
            if name == 'length':
                return len(obj)
            return None
        if isinstance(obj, list):
            if name in ('length', 'count'):
                return len(obj)
            return None
        return None

    _ENCODING_MAP = {
        'ascii'            : 'ascii',
        'utf8'             : 'utf-8',
        'unicode'          : 'utf-16-le',
        'bigendianunicode' : 'utf-16-be',
        'default'          : 'latin-1',
    }

    _CONVERT_TYPES = frozenset({'convert', 'system.convert'})

    _ENCODING_TYPES = frozenset({'system.text.encoding', 'text.encoding'})

    def _eval_invoke_member(self, node: Ps1InvokeMember) -> _Value:
        if node.access == Ps1AccessKind.STATIC:
            return self._eval_static_invoke(node)
        enc = self._try_encoding_chain(node)
        if enc is not None:
            return enc
        obj = self._eval(node.object)
        member = node.member if isinstance(node.member, str) else None
        if member is None:
            if isinstance(node.member, Ps1StringLiteral):
                member = node.member.value
            else:
                raise _Ps1InterpreterError
        name = member.lower()
        args = [self._eval(a) for a in node.arguments]
        if isinstance(obj, str):
            return self._invoke_string_method(obj, name, args)
        if isinstance(obj, list):
            return self._invoke_list_method(obj, name, args)
        raise _Ps1InterpreterError

    def _eval_static_invoke(self, node: Ps1InvokeMember) -> _Value:
        if not isinstance(node.object, Ps1TypeExpression):
            raise _Ps1InterpreterError
        type_name = node.object.name.lower().replace(' ', '')
        member = node.member if isinstance(node.member, str) else None
        if member is None:
            if isinstance(node.member, Ps1StringLiteral):
                member = node.member.value
            else:
                raise _Ps1InterpreterError
        name = member.lower()
        args = [self._eval(a) for a in node.arguments]
        if type_name in self._CONVERT_TYPES:
            return self._invoke_convert(name, args)
        if type_name in self._ENCODING_TYPES:
            return self._invoke_encoding(name, args)
        raise _Ps1InterpreterError

    def _invoke_convert(self, method: str, args: list[_Value]) -> _Value:
        try:
            if method == 'tobyte' and len(args) == 2:
                return int(self._to_str(args[0]), self._to_int(args[1])) & 0xFF
            if method == 'toint16' and len(args) == 2:
                v = int(self._to_str(args[0]), self._to_int(args[1]))
                if v >= 0x8000:
                    v -= 0x10000
                return v
            if method == 'toint32' and len(args) == 2:
                v = int(self._to_str(args[0]), self._to_int(args[1]))
                if v >= 0x80000000:
                    v -= 0x100000000
                return v
            if method == 'toint64' and len(args) == 2:
                return int(self._to_str(args[0]), self._to_int(args[1]))
            if method == 'tochar' and len(args) == 1:
                return chr(self._to_int(args[0]))
            if method == 'tostring' and len(args) == 1:
                return self._to_str(args[0])
        except (ValueError, OverflowError, TypeError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_encoding(self, method: str, args: list[_Value]) -> _Value:
        encoding = self._ENCODING_MAP.get(method)
        if encoding is None or len(args) != 1:
            raise _Ps1InterpreterError
        return self._decode_byte_list(args[0], encoding)

    def _try_encoding_chain(self, node: Ps1InvokeMember) -> _Value | None:
        member = node.member if isinstance(node.member, str) else None
        if member is None or member.lower() != 'getstring':
            return None
        obj = node.object
        if not isinstance(obj, Ps1MemberAccess):
            return None
        if obj.access != Ps1AccessKind.STATIC:
            return None
        if not isinstance(obj.object, Ps1TypeExpression):
            return None
        type_name = obj.object.name.lower().replace(' ', '')
        if type_name not in self._ENCODING_TYPES:
            return None
        enc_name = obj.member if isinstance(obj.member, str) else None
        if enc_name is None:
            return None
        encoding = self._ENCODING_MAP.get(enc_name.lower(), enc_name.lower())
        if len(node.arguments) != 1:
            raise _Ps1InterpreterError
        arg = self._eval(node.arguments[0])
        return self._decode_byte_list(arg, encoding)

    def _decode_byte_list(self, value: _Value, encoding: str) -> str:
        if not isinstance(value, list):
            raise _Ps1InterpreterError
        try:
            raw = bytearray(int(b) for b in value)
            return raw.decode(encoding)
        except (ValueError, OverflowError, UnicodeDecodeError, LookupError):
            raise _Ps1InterpreterError

    def _invoke_string_method(
        self, s: str, method: str, args: list[_Value],
    ) -> _Value:
        try:
            if method == 'substring':
                if len(args) == 1:
                    start = self._to_int(args[0])
                    return s[start:]
                if len(args) == 2:
                    start = self._to_int(args[0])
                    length = self._to_int(args[1])
                    return s[start:start + length]
            if method == 'replace' and len(args) == 2:
                old = self._to_str(args[0])
                new = self._to_str(args[1])
                return s.replace(old, new)
            if method == 'tolower' and not args:
                return s.lower()
            if method == 'toupper' and not args:
                return s.upper()
            if method == 'trim' and not args:
                return s.strip()
            if method == 'trimstart' and not args:
                return s.lstrip()
            if method == 'trimend' and not args:
                return s.rstrip()
            if method == 'tochararray' and not args:
                return list(s)
            if method == 'split' and len(args) == 1:
                sep = self._to_str(args[0])
                return s.split(sep)
            if method == 'indexof' and len(args) == 1:
                sub = self._to_str(args[0])
                return s.find(sub)
            if method == 'contains' and len(args) == 1:
                sub = self._to_str(args[0])
                return sub in s
            if method == 'startswith' and len(args) == 1:
                prefix = self._to_str(args[0])
                return s.startswith(prefix)
            if method == 'endswith' and len(args) == 1:
                suffix = self._to_str(args[0])
                return s.endswith(suffix)
            if method == 'insert' and len(args) == 2:
                idx = self._to_int(args[0])
                val = self._to_str(args[1])
                return s[:idx] + val + s[idx:]
            if method == 'remove':
                if len(args) == 1:
                    idx = self._to_int(args[0])
                    return s[:idx]
                if len(args) == 2:
                    idx = self._to_int(args[0])
                    count = self._to_int(args[1])
                    return s[:idx] + s[idx + count:]
            if method == 'padleft' and len(args) >= 1:
                width = self._to_int(args[0])
                ch = self._to_str(args[1]) if len(args) > 1 else ' '
                return s.rjust(width, ch)
            if method == 'padright' and len(args) >= 1:
                width = self._to_int(args[0])
                ch = self._to_str(args[1]) if len(args) > 1 else ' '
                return s.ljust(width, ch)
        except (IndexError, ValueError, TypeError, OverflowError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_list_method(
        self, lst: list, method: str, args: list[_Value],
    ) -> _Value:
        if method == 'contains' and len(args) == 1:
            return args[0] in lst
        raise _Ps1InterpreterError

    def _eval_index(self, node: Ps1IndexExpression) -> _Value:
        obj = self._eval(node.object)
        idx = self._eval(node.index)
        if not isinstance(idx, int):
            raise _Ps1InterpreterError
        try:
            if isinstance(obj, str):
                return obj[idx]
            if isinstance(obj, list):
                return obj[idx]
        except IndexError:
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _eval_cast(self, node: Ps1CastExpression) -> _Value:
        tn = node.type_name.lower().replace(' ', '')
        val = self._eval(node.operand)
        if tn == 'string':
            return self._to_str(val)
        if tn in ('int', 'int32', 'int64'):
            return self._to_int(val)
        if tn == 'char':
            if isinstance(val, int):
                try:
                    return chr(val)
                except (ValueError, OverflowError):
                    raise _Ps1InterpreterError
            raise _Ps1InterpreterError
        if tn == 'char[]':
            if isinstance(val, str):
                return list(val)
            raise _Ps1InterpreterError
        if tn == 'byte':
            return self._to_int(val) & 0xFF
        raise _Ps1InterpreterError

    def _add(self, left: _Value, right: _Value) -> _Value:
        if left is None and isinstance(right, str):
            return right
        if isinstance(left, str) and right is None:
            return left
        if isinstance(left, str) or isinstance(right, str):
            result = self._to_str(left) + self._to_str(right)
            if len(result) > self.max_string_length:
                raise _Ps1InterpreterError
            return result
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            return self._numeric_op(left, right, int.__add__, float.__add__)
        if left is None and isinstance(right, (int, float)):
            return right
        if isinstance(left, list):
            if isinstance(right, list):
                return left + right
            return left + [right]
        raise _Ps1InterpreterError

    def _multiply(self, left: _Value, right: _Value) -> _Value:
        if isinstance(left, str) and isinstance(right, int):
            result = left * right
            if len(result) > self.max_string_length:
                raise _Ps1InterpreterError
            return result
        return self._numeric_op(left, right, int.__mul__, float.__mul__)

    @staticmethod
    def _numeric_op(left: _Value, right: _Value, int_op, float_op) -> int | float:
        if left is None:
            left = 0
        if right is None:
            right = 0
        try:
            if isinstance(left, float) or isinstance(right, float):
                return float_op(float(left), float(right))  # type: ignore
            if isinstance(left, int) and isinstance(right, int):
                return int_op(left, right)
        except (ZeroDivisionError, ValueError, OverflowError, ArithmeticError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    @staticmethod
    def _int_op(left: _Value, right: _Value, op) -> int:
        if left is None:
            left = 0
        if right is None:
            right = 0
        if isinstance(left, int) and isinstance(right, int):
            return op(left, right)
        raise _Ps1InterpreterError

    @staticmethod
    def _compare(left: _Value, right: _Value, op) -> bool:
        if isinstance(left, str) and isinstance(right, str):
            return op(left.lower(), right.lower())
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return op(left, right)
        if left is None:
            left = 0
        if right is None:
            right = 0
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return op(left, right)
        raise _Ps1InterpreterError

    @staticmethod
    def _truthy(value: _Value) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, float):
            return value != 0.0
        if isinstance(value, str):
            return len(value) > 0
        if isinstance(value, list):
            return len(value) > 0
        return True

    @staticmethod
    def _to_str(value: _Value) -> str:
        if isinstance(value, str):
            return value
        if value is None:
            return ''
        if isinstance(value, bool):
            return 'True' if value else 'False'
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return str(value)
        raise _Ps1InterpreterError

    @staticmethod
    def _to_int(value: _Value) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                raise _Ps1InterpreterError
        if value is None:
            return 0
        raise _Ps1InterpreterError


class Ps1FunctionEvaluator(Transformer):
    """
    Evaluate calls to user-defined functions when all arguments are constants.
    Replaces the call expression with the computed string or integer literal.
    Removes function definitions once all their calls have been resolved.
    """

    def __init__(
        self,
        max_iterations: int = 100_000,
        max_string_length: int = 1_000_000,
    ):
        super().__init__()
        self.max_iterations = max_iterations
        self.max_string_length = max_string_length
        self._functions: dict[str, Ps1FunctionDefinition] = {}
        self._call_counts: dict[str, int] = {}
        self._replaced_counts: dict[str, int] = {}
        self._entry = False

    def visit(self, node):
        if self._entry:
            return super().visit(node)
        self._entry = True
        try:
            self._functions.clear()
            self._call_counts.clear()
            self._replaced_counts.clear()
            self._collect_functions(node)
            if not self._functions:
                return None
            super().visit(node)
            self._remove_resolved_definitions(node)
            return None
        finally:
            self._entry = False

    def _collect_functions(self, root):
        for node in root.walk():
            if isinstance(node, Ps1FunctionDefinition):
                if node.is_filter:
                    continue
                if not node.name:
                    continue
                if node.body is None:
                    continue
                self._functions[node.name.lower()] = node

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        self.generic_visit(node)
        name_str = self._get_command_name(node)
        if name_str is None:
            return None
        key = name_str.lower()
        funcdef = self._functions.get(key)
        if funcdef is None:
            return None
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        args = self._extract_constant_args(node)
        if args is None:
            return None
        bindings = self._bind_parameters(funcdef, args)
        if bindings is None:
            return None
        interpreter = _Ps1Interpreter(
            max_iterations=self.max_iterations,
            max_string_length=self.max_string_length,
        )
        if funcdef.body is None:
            return None
        try:
            result = interpreter.execute(funcdef.body, bindings)
        except _Ps1InterpreterError:
            return None
        replacement = self._value_to_node(result)
        if replacement is None:
            return None
        self._replaced_counts[key] = self._replaced_counts.get(key, 0) + 1
        return replacement

    @staticmethod
    def _get_command_name(node: Ps1CommandInvocation) -> str | None:
        if isinstance(node.name, Ps1StringLiteral):
            return node.name.value
        return None

    @staticmethod
    def _extract_constant_args(node: Ps1CommandInvocation) -> list[_Value] | None:
        args: list[_Value] = []
        for arg in node.arguments:
            if isinstance(arg, Ps1CommandArgument):
                if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                    return None
                val = arg.value
            elif isinstance(arg, Expression):
                val = arg
            else:
                return None
            sv = _string_value(val) if val is not None else None
            if sv is not None:
                args.append(sv)
                continue
            if isinstance(val, Ps1IntegerLiteral):
                args.append(val.value)
                continue
            if isinstance(val, Ps1RealLiteral):
                args.append(val.value)
                continue
            return None
        return args

    @staticmethod
    def _bind_parameters(
        funcdef: Ps1FunctionDefinition,
        args: list[_Value],
    ) -> dict[str, _Value] | None:
        body = funcdef.body
        if body is None:
            return None
        param_block = body.param_block
        if param_block is None:
            if args:
                return {'args': args}
            return {}
        params = param_block.parameters
        bindings: dict[str, _Value] = {}
        for i, param in enumerate(params):
            if not isinstance(param.variable, Ps1Variable):
                return None
            key = param.variable.name.lower()
            if i < len(args):
                bindings[key] = args[i]
            elif param.default_value is not None:
                sv = _string_value(param.default_value)
                if sv is not None:
                    bindings[key] = sv
                elif isinstance(param.default_value, Ps1IntegerLiteral):
                    bindings[key] = param.default_value.value
                elif isinstance(param.default_value, Ps1RealLiteral):
                    bindings[key] = param.default_value.value
                else:
                    return None
            else:
                bindings[key] = None
        return bindings

    @staticmethod
    def _value_to_node(value: _Value) -> Expression | None:
        if isinstance(value, str):
            return _make_string_literal(value)
        if isinstance(value, int) and not isinstance(value, bool):
            return Ps1IntegerLiteral(value=value, raw=str(value))
        return None

    def _remove_resolved_definitions(self, _root):
        for key, funcdef in self._functions.items():
            call_count = self._call_counts.get(key, 0)
            replaced_count = self._replaced_counts.get(key, 0)
            if call_count == 0 or replaced_count < call_count:
                continue
            parent = funcdef.parent
            if parent is None:
                continue
            if isinstance(parent, Ps1Script):
                body = parent.body
            elif isinstance(parent, Block):
                body = parent.body
            else:
                continue
            if funcdef in body:
                body.remove(funcdef)
                self.mark_changed()
