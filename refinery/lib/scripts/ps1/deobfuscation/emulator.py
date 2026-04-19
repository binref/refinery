"""
Evaluate user-defined PowerShell functions called with constant arguments.
"""
from __future__ import annotations

import base64
import re

from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import TypeAlias

from refinery.lib.scripts import Block, Transformer
from refinery.lib.scripts.ps1.deobfuscation.helpers import (
    detect_encoding_chain,
    extract_foreach_scriptblock,
    get_command_name,
    get_member_name,
    make_string_literal,
    string_value,
    unwrap_to_array_literal,
)
from refinery.lib.scripts.ps1.deobfuscation.names import (
    ENCODING_MAP,
    apply_format_string,
    normalize_dotnet_type_name,
    normalize_type_expression,
)
from refinery.lib.scripts.ps1.deobfuscation.typenames import is_type
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DoLoop,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HereString,
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
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)

_Value: TypeAlias = Union[str, int, float, bool, list, None]


class _Ps1InterpreterError(Exception):
    pass


class _ReturnSignal(Exception):
    def __init__(self, value: _Value):
        self.value = value


class _BreakSignal(Exception):
    pass


class _ContinueSignal(Exception):
    pass


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
        if isinstance(stmt, Ps1DoLoop):
            return self._exec_do_loop(stmt)
        if isinstance(stmt, Ps1IfStatement):
            return self._exec_if(stmt)
        if isinstance(stmt, Ps1SwitchStatement):
            return self._exec_switch(stmt)
        if isinstance(stmt, Ps1ReturnStatement):
            value = self._eval(stmt.pipeline) if stmt.pipeline else None
            raise _ReturnSignal(value)
        if isinstance(stmt, Ps1BreakStatement):
            raise _BreakSignal
        if isinstance(stmt, Ps1ContinueStatement):
            raise _ContinueSignal
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
            try:
                result = self._exec_block(node.body)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
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
            try:
                result = self._exec_block(node.body)
            except _BreakSignal:
                break
            except _ContinueSignal:
                continue
        return result

    def _exec_while(self, node: Ps1WhileLoop) -> _Value:
        result: _Value = None
        while True:
            self._tick()
            if not self._truthy(self._eval(node.condition)):
                break
            try:
                result = self._exec_block(node.body)
            except _BreakSignal:
                break
            except _ContinueSignal:
                continue
        return result

    def _exec_do_loop(self, node: Ps1DoLoop) -> _Value:
        result: _Value = None
        while True:
            self._tick()
            try:
                result = self._exec_block(node.body)
            except _BreakSignal:
                break
            except _ContinueSignal:
                pass
            truth = self._truthy(self._eval(node.condition))
            if node.is_until == truth:
                break
        return result

    def _exec_if(self, node: Ps1IfStatement) -> _Value:
        for condition, body in node.clauses:
            if self._truthy(self._eval(condition)):
                return self._exec_block(body)
        if node.else_block:
            return self._exec_block(node.else_block)
        return None

    def _exec_switch(self, node: Ps1SwitchStatement) -> _Value:
        value = self._eval(node.value)
        default_block = None
        for condition, block in node.clauses:
            if condition is None:
                default_block = block
                continue
            cond_val = self._eval(condition)
            if self._switch_matches(value, cond_val):
                try:
                    return self._exec_block(block)
                except _BreakSignal:
                    return None
        if default_block is not None:
            try:
                return self._exec_block(default_block)
            except _BreakSignal:
                return None
        return None

    @staticmethod
    def _switch_matches(value: _Value, condition: _Value) -> bool:
        if isinstance(value, str) and isinstance(condition, str):
            return value.lower() == condition.lower()
        if isinstance(value, (int, float)) and isinstance(condition, (int, float)):
            return value == condition
        if isinstance(value, int) and isinstance(condition, str):
            try:
                return value == int(condition)
            except ValueError:
                return False
        if isinstance(value, str) and isinstance(condition, int):
            try:
                return int(value) == condition
            except ValueError:
                return False
        return value is condition

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
        if isinstance(expr, Ps1ExpandableString):
            return self._eval_string_parts(expr.parts)
        if isinstance(expr, Ps1ExpandableHereString):
            return self._eval_string_parts(expr.parts)
        if isinstance(expr, Ps1HereString):
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
        if isinstance(expr, Ps1ArrayExpression):
            return self._eval_array_expression(expr)
        if isinstance(expr, Ps1CastExpression):
            return self._eval_cast(expr)
        if isinstance(expr, Ps1SubExpression):
            return self._exec_statements(expr.body)
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

    def _eval_string_parts(self, parts: list) -> str:
        """
        Evaluate the parts of an expandable string or expandable here-string by
        resolving each variable / subexpression and concatenating the results.
        """
        out: list[str] = []
        for part in parts:
            if isinstance(part, Ps1StringLiteral):
                out.append(part.value)
            elif isinstance(part, Ps1SubExpression):
                val = self._exec_statements(part.body)
                out.append(self._to_str(val))
            else:
                out.append(self._to_str(self._eval(part)))
        result = ''.join(out)
        if len(result) > self.max_string_length:
            raise _Ps1InterpreterError
        return result

    def _eval_array_expression(self, expr: Ps1ArrayExpression) -> list:
        """
        Evaluate an `@( ... )` array expression by executing its body statements
        and flattening the results into a list.
        """
        results: list[_Value] = []
        for stmt in expr.body:
            val = self._exec_statement(stmt)
            if isinstance(val, list):
                results.extend(val)
            elif val is not None:
                results.append(val)
        return results

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
        if op == '-as':
            if not isinstance(node.right, Ps1TypeExpression):
                raise _Ps1InterpreterError
            left = self._eval(node.left)
            return self._apply_type_cast(node.right.name, left)
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
        if op == '-shl':
            return self._int_op(left, right, int.__lshift__)
        if op == '-shr':
            return self._int_op(left, right, int.__rshift__)
        if op in ('-and', '-or', '-xor'):
            lb = self._truthy(left)
            rb = self._truthy(right)
            if op == '-and':
                return lb and rb
            if op == '-or':
                return lb or rb
            return lb != rb
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
        if op in ('-split', '-csplit', '-isplit'):
            return self._eval_split(left, right, op)
        if op == '-join':
            return self._eval_join(left, right)
        if op in ('-replace', '-creplace', '-ireplace'):
            return self._eval_replace(left, right, op)
        if op in ('-match', '-cmatch', '-imatch'):
            return self._eval_match(left, right, op)
        if op in ('-notmatch', '-cnotmatch', '-inotmatch'):
            return not self._eval_match(left, right, op)
        if op == '-contains':
            return self._eval_contains(left, right)
        if op == '-notcontains':
            return not self._eval_contains(left, right)
        if op == '-in':
            return self._eval_contains(right, left)
        if op == '-notin':
            return not self._eval_contains(right, left)
        if op in ('-like', '-clike', '-ilike'):
            return self._eval_like(left, right, op)
        if op in ('-notlike', '-cnotlike', '-inotlike'):
            return not self._eval_like(left, right, op)
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
        if op.lower() == '-not' or op == '!':
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
        if op.lower() == '-split':
            val = self._eval(node.operand)
            parts = re.split(r'\s+', self._to_str(val))
            return [p for p in parts if p]
        if op.lower() == '-join':
            val = self._eval(node.operand)
            if isinstance(val, list):
                return ''.join(self._to_str(item) for item in val)
            return self._to_str(val)
        raise _Ps1InterpreterError

    _MEMBER_ARITHMETIC = re.compile(r'^(\w+)([+\-])(\d+)$')

    def _eval_member_access(self, node: Ps1MemberAccess) -> _Value:
        obj = self._eval(node.object)
        member = get_member_name(node.member)
        if member is None:
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

    def _eval_invoke_member(self, node: Ps1InvokeMember) -> _Value:
        if node.access == Ps1AccessKind.STATIC:
            return self._eval_static_invoke(node)
        enc = self._try_encoding_chain(node)
        if enc is not None:
            return enc
        obj = self._eval(node.object)
        member = get_member_name(node.member)
        if member is None:
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
        type_name = normalize_type_expression(node.object.name)
        member = get_member_name(node.member)
        if member is None:
            raise _Ps1InterpreterError
        name = member.lower()
        args = [self._eval(a) for a in node.arguments]
        if is_type(type_name, 'system.convert'):
            return self._invoke_convert(name, args)
        if is_type(type_name, 'system.text.encoding'):
            return self._invoke_encoding(name, args)
        if is_type(type_name, 'system.string'):
            return self._invoke_string_static(name, args)
        if is_type(type_name, 'system.math'):
            return self._invoke_math_static(name, args)
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
            if method == 'frombase64string' and len(args) == 1:
                return list(base64.b64decode(self._to_str(args[0])))
            if method == 'tobase64string' and len(args) == 1:
                value = args[0]
                if not isinstance(value, list):
                    raise _Ps1InterpreterError
                return base64.b64encode(bytearray(int(b) for b in value)).decode('ascii')
        except (ValueError, OverflowError, TypeError):
            raise _Ps1InterpreterError
        raise _Ps1InterpreterError

    def _invoke_encoding(self, method: str, args: list[_Value]) -> _Value:
        encoding = ENCODING_MAP.get(method)
        if encoding is None or len(args) != 1:
            raise _Ps1InterpreterError
        return self._decode_byte_list(args[0], encoding)

    def _try_encoding_chain(self, node: Ps1InvokeMember) -> _Value | None:
        enc_name = detect_encoding_chain(node)
        if enc_name is None:
            return None
        encoding = ENCODING_MAP.get(enc_name.lower(), enc_name.lower())
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

    def _invoke_string_static(self, method: str, args: list[_Value]) -> _Value:
        if method == 'join' and len(args) == 2:
            separator = self._to_str(args[0])
            collection = args[1]
            if isinstance(collection, list):
                return separator.join(self._to_str(item) for item in collection)
            return self._to_str(collection)
        if method == 'format' and len(args) >= 1:
            fmt = self._to_str(args[0])
            str_args = [self._to_str(a) for a in args[1:]]
            result = apply_format_string(fmt, str_args)
            if result is None:
                raise _Ps1InterpreterError
            return result
        if method == 'isnullorempty' and len(args) == 1:
            v = args[0]
            return v is None or (isinstance(v, str) and len(v) == 0)
        if method == 'concat' and len(args) >= 1:
            return ''.join(self._to_str(a) for a in args)
        raise _Ps1InterpreterError

    def _invoke_math_static(self, method: str, args: list[_Value]) -> _Value:
        import math
        try:
            if method == 'abs' and len(args) == 1:
                v = args[0]
                if isinstance(v, int):
                    return abs(v)
                if isinstance(v, float):
                    return abs(v)
            if method == 'floor' and len(args) == 1:
                return int(math.floor(float(self._to_int(args[0]))))
            if method == 'ceiling' and len(args) == 1:
                return int(math.ceil(float(self._to_int(args[0]))))
            if method == 'round' and len(args) in (1, 2):
                val = float(args[0]) if isinstance(args[0], (int, float)) else float(self._to_str(args[0]))
                digits = self._to_int(args[1]) if len(args) == 2 else 0
                result = round(val, digits)
                return int(result) if digits == 0 else result
            if method == 'pow' and len(args) == 2:
                base = float(args[0]) if isinstance(args[0], (int, float)) else float(self._to_str(args[0]))
                exp = float(args[1]) if isinstance(args[1], (int, float)) else float(self._to_str(args[1]))
                result = math.pow(base, exp)
                return int(result) if result == int(result) else result
            if method == 'sqrt' and len(args) == 1:
                val = float(args[0]) if isinstance(args[0], (int, float)) else float(self._to_str(args[0]))
                return math.sqrt(val)
            if method == 'min' and len(args) == 2:
                a = args[0] if isinstance(args[0], (int, float)) else self._to_int(args[0])
                b = args[1] if isinstance(args[1], (int, float)) else self._to_int(args[1])
                return min(a, b)
            if method == 'max' and len(args) == 2:
                a = args[0] if isinstance(args[0], (int, float)) else self._to_int(args[0])
                b = args[1] if isinstance(args[1], (int, float)) else self._to_int(args[1])
                return max(a, b)
        except (ValueError, OverflowError, TypeError):
            raise _Ps1InterpreterError
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
            if method == 'tostring' and not args:
                return s
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
                if not sep:
                    return [s]
                pattern = '[' + re.escape(sep) + ']'
                return re.split(pattern, s)
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
        val = self._eval(node.operand)
        return self._apply_type_cast(node.type_name, val)

    def _apply_type_cast(self, type_name: str, val: _Value) -> _Value:
        tn = normalize_dotnet_type_name(type_name)
        if tn == 'string':
            if isinstance(val, list):
                return ' '.join(self._to_str(item) for item in val)
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
        if isinstance(left, str):
            left = _Ps1Interpreter._to_int(left)
        if isinstance(right, str):
            right = _Ps1Interpreter._to_int(right)
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

    def _eval_split(self, left: _Value, right: _Value, op: str) -> list:
        s = self._to_str(left)
        pattern = self._to_str(right)
        flags = re.IGNORECASE if op != '-csplit' else 0
        try:
            return re.split(pattern, s, flags=flags)
        except re.error:
            raise _Ps1InterpreterError

    def _eval_join(self, left: _Value, right: _Value) -> str:
        separator = self._to_str(right)
        if isinstance(left, list):
            return separator.join(self._to_str(item) for item in left)
        return self._to_str(left)

    def _eval_replace(self, left: _Value, right: _Value, op: str) -> str:
        s = self._to_str(left)
        if isinstance(right, list) and len(right) == 2:
            pattern = self._to_str(right[0])
            replacement = self._to_str(right[1])
        else:
            raise _Ps1InterpreterError
        flags = re.IGNORECASE if op != '-creplace' else 0
        try:
            return re.sub(pattern, replacement, s, flags=flags)
        except re.error:
            raise _Ps1InterpreterError

    @staticmethod
    def _eval_match(left: _Value, right: _Value, op: str) -> bool:
        if not isinstance(left, str) or not isinstance(right, str):
            raise _Ps1InterpreterError
        flags = re.IGNORECASE if op[1] != 'c' else 0
        try:
            return re.search(right, left, flags=flags) is not None
        except re.error:
            raise _Ps1InterpreterError

    @staticmethod
    def _eval_contains(collection: _Value, item: _Value) -> bool:
        if isinstance(collection, list):
            for elem in collection:
                if isinstance(elem, str) and isinstance(item, str):
                    if elem.lower() == item.lower():
                        return True
                elif elem == item:
                    return True
            return False
        raise _Ps1InterpreterError

    @staticmethod
    def _eval_like(left: _Value, right: _Value, op: str) -> bool:
        if not isinstance(left, str) or not isinstance(right, str):
            raise _Ps1InterpreterError
        flags = re.IGNORECASE if op[1] != 'c' else 0
        pattern = re.escape(right).replace(r'\*', '.*').replace(r'\?', '.')
        try:
            return re.fullmatch(pattern, left, flags=flags) is not None
        except re.error:
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
                return int(value, 0)
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
        name_str = get_command_name(node)
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
            sv = string_value(val) if val is not None else None
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
                sv = string_value(param.default_value)
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
            return make_string_literal(value)
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


class Ps1ForEachPipeline(Transformer):
    """
    Evaluate pipelines of the form `<array> | %{ <scriptblock> }` by executing
    the scriptblock for each element and replacing the pipeline with the
    computed result.
    """

    _BUILTIN_VARS = frozenset({'_', 'true', 'false', 'null'})

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        self.generic_visit(node)
        if len(node.elements) != 2:
            return None
        src_elem = node.elements[0]
        cmd_elem = node.elements[1]
        if not isinstance(src_elem, Ps1PipelineElement) or src_elem.redirections:
            return None
        if not isinstance(cmd_elem, Ps1PipelineElement) or cmd_elem.redirections:
            return None
        items = self._get_constant_array(src_elem.expression)
        if items is None:
            return None
        if cmd_elem.expression is None:
            return None
        script_block = extract_foreach_scriptblock(cmd_elem.expression)
        if script_block is None:
            return None
        if self._has_free_variables(script_block):
            return None
        results: list[_Value] = []
        interpreter = _Ps1Interpreter()
        for item in items:
            try:
                result = interpreter.execute(script_block, {'_': item})
            except _Ps1InterpreterError:
                return None
            results.append(result)
        return self._results_to_node(results)

    @staticmethod
    def _has_free_variables(script_block: Ps1ScriptBlock) -> bool:
        for node in script_block.walk():
            if isinstance(node, Ps1Variable):
                if node.scope not in (Ps1ScopeModifier.NONE, Ps1ScopeModifier.LOCAL):
                    return True
                if node.name.lower() not in Ps1ForEachPipeline._BUILTIN_VARS:
                    return True
        return False

    @staticmethod
    def _get_constant_array(expr: Expression | None) -> list[_Value] | None:
        while isinstance(expr, Ps1CastExpression):
            expr = expr.operand
        if expr is not None:
            array = unwrap_to_array_literal(expr)
            if array is not None:
                expr = array
        if not isinstance(expr, Ps1ArrayLiteral):
            return None
        values: list[_Value] = []
        for elem in expr.elements:
            sv = string_value(elem)
            if sv is not None:
                values.append(sv)
                continue
            if isinstance(elem, Ps1IntegerLiteral):
                values.append(elem.value)
                continue
            if (
                isinstance(elem, Ps1UnaryExpression)
                and elem.operator == '-'
                and isinstance(elem.operand, Ps1IntegerLiteral)
            ):
                values.append(-elem.operand.value)
                continue
            return None
        return values

    @staticmethod
    def _results_to_node(results: list[_Value]) -> Expression | None:
        if all(isinstance(r, str) for r in results):
            return make_string_literal(''.join(r for r in results if isinstance(r, str)))
        if all(isinstance(r, int) and not isinstance(r, bool) for r in results):
            elements: list[Expression] = [
                Ps1IntegerLiteral(value=v, raw=str(v))
                for v in results if isinstance(v, int)
            ]
            return Ps1ArrayLiteral(elements=elements)
        if all(isinstance(r, (str, int)) and not isinstance(r, bool) for r in results):
            try:
                parts = [chr(r) if isinstance(r, int) else str(r) for r in results]
                return make_string_literal(''.join(parts))
            except (ValueError, OverflowError):
                pass
        return None


def evaluate_truthy(
    condition: Expression,
    bindings: Mapping[str, int | float | str | bool | None],
) -> bool | None:
    """
    Evaluate a PS1 condition with the given variable bindings and return its truthiness. Returns
    None if the expression cannot be evaluated.
    """
    try:
        interp = _Ps1Interpreter(max_iterations=100)
        interp._env = dict(bindings)
        value = interp._eval(condition)
        return _Ps1Interpreter._truthy(value)
    except _Ps1InterpreterError:
        return None
