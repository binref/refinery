"""
Evaluate user-defined VBA functions called with constant arguments.
"""
from __future__ import annotations

from typing import Any, Callable

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _Value,
    _is_literal,
    _literal_value,
    _value_to_node,
)
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaDebugPrintStatement,
    VbaDoLoopStatement,
    VbaExitKind,
    VbaExitStatement,
    VbaExpressionStatement,
    VbaFloatLiteral,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaIdentifier,
    VbaIfStatement,
    VbaIntegerLiteral,
    VbaLetStatement,
    VbaLoopConditionPosition,
    VbaLoopConditionType,
    VbaModule,
    VbaParenExpression,
    VbaStringLiteral,
    VbaUnaryExpression,
    VbaVariableDeclaration,
)


class _VbaInterpreterError(Exception):
    pass


class _ExitFunctionSignal(Exception):
    pass


def _cast_to_int(value):
    as_flt = float(value)
    as_int = int(as_flt)
    if as_flt < 0 and as_flt != int(as_flt):
        as_int -= 1
    return as_int


class _VbaInterpreter:

    def __init__(
        self,
        function_name: str,
        max_iterations: int = 100_000,
        max_string_length: int = 1_000_000,
    ):
        self.function_name = function_name.lower()
        self.max_iterations = max_iterations
        self.max_string_length = max_string_length
        self._env: dict[str, _Value] = {}
        self._iterations = 0

    def execute(self, body: list, bindings: dict[str, _Value]) -> _Value:
        self._env = dict(bindings)
        self._iterations = 0
        try:
            self._exec_statements(body)
        except _ExitFunctionSignal:
            pass
        return self._env.get(self.function_name)

    def _exec_statements(self, stmts: list):
        for stmt in stmts:
            self._exec_statement(stmt)

    def _exec_statement(self, stmt):
        if isinstance(stmt, VbaLetStatement):
            return self._exec_let(stmt)
        if isinstance(stmt, VbaConstDeclaration):
            return self._exec_const(stmt)
        if isinstance(stmt, VbaIfStatement):
            return self._exec_if(stmt)
        if isinstance(stmt, VbaForStatement):
            return self._exec_for(stmt)
        if isinstance(stmt, VbaDoLoopStatement):
            return self._exec_do_loop(stmt)
        if isinstance(stmt, VbaExitStatement):
            if stmt.kind is VbaExitKind.FUNCTION:
                raise _ExitFunctionSignal
            raise _VbaInterpreterError
        if isinstance(stmt, VbaExpressionStatement):
            return
        if isinstance(stmt, VbaDebugPrintStatement):
            return
        if isinstance(stmt, VbaVariableDeclaration):
            return
        raise _VbaInterpreterError

    def _exec_let(self, stmt: VbaLetStatement):
        if not isinstance(stmt.target, VbaIdentifier):
            raise _VbaInterpreterError
        key = stmt.target.name.lower()
        value = self._eval(stmt.value)
        self._env[key] = value

    def _exec_const(self, stmt: VbaConstDeclaration):
        for d in stmt.declarators:
            key = d.name.lower()
            value = self._eval(d.value)
            self._env[key] = value

    def _exec_if(self, stmt: VbaIfStatement):
        cond = self._eval(stmt.condition)
        if self._truthy(cond):
            self._exec_statements(stmt.body)
            return
        for clause in stmt.elseif_clauses:
            cond = self._eval(clause.condition)
            if self._truthy(cond):
                self._exec_statements(clause.body)
                return
        if stmt.else_body:
            self._exec_statements(stmt.else_body)

    def _exec_for(self, stmt: VbaForStatement):
        if not isinstance(stmt.variable, VbaIdentifier):
            raise _VbaInterpreterError
        key = stmt.variable.name.lower()
        start = self._to_number(self._eval(stmt.start))
        end = self._to_number(self._eval(stmt.end))
        step = self._to_number(self._eval(stmt.step)) if stmt.step else 1
        if step == 0:
            raise _VbaInterpreterError
        counter = start
        while True:
            self._tick()
            if step > 0 and counter > end:
                break
            if step < 0 and counter < end:
                break
            self._env[key] = counter
            self._exec_statements(stmt.body)
            counter = counter + step

    def _exec_do_loop(self, stmt: VbaDoLoopStatement):
        check_before = stmt.condition_position is VbaLoopConditionPosition.PRE
        is_until = stmt.condition_type is VbaLoopConditionType.UNTIL
        while True:
            self._tick()
            if check_before and stmt.condition is not None:
                cond = self._truthy(self._eval(stmt.condition))
                if is_until and cond:
                    break
                if not is_until and not cond:
                    break
            self._exec_statements(stmt.body)
            if not check_before and stmt.condition is not None:
                cond = self._truthy(self._eval(stmt.condition))
                if is_until and cond:
                    break
                if not is_until and not cond:
                    break

    def _tick(self):
        self._iterations += 1
        if self._iterations > self.max_iterations:
            raise _VbaInterpreterError

    def _eval(self, expr) -> _Value:
        if expr is None:
            return None
        if isinstance(expr, VbaStringLiteral):
            return expr.value
        if isinstance(expr, VbaIntegerLiteral):
            return expr.value
        if isinstance(expr, VbaFloatLiteral):
            return expr.value
        if isinstance(expr, VbaBooleanLiteral):
            return expr.value
        if isinstance(expr, VbaIdentifier):
            return self._env.get(expr.name.lower())
        if isinstance(expr, VbaBinaryExpression):
            return self._eval_binary(expr)
        if isinstance(expr, VbaUnaryExpression):
            return self._eval_unary(expr)
        if isinstance(expr, VbaParenExpression):
            return self._eval(expr.expression)
        if isinstance(expr, VbaCallExpression):
            return self._eval_call(expr)
        raise _VbaInterpreterError

    def _eval_binary(self, node: VbaBinaryExpression) -> _Value:
        left = self._eval(node.left)
        right = self._eval(node.right)
        op = node.operator
        if op == '&':
            return self._concat(left, right)
        if op == '+':
            if isinstance(left, str) or isinstance(right, str):
                return self._concat(left, right)
            return self._numeric_op(left, right, lambda a, b: a + b)
        if op == '-':
            return self._numeric_op(left, right, lambda a, b: a - b)
        if op == '*':
            return self._numeric_op(left, right, lambda a, b: a * b)
        if op == '/':
            return self._numeric_op(left, right, lambda a, b: a / b)
        if op == '\\':
            a = self._to_int(left)
            b = self._to_int(right)
            if b == 0:
                raise _VbaInterpreterError
            return a // b
        if op.lower() == 'mod':
            a = self._to_int(left)
            b = self._to_int(right)
            if b == 0:
                raise _VbaInterpreterError
            return a % b
        if op == '^':
            return self._numeric_op(left, right, lambda a, b: a ** b)
        if op.lower() == 'xor':
            return self._to_int(left) ^ self._to_int(right)
        if op.lower() == 'and':
            return self._to_int(left) & self._to_int(right)
        if op.lower() == 'or':
            return self._to_int(left) | self._to_int(right)
        if op == '=':
            return left == right
        if op == '<>':
            return left != right
        if op == '<':
            return self._compare(left, right, lambda a, b: a < b)
        if op == '>':
            return self._compare(left, right, lambda a, b: a > b)
        if op == '<=':
            return self._compare(left, right, lambda a, b: a <= b)
        if op == '>=':
            return self._compare(left, right, lambda a, b: a >= b)
        raise _VbaInterpreterError

    def _eval_unary(self, node: VbaUnaryExpression) -> _Value:
        val = self._eval(node.operand)
        op = node.operator
        if op == '-':
            n = self._to_number(val)
            return -n
        if op.lower() == 'not':
            if isinstance(val, bool):
                return not val
            return ~self._to_int(val)
        raise _VbaInterpreterError

    _BUILTINS: dict[str, Callable[[Any], _Value]] = {
        'chr'       : lambda v: chr(int(v)),
        'chrw'      : lambda v: chr(int(v)),
        'chr$'      : lambda v: chr(int(v)),
        'chrw$'     : lambda v: chr(int(v)),
        'asc'       : lambda v: ord(str(v)[0]),
        'ascw'      : lambda v: ord(str(v)[0]),
        'len'       : lambda v: len(str(v)),
        'lcase'     : lambda v: str(v).lower(),
        'lcase$'    : lambda v: str(v).lower(),
        'ucase'     : lambda v: str(v).upper(),
        'ucase$'    : lambda v: str(v).upper(),
        'trim'      : lambda v: str(v).strip(),
        'trim$'     : lambda v: str(v).strip(),
        'ltrim'     : lambda v: str(v).lstrip(),
        'ltrim$'    : lambda v: str(v).lstrip(),
        'rtrim'     : lambda v: str(v).rstrip(),
        'rtrim$'    : lambda v: str(v).rstrip(),
        'strreverse': lambda v: str(v)[::-1],
        'cstr'      : lambda v: str(v),
        'cint'      : lambda v: int(round(float(v))),
        'clng'      : lambda v: int(round(float(v))),
        'cdbl'      : lambda v: float(v),
        'csng'      : lambda v: float(v),
        'cbool'     : lambda v: bool(v),
        'abs'       : lambda v: abs(v),
        'sgn'       : lambda v: (1 if v > 0 else (-1 if v < 0 else 0)),
        'int'       : _cast_to_int,
        'fix'       : lambda v: int(float(v)),
        'hex'       : lambda v: format(int(v), 'X'),
        'hex$'      : lambda v: format(int(v), 'X'),
        'oct'       : lambda v: format(int(v), 'o'),
        'oct$'      : lambda v: format(int(v), 'o'),
        'cbyte'     : lambda v: int(v) & 0xFF,
        'space'     : lambda v: ' ' * int(v),
        'space$'    : lambda v: ' ' * int(v),
    }

    def _eval_call(self, node: VbaCallExpression) -> _Value:
        if not isinstance(node.callee, VbaIdentifier):
            raise _VbaInterpreterError
        name = node.callee.name.lower()
        args = [self._eval(a) for a in node.arguments if a is not None]
        handler = self._BUILTINS.get(name)
        if handler is not None and len(args) == 1:
            try:
                return handler(args[0])
            except (ValueError, OverflowError, TypeError, IndexError):
                raise _VbaInterpreterError
        if name == 'mid' or name == 'mid$':
            return self._builtin_mid(args)
        if name == 'left' or name == 'left$':
            return self._builtin_left(args)
        if name == 'right' or name == 'right$':
            return self._builtin_right(args)
        if name == 'string' or name == 'string$':
            return self._builtin_string(args)
        if name == 'replace':
            return self._builtin_replace(args)
        if name == 'instr':
            return self._builtin_instr(args)
        raise _VbaInterpreterError

    @staticmethod
    def _builtin_mid(args: list[_Value]) -> str:
        if len(args) not in (2, 3):
            raise _VbaInterpreterError
        s = str(args[0]) if args[0] is not None else ''
        start = int(args[1]) - 1  # type: ignore
        if start < 0:
            raise _VbaInterpreterError
        if len(args) == 3:
            length = int(args[2])  # type: ignore
            return s[start:start + length]
        return s[start:]

    @staticmethod
    def _builtin_left(args: list[_Value]) -> str:
        if len(args) != 2:
            raise _VbaInterpreterError
        s = str(args[0]) if args[0] is not None else ''
        n = int(args[1])  # type: ignore
        return s[:n]

    @staticmethod
    def _builtin_right(args: list[_Value]) -> str:
        if len(args) != 2:
            raise _VbaInterpreterError
        s = str(args[0]) if args[0] is not None else ''
        n = int(args[1])  # type: ignore
        return s[-n:] if n > 0 else ''

    @staticmethod
    def _builtin_string(args: list[_Value]) -> str:
        if len(args) != 2:
            raise _VbaInterpreterError
        n = int(args[0])  # type: ignore
        c = str(args[1]) if args[1] is not None else ''
        if not c:
            raise _VbaInterpreterError
        return c[0] * n

    @staticmethod
    def _builtin_replace(args: list[_Value]) -> str:
        if len(args) < 3:
            raise _VbaInterpreterError
        haystack = str(args[0]) if args[0] is not None else ''
        needle = str(args[1]) if args[1] is not None else ''
        insert = str(args[2]) if args[2] is not None else ''
        if not needle:
            raise _VbaInterpreterError
        return haystack.replace(needle, insert)

    @staticmethod
    def _builtin_instr(args: list[_Value]) -> int:
        if len(args) == 2:
            haystack = str(args[0]) if args[0] is not None else ''
            needle = str(args[1]) if args[1] is not None else ''
            idx = haystack.find(needle)
            return idx + 1 if idx >= 0 else 0
        if len(args) == 3:
            start = int(args[0])  # type: ignore
            haystack = str(args[1]) if args[1] is not None else ''
            needle = str(args[2]) if args[2] is not None else ''
            idx = haystack.find(needle, start - 1)
            return idx + 1 if idx >= 0 else 0
        raise _VbaInterpreterError

    def _concat(self, lhs: _Value, rhs: _Value) -> str:
        a = str(lhs) if lhs is not None else ''
        b = str(rhs) if rhs is not None else ''
        result = a + b
        if len(result) > self.max_string_length:
            raise _VbaInterpreterError
        return result

    @staticmethod
    def _to_number(v: _Value) -> int | float:
        if v is None:
            return 0
        if isinstance(v, bool):
            return -1 if v else 0
        if isinstance(v, (int, float)):
            return v
        if isinstance(v, str):
            try:
                return int(v)
            except ValueError:
                try:
                    return float(v)
                except ValueError:
                    raise _VbaInterpreterError

    @staticmethod
    def _to_int(v: _Value) -> int:
        if v is None:
            return 0
        if isinstance(v, bool):
            return -1 if v else 0
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            return int(v)
        if isinstance(v, str):
            try:
                return int(v)
            except ValueError:
                raise _VbaInterpreterError
        raise _VbaInterpreterError

    def _numeric_op(self, left: _Value, right: _Value, op) -> int | float:
        a = self._to_number(left)
        b = self._to_number(right)
        try:
            result = op(a, b)
        except (ZeroDivisionError, ValueError, OverflowError, ArithmeticError):
            raise _VbaInterpreterError
        if isinstance(result, float) and (result != result or abs(result) == float('inf')):
            raise _VbaInterpreterError
        return result

    @staticmethod
    def _compare(left: _Value, right: _Value, op) -> bool:
        if isinstance(left, str) and isinstance(right, str):
            return op(left.lower(), right.lower())
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return op(left, right)
        raise _VbaInterpreterError

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
        return True


class VbaFunctionEvaluator(Transformer):
    """
    Evaluate calls to user-defined VBA functions when all arguments are constants.
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
        self._functions: dict[str, VbaFunctionDeclaration] = {}
        self._call_counts: dict[str, int] = {}
        self._replaced_counts: dict[str, int] = {}
        self._entry = False
        self._inside_function: str | None = None

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
            if isinstance(node, VbaFunctionDeclaration):
                if not node.name:
                    continue
                self._functions[node.name.lower()] = node

    def visit_VbaFunctionDeclaration(self, node: VbaFunctionDeclaration):
        key = node.name.lower() if node.name else None
        old = self._inside_function
        self._inside_function = key
        self.generic_visit(node)
        self._inside_function = old
        return None

    def visit_VbaCallExpression(self, node: VbaCallExpression):
        self.generic_visit(node)
        if not isinstance(node.callee, VbaIdentifier):
            return None
        key = node.callee.name.lower()
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
        result = self._try_evaluate(funcdef, bindings)
        if result is None:
            return None
        replacement = _value_to_node(result)
        if replacement is None:
            return None
        self._replaced_counts[key] = self._replaced_counts.get(key, 0) + 1
        return replacement

    def visit_VbaIdentifier(self, node: VbaIdentifier):
        key = node.name.lower()
        if key == self._inside_function:
            return None
        funcdef = self._functions.get(key)
        if funcdef is None:
            return None
        if funcdef.params:
            required = [p for p in funcdef.params if not p.is_optional and p.default is None]
            if required:
                return None
        parent = node.parent
        if isinstance(parent, VbaLetStatement) and parent.target is node:
            return None
        if isinstance(parent, VbaCallExpression) and parent.callee is node:
            return None
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        bindings = self._bind_parameters(funcdef, [])
        if bindings is None:
            return None
        result = self._try_evaluate(funcdef, bindings)
        if result is None:
            return None
        replacement = _value_to_node(result)
        if replacement is None:
            return None
        self._replaced_counts[key] = self._replaced_counts.get(key, 0) + 1
        return replacement

    def _try_evaluate(
        self,
        funcdef: VbaFunctionDeclaration,
        bindings: dict[str, _Value],
    ) -> _Value:
        interpreter = _VbaInterpreter(
            function_name=funcdef.name,
            max_iterations=self.max_iterations,
            max_string_length=self.max_string_length,
        )
        try:
            return interpreter.execute(funcdef.body, bindings)
        except _VbaInterpreterError:
            return None

    @staticmethod
    def _extract_constant_args(node: VbaCallExpression) -> list[_Value] | None:
        args: list[_Value] = []
        for arg in node.arguments:
            if arg is None:
                args.append(None)
                continue
            if not _is_literal(arg):
                return None
            args.append(_literal_value(arg))
        return args

    @staticmethod
    def _bind_parameters(
        funcdef: VbaFunctionDeclaration,
        args: list[_Value],
    ) -> dict[str, _Value] | None:
        bindings: dict[str, _Value] = {}
        for i, param in enumerate(funcdef.params):
            key = param.name.lower()
            if i < len(args):
                bindings[key] = args[i]
            elif param.is_optional and param.default is not None:
                if _is_literal(param.default):
                    bindings[key] = _literal_value(param.default)
                else:
                    return None
            elif param.is_optional:
                bindings[key] = None
            else:
                return None
        return bindings

    def _remove_resolved_definitions(self, _root):
        for key, funcdef in self._functions.items():
            call_count = self._call_counts.get(key, 0)
            replaced_count = self._replaced_counts.get(key, 0)
            if call_count == 0 or replaced_count < call_count:
                continue
            parent = funcdef.parent
            if parent is None:
                continue
            if isinstance(parent, VbaModule):
                body = parent.body
            else:
                continue
            if funcdef in body:
                body.remove(funcdef)
                self.mark_changed()
