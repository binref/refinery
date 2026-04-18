"""
Evaluate user-defined VBA functions called with constant arguments.
"""
from __future__ import annotations

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _SINGLE_ARG_BUILTINS,
    _eval_string_builtin,
    _is_identifier_read,
    _is_literal,
    _is_nan_or_inf,
    _literal_value,
    _Value,
    _value_to_node,
)
from refinery.lib.scripts.vba.model import (
    VbaBinaryExpression,
    VbaCallExpression,
    VbaConstDeclaration,
    VbaDebugPrintStatement,
    VbaDoLoopStatement,
    VbaExitKind,
    VbaExitStatement,
    VbaExpressionStatement,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaIdentifier,
    VbaIfStatement,
    VbaLetStatement,
    VbaLoopConditionPosition,
    VbaLoopConditionType,
    VbaModule,
    VbaOnErrorAction,
    VbaOnErrorStatement,
    VbaParenExpression,
    VbaUnaryExpression,
    VbaVariableDeclaration,
)


class _VbaInterpreterError(Exception):
    pass


class _UnevaluableError(Exception):
    """
    Raised for statements the interpreter cannot model, such as implicit calls with potential side
    effects. Unlike `_VbaInterpreterError`, this is not suppressed by On Error Resume Next, because
    skipping a side-effecting statement would silently lose behavior.
    """
    pass


class _ExitFunctionSignal(Exception):
    pass


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
        self._on_error_resume_next = False

    def execute(self, body: list, bindings: dict[str, _Value]) -> _Value:
        self._env = dict(bindings)
        self._iterations = 0
        self._on_error_resume_next = False
        try:
            self._exec_statements(body)
        except _ExitFunctionSignal:
            pass
        return self._env.get(self.function_name)

    def _exec_statements(self, stmts: list):
        for stmt in stmts:
            if self._on_error_resume_next:
                try:
                    self._exec_statement(stmt)
                except _VbaInterpreterError:
                    continue
            else:
                self._exec_statement(stmt)

    def _exec_statement(self, stmt):
        if isinstance(stmt, VbaOnErrorStatement):
            self._on_error_resume_next = stmt.action is VbaOnErrorAction.RESUME_NEXT
            return
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
            raise _UnevaluableError
        if isinstance(stmt, VbaDebugPrintStatement):
            return
        if isinstance(stmt, VbaVariableDeclaration):
            return
        raise _UnevaluableError

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
            if check_before and self._should_exit_loop(stmt.condition, is_until):
                break
            self._exec_statements(stmt.body)
            if not check_before and self._should_exit_loop(stmt.condition, is_until):
                break

    def _should_exit_loop(self, condition, is_until: bool) -> bool:
        if condition is None:
            return False
        cond = self._truthy(self._eval(condition))
        if is_until:
            return cond
        return not cond

    def _tick(self):
        self._iterations += 1
        if self._iterations > self.max_iterations:
            raise _VbaInterpreterError

    def _eval(self, expr) -> _Value:
        if expr is None:
            return None
        value = _literal_value(expr)
        if value is not None:
            return value
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

    def _eval_call(self, node: VbaCallExpression) -> _Value:
        if not isinstance(node.callee, VbaIdentifier):
            raise _VbaInterpreterError
        name = node.callee.name.lower()
        args = [self._eval(a) for a in node.arguments if a is not None]
        handler = _SINGLE_ARG_BUILTINS.get(name)
        if handler is not None and len(args) == 1:
            try:
                return handler(args[0])
            except (ValueError, OverflowError, TypeError, IndexError):
                raise _VbaInterpreterError
        stripped = name.rstrip('$')
        try:
            result = _eval_string_builtin(stripped, args)
        except (ValueError, OverflowError, TypeError):
            raise _VbaInterpreterError
        if result is not None:
            return result
        if name == 'instr':
            return self._builtin_instr(args)
        raise _VbaInterpreterError

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
        result = _VbaInterpreter._to_number(v)
        return result if isinstance(result, int) else int(result)

    def _numeric_op(self, left: _Value, right: _Value, op) -> int | float:
        a = self._to_number(left)
        b = self._to_number(right)
        try:
            result = op(a, b)
        except (ZeroDivisionError, ValueError, OverflowError, ArithmeticError):
            raise _VbaInterpreterError
        if _is_nan_or_inf(result):
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
        if not _is_identifier_read(node):
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
        except (_VbaInterpreterError, _UnevaluableError):
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
