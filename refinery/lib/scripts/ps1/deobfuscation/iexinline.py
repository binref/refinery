"""
Inline constant IEX (Invoke-Expression) and [scriptblock]::Create() calls
by parsing the string argument.

When the argument is not a plain string literal but a .NET expression chain
(e.g. base64-decode -> decompress -> stream-read), the evaluator attempts to
resolve it to a string value at deobfuscation time.
"""
from __future__ import annotations

import base64
import gzip
import zlib

from refinery.lib.scripts import Expression, Transformer
from refinery.lib.scripts.ps1.analysis.blocks import runs_alike_in_the_scope_around_it
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.values import collect_byte_array
from refinery.lib.scripts.ps1.ast import (
    extract_new_object,
    get_body,
    get_command_name,
    get_named_blocks,
    is_scriptblock_create,
    normalize_dotnet_type_name,
    string_value,
)
from refinery.lib.scripts.ps1.data import ENCODING_MAP, is_type
from refinery.lib.scripts.ps1.deobfuscation.helpers import extract_foreach_scriptblock
from refinery.lib.scripts.ps1.deobfuscation.substitution import (
    substitute,
    substitute_field,
    substitute_statement,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1TypeExpression,
    Ps1Variable,
)

_IEX_NAMES = frozenset({'iex', 'invoke-expression'})

_INVOKE_METHODS = frozenset({'invoke', 'invokereturnasis'})

_INVOKE_COMMAND_NAMES = frozenset({'invoke-command', 'icm'})

_REMOTING_PARAMS = frozenset({
    '-computername',
    '-cn',
    '-session',
    '-hostname',
    '-vmid',
    '-vmname',
    '-containerid',
})


def _try_extract_invoke_command_body(cmd: Ps1CommandInvocation) -> list | None:
    """
    If `cmd` is `Invoke-Command -ScriptBlock { ... }`, optionally with `-NoNewScope`, and its
    statements do the same in place of the call, return them.

    Any other argument refuses the call. A remoting parameter runs the block somewhere else, and an
    argument list or input object binds values the statements would no longer receive. Without
    `-NoNewScope` the block runs in a child scope, which only statements that
    `refinery.lib.scripts.ps1.analysis.blocks.runs_alike_in_the_scope_around_it` clears may leave.
    The block is not otherwise rewritten: it is written out in the source already, and the call
    around it hides nothing an analyst has to decode.

    An empty block resolves to no statements, which is not code to inline but a statement to delete,
    and deleting one is `refinery.lib.scripts.ps1.deobfuscation.removal`'s question rather than this
    pass's. It is reported as nothing resolved, the same answer `_try_parse` gives for a string that
    parses to an empty script.
    """
    name = get_command_name(cmd)
    if name is None or name.lower() not in _INVOKE_COMMAND_NAMES:
        return None
    if cmd.redirections:
        return None
    scriptblock: Ps1ScriptBlock | None = None
    own_scope = True
    index = 0
    args = cmd.arguments
    while index < len(args):
        arg = args[index]
        if not isinstance(arg, Ps1CommandArgument) or arg.kind != Ps1CommandArgumentKind.SWITCH:
            return None
        name_lower = arg.name.lower() if isinstance(arg.name, str) else ''
        if name_lower == '-nonewscope':
            own_scope = False
            index += 1
            continue
        if name_lower != '-scriptblock' or scriptblock is not None or index + 1 >= len(args):
            return None
        next_arg = args[index + 1]
        if isinstance(next_arg, Ps1CommandArgument):
            if next_arg.kind != Ps1CommandArgumentKind.POSITIONAL:
                return None
            next_arg = next_arg.value
        if not isinstance(next_arg, Ps1ScriptBlock):
            return None
        scriptblock = next_arg
        index += 2
    if scriptblock is None or not scriptblock.body:
        return None
    if not runs_alike_in_the_scope_around_it(scriptblock, own_scope):
        return None
    return list(scriptblock.body)


def _is_execution_context_invoke_script(expr: Ps1InvokeMember) -> bool:
    """
    Return `True` when `expr` matches `$ExecutionContext.InvokeCommand.InvokeScript(...)`.
    """
    return (
        expr.access == Ps1AccessKind.INSTANCE
        and isinstance(expr.member, str)
        and expr.member.lower() == 'invokescript'
        and len(expr.arguments) == 1
        and isinstance(mid := expr.object, Ps1MemberAccess)
        and mid.access == Ps1AccessKind.INSTANCE
        and isinstance(mid.member, str)
        and mid.member.lower() == 'invokecommand'
        and isinstance(root := mid.object, Ps1Variable)
        and root.name.lower() == 'executioncontext'
    )


def _is_command_switch(arg) -> bool:
    return (
        isinstance(arg, Ps1CommandArgument)
        and arg.kind == Ps1CommandArgumentKind.SWITCH
        and isinstance(arg.name, str)
        and arg.name.lower().startswith('-c')
    )


def _extract_iex_value(cmd: Ps1CommandInvocation) -> Expression | None:
    args = cmd.arguments
    if len(args) == 1:
        arg = args[0]
    elif len(args) == 2 and _is_command_switch(args[0]):
        arg = args[1]
    else:
        return None
    if isinstance(arg, Ps1CommandArgument):
        if arg.kind != Ps1CommandArgumentKind.POSITIONAL:
            return None
        return arg.value
    return arg


def _try_extract_scriptblock_create_arg(expr: Expression) -> Expression | None:
    """
    If `expr` is `[scriptblock]::Create(arg)` with a single argument, return that argument. The
    recognition is shared with the closed-world predicate through
    `refinery.lib.scripts.ps1.ast.is_scriptblock_create`; the arity check stays local, because
    inlining needs the one argument the predicate, which only classifies, does not.
    """
    if not is_scriptblock_create(expr):
        return None
    if len(expr.arguments) != 1:
        return None
    return expr.arguments[0]


def _resolve_encoding(expr: Expression) -> str | None:
    """
    Resolve `[Text.Encoding]::ASCII` and similar to a Python codec name.
    """
    if not isinstance(expr, Ps1MemberAccess):
        return None
    if expr.access != Ps1AccessKind.STATIC:
        return None
    if not isinstance(expr.object, Ps1TypeExpression):
        return None
    if not is_type(expr.object.name, 'System.Text.Encoding'):
        return None
    if not isinstance(expr.member, str):
        return None
    return ENCODING_MAP.get(expr.member.lower())


def _try_evaluate(
    expr: Expression,
    bindings: dict[str, str | bytes] | None = None,
    shadowed: frozenset[str] = frozenset(),
) -> str | bytes | None:
    """
    Recursively evaluate a .NET expression chain to `str` or `bytes`. Handles the pattern:

        [Convert]::FromBase64String(literal)
        -> [IO.MemoryStream]
        -> New-Object DeflateStream/GZipStream(stream, Decompress)
        -> New-Object StreamReader(stream, encoding)
        -> .ReadToEnd()

    Also handles pipelines of the form

        expr | %{ body } | %{ body }

    where the `ForEach-Object` stage receives the previous result via `$_`.

    *shadowed* is the whole-run set of command names the script has taken over. A pipeline stage
    reads it so a `%` the script has redefined runs its own body rather than the cmdlet, and the
    chain refuses rather than decode what 5.1 never decodes — see `extract_foreach_scriptblock`.
    """
    if isinstance(expr, Ps1StringLiteral):
        return expr.value

    if isinstance(expr, Ps1ParenExpression) and expr.expression is not None:
        return _try_evaluate(expr.expression, bindings, shadowed)

    if isinstance(expr, Ps1SubExpression):
        if len(expr.body) == 1:
            stmt = expr.body[0]
            if isinstance(stmt, Ps1ExpressionStatement) and stmt.expression is not None:
                return _try_evaluate(stmt.expression, bindings, shadowed)
        return None

    if isinstance(expr, Ps1Variable):
        if bindings and expr.name.lower() in bindings:
            return bindings[expr.name.lower()]
        return None

    if isinstance(expr, (Ps1ArrayLiteral, Ps1ArrayExpression)):
        return collect_byte_array(expr)

    if isinstance(expr, Ps1BinaryExpression) and expr.operator == '+':
        if expr.left is not None and expr.right is not None:
            left = _try_evaluate(expr.left, bindings, shadowed)
            right = _try_evaluate(expr.right, bindings, shadowed)
            if isinstance(left, str) and isinstance(right, str):
                return left + right

    if isinstance(expr, Ps1InvokeMember):
        if (
            expr.access == Ps1AccessKind.STATIC
            and isinstance(expr.object, Ps1TypeExpression)
            and is_type(expr.object.name, 'System.Convert')
            and isinstance(expr.member, str)
            and expr.member.lower() == 'frombase64string'
            and len(expr.arguments) == 1
        ):
            sv = string_value(expr.arguments[0])
            if sv is not None:
                try:
                    return base64.b64decode(sv)
                except Exception:
                    return None

        if (
            expr.access == Ps1AccessKind.INSTANCE
            and isinstance(expr.member, str)
            and expr.member.lower() == 'readtoend'
            and len(expr.arguments) == 0
            and expr.object is not None
        ):
            return _try_evaluate(expr.object, bindings, shadowed)

    if isinstance(expr, Ps1CastExpression) and expr.operand is not None:
        tn = normalize_dotnet_type_name(expr.type_name)
        if tn == 'io.memorystream':
            return _try_evaluate(expr.operand, bindings, shadowed)

    if isinstance(expr, Ps1CommandInvocation):
        result = extract_new_object(expr)
        if result is None:
            return None
        type_name, ctor_args = result
        tn = normalize_dotnet_type_name(type_name)

        if tn == 'io.memorystream' and len(ctor_args) >= 1:
            return _try_evaluate(ctor_args[0], bindings, shadowed)

        if tn == 'io.compression.deflatestream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings, shadowed)
            if isinstance(data, bytes):
                try:
                    return zlib.decompress(data, -15)
                except Exception:
                    return None

        if tn == 'io.compression.gzipstream' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings, shadowed)
            if isinstance(data, bytes):
                try:
                    return gzip.decompress(data)
                except Exception:
                    return None

        if tn == 'io.streamreader' and len(ctor_args) >= 1:
            data = _try_evaluate(ctor_args[0], bindings, shadowed)
            if not isinstance(data, bytes):
                return None
            codec = 'utf-8'
            if len(ctor_args) >= 2:
                resolved = _resolve_encoding(ctor_args[1])
                if resolved is not None:
                    codec = resolved
            try:
                return data.decode(codec)
            except Exception:
                return None

    if isinstance(expr, Ps1Pipeline):
        return _try_evaluate_pipeline(expr, bindings, shadowed)

    return None


def _try_evaluate_pipeline(
    node: Ps1Pipeline,
    bindings: dict[str, str | bytes] | None = None,
    shadowed: frozenset[str] = frozenset(),
) -> str | bytes | None:
    """
    Evaluate a pipeline `expr | %{ body } | %{ body }` by threading the result of each stage into
    the next via `$_` bindings. *shadowed* refuses a stage whose `ForEach-Object` the script has
    redefined — see `extract_foreach_scriptblock`.
    """
    if not node.elements:
        return None
    first = node.elements[0]
    if not isinstance(first, Ps1PipelineElement):
        return None
    if first.expression is None:
        return None
    value = _try_evaluate(first.expression, bindings, shadowed)
    if value is None:
        return None
    for elem in node.elements[1:]:
        if not isinstance(elem, Ps1PipelineElement):
            return None
        if elem.expression is None:
            return None
        script_block = extract_foreach_scriptblock(elem.expression, shadowed)
        if script_block is None:
            return None
        if len(script_block.body) != 1:
            return None
        stmt = script_block.body[0]
        if isinstance(stmt, Ps1ExpressionStatement):
            inner_expr = stmt.expression
        elif isinstance(stmt, Expression):
            inner_expr = stmt
        else:
            return None
        if inner_expr is None:
            return None
        stage_bindings: dict[str, str | bytes] = {**(bindings or {}), '_': value}
        value = _try_evaluate(inner_expr, stage_bindings, shadowed)
        if value is None:
            return None
    return value


def _resolve_to_string(expr: Expression, shadowed: frozenset[str] = frozenset()) -> str | None:
    """
    Try to resolve an expression to a string: first as a literal, then via evaluation. *shadowed* is
    the whole-run set of command names the script has taken over, threaded to `_try_evaluate` so a
    redefined `ForEach-Object` in a decode pipeline is not read as the cmdlet.
    """
    s = string_value(expr)
    if s is not None:
        return s
    result = _try_evaluate(expr, shadowed=shadowed)
    if isinstance(result, str):
        return result
    return None


def _try_extract_scriptblock_create_from_statement(expr: Expression) -> Expression | None:
    """
    Given a top-level expression, check whether it is one of:

    - `&([scriptblock]::Create(arg))`
    - `[scriptblock]::Create(arg).Invoke()`
    - `[scriptblock]::Create(arg).InvokeReturnAsIs()`
    - `$ExecutionContext.InvokeCommand.InvokeScript(arg)`

    Returns the `Create`/`InvokeScript` argument expression, or `None`. Each of these runs the code
    in a scope of its own, which is what `Ps1IexInlining._splice_or_call` keeps. A call that passes
    arguments is not matched: they bind to the code's parameters, which the inlined code would no
    longer have.
    """
    if isinstance(expr, Ps1CommandInvocation) and expr.invocation_operator == '&':
        if expr.arguments or expr.redirections:
            return None
        name = expr.name
        if isinstance(name, Ps1ParenExpression):
            name = name.expression
        if name is not None:
            return _try_extract_scriptblock_create_arg(name)
    if isinstance(expr, Ps1InvokeMember):
        if (
            expr.access == Ps1AccessKind.INSTANCE
            and isinstance(expr.member, str)
            and expr.member.lower() in _INVOKE_METHODS
            and expr.object is not None
            and not expr.arguments
        ):
            return _try_extract_scriptblock_create_arg(expr.object)
        if _is_execution_context_invoke_script(expr):
            return expr.arguments[0]
    return None


class Ps1IexInlining(Transformer):
    """
    Replaces the following patterns with the parsed statements from the
    reflectively loaded code:

    - `'CODE' | Invoke-Expression`
    - `Invoke-Expression 'CODE'`
    - `[scriptblock]::Create('CODE')`
    """

    def visit(self, node):
        self._inline_statements(node)
        self._inline_expressions(node)
        return None

    def _shadowed_at(self, node) -> frozenset[str]:
        """
        The whole-run set of command names the script has taken over, read fresh at *node* rather
        than snapshotted once for the pass. An `Invoke-Expression` this pass has already inlined can
        install a `function ForEach-Object`, and a decode pipeline folded later in the same pass
        must see it or it inlines what 5.1 never runs — the folding and emulator recognizers read
        the set at the fold point for this reason too. See `extract_foreach_scriptblock`.
        """
        return model_cache(self, node).closed_world.shadowed_names

    def _inline_statements(self, node):
        for container in list(node.walk()):
            body = get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                statement = body[i]
                parsed = self._try_resolve_inline(statement)
                installed = None
                if parsed is not None:
                    installed = self._install(container, statement, parsed)
                if installed is None:
                    i += 1
                    continue
                self.mark_changed()
                i += installed

    @staticmethod
    def _install(container, stmt, parsed: list) -> int | None:
        """
        Put the parsed code where `stmt` stands and report how many statements now sit in its place,
        or `None` when nothing was installed.

        When the statement assigns the (piped) `Invoke-Expression` result to a target, the
        assignment is kept and the inlined expression bound to it. Resolved code that is not a
        single expression cannot be bound to one, so the statement is left untouched rather than the
        assignment target silently discarded.

        A refused substitution is reported the same way as nothing to install, and the caller must
        not advance the mutation counter for it:
        `refinery.lib.scripts.ps1.deobfuscation.deobfuscate` runs its passes to a fixpoint, so a
        pass that reports a change it did not make never converges.
        """
        if (
            isinstance(stmt, Ps1ExpressionStatement)
            and isinstance(assignment := stmt.expression, Ps1AssignmentExpression)
        ):
            if len(parsed) != 1:
                return None
            inlined = parsed[0]
            if not isinstance(inlined, Ps1ExpressionStatement) or inlined.expression is None:
                return None
            if not substitute_field(assignment, 'value', inlined.expression):
                return None
            return 1
        if not substitute_statement(container, stmt, parsed):
            return None
        return len(parsed)

    def _try_resolve_inline(self, stmt) -> list | None:
        shadowed = self._shadowed_at(stmt)
        code = self._try_extract_iex_string(stmt, shadowed)
        if code is None:
            code = self._try_extract_piped_iex_string(stmt, shadowed)
        if code is not None:
            return self._try_parse(code)
        code = self._try_extract_scriptblock_create_string(stmt, shadowed)
        if code is not None:
            return self._splice_or_call(code)
        return self._try_extract_invoke_command(stmt)

    def _inline_expressions(self, node):
        for expr in list(node.walk()):
            if isinstance(expr, Ps1CommandInvocation):
                if isinstance(expr.parent, Ps1ExpressionStatement):
                    continue
                replacement = self._try_inline_expression(expr)
            elif isinstance(expr, Ps1InvokeMember):
                if isinstance(expr.parent, Ps1ExpressionStatement):
                    continue
                replacement = self._try_inline_scriptblock_create_expression(expr)
            else:
                continue
            if replacement is None:
                continue
            if not substitute(expr, replacement):
                continue
            self.mark_changed()

    def _try_inline_expression(self, node: Ps1CommandInvocation) -> Expression | None:
        sb_arg = _try_extract_scriptblock_create_from_statement(node)
        if sb_arg is not None:
            code = _resolve_to_string(sb_arg, self._shadowed_at(node))
            parsed = None if code is None else self._try_parse_in_a_scope_of_its_own(code)
        else:
            name = get_command_name(node)
            if name is None or name.lower() not in _IEX_NAMES:
                return None
            val = _extract_iex_value(node)
            if val is None:
                return None
            code = _resolve_to_string(val, self._shadowed_at(node))
            parsed = None if code is None else self._try_parse(code)
        if parsed is None or len(parsed) != 1:
            return None
        stmt = parsed[0]
        if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
            return None
        return stmt.expression

    def _try_inline_scriptblock_create_expression(self, node: Ps1InvokeMember) -> Expression | None:
        """
        Handles:
        - `[scriptblock]::Create(expr).Invoke()`
        - `$ExecutionContext.InvokeCommand.InvokeScript(expr)`
        in expression position.
        """
        if _is_execution_context_invoke_script(node):
            sb_arg = node.arguments[0]
        elif (
            node.access == Ps1AccessKind.INSTANCE
            and isinstance(node.member, str)
            and node.member.lower() in _INVOKE_METHODS
            and node.object is not None
        ):
            sb_arg = _try_extract_scriptblock_create_arg(node.object)
        else:
            return None
        if sb_arg is None:
            return None
        code = _resolve_to_string(sb_arg, self._shadowed_at(node))
        if code is None:
            return None
        parsed = self._try_parse_in_a_scope_of_its_own(code)
        if parsed is None or len(parsed) != 1:
            return None
        stmt = parsed[0]
        if not isinstance(stmt, Ps1ExpressionStatement) or stmt.expression is None:
            return None
        return stmt.expression

    @staticmethod
    def _is_bare_iex(cmd) -> bool:
        if not isinstance(cmd, Ps1CommandInvocation):
            return False
        name = get_command_name(cmd)
        if name is None or name.lower() not in _IEX_NAMES:
            return False
        if len(cmd.arguments) == 0:
            return True
        return len(cmd.arguments) == 1 and _is_command_switch(cmd.arguments[0])

    @staticmethod
    def _try_extract_iex_string(stmt, shadowed: frozenset[str] = frozenset()) -> str | None:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        cmd = stmt.expression
        if not isinstance(cmd, Ps1CommandInvocation):
            return None
        name = get_command_name(cmd)
        if name is None or name.lower() not in _IEX_NAMES:
            return None
        val = _extract_iex_value(cmd)
        if val is None:
            return None
        return _resolve_to_string(val, shadowed)

    @classmethod
    def _try_extract_piped_iex_string(
        cls, stmt, shadowed: frozenset[str] = frozenset()
    ) -> str | None:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        pipeline = stmt.expression
        if isinstance(pipeline, Ps1AssignmentExpression):
            pipeline = pipeline.value
        if not isinstance(pipeline, Ps1Pipeline):
            return None
        if len(pipeline.elements) < 2:
            return None
        last = pipeline.elements[-1]
        if not cls._is_bare_iex(last.expression):
            return None
        if len(pipeline.elements) != 2:
            return None
        source = pipeline.elements[0].expression
        if source is None:
            return None
        return _resolve_to_string(source, shadowed)

    @staticmethod
    def _try_extract_scriptblock_create_string(
        stmt, shadowed: frozenset[str] = frozenset()
    ) -> str | None:
        """
        Match `&([scriptblock]::Create(expr))` and
        `[scriptblock]::Create(expr).Invoke()` at the statement level.
        """
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        expr = stmt.expression
        if expr is None:
            return None
        sb_arg = _try_extract_scriptblock_create_from_statement(expr)
        if sb_arg is None:
            return None
        return _resolve_to_string(sb_arg, shadowed)

    @staticmethod
    def _try_extract_invoke_command(stmt) -> list | None:
        if not isinstance(stmt, Ps1ExpressionStatement):
            return None
        cmd = stmt.expression
        if not isinstance(cmd, Ps1CommandInvocation):
            return None
        return _try_extract_invoke_command_body(cmd)

    @staticmethod
    def _try_parse_script(code: str) -> Ps1Script | None:
        try:
            from refinery.lib.scripts.ps1.parser import Ps1Parser
            return Ps1Parser(code).parse()
        except Exception:
            return None

    @classmethod
    def _try_parse(cls, code: str) -> list | None:
        parsed = cls._try_parse_script(code)
        if parsed is None or not parsed.body:
            return None
        return list(parsed.body)

    @classmethod
    def _try_parse_in_a_scope_of_its_own(cls, code: str) -> list | None:
        """
        The statements of code that runs in a scope of its own, where they do the same in place of
        the call that runs it; `None` where they do not, or where the code does not parse to any.
        """
        parsed = cls._try_parse_script(code)
        if parsed is None or not parsed.body or not runs_alike_in_the_scope_around_it(parsed):
            return None
        return list(parsed.body)

    @classmethod
    def _splice_or_call(cls, code: str) -> list | None:
        """
        What a statement that runs `code` in a scope of its own becomes: the statements of the code
        where they do the same in place of the call, and otherwise a call of the code as a block,
        `& { ... }`, which keeps the scope and still shows what runs.
        """
        parsed = cls._try_parse_script(code)
        if parsed is None or not (parsed.body or get_named_blocks(parsed)):
            return None
        if parsed.body and runs_alike_in_the_scope_around_it(parsed):
            return list(parsed.body)
        block = Ps1ScriptBlock(
            param_block=parsed.param_block,
            begin_block=parsed.begin_block,
            process_block=parsed.process_block,
            end_block=parsed.end_block,
            dynamicparam_block=parsed.dynamicparam_block,
            body=list(parsed.body),
        )
        call = Ps1CommandInvocation(name=block, invocation_operator='&')
        return [Ps1ExpressionStatement(expression=call)]
