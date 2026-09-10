"""
AST-to-source synthesizer for PowerShell.
"""
from __future__ import annotations

import contextlib
import io

from collections.abc import Callable

from refinery.lib.scripts import Block, Node, Synthesizer
from refinery.lib.scripts.ps1 import precedence
from refinery.lib.scripts.ps1.lexer import Ps1LexerMode, reads_as_one_numeral
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1Attribute,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CastExpression,
    Ps1ClassDefinition,
    Ps1Code,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoLoop,
    Ps1EnumDefinition,
    Ps1EnumMember,
    Ps1ErrorNode,
    Ps1Exit,
    Ps1ExitStatement,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FileRedirection,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1InputRedirection,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1Jump,
    Ps1MemberAccess,
    Ps1MemberModifier,
    Ps1MergingRedirection,
    Ps1MethodMember,
    Ps1ParamBlock,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1PropertyMember,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1RedirectionStream,
    Ps1ReturnStatement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)
from refinery.lib.scripts.ps1.token import BACKTICK_ENCODE, KEYWORD_SPELLING


def _fuses_with_a_sign(spelling: str) -> bool:
    """
    Whether a `+` or `-` written straight against `spelling` would join with it into one token.
    A numeral does: `- 5` printed as `-5` is one Int32 literal where the source had unary minus over
    an Int32, and the two differ at the width boundary — `- 2147483648` is an Int64 and
    `-2147483648` an Int32. A spelling that already begins with a sign fuses the other way, since
    `- -5` printed as `--5` re-lexes as the decrement operator.

    The question is asked of the text rather than of the node, because the leading character is what
    decides and it can belong to a node several levels down: `- 1kb.GetType()` is a member of one
    kilobyte, and printed as `-1kb.GetType()` it becomes a member of *minus* one kilobyte instead.
    """
    head = spelling[:1]
    if head in ('+', '-'):
        return True
    if head == '.':
        return spelling[1:2].isdigit()
    return head.isdigit()


def _numeral_spelling(node: Expression) -> str | None:
    """
    How a numeral is written, or `None` for a node that is not one. This is the only kind of leaf
    whose spelling can be swallowed by what stands beside it, because it is the only one that ends
    where the next character says it does rather than at a delimiter of its own.
    """
    if isinstance(node, (Ps1IntegerLiteral, Ps1RealLiteral)):
        return node.raw
    return None


class Ps1Synthesizer(Synthesizer):
    """
    Three things decide how a node is written, and all three are properties of the slot it goes into
    rather than of the node: how tightly the slot binds, which decides whether a bracket is needed
    (`refinery.lib.scripts.ps1.precedence`); whether the slot reads a bare word as a value, which
    decides how a leaf is spelled (`_word_slot`); and how the text will be lexed back, which decides
    where a spelling runs on into what touches it (`_mode`).

    A word with no quotes means a value where a command's name and arguments are read, and begins a
    command everywhere else. So `foo a, b` may keep its words while `foo (a, b)` may not — the
    bracket makes `a` a command name, and 5.1 then rejects the whole line. The parser's `raw` is
    only true of the slot it was read from, which is why replaying it is not enough.

    The arming is spent on one node, since only the leaf in the slot is spelled by it; the mode holds
    until a delimiter is written, since 5.1 lexes a command's arguments in command mode until one
    opens a new slot. `Write-Output $t.GetType()` is where they part: the member access takes the
    arming, and the numeral several levels under it is still in the argument's text.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._word_slot_ahead = False
        self._word_slot = False
        self._mode = Ps1LexerMode.EXPRESSION

    def visit(self, node: Node) -> Node | None:
        """
        Take the arming set by the slot, so that it applies to this node and no other. A slot that
        arms nothing yields the quoted spelling, which is the reading that is valid everywhere;
        forgetting to arm one therefore costs a pair of quotes rather than the meaning of a script.
        """
        self._word_slot, self._word_slot_ahead = self._word_slot_ahead, False
        return super().visit(node)

    @contextlib.contextmanager
    def _reading(self, mode: Ps1LexerMode):
        """
        Write what follows as text that will be lexed in `mode`, and put back the mode that was
        running when it is done.
        """
        saved, self._mode = self._mode, mode
        try:
            yield
        finally:
            self._mode = saved

    def _emit_word(self, node: Expression, minimum: int):
        """
        Write `node` into a slot that reads a bare word as a value, which is the slot 5.1 lexes in
        command mode.
        """
        self._word_slot_ahead = True
        with self._reading(Ps1LexerMode.ARGUMENT):
            self._emit_operand(node, minimum)

    def _emit_block(self, block: Block):
        self._write('{')
        self._depth += 1
        for stmt in block.body:
            self._newline()
            with self._reading(Ps1LexerMode.EXPRESSION):
                self.visit(stmt)
        self._depth -= 1
        if block.body:
            self._newline()
        self._write('}')

    def _emit_statement_list(self, stmts: list):
        for i, stmt in enumerate(stmts):
            if i > 0:
                self._newline()
            with self._reading(Ps1LexerMode.EXPRESSION):
                self.visit(stmt)

    @staticmethod
    def _variable_scope_prefix(node: Ps1Variable) -> str:
        if node.scope == Ps1ScopeModifier.NONE:
            return ''
        if node.scope == Ps1ScopeModifier.DRIVE:
            return F'{node.drive}:'
        return F'{node.scope.value}:'

    def visit_Ps1Variable(self, node: Ps1Variable):
        prefix = '@' if node.splatted else '$'
        body = F'{self._variable_scope_prefix(node)}{node.name}'
        if node.braced:
            body = F'{{{body}}}'
        self._write(F'{prefix}{body}')

    def visit_Ps1IntegerLiteral(self, node: Ps1IntegerLiteral):
        """
        A numeral is written exactly as it is spelled, and a numeral the source spelled is never
        re-spelled. Where it stands in a command argument the text itself is passed on: the
        receiving command reads back what was written — `Write-Host 1.10` prints `1.10` and
        `notepad.exe 0x10` receives `0x10` rather than `16`. Holding only `raw` is what makes that
        true by construction, and a pass that normalized one would break it here without anything
        noticing.
        """
        self._write(node.raw)

    def visit_Ps1RealLiteral(self, node: Ps1RealLiteral):
        self._write(node.raw)

    def visit_Ps1StringLiteral(self, node: Ps1StringLiteral):
        if '\n' in node.raw:
            self._write(F'"{self._escape_for_dq(node.value)}"')
        elif node.is_bare_word and not self._word_slot:
            self._write(F"'{self._escape_for_sq(node.value)}'")
        else:
            self._write(node.raw)

    def visit_Ps1ExpandableString(self, node: Ps1ExpandableString):
        self._emit_expandable_parts(node.parts)

    def _emit_expandable_parts(self, parts):
        self._write('"')
        for part in parts:
            if isinstance(part, Ps1StringLiteral):
                self._write(self._escape_for_dq(part.value))
            elif isinstance(part, Ps1Variable):
                self._emit_variable_in_dq(part)
            else:
                self.visit(part)
        self._write('"')

    def _emit_variable_in_dq(self, node: Ps1Variable):
        prefix = '@' if node.splatted else '$'
        self._write(F'{prefix}{{{self._variable_scope_prefix(node)}{node.name}}}')

    @staticmethod
    def _escape_for_sq(value: str) -> str:
        return value.replace("'", "''")

    @staticmethod
    def _escape_for_dq(value: str) -> str:
        for c in '`"$':
            value = value.replace(c, F'`{c}')
        for ch, esc in BACKTICK_ENCODE.items():
            value = value.replace(ch, esc)
        return value

    def visit_Ps1HereString(self, node: Ps1HereString):
        if '\n' in node.value:
            self._write(F'"{self._escape_for_dq(node.value)}"')
        else:
            self._write(node.raw)

    def visit_Ps1ExpandableHereString(self, node: Ps1ExpandableHereString):
        # Emit from the (possibly transform-rewritten) parts rather than the stale `raw`, otherwise
        # an inlined variable/constant would be lost while its source assignment is removed. A
        # double-quoted expandable string is semantically equivalent to the here-string.
        self._emit_expandable_parts(node.parts)

    def _emit_operand(self, node: Expression, minimum: int):
        """
        Write `node` into a slot that binds at least as tightly as `minimum`, bracketing it when it
        does not. Every slot that can absorb what is printed beside it goes through here, naming
        what it requires; a tree built by a pass carries no parentheses of its own, so this is the
        only thing standing between `Binary(Binary(1, '+', 2), '*', 3)` and `1 + 2 * 3`.
        """
        if precedence.needs_brackets(node, minimum):
            self._emit_bracketed(node)
        else:
            self.visit(node)

    def _emit_bracketed(self, node: Expression):
        """
        Write `node` inside a bracket. What stands inside one is read as a pipeline, so the slot the
        bracket creates is never one that reads a bare word as a value, whatever the slot outside it
        was, and the text in it is lexed as an expression however it got here.
        """
        self._word_slot_ahead = False
        self._write('(')
        with self._reading(Ps1LexerMode.EXPRESSION):
            self.visit(node)
        self._write(')')

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        # The left spine is walked rather than recursed through, because a folded concatenation is
        # thousands of operators deep and recursion would not reach the end of one. Walking stops
        # where a left operand binds more loosely than its parent, since that one needs a bracket
        # and so is not part of the same flat chain.
        spine: list[tuple[str, Expression | None, int]] = []
        current = node
        while True:
            power = precedence.of_operator(current.operator)
            spine.append((current.operator, current.right, power))
            left = current.left
            if (
                isinstance(left, Ps1BinaryExpression)
                and precedence.of_operator(left.operator) >= power
            ):
                current = left
                continue
            break
        if (head := current.left) is not None:
            self._emit_operand(head, spine[-1][2])
        for operator, right, power in reversed(spine):
            self._write(F' {operator} ')
            if right is not None:
                self._emit_operand(right, power + 1)

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        operand = node.operand
        if not node.prefix:
            if operand is not None:
                self._emit_operand(operand, precedence.UNARY)
            self._write(node.operator)
            return
        spelling = '' if operand is None else self._operand_to_string(operand, precedence.UNARY)
        self._write(node.operator)
        if node.operator.startswith('-') and len(node.operator) > 1:
            self._write(' ')
        elif node.operator in ('+', '-') and _fuses_with_a_sign(spelling):
            self._write(' ')
        self._write(spelling)

    def visit_Ps1TypeExpression(self, node: Ps1TypeExpression):
        self._write(F'[{node.name}]')

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self._write(F'[{node.type_name}]')
        if node.operand:
            self._emit_operand(node.operand, precedence.UNARY)

    def _emit_receiver(self, node: Expression, access: str):
        """
        Write `node` as the thing `access` reads from. The receiver has to be a primary expression:
        `.` and `::` bind tighter than anything written with an operator, so `(Get-Variable Y).Tls`
        printed bare would read the member off the last argument of the command rather than off its
        result.

        A numeral needs more than that, because it does not end where the tree says it does: `3` in
        front of `.ToString` is the one word `3.ToString`, and in front of `[0]` or `::MaxValue`
        every numeral is, since neither bracket nor colon ends one. The lexer is asked, so that what
        is written here and what reads it back are the same rule. No space is ever written before
        the access instead: `(3) .ToString()` is a parse error, measured.
        """
        raw = _numeral_spelling(node)
        if raw is not None and not reads_as_one_numeral(raw, access, self._mode):
            self._emit_bracketed(node)
        else:
            self._emit_operand(node, precedence.ATOM)

    def _emit_member_prefix(self, node: Ps1MemberAccess | Ps1InvokeMember):
        if node.object:
            self._emit_receiver(node.object, node.access.value)
        self._write(node.access.value)
        if isinstance(node.member, Expression):
            self.visit(node.member)
        else:
            self._write(str(node.member))

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self._emit_member_prefix(node)

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        if node.object:
            self._emit_receiver(node.object, '[')
        self._write('[')
        if node.index:
            with self._reading(Ps1LexerMode.EXPRESSION):
                self.visit(node.index)
        self._write(']')

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self._emit_member_prefix(node)
        self._write('(')
        with self._reading(Ps1LexerMode.EXPRESSION):
            for i, arg in enumerate(node.arguments):
                if i > 0:
                    self._write(', ')
                if precedence.needs_brackets_between_delimiters(arg):
                    self._write('(')
                    self.visit(arg)
                    self._write(')')
                else:
                    self.visit(arg)
        self._write(')')

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        if node.invocation_operator:
            self._write(node.invocation_operator)
            self._write(' ')
        if node.name:
            # `& 'i' + 'ex'` invokes `i` and then concatenates, so a computed command name needs
            # brackets for the invocation operator to reach the whole expression.
            self._emit_word(node.name, precedence.ATOM)
        for arg in node.arguments:
            self._write(' ')
            self.visit(arg)
        for redir in node.redirections:
            self._write(' ')
            self.visit(redir)

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        if node.kind == Ps1CommandArgumentKind.SWITCH:
            self._write(node.name)
        elif node.kind == Ps1CommandArgumentKind.NAMED:
            self._write(F'{node.name}:')
            if node.value:
                self._emit_argument_value(node.value)
        elif node.kind == Ps1CommandArgumentKind.POSITIONAL:
            if node.value:
                self._emit_argument_value(node.value)

    def _emit_argument_value(self, value: Expression):
        """
        An argument is read back by the rule that reads one bare, which reaches nothing an operator
        holds together: an operator would reach across the arguments beside this one, a range
        re-lexes as a single bare word in argument mode, and a command swallows the rest of the line.
        The comma is bracketed too, though it binds tighter than all of them, because it separates
        one argument from the next.

        Two spellings survive the precedence scale and are still read as something else here, and
        both are bracketed. A numeral whose spelling this slot does not end where the tree does is
        one: `Write-Output -1` passes the String `-1` where `Write-Output (-1)` passes an Int32, and
        `f +1` and `f -0.0` are words the same way. A cast is the other, measured: `f [byte] 5` is
        the one word `[byte]5`.

        Neither spelling can reach here from a source — a dash or a bracket in an argument begins a
        word — so a numeral or a cast standing in this slot is one a pass put here, and bracketing it
        is what makes it mean what the pass meant.
        """
        raw = _numeral_spelling(value)
        misread = isinstance(value, (Ps1CastExpression, Ps1TypeExpression)) or (
            raw is not None and not reads_as_one_numeral(raw, '', Ps1LexerMode.ARGUMENT)
        )
        if misread:
            self._emit_bracketed(value)
        else:
            self._emit_word(value, precedence.COMMA + 1)

    def visit_Ps1AssignmentExpression(self, node: Ps1AssignmentExpression):
        if node.target:
            # The target is delimited by the operator that follows it, and a multi-assignment
            # writes through a comma-built list of targets, so this slot brackets nothing either.
            self.visit(node.target)
        self._write(F' {node.operator} ')
        if (value := node.value) is not None:
            # Nothing is bracketed here. The right side of an assignment runs to the end of the
            # statement, so there is nothing beside it for a command or an operator to reach into;
            # an assignment standing somewhere tighter is bracketed by that slot instead.
            self.visit(value)

    def visit_Ps1ArrayLiteral(self, node: Ps1ArrayLiteral):
        # A one-element array is written with the leading unary comma that builds it. Printing the
        # element alone yields the element, not an array of it, which is why
        # `New-Object IO.MemoryStream(,$bytes)` must keep its comma: without it the constructor is
        # handed the buffer's elements as separate arguments and throws.
        if len(node.elements) == 1:
            self._write(',')
        # An array standing where bare words are read as values holds its elements in that same
        # slot: `foo a, b` passes two words. Bracket the array and they are in a pipeline instead,
        # where the first would become a command name, so the arming is not passed on.
        word_slot = self._word_slot
        for i, elem in enumerate(node.elements):
            if i > 0:
                self._write(', ')
            self._word_slot_ahead = word_slot
            self._emit_operand(elem, precedence.COMMA + 1)

    def visit_Ps1ArrayExpression(self, node: Ps1ArrayExpression):
        self._write('@(')
        self._emit_statement_list(node.body)
        self._write(')')

    def visit_Ps1HashLiteral(self, node: Ps1HashLiteral):
        self._write('@{')
        if node.pairs:
            self._depth += 1
            for key, value in node.pairs:
                self._newline()
                # A key is read as a word rather than as a command: `@{ Name = 1 }` is a hash of
                # one entry, not a call to `Name`.
                self._emit_word(key, precedence.COMMA + 1)
                self._write(' = ')
                with self._reading(Ps1LexerMode.EXPRESSION):
                    self.visit(value)
            self._depth -= 1
            self._newline()
        self._write('}')

    def visit_Ps1SubExpression(self, node: Ps1SubExpression):
        self._write('$(')
        self._emit_statement_list(node.body)
        self._write(')')

    def visit_Ps1ParenExpression(self, node: Ps1ParenExpression):
        self._write('(')
        if node.expression:
            with self._reading(Ps1LexerMode.EXPRESSION):
                self.visit(node.expression)
        self._write(')')

    def _emit_script_body(self, node: Ps1Code, *, newline_after: bool):
        has_named = (
            node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_named:
            for keyword, block in (
                ('begin', node.begin_block),
                ('process', node.process_block),
                ('end', node.end_block),
                ('dynamicparam', node.dynamicparam_block),
            ):
                if block:
                    if not newline_after:
                        self._newline()
                    self._write(F'{keyword} ')
                    self._emit_block(block)
                    if newline_after:
                        self._newline()
        else:
            if newline_after:
                self._emit_statement_list(node.body)
            else:
                for stmt in node.body:
                    self._newline()
                    self.visit(stmt)

    def visit_Ps1ScriptBlock(self, node: Ps1ScriptBlock):
        self._write('{')
        self._depth += 1
        if node.param_block:
            self._newline()
            self.visit(node.param_block)
        self._emit_script_body(node, newline_after=False)
        self._depth -= 1
        has_content = (
            node.body or node.param_block
            or node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_content:
            self._newline()
        self._write('}')

    def visit_Ps1RangeExpression(self, node: Ps1RangeExpression):
        if node.start:
            self._emit_operand(node.start, precedence.RANGE)
        self._write('..')
        if node.end:
            self._emit_operand(node.end, precedence.RANGE + 1)

    def _captured(self, emit: Callable[[], object]) -> str:
        """
        What `emit` writes, handed back instead of written. The emission itself is the real one and
        runs once, so whatever it does to the arming a slot set is done exactly as it would be.
        """
        saved = self._parts
        self._parts = io.StringIO()
        try:
            emit()
            return self._parts.getvalue()
        finally:
            self._parts = saved

    def _render_to_string(self, node: Node) -> str:
        return self._captured(lambda: self.visit(node))

    def _operand_to_string(self, node: Expression, minimum: int) -> str:
        """
        What `_emit_operand` would write for `node`, including any bracket it decides on. A slot
        that has to know what its content begins with cannot ask the tree: the answer is the first
        character of a rendering, which no single node holds.
        """
        return self._captured(lambda: self._emit_operand(node, minimum))

    def visit_Ps1Attribute(self, node: Ps1Attribute):
        # The argument list is written even when it is empty, because it is what distinguishes an
        # attribute from a type constraint: `[CmdletBinding]` reads back as the type `CmdletBinding`
        # and is then dropped, and `class C { [ValidateNotNull()] [int] $P }` loses the `[int]` to
        # the same confusion.
        self._write(F'[{node.name}(')
        items: list[str] = []
        for arg in node.positional_args:
            items.append(self._render_to_string(arg))
        for key, val in node.named_args:
            items.append(F'{key}={self._render_to_string(val)}')
        self._write(', '.join(items))
        self._write(')]')

    def visit_Ps1ParameterDeclaration(self, node: Ps1ParameterDeclaration):
        for attr in node.attributes:
            self.visit(attr)
        if node.variable:
            self.visit(node.variable)
        if node.default_value:
            self._write(' = ')
            # The commas of the parameter list delimit this slot exactly as a command's arguments
            # delimit theirs, so a default that is a command or is built with a comma needs to say
            # where it ends.
            self._emit_operand(node.default_value, precedence.COMMA + 1)

    def visit_Ps1ParamBlock(self, node: Ps1ParamBlock):
        for attr in node.attributes:
            self.visit(attr)
            self._newline()
        self._write(KEYWORD_SPELLING.get('param', 'param'))
        self._write('(')
        for i, param in enumerate(node.parameters):
            if i > 0:
                self._write(', ')
            self.visit(param)
        self._write(')')

    def _emit_redirection_stream(self, stream: Ps1RedirectionStream) -> str:
        if stream == Ps1RedirectionStream.OUTPUT:
            return ''
        if stream == Ps1RedirectionStream.ALL:
            return '*'
        return str(stream.value)

    def visit_Ps1FileRedirection(self, node: Ps1FileRedirection):
        prefix = self._emit_redirection_stream(node.stream)
        op = '>>' if node.append else '>'
        self._write(F'{prefix}{op}')
        if node.target:
            # A redirection names its file the way a command names an argument, so a path may
            # stand there without quotes.
            self._write(' ')
            self._emit_word(node.target, precedence.COMMA + 1)

    def visit_Ps1InputRedirection(self, node: Ps1InputRedirection):
        self._write('<')
        if node.source:
            self._write(' ')
            self._emit_word(node.source, precedence.COMMA + 1)

    def visit_Ps1MergingRedirection(self, node: Ps1MergingRedirection):
        # A file redirection of the output stream is written bare, but a merge names its source
        # even then: dropping the `1` from `1>&2` produces `>&2`, which is a file redirection to
        # the target `&2` and does not read back as the statement that was written.
        if node.from_stream is Ps1RedirectionStream.ALL:
            prefix = '*'
        else:
            prefix = str(node.from_stream.value)
        self._write(F'{prefix}>&{node.to_stream.value}')

    def visit_Ps1PipelineElement(self, node: Ps1PipelineElement):
        if node.expression:
            self.visit(node.expression)
        for redir in node.redirections:
            self._write(' ')
            self.visit(redir)

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        for i, elem in enumerate(node.elements):
            if i > 0:
                self._write(' | ')
            self.visit(elem)

    def visit_Ps1ExpressionStatement(self, node: Ps1ExpressionStatement):
        if node.expression:
            self.visit(node.expression)

    def visit_Ps1IfStatement(self, node: Ps1IfStatement):
        for i, (cond, body) in enumerate(node.clauses):
            if i == 0:
                self._write('if (')
            else:
                self._write(' elseif (')
            if cond:
                self.visit(cond)
            self._write(') ')
            self._emit_block(body)
        if node.else_block:
            self._write(' else ')
            self._emit_block(node.else_block)

    def visit_Ps1WhileLoop(self, node: Ps1WhileLoop):
        if node.label:
            self._write(F'{node.label} ')
        self._write('while (')
        if node.condition:
            self.visit(node.condition)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1DoLoop(self, node: Ps1DoLoop):
        if node.label:
            self._write(F'{node.label} ')
        self._write('do ')
        if node.body:
            self._emit_block(node.body)
        keyword = 'until' if node.is_until else 'while'
        self._write(F' {keyword} (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')

    def visit_Ps1ForLoop(self, node: Ps1ForLoop):
        if node.label:
            self._write(F'{node.label} ')
        self._write('for (')
        if node.initializer:
            self.visit(node.initializer)
        self._write('; ')
        if node.condition:
            self.visit(node.condition)
        self._write('; ')
        if node.iterator:
            self.visit(node.iterator)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1ForEachLoop(self, node: Ps1ForEachLoop):
        if node.label:
            self._write(F'{node.label} ')
        self._write('foreach ')
        if node.parallel:
            self._write('-Parallel ')
        self._write('(')
        if node.variable:
            self.visit(node.variable)
        self._write(' in ')
        if node.iterable:
            self.visit(node.iterable)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1SwitchStatement(self, node: Ps1SwitchStatement):
        if node.label:
            self._write(F'{node.label} ')
        self._write('switch ')
        if node.regex:
            self._write('-Regex ')
        if node.wildcard:
            self._write('-Wildcard ')
        if node.exact:
            self._write('-Exact ')
        if node.case_sensitive:
            self._write('-CaseSensitive ')
        if node.file:
            self._write('-File ')
            if node.value:
                self.visit(node.value)
            self._write(' {')
        else:
            self._write('(')
            if node.value:
                self.visit(node.value)
            self._write(') {')
        self._depth += 1
        for cond, body in node.clauses:
            self._newline()
            if cond is None:
                self._write('default ')
            else:
                # A clause is matched against a pattern, so a bare word here is the string it
                # spells rather than a command to run.
                self._emit_word(cond, precedence.COMMA + 1)
                self._write(' ')
            self._emit_block(body)
        self._depth -= 1
        self._newline()
        self._write('}')

    def visit_Ps1TryCatchFinally(self, node: Ps1TryCatchFinally):
        self._write('try ')
        if node.try_block:
            self._emit_block(node.try_block)
        for clause in node.catch_clauses:
            self._write(' catch')
            if clause.types:
                self._write(' ')
                self._write(', '.join(F'[{t}]' for t in clause.types))
            self._write(' ')
            if clause.body:
                self._emit_block(clause.body)
        if node.finally_block:
            self._write(' finally ')
            self._emit_block(node.finally_block)

    def visit_Ps1TrapStatement(self, node: Ps1TrapStatement):
        self._write('trap ')
        if node.type_name:
            self._write(F'[{node.type_name}] ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1FunctionDefinition(self, node: Ps1FunctionDefinition):
        kw = 'filter' if node.is_filter else 'function'
        self._write(F'{kw} {node.name} ')
        if node.body:
            self.visit(node.body)

    def _emit_member_modifiers(self, modifiers: Ps1MemberModifier):
        if Ps1MemberModifier.STATIC in modifiers:
            self._write('static ')
        if Ps1MemberModifier.HIDDEN in modifiers:
            self._write('hidden ')

    def visit_Ps1PropertyMember(self, node: Ps1PropertyMember):
        for attr in node.attributes:
            self.visit(attr)
        self._emit_member_modifiers(node.modifiers)
        if node.type_constraint:
            self.visit(node.type_constraint)
        if node.variable:
            self.visit(node.variable)
        if node.initial_value:
            self._write(' = ')
            self.visit(node.initial_value)

    def visit_Ps1MethodMember(self, node: Ps1MethodMember):
        for attr in node.attributes:
            self.visit(attr)
        self._emit_member_modifiers(node.modifiers)
        if node.return_type:
            self.visit(node.return_type)
            self._write(' ')
        if node.definition:
            funcdef = node.definition
            self._write(F'{funcdef.name}(')
            if funcdef.body and funcdef.body.param_block:
                for i, param in enumerate(funcdef.body.param_block.parameters):
                    if i > 0:
                        self._write(', ')
                    self.visit(param)
            self._write(') {')
            self._depth += 1
            if funcdef.body:
                self._emit_script_body(funcdef.body, newline_after=False)
            self._depth -= 1
            has_content = funcdef.body and (
                funcdef.body.body
                or funcdef.body.begin_block
                or funcdef.body.process_block
                or funcdef.body.end_block
                or funcdef.body.dynamicparam_block
            )
            if has_content:
                self._newline()
            self._write('}')

    def visit_Ps1ClassDefinition(self, node: Ps1ClassDefinition):
        self._write(F'class {node.name}')
        if node.base_types:
            self._write(' : ')
            self._write(', '.join(node.base_types))
        self._write(' {')
        self._depth += 1
        for member in node.members:
            self._newline()
            self.visit(member)
        self._depth -= 1
        if node.members:
            self._newline()
        self._write('}')

    def visit_Ps1EnumMember(self, node: Ps1EnumMember):
        self._write(node.name)
        if node.value is not None:
            self._write(' = ')
            self.visit(node.value)

    def visit_Ps1EnumDefinition(self, node: Ps1EnumDefinition):
        self._write(F'enum {node.name}')
        if node.base_type:
            self._write(F' : {node.base_type}')
        self._write(' {')
        self._depth += 1
        for member in node.members:
            self._newline()
            self.visit(member)
        self._depth -= 1
        if node.members:
            self._newline()
        self._write('}')

    def _visit_jump(self, node: Ps1Jump, name: str):
        self._write(name)
        if suffix := node.label:
            # The label is read the way an argument is, and the colon in `break :outer` is part of
            # that spelling rather than of the name: quoted, it would name a label called `:outer`.
            self._write(' ')
            self._emit_word(suffix, precedence.COMMA + 1)

    def _visit_exit(self, node: Ps1Exit, name: str):
        self._write(name)
        if suffix := node.pipeline:
            self._write(' ')
            self.visit(suffix)

    def visit_Ps1ReturnStatement(self, node: Ps1ReturnStatement):
        self._visit_exit(node, 'return')

    def visit_Ps1ExitStatement(self, node: Ps1ExitStatement):
        self._visit_exit(node, 'exit')

    def visit_Ps1ThrowStatement(self, node: Ps1ThrowStatement):
        self._visit_exit(node, 'throw')

    def visit_Ps1BreakStatement(self, node: Ps1BreakStatement):
        self._visit_jump(node, 'break')

    def visit_Ps1ContinueStatement(self, node: Ps1ContinueStatement):
        self._visit_jump(node, 'continue')

    def visit_Ps1DataSection(self, node: Ps1DataSection):
        self._write('data ')
        if node.name:
            self._write(F'{node.name} ')
        if node.commands:
            self._write('-SupportedCommand ')
            for i, cmd in enumerate(node.commands):
                if i > 0:
                    self._write(', ')
                self.visit(cmd)
            self._write(' ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1ErrorNode(self, node: Ps1ErrorNode):
        self._write(node.text)

    def visit_Ps1Script(self, node: Ps1Script):
        if node.param_block:
            self.visit(node.param_block)
            self._newline()
        self._emit_script_body(node, newline_after=True)

    def visit_Block(self, node: Block):
        self._emit_block(node)
