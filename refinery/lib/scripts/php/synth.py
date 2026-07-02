from __future__ import annotations

from refinery.lib.scripts import Node, Statement, Synthesizer
from refinery.lib.scripts.php.deobfuscation.helpers import escape_php_string
from refinery.lib.scripts.php.model import (
    PhpArg,
    PhpArray,
    PhpArrayDimFetch,
    PhpArrayItem,
    PhpArrowFunction,
    PhpAssignment,
    PhpAttribute,
    PhpAttributeGroup,
    PhpBinaryExpression,
    PhpBlock,
    PhpBooleanLiteral,
    PhpBreak,
    PhpCase,
    PhpCastExpression,
    PhpCatch,
    PhpClass,
    PhpClassConst,
    PhpClassConstFetch,
    PhpClassMethod,
    PhpClone,
    PhpClosure,
    PhpClosureUse,
    PhpConst,
    PhpConstDeclaration,
    PhpConstFetch,
    PhpContinue,
    PhpDeclare,
    PhpDeclareDirective,
    PhpDoWhile,
    PhpEcho,
    PhpEchoTagStatement,
    PhpEmpty,
    PhpEnumCase,
    PhpErrorNode,
    PhpErrorSuppress,
    PhpEval,
    PhpExit,
    PhpExpressionStatement,
    PhpFloatLiteral,
    PhpFor,
    PhpForeach,
    PhpFunctionCall,
    PhpFunctionDeclaration,
    PhpGlobal,
    PhpGoto,
    PhpGroupUse,
    PhpHaltCompiler,
    PhpHeredoc,
    PhpIdentifier,
    PhpIf,
    PhpInclude,
    PhpInlineHTML,
    PhpInstanceof,
    PhpIntLiteral,
    PhpInterpolatedString,
    PhpIntersectionType,
    PhpIsset,
    PhpLabel,
    PhpList,
    PhpMagicConstant,
    PhpMatch,
    PhpMatchArm,
    PhpMethodCall,
    PhpName,
    PhpNameKind,
    PhpNamespace,
    PhpNew,
    PhpNewAnonymous,
    PhpNop,
    PhpNullableType,
    PhpNullLiteral,
    PhpParam,
    PhpParenExpression,
    PhpPrint,
    PhpProperty,
    PhpPropertyDeclaration,
    PhpPropertyFetch,
    PhpReturn,
    PhpScript,
    PhpShellExec,
    PhpStaticCall,
    PhpStaticPropertyFetch,
    PhpStaticVar,
    PhpStaticVarDeclaration,
    PhpStringLiteral,
    PhpSwitch,
    PhpTernary,
    PhpThrowExpression,
    PhpThrowStatement,
    PhpTraitAdaptation,
    PhpTraitUse,
    PhpTry,
    PhpUnaryExpression,
    PhpUnionType,
    PhpUnset,
    PhpUpdateExpression,
    PhpUse,
    PhpUseItem,
    PhpUseKind,
    PhpVariable,
    PhpVariableVariable,
    PhpWhile,
    PhpYield,
    PhpYieldFrom,
)
from refinery.lib.scripts.php.precedence import needs_parens


class PhpSynthesizer(Synthesizer):
    """
    Synthesize PHP source from a `PhpScript` AST. Correctness of expression nesting is provided by
    `precedence.needs_parens` rather than by the presence of `PhpParenExpression` nodes, so a tree
    produced by a deobfuscation pass that dropped explicit parentheses still prints correctly.
    """

    def __init__(
        self,
        indent: str = '    ',
        line_length: int = 140,
        unescape_strings: bool = False,
        strip_comments: bool = False,
    ):
        super().__init__(indent, line_length)
        self._unescape_strings = unescape_strings
        self._strip_comments = strip_comments

    def _emit_leading_comments(self, node: Node):
        if self._strip_comments or not node.leading_comments:
            return
        for comment in node.leading_comments:
            self._write(comment)
            self._newline()

    def _emit_child(self, child: Node | None, parent: Node):
        if child is None:
            return
        if needs_parens(child, parent):
            self._write('(')
            self.visit(child)
            self._write(')')
        else:
            self.visit(child)

    def _comma_list(self, nodes: list):
        for i, node in enumerate(nodes):
            if i > 0:
                self._write(', ')
            if node is None:
                continue
            self.visit(node)

    def _emit_statements(self, body: list[Statement]):
        self._depth += 1
        for stmt in body:
            self._newline()
            self._emit_leading_comments(stmt)
            self.visit(stmt)
        self._depth -= 1
        if body:
            self._newline()

    def _emit_brace_block(self, body: list[Statement]):
        self._write('{')
        self._emit_statements(body)
        self._write('}')

    def visit_PhpIntLiteral(self, node: PhpIntLiteral):
        self._write(node.raw)

    def visit_PhpFloatLiteral(self, node: PhpFloatLiteral):
        self._write(node.raw)

    def visit_PhpStringLiteral(self, node: PhpStringLiteral):
        if self._unescape_strings:
            quote = node.raw[:1] if node.raw[:1] in ('"', "'") else "'"
            self._write(F'{quote}{escape_php_string(node.value, quote)}{quote}')
        else:
            self._write(node.raw)

    def visit_PhpInterpolatedString(self, node: PhpInterpolatedString):
        self._write(node.raw)

    def visit_PhpHeredoc(self, node: PhpHeredoc):
        self._write(node.raw)

    def visit_PhpShellExec(self, node: PhpShellExec):
        self._write(node.raw)

    def visit_PhpBooleanLiteral(self, node: PhpBooleanLiteral):
        self._write(node.raw)

    def visit_PhpNullLiteral(self, node: PhpNullLiteral):
        self._write(node.raw)

    def visit_PhpMagicConstant(self, node: PhpMagicConstant):
        self._write(node.name)

    def visit_PhpVariable(self, node: PhpVariable):
        self._write(node.name)

    def visit_PhpVariableVariable(self, node: PhpVariableVariable):
        self._write('$')
        if isinstance(node.expression, PhpVariable):
            self.visit(node.expression)
        else:
            self._write('{')
            if node.expression:
                self.visit(node.expression)
            self._write('}')

    def visit_PhpIdentifier(self, node: PhpIdentifier):
        self._write(node.name)

    def visit_PhpName(self, node: PhpName):
        if node.kind is PhpNameKind.FULLY_QUALIFIED:
            self._write('\\')
        elif node.kind is PhpNameKind.RELATIVE:
            self._write('namespace\\')
        self._write('\\'.join(node.parts))

    def visit_PhpConstFetch(self, node: PhpConstFetch):
        if node.name:
            self.visit(node.name)

    def visit_PhpErrorNode(self, node: PhpErrorNode):
        self._write(node.text)

    def visit_PhpParenExpression(self, node: PhpParenExpression):
        self._write('(')
        if node.expression:
            self.visit(node.expression)
        self._write(')')

    def _emit_binary(self, node: PhpBinaryExpression):
        self._emit_child(node.left, node)
        self._write(F' {node.operator} ')
        self._emit_child(node.right, node)

    visit_PhpBinaryExpression = _emit_binary

    def visit_PhpAssignment(self, node: PhpAssignment):
        self._emit_child(node.target, node)
        self._write(F' {node.operator} ')
        if node.by_ref:
            self._write('&')
        self._emit_child(node.value, node)

    def visit_PhpUnaryExpression(self, node: PhpUnaryExpression):
        self._write(node.operator)
        self._emit_child(node.operand, node)

    def visit_PhpUpdateExpression(self, node: PhpUpdateExpression):
        if node.prefix:
            self._write(node.operator)
            self._emit_child(node.operand, node)
        else:
            self._emit_child(node.operand, node)
            self._write(node.operator)

    def visit_PhpCastExpression(self, node: PhpCastExpression):
        self._write(F'({node.cast}) ')
        self._emit_child(node.operand, node)

    def visit_PhpErrorSuppress(self, node: PhpErrorSuppress):
        self._write('@')
        self._emit_child(node.operand, node)

    def visit_PhpClone(self, node: PhpClone):
        self._write('clone ')
        self._emit_child(node.operand, node)

    def visit_PhpInstanceof(self, node: PhpInstanceof):
        self._emit_child(node.operand, node)
        self._write(' instanceof ')
        self._emit_child(node.class_name, node)

    def visit_PhpTernary(self, node: PhpTernary):
        self._emit_child(node.condition, node)
        if node.consequent is None:
            self._write(' ?: ')
        else:
            self._write(' ? ')
            self._emit_child(node.consequent, node)
            self._write(' : ')
        self._emit_child(node.alternate, node)

    def visit_PhpPrint(self, node: PhpPrint):
        self._write('print ')
        self._emit_child(node.operand, node)

    def visit_PhpInclude(self, node: PhpInclude):
        self._write(F'{node.kind} ')
        self._emit_child(node.operand, node)

    def visit_PhpThrowExpression(self, node: PhpThrowExpression):
        self._write('throw ')
        self._emit_child(node.operand, node)

    def visit_PhpYield(self, node: PhpYield):
        self._write('yield')
        if node.value is not None:
            self._write(' ')
            if node.key is not None:
                self._emit_child(node.key, node)
                self._write(' => ')
            self._emit_child(node.value, node)

    def visit_PhpYieldFrom(self, node: PhpYieldFrom):
        self._write('yield from ')
        self._emit_child(node.operand, node)

    def _emit_args(self, args: list[PhpArg], first_class_callable: bool):
        self._write('(')
        if first_class_callable:
            self._write('...')
        else:
            self._comma_list(args)
        self._write(')')

    def visit_PhpArg(self, node: PhpArg):
        if node.name is not None:
            self._write(F'{node.name}: ')
        if node.spread:
            self._write('...')
        if node.by_ref:
            self._write('&')
        if node.value:
            self.visit(node.value)

    def visit_PhpFunctionCall(self, node: PhpFunctionCall):
        self._emit_child(node.callee, node)
        self._emit_args(node.args, node.first_class_callable)

    def visit_PhpMethodCall(self, node: PhpMethodCall):
        self._emit_child(node.receiver, node)
        self._write('?->' if node.nullsafe else '->')
        self._emit_member_name(node.method)
        self._emit_args(node.args, node.first_class_callable)

    def visit_PhpStaticCall(self, node: PhpStaticCall):
        self._emit_child(node.class_name, node)
        self._write('::')
        self._emit_member_name(node.method)
        self._emit_args(node.args, node.first_class_callable)

    def visit_PhpPropertyFetch(self, node: PhpPropertyFetch):
        self._emit_child(node.receiver, node)
        self._write('?->' if node.nullsafe else '->')
        self._emit_member_name(node.name)

    def visit_PhpStaticPropertyFetch(self, node: PhpStaticPropertyFetch):
        self._emit_child(node.class_name, node)
        self._write('::')
        self._emit_member_name(node.name)

    def visit_PhpClassConstFetch(self, node: PhpClassConstFetch):
        self._emit_child(node.class_name, node)
        self._write('::')
        self._emit_member_name(node.name)

    def _emit_member_name(self, name: Node | None):
        if name is None:
            return
        if isinstance(name, (PhpIdentifier, PhpVariable, PhpVariableVariable)):
            self.visit(name)
        else:
            self._write('{')
            self.visit(name)
            self._write('}')

    def visit_PhpArrayDimFetch(self, node: PhpArrayDimFetch):
        self._emit_child(node.receiver, node)
        self._write('[')
        if node.index is not None:
            self.visit(node.index)
        self._write(']')

    def visit_PhpArray(self, node: PhpArray):
        if node.short:
            self._write('[')
            self._comma_list(node.items)
            self._write(']')
        else:
            self._write('array(')
            self._comma_list(node.items)
            self._write(')')

    def visit_PhpList(self, node: PhpList):
        self._write('list(')
        self._comma_list(node.items)
        self._write(')')

    def visit_PhpArrayItem(self, node: PhpArrayItem):
        if node.spread:
            self._write('...')
        if node.key is not None:
            self._emit_child(node.key, node)
            self._write(' => ')
        if node.by_ref:
            self._write('&')
        if node.value is not None:
            self._emit_child(node.value, node)

    def visit_PhpMatch(self, node: PhpMatch):
        self._write('match (')
        if node.subject:
            self.visit(node.subject)
        self._write(') {')
        self._depth += 1
        for arm in node.arms:
            self._newline()
            self.visit(arm)
            self._write(',')
        self._depth -= 1
        if node.arms:
            self._newline()
        self._write('}')

    def visit_PhpMatchArm(self, node: PhpMatchArm):
        if node.is_default:
            self._write('default')
        else:
            self._comma_list(node.conditions)
        self._write(' => ')
        if node.body:
            self._emit_child(node.body, node)

    def visit_PhpIsset(self, node: PhpIsset):
        self._write('isset(')
        self._comma_list(node.variables)
        self._write(')')

    def visit_PhpEmpty(self, node: PhpEmpty):
        self._write('empty(')
        if node.operand:
            self.visit(node.operand)
        self._write(')')

    def visit_PhpEval(self, node: PhpEval):
        self._write('eval(')
        if node.operand:
            self.visit(node.operand)
        self._write(')')

    def visit_PhpExit(self, node: PhpExit):
        self._write(node.keyword)
        if node.operand is not None:
            self._write('(')
            self.visit(node.operand)
            self._write(')')

    def _emit_params(self, params: list[PhpParam]):
        self._write('(')
        self._comma_list(params)
        self._write(')')

    def visit_PhpParam(self, node: PhpParam):
        for group in node.attributes:
            self.visit(group)
            self._write(' ')
        if node.visibility is not None:
            self._write(F'{node.visibility.value} ')
        if node.readonly:
            self._write('readonly ')
        if node.type is not None:
            self.visit(node.type)
            self._write(' ')
        if node.by_ref:
            self._write('&')
        if node.variadic:
            self._write('...')
        self._write(node.name)
        if node.default is not None:
            self._write(' = ')
            self._emit_child(node.default, node)

    def visit_PhpNullableType(self, node: PhpNullableType):
        self._write('?')
        if node.type:
            self.visit(node.type)

    def visit_PhpUnionType(self, node: PhpUnionType):
        for i, t in enumerate(node.types):
            if i > 0:
                self._write('|')
            self.visit(t)

    def visit_PhpIntersectionType(self, node: PhpIntersectionType):
        for i, t in enumerate(node.types):
            if i > 0:
                self._write('&')
            self.visit(t)

    def visit_PhpClosure(self, node: PhpClosure):
        if node.is_static:
            self._write('static ')
        self._write('function ')
        if node.by_ref:
            self._write('&')
        self._emit_params(node.params)
        if node.uses:
            self._write(' use (')
            self._comma_list(node.uses)
            self._write(')')
        if node.return_type is not None:
            self._write(': ')
            self.visit(node.return_type)
        self._write(' ')
        if node.body:
            self._emit_brace_block(node.body.body)

    def visit_PhpClosureUse(self, node: PhpClosureUse):
        if node.by_ref:
            self._write('&')
        if node.variable:
            self.visit(node.variable)

    def visit_PhpArrowFunction(self, node: PhpArrowFunction):
        if node.is_static:
            self._write('static ')
        self._write('fn')
        if node.by_ref:
            self._write('&')
        self._emit_params(node.params)
        if node.return_type is not None:
            self._write(': ')
            self.visit(node.return_type)
        self._write(' => ')
        if node.body:
            self._emit_child(node.body, node)

    def visit_PhpNew(self, node: PhpNew):
        self._write('new ')
        self._emit_child(node.class_name, node)
        if node.has_parens or node.args:
            self._write('(')
            self._comma_list(node.args)
            self._write(')')

    def visit_PhpNewAnonymous(self, node: PhpNewAnonymous):
        self._write('new ')
        if node.declaration:
            for modifier in node.declaration.modifiers:
                self._write(F'{modifier} ')
        self._write('class')
        if node.has_parens or node.args:
            self._write('(')
            self._comma_list(node.args)
            self._write(')')
        if node.declaration:
            self._emit_class_heritage(node.declaration)
            self._write(' ')
            self._emit_brace_block(node.declaration.members)

    def visit_PhpScript(self, node: PhpScript):
        self._emit_top_level(node.body)

    def _emit_top_level(self, body: list[Statement]):
        """
        Emit a run of top-level statements, opening a `<?php` island around the code segments and
        writing `PhpInlineHTML` nodes verbatim with `?>` / `<?php` tag toggling around them.
        """
        in_php = False
        for stmt in body:
            if isinstance(stmt, PhpInlineHTML):
                if in_php:
                    self._write(' ?>')
                    in_php = False
                self._write(stmt.value)
                continue
            if isinstance(stmt, PhpEchoTagStatement):
                if in_php:
                    self._write(' ?>')
                    in_php = False
                self._emit_leading_comments(stmt)
                self.visit(stmt)
                continue
            if not in_php:
                self._write('<?php')
                self._newline()
                in_php = True
            else:
                self._newline()
            self._emit_leading_comments(stmt)
            self.visit(stmt)
        if in_php:
            self._newline()

    def visit_PhpInlineHTML(self, node: PhpInlineHTML):
        self._write(node.value)

    def visit_PhpEchoTagStatement(self, node: PhpEchoTagStatement):
        self._write('<?= ')
        self._comma_list(node.expressions)
        self._write(' ?>')

    def visit_PhpNop(self, node: PhpNop):
        self._write(';')

    def visit_PhpBlock(self, node: PhpBlock):
        self._emit_brace_block(node.body)

    def visit_PhpExpressionStatement(self, node: PhpExpressionStatement):
        if node.expression is not None:
            self.visit(node.expression)
        self._write(';')

    def visit_PhpEcho(self, node: PhpEcho):
        self._write('echo ')
        self._comma_list(node.expressions)
        self._write(';')

    def _emit_body_or_alt(
        self,
        body: list[Statement],
        alternative_syntax: bool,
        end_keyword: str,
    ):
        if alternative_syntax:
            self._write(':')
            self._emit_statements(body)
            self._write(end_keyword)
            self._write(';')
        else:
            self._write(' ')
            self._emit_brace_block(body)

    def visit_PhpIf(self, node: PhpIf):
        self._write('if (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')
        alt = node.alternative_syntax
        self._emit_if_body(node.consequent, alt)
        for elseif in node.elseifs:
            if alt:
                self._write('elseif (')
            else:
                self._write(' elseif (')
            if elseif.condition:
                self.visit(elseif.condition)
            self._write(')')
            self._emit_if_body(elseif.body, alt)
        if node.alternate is not None:
            self._write('else' if alt else ' else')
            self._emit_if_body(node.alternate, alt)
        if alt:
            self._write('endif;')

    def _emit_if_body(self, body: list[Statement], alt: bool):
        if alt:
            self._write(':')
            self._emit_statements(body)
            if not body:
                self._newline()
        else:
            self._write(' ')
            self._emit_brace_block(body)

    def visit_PhpWhile(self, node: PhpWhile):
        self._write('while (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')
        self._emit_body_or_alt(node.body, node.alternative_syntax, 'endwhile')

    def visit_PhpDoWhile(self, node: PhpDoWhile):
        self._write('do ')
        self._emit_brace_block(node.body)
        self._write(' while (')
        if node.condition:
            self.visit(node.condition)
        self._write(');')

    def visit_PhpFor(self, node: PhpFor):
        self._write('for (')
        self._comma_list(node.init)
        self._write('; ')
        self._comma_list(node.condition)
        self._write('; ')
        self._comma_list(node.update)
        self._write(')')
        self._emit_body_or_alt(node.body, node.alternative_syntax, 'endfor')

    def visit_PhpForeach(self, node: PhpForeach):
        self._write('foreach (')
        if node.subject:
            self.visit(node.subject)
        self._write(' as ')
        if node.key is not None:
            self.visit(node.key)
            self._write(' => ')
        if node.by_ref:
            self._write('&')
        if node.value:
            self.visit(node.value)
        self._write(')')
        self._emit_body_or_alt(node.body, node.alternative_syntax, 'endforeach')

    def visit_PhpSwitch(self, node: PhpSwitch):
        self._write('switch (')
        if node.subject:
            self.visit(node.subject)
        self._write(')')
        if node.alternative_syntax:
            self._write(':')
        else:
            self._write(' {')
        self._depth += 1
        for case in node.cases:
            self._newline()
            self.visit(case)
        self._depth -= 1
        if node.cases:
            self._newline()
        elif node.alternative_syntax:
            self._newline()
        if node.alternative_syntax:
            self._write('endswitch;')
        else:
            self._write('}')

    def visit_PhpCase(self, node: PhpCase):
        if node.test is not None:
            self._write('case ')
            self.visit(node.test)
            self._write(':')
        else:
            self._write('default:')
        self._depth += 1
        for stmt in node.body:
            self._newline()
            self._emit_leading_comments(stmt)
            self.visit(stmt)
        self._depth -= 1

    def visit_PhpBreak(self, node: PhpBreak):
        self._write('break')
        if node.level is not None:
            self._write(' ')
            self.visit(node.level)
        self._write(';')

    def visit_PhpContinue(self, node: PhpContinue):
        self._write('continue')
        if node.level is not None:
            self._write(' ')
            self.visit(node.level)
        self._write(';')

    def visit_PhpReturn(self, node: PhpReturn):
        self._write('return')
        if node.value is not None:
            self._write(' ')
            self.visit(node.value)
        self._write(';')

    def visit_PhpThrowStatement(self, node: PhpThrowStatement):
        self._write('throw ')
        if node.operand:
            self.visit(node.operand)
        self._write(';')

    def visit_PhpTry(self, node: PhpTry):
        self._write('try ')
        self._emit_brace_block(node.body)
        for catch in node.catches:
            self._write(' ')
            self.visit(catch)
        if node.finally_body is not None:
            self._write(' finally ')
            self._emit_brace_block(node.finally_body)

    def visit_PhpCatch(self, node: PhpCatch):
        self._write('catch (')
        for i, t in enumerate(node.types):
            if i > 0:
                self._write(' | ')
            self.visit(t)
        if node.variable is not None:
            self._write(' ')
            self.visit(node.variable)
        self._write(') ')
        self._emit_brace_block(node.body)

    def visit_PhpUnset(self, node: PhpUnset):
        self._write('unset(')
        self._comma_list(node.variables)
        self._write(');')

    def visit_PhpGlobal(self, node: PhpGlobal):
        self._write('global ')
        self._comma_list(node.variables)
        self._write(';')

    def visit_PhpStaticVar(self, node: PhpStaticVar):
        self._write('static ')
        self._comma_list(node.declarations)
        self._write(';')

    def visit_PhpStaticVarDeclaration(self, node: PhpStaticVarDeclaration):
        if node.variable:
            self.visit(node.variable)
        if node.default is not None:
            self._write(' = ')
            self._emit_child(node.default, node)

    def visit_PhpGoto(self, node: PhpGoto):
        self._write(F'goto {node.label};')

    def visit_PhpLabel(self, node: PhpLabel):
        self._write(F'{node.name}:')

    def visit_PhpHaltCompiler(self, node: PhpHaltCompiler):
        self._write('__halt_compiler();')
        self._write(node.remainder)

    def visit_PhpNamespace(self, node: PhpNamespace):
        self._write('namespace')
        if node.name is not None:
            self._write(' ')
            self.visit(node.name)
        if node.body is not None:
            self._write(' ')
            self._emit_brace_block(node.body)
        else:
            self._write(';')

    def visit_PhpUse(self, node: PhpUse):
        self._write('use ')
        self._emit_use_kind(node.kind)
        self._comma_list(node.uses)
        self._write(';')

    def visit_PhpGroupUse(self, node: PhpGroupUse):
        self._write('use ')
        self._emit_use_kind(node.kind)
        if node.prefix:
            self.visit(node.prefix)
        self._write('\\{')
        self._comma_list(node.uses)
        self._write('};')

    def _emit_use_kind(self, kind: PhpUseKind):
        if kind is PhpUseKind.FUNCTION:
            self._write('function ')
        elif kind is PhpUseKind.CONSTANT:
            self._write('const ')

    def visit_PhpUseItem(self, node: PhpUseItem):
        if node.kind is PhpUseKind.FUNCTION:
            self._write('function ')
        elif node.kind is PhpUseKind.CONSTANT:
            self._write('const ')
        if node.name:
            self.visit(node.name)
        if node.alias is not None:
            self._write(F' as {node.alias}')

    def visit_PhpConst(self, node: PhpConst):
        self._write('const ')
        self._comma_list(node.consts)
        self._write(';')

    def visit_PhpConstDeclaration(self, node: PhpConstDeclaration):
        self._write(node.name)
        self._write(' = ')
        if node.value is not None:
            self._emit_child(node.value, node)

    def visit_PhpDeclare(self, node: PhpDeclare):
        self._write('declare(')
        self._comma_list(node.directives)
        self._write(')')
        if node.body is not None:
            if node.alternative_syntax:
                self._write(':')
                self._emit_statements(node.body)
                self._write('enddeclare;')
            else:
                self._write(' ')
                self._emit_brace_block(node.body)
        else:
            self._write(';')

    def visit_PhpDeclareDirective(self, node: PhpDeclareDirective):
        self._write(F'{node.name}=')
        if node.value is not None:
            self.visit(node.value)

    def visit_PhpAttributeGroup(self, node: PhpAttributeGroup):
        self._write('#[')
        self._comma_list(node.attributes)
        self._write(']')

    def visit_PhpAttribute(self, node: PhpAttribute):
        if node.name:
            self.visit(node.name)
        if node.args:
            self._write('(')
            self._comma_list(node.args)
            self._write(')')

    def _emit_attribute_groups(self, groups: list[PhpAttributeGroup]):
        for group in groups:
            self.visit(group)
            self._newline()

    def visit_PhpFunctionDeclaration(self, node: PhpFunctionDeclaration):
        self._emit_attribute_groups(node.attributes)
        self._write('function ')
        if node.by_ref:
            self._write('&')
        self._write(node.name)
        self._emit_params(node.params)
        if node.return_type is not None:
            self._write(': ')
            self.visit(node.return_type)
        if node.body is not None:
            self._write(' ')
            self._emit_brace_block(node.body.body)
        else:
            self._write(';')

    def _emit_class_heritage(self, node: PhpClass):
        if node.extends:
            self._write(' extends ')
            for i, name in enumerate(node.extends):
                if i > 0:
                    self._write(', ')
                self.visit(name)
        if node.implements:
            self._write(' implements ')
            for i, name in enumerate(node.implements):
                if i > 0:
                    self._write(', ')
                self.visit(name)

    def visit_PhpClass(self, node: PhpClass):
        self._emit_attribute_groups(node.attributes)
        for modifier in node.modifiers:
            self._write(F'{modifier} ')
        self._write(F'{node.kind.value} {node.name}')
        if node.enum_backing_type is not None:
            self._write(': ')
            self.visit(node.enum_backing_type)
        self._emit_class_heritage(node)
        self._write(' ')
        self._emit_brace_block(node.members)

    def _emit_modifiers(self, modifiers: list[str]):
        for modifier in modifiers:
            self._write(F'{modifier} ')

    def visit_PhpClassMethod(self, node: PhpClassMethod):
        self._emit_attribute_groups(node.attributes)
        self._emit_modifiers(node.modifiers)
        self._write('function ')
        if node.by_ref:
            self._write('&')
        self._write(node.name)
        self._emit_params(node.params)
        if node.return_type is not None:
            self._write(': ')
            self.visit(node.return_type)
        if node.body is not None:
            self._write(' ')
            self._emit_brace_block(node.body.body)
        else:
            self._write(';')

    def visit_PhpProperty(self, node: PhpProperty):
        self._emit_attribute_groups(node.attributes)
        self._emit_modifiers(node.modifiers)
        if node.type is not None:
            self.visit(node.type)
            self._write(' ')
        self._comma_list(node.props)
        self._write(';')

    def visit_PhpPropertyDeclaration(self, node: PhpPropertyDeclaration):
        if node.variable:
            self.visit(node.variable)
        if node.default is not None:
            self._write(' = ')
            self._emit_child(node.default, node)

    def visit_PhpClassConst(self, node: PhpClassConst):
        self._emit_attribute_groups(node.attributes)
        self._emit_modifiers(node.modifiers)
        self._write('const ')
        if node.type is not None:
            self.visit(node.type)
            self._write(' ')
        self._comma_list(node.consts)
        self._write(';')

    def visit_PhpEnumCase(self, node: PhpEnumCase):
        self._emit_attribute_groups(node.attributes)
        self._write(F'case {node.name}')
        if node.value is not None:
            self._write(' = ')
            self.visit(node.value)
        self._write(';')

    def visit_PhpTraitUse(self, node: PhpTraitUse):
        self._write('use ')
        for i, name in enumerate(node.traits):
            if i > 0:
                self._write(', ')
            self.visit(name)
        if not node.adaptations:
            self._write(';')
            return
        self._write(' {')
        self._depth += 1
        for adaptation in node.adaptations:
            self._newline()
            self.visit(adaptation)
        self._depth -= 1
        if node.adaptations:
            self._newline()
        self._write('}')

    def visit_PhpTraitAdaptation(self, node: PhpTraitAdaptation):
        if node.trait is not None:
            self.visit(node.trait)
            self._write('::')
        self._write(node.method)
        if node.kind == 'insteadof':
            self._write(' insteadof ')
            for i, name in enumerate(node.insteadof):
                if i > 0:
                    self._write(', ')
                self.visit(name)
        else:
            self._write(' as')
            if node.new_modifier is not None:
                self._write(F' {node.new_modifier}')
            if node.new_name is not None:
                self._write(F' {node.new_name}')
        self._write(';')
