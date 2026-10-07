"""
The AutoIt3 the au3 tests are quantified over, and what the language says about the shape of a tree
that spells it.

Everything here is hand-authored and nothing is read from disk, downloaded, or derived from a sample.
No AutoIt3 installation was available to check a snippet against, so a snippet is AutoIt3 because
the pegjs grammar of the reference repository and the operator table of the language documentation
both read it, and not because our own parser accepted it. The real-world half of the corpus is a
compiled script that the `a3x` tests decompile in memory and read back through this stack.

Nothing in this module may ever be executed. The fidelity harness only ever parses and prints.
"""
from __future__ import annotations

from refinery.lib.scripts import Node

#: One program per node class, written by hand rather than generated, and kept minimal so that a
#: failure names the construct it is about. Where a node has a child list, the snippet fills it with
#: two entries: the fidelity generator truncates from there, and a rendering that is only correct at
#: the cardinality its author had in mind is what that is looking for.
SNIPPETS: dict[str, str] = {
    'Au3ArrayAccess'          : '$x = $a[0]',
    'Au3ArrayLiteral'         : '$a = [1, 2]',
    'Au3Assignment'           : '$x = 1',
    'Au3BinaryExpression'     : '$x = 1 + 2',
    'Au3BooleanLiteral'       : '$x = True',
    'Au3Call'                 : 'MsgBox(0, "t", "m")',
    'Au3CaseRange'            : 'Switch $x\nCase 1 To 5\n$y = 1\nEndSwitch',
    'Au3ContinueCaseStatement': 'Switch $x\nCase 1\nContinueCase\nCase 2\n$y = 2\nEndSwitch',
    'Au3ContinueLoopStatement': 'For $i = 1 To 2\nContinueLoop\nNext',
    'Au3DefaultLiteral'       : '$x = Default',
    'Au3Directive'            : '#RequireAdmin',
    'Au3DoUntilStatement'     : 'Do\n$x = 1\n$y = 2\nUntil $x',
    'Au3ElseIf'               : 'If $x Then\n$y = 1\nElseIf $z Then\n$y = 2\nElse\n$y = 3\nEndIf',
    'Au3EnumDeclaration'      : 'Enum $e1 = 1, $e2 = 2',
    'Au3EnumDeclarator'       : 'Enum $e1 = 1, $e2 = 2',
    'Au3ExitLoopStatement'    : 'While $x\nExitLoop\nWend',
    'Au3ExitStatement'        : 'Exit 1',
    'Au3ExpressionStatement'  : 'Foo(1, 2)',
    'Au3FloatLiteral'         : '$x = 1.5',
    'Au3ForInStatement'      : 'For $x In $a\n$y = 1\n$y = 2\nNext',
    'Au3ForStatement'         : 'For $i = 0 To 10 Step 2\n$x = 1\n$y = 2\nNext',
    'Au3FunctionDeclaration'  : 'Func _f($a, $b)\nReturn $a\nEndFunc',
    'Au3Identifier'           : 'Func f($a)\nReturn $a\nEndFunc',
    'Au3IfStatement'          : 'If $x Then\n$y = 1\nElse\n$y = 2\nEndIf',
    'Au3Include'              : '#include <File.au3>',
    'Au3IncludeOnce'          : '#include-once',
    'Au3IntLiteral'           : '$x = 1',
    'Au3Macro'                : '$x = @ScriptDir',
    'Au3MemberAccess'         : '$x = $o.prop',
    'Au3NullLiteral'          : '$x = Null',
    'Au3Parameter'            : 'Func _f($a, $b)\nReturn $a\nEndFunc',
    'Au3ParenExpression'      : '$x = (1 + 2)',
    'Au3ReDimStatement'       : 'ReDim $a[10], $b[20]',
    'Au3ReDimTarget'          : 'ReDim $a[10], $b[20]',
    'Au3ReturnStatement'      : 'Func _f($a)\nReturn $a\nEndFunc',
    'Au3Script'               : '$x = 1\n$y = 2',
    'Au3SelectCase'           : 'Select\nCase $x\n$y = 1\nCase Else\n$y = 2\nEndSelect',
    'Au3SelectStatement'      : 'Select\nCase $x\n$y = 1\nCase Else\n$y = 2\nEndSelect',
    'Au3StringLiteral'        : '$x = "a"',
    'Au3SwitchCase'           : 'Switch $x\nCase 1, 2\n$y = 1\nCase Else\n$y = 2\nEndSwitch',
    'Au3SwitchStatement'      : 'Switch $x\nCase 1, 2\n$y = 1\nCase Else\n$y = 2\nEndSwitch',
    'Au3Ternary'              : '$x = $y ? 1 : 2',
    'Au3UnaryExpression'      : '$x = Not $y',
    'Au3Variable'             : '$x = 1',
    'Au3VariableDeclaration'  : 'Local $a = 1, $b = 2',
    'Au3VariableDeclarator'    : 'Local $a = 1, $b = 2',
    'Au3WhileStatement'       : 'While $x\n$y = 1\n$y = 2\nWend',
    'Au3WithMember'           : 'With $o\n.x = 1\nEndWith',
    'Au3WithStatement'        : 'With $o\n.x = 1\nEndWith',
}

#: The shortest a child list may be and still spell something. A list absent from here may be empty,
#: which is most of them: a call with no arguments, a block with no statements and a function with no
#: parameters are all programs. The ones that are not are the lists a declaration cannot run dry
#: of, plus the values of a Switch case, where an empty list and the `None` that stands for
#: `Case Else` are two different trees and only the second has text.
SHORTEST_LIST: dict[str, dict[str, int]] = {
    'Au3EnumDeclaration'     : {'declarations': 1},
    'Au3ReDimStatement'      : {'targets': 1},
    'Au3ReDimTarget'         : {'dimensions': 1},
    'Au3SwitchCase'          : {'values': 1},
    'Au3VariableDeclaration' : {'declarations': 1},
}


def shapes_the_grammar_forbids(root: Node) -> list[str]:
    """
    Every part of the tree at `root` that no AutoIt3 text spells, named one at a time.

    The rules are stated from the grammar rather than from the parser: a variable, a macro, an
    identifier and a member name are at least one character; a declaration declares at least one
    name; a `ReDim` names at least one array and gives it at least one dimension; and a Switch case
    that is not `Else` lists at least one value.

    Two callers need the answer for opposite reasons. The generators use it to avoid manufacturing
    a tree that is not a program, since printing one says nothing about whether printing is
    faithful. The parser is held to it, because a shape with no text is one no parser may hand back:
    the synthesizer would have to invent a spelling for it, and inventing one is how a script quietly
    starts meaning something else.
    """
    found: list[str] = []
    for node in root.walk():
        name = type(node).__name__
        if getattr(node, 'name', None) == '':
            found.append(F'{name} has no name')
        if getattr(node, 'member', None) == '':
            found.append(F'{name} has no member')
        for attribute, shortest in SHORTEST_LIST.get(name, {}).items():
            held = getattr(node, attribute)
            if held is not None and len(held) < shortest:
                found.append(F'{name} holds {len(held)} of {attribute}, fewer than {shortest}')
    return found
