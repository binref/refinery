"""
Whether a file may run code its text does not hold, code that may read or change a property of the
global object while a function of the file runs. A global that one function uses as a local of its
own moves into that function (`refinery.lib.scripts.js.analysis.localization`) only where no such
code may run. In

    function stage(code) { result = 0; require('vm').runInThisContext(code); return result; }
    console.log(stage('result = 6 * 7'));

the code handed to `vm` stores `42` into the global `result`, and a `result` moved into `stage`
would be returned as `0`. Each shape of such code is one check of `may_run_code_it_does_not_hold`,
so a shape found later is one more check there.
"""
from __future__ import annotations

from typing import Callable

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.model import (
    Role,
    SemanticModel,
    enclosing_operator,
    is_global_object_base,
    is_member_write_target,
    reference_role,
)
from refinery.lib.scripts.js.keys import call_argument, key_is, key_named
from refinery.lib.scripts.js.model import (
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsStringLiteral,
    JsTemplateElement,
    JsUnaryExpression,
    strip_parens,
)

_DOCUMENTS = frozenset({'document', 'contentDocument', 'ownerDocument'})
_MARKUP_WRITERS = frozenset({'write', 'writeln', 'createContextualFragment'})
_IMPORT_SCRIPTS = frozenset({'importScripts'})
_CREATE_ELEMENT = frozenset({'createElement'})
_CREATE_ELEMENT_NS = frozenset({'createElementNS'})
_MARKUP_PROPERTIES = frozenset({'innerHTML', 'outerHTML', 'srcdoc'})
_CODE_RUNNING_METHODS = frozenset({'insertAdjacentHTML', 'setHTMLUnsafe', '_compile'})
_SET_ATTRIBUTE = frozenset({'setAttribute'})
_SET_ATTRIBUTE_NS = frozenset({'setAttributeNS'})


def may_run_code_it_does_not_hold(model: SemanticModel) -> bool:
    """
    Whether the file of *model* may run code its text does not hold, in one of these shapes:

    - a reflection surface: `eval`, `Function`, a string timer, `import()` or a `with`
      (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_reflection_surface`);
    - code loaded from a file or a package, `require('./x')` or `import 'x'`, and the code a
      built-in module such as `vm` runs, which the trusting model takes for inert
      (`refinery.lib.scripts.js.analysis.model.SemanticModel.code_load_sites` and
      `refinery.lib.scripts.js.analysis.model.SemanticModel.imports_code`);
    - a script a browser or a worker loads (`_loads_a_script`), and markup written into a document
      the file reads (`_writes_markup`, `_reads_a_document`), which may load one;
    - under the suspecting model, a string the host runs as code (`_runs_a_string_as_code`), which
      the trusting model takes for inert as it does the text handed to `eval`;
    - a use of a global that neither the file nor any host its environment covers defines
      (`_uses_a_global_nothing_defines`), which may be a function running any code.
    """
    if model.has_reflection_surface() or model.imports_code() or model.code_load_sites():
        return True
    checks: list[Callable[[SemanticModel, Node], bool]] = [
        _uses_a_global_nothing_defines,
        _loads_a_script,
    ]
    if not model.trust_eval:
        checks.append(_runs_a_string_as_code)
    reads_a_document = writes_markup = False
    for node in model.root.walk():
        if any(check(model, node) for check in checks):
            return True
        reads_a_document = reads_a_document or _reads_a_document(model, node)
        writes_markup = writes_markup or _writes_markup(model, node)
    return reads_a_document and writes_markup


def _uses_a_global_nothing_defines(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads a global that neither the file nor any host its environment covers
    defines (`refinery.lib.scripts.js.analysis.environment.HostEnvironment.has_a_global`): a bare
    name no binding of the file resolves, or a member of the global object under a key no global
    binding of the file has. A `typeof` of the name runs nothing. The global object is the one the
    base is spelled as or a name the file gives it, read as narrowly as a reflection surface is
    (`refinery.lib.scripts.js.analysis.model.is_global_object_base`): the `this` of a function is
    the receiver of a method wherever the file has one, and a read of each would refuse every move.
    """
    environment = model.environment
    if isinstance(node, JsMemberExpression):
        if is_member_write_target(node):
            return False
        if not is_global_object_base(node.object) and not model.names_the_global_object(node.object):
            return False
        name = key_named(node, model.assumed_keys)
        if name is None or environment.has_a_global(name):
            return False
        binding = model.root_scope.bindings.get(name)
        return binding is None or not model.reaches_global_object(binding)
    if not isinstance(node, JsIdentifier) or not model.is_reference(node):
        return False
    if reference_role(node) is not Role.READ or _is_the_operand_of_typeof(node):
        return False
    return model.resolve(node) is None and not environment.has_a_global(node.name)


def _is_the_operand_of_typeof(node: Node) -> bool:
    operator = enclosing_operator(node)
    return isinstance(operator, JsUnaryExpression) and operator.operator == 'typeof'


def _loads_a_script(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* has a browser or a worker load a script: a call of `importScripts`, or of
    `createElement` or `createElementNS` for an element that may be a `script`.
    """
    if not isinstance(node, JsCallExpression):
        return False
    callee = strip_parens(node.callee)
    if isinstance(callee, JsIdentifier):
        return callee.name in _IMPORT_SCRIPTS and model.resolve(callee) is None
    if not isinstance(callee, JsMemberExpression):
        return False
    assumptions = model.assumed_keys
    if key_is(callee, _CREATE_ELEMENT, assumptions):
        return _may_be(call_argument(node, 0), 'script')
    if key_is(callee, _CREATE_ELEMENT_NS, assumptions):
        return _may_be(call_argument(node, 1), 'script')
    return key_is(callee, _IMPORT_SCRIPTS, assumptions)


def _reads_a_document(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads a document: the name `document`, or a member that holds one.
    """
    if isinstance(node, JsIdentifier):
        return node.name == 'document' and model.is_reference(node)
    return isinstance(node, JsMemberExpression) and key_is(node, _DOCUMENTS, model.assumed_keys)


def _writes_markup(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* calls a method that writes markup into a document, where every script the markup
    holds runs: `write`, `writeln`, or `createContextualFragment` of a range.
    """
    if not isinstance(node, JsCallExpression):
        return False
    callee = strip_parens(node.callee)
    return isinstance(callee, JsMemberExpression) and key_is(callee, _MARKUP_WRITERS, model.assumed_keys)


def _runs_a_string_as_code(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* hands the host a string it runs as code: a string spelling a `javascript:`
    address, markup written into an element (`innerHTML`, `outerHTML`, `srcdoc`,
    `insertAdjacentHTML`, `setHTMLUnsafe`), whose handlers run, an attribute set under a name that
    may be one of an event handler, and the `_compile` of a module.
    """
    if isinstance(node, (JsStringLiteral, JsTemplateElement)):
        return node.value is not None and 'javascript:' in node.value.lower()
    assumptions = model.assumed_keys
    if isinstance(node, JsMemberExpression):
        return is_member_write_target(node) and key_is(node, _MARKUP_PROPERTIES, assumptions)
    if not isinstance(node, JsCallExpression):
        return False
    callee = strip_parens(node.callee)
    if not isinstance(callee, JsMemberExpression):
        return False
    if key_is(callee, _CODE_RUNNING_METHODS, assumptions):
        return True
    if key_is(callee, _SET_ATTRIBUTE, assumptions):
        return _may_start_with(call_argument(node, 0), 'on')
    if key_is(callee, _SET_ATTRIBUTE_NS, assumptions):
        return _may_start_with(call_argument(node, 1), 'on')
    return False


def _may_be(argument: Node | None, name: str) -> bool:
    """
    Whether the argument *argument* may be the string *name* in any case: it is no string literal,
    or one spelling *name*. A missing argument is none.
    """
    if argument is None:
        return False
    text = _lower_case_text(argument)
    return text is None or text == name


def _may_start_with(argument: Node | None, prefix: str) -> bool:
    """
    Whether the argument *argument* may be a string starting with *prefix* in any case: it is no
    string literal, or one starting with *prefix*. A missing argument is none.
    """
    if argument is None:
        return False
    text = _lower_case_text(argument)
    return text is None or text.startswith(prefix)


def _lower_case_text(argument: Node) -> str | None:
    """
    The text of the string literal *argument* in lower case, `None` where it is no string literal
    or one denoting no text.
    """
    literal = strip_parens(argument)
    if not isinstance(literal, JsStringLiteral) or literal.value is None:
        return None
    return literal.value.lower()
