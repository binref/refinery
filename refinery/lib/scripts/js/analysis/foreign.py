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
from refinery.lib.scripts.js.keys import call_argument, key_is, key_may_be, key_named
from refinery.lib.scripts.js.model import (
    JsAssignmentExpression,
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
_REQUIRE = frozenset({'require'})
_INVOCATIONS = frozenset({'call', 'apply', 'bind'})
_LISTENER_RUNNERS = frozenset({'dispatchEvent', 'fireEvent'})
_LOCATIONS = frozenset({'location'})
_ADDRESS_OF_A_LOCATION = frozenset({'href'})
_NAVIGATIONS = frozenset({'assign', 'replace'})
_JAVASCRIPT_SCHEME = 'javascript:'
_URL_TABS_AND_LINE_BREAKS = str.maketrans('', '', '\t\n\r')
"""
The characters a URL parser removes from an address before it reads the scheme: a tab and a line
break inside `javascript:` leave it a `javascript:` address.
"""


def may_run_code_it_does_not_hold(model: SemanticModel) -> bool:
    """
    Whether the file of *model* may run code its text does not hold, in one of these shapes:

    - a reflection surface: `eval`, `Function`, a string timer, `import()` or a `with`
      (`refinery.lib.scripts.js.analysis.model.SemanticModel.has_reflection_surface`);
    - code loaded from a file or a package, `require('./x')` or `import 'x'`, and the code a
      built-in module such as `vm` runs, which the trusting model takes for inert
      (`refinery.lib.scripts.js.analysis.model.SemanticModel.code_load_sites` and
      `refinery.lib.scripts.js.analysis.model.SemanticModel.imports_code`);
    - Node's `require` read in a way those sites do not follow (`_requires_another_way`);
    - a script a browser or a worker loads (`_loads_a_script`), and markup written into a document
      the file reads (`_writes_markup`, `_reads_a_document`), which may load one;
    - a call that runs the listeners other code registered (`_runs_listeners`);
    - under the suspecting model, a string the host runs as code (`_runs_a_string_as_code`), and an
      address the window navigates to that the file computes (`_navigates_to_a_computed_address`),
      which the trusting model takes for inert as it does the text handed to `eval`;
    - a use of a global that neither the file nor any host its environment covers defines
      (`_uses_a_global_nothing_defines`), which may be a function running any code.

    A method of these shapes is found wherever the file reads it to call it, in place or handed
    on: its `call`, `apply` and `bind`, and a name it is stored under, call it as it is called in
    place (`_may_be_called_with`).
    """
    if model.has_reflection_surface() or model.imports_code() or model.code_load_sites():
        return True
    checks: list[Callable[[SemanticModel, Node], bool]] = [
        _uses_a_global_nothing_defines,
        _requires_another_way,
        _loads_a_script,
        _runs_listeners,
    ]
    if not model.trust_eval:
        checks.append(_runs_a_string_as_code)
        checks.append(_navigates_to_a_computed_address)
    reads_a_document = writes_markup = False
    for node in model.root.walk():
        if any(check(model, node) for check in checks):
            return True
        reads_a_document = reads_a_document or _reads_a_document(model, node)
        writes_markup = writes_markup or _writes_markup(model, node)
        if reads_a_document and writes_markup:
            return True
    return False


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


def _requires_another_way(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads Node's `require` in a way
    `refinery.lib.scripts.js.analysis.model.SemanticModel.code_load_sites` does not follow: the
    host's `require` handed on, through its `call`, `apply` or `bind` or under another name, which
    may then load any module, or the `require` of another object, such as `require.main` or
    `process.mainModule`, read to load a module that may run code
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.specifier_loads_code`). A read of any
    other member of the host's `require`, such as its `main` or its `resolve`, calls it not.
    """
    if isinstance(node, JsIdentifier):
        if node.name not in _REQUIRE or not model.is_reference(node) or _is_the_operand_of_typeof(node):
            return False
        user = enclosing_operator(node)
        if isinstance(user, JsCallExpression) and strip_parens(user.callee) is node:
            return False
        if (
            isinstance(user, JsMemberExpression)
            and strip_parens(user.object) is node
            and not key_may_be(user, _INVOCATIONS)
        ):
            return False
        return model.may_hold_what_the_host_passed(node)
    if not isinstance(node, JsMemberExpression) or not key_is(node, _REQUIRE, model.assumed_keys):
        return False
    return _reads_the_method(node) and _may_be_called_with(node, 0, False, model.specifier_loads_code)


def _loads_a_script(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* may have a browser or a worker load a script: a read of `importScripts` to call
    it, or of `createElement` or `createElementNS` to call it for an element that may be a
    `script`, a name `createElementNS` may qualify with a prefix.
    """
    if isinstance(node, JsIdentifier):
        return (
            node.name in _IMPORT_SCRIPTS
            and model.is_reference(node)
            and model.resolve(node) is None
            and not _is_the_operand_of_typeof(node)
        )
    if not isinstance(node, JsMemberExpression):
        return False
    assumptions = model.assumed_keys
    if key_is(node, _CREATE_ELEMENT, assumptions):
        return _reads_the_method(node) and _may_be_called_with(node, 0, False, _names_a_script)
    if key_is(node, _CREATE_ELEMENT_NS, assumptions):
        return _reads_the_method(node) and _may_be_called_with(node, 1, True, _names_a_script)
    return key_is(node, _IMPORT_SCRIPTS, assumptions) and _reads_the_method(node)


def _runs_listeners(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads a method that runs the listeners registered for an event, which other
    scripts of a page may have registered, to call it: `dispatchEvent`, and the `fireEvent` of
    older browsers.
    """
    return (
        isinstance(node, JsMemberExpression)
        and key_is(node, _LISTENER_RUNNERS, model.assumed_keys)
        and _reads_the_method(node)
    )


def _reads_a_document(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads a document: the name `document`, or a member that holds one.
    """
    if isinstance(node, JsIdentifier):
        return node.name == 'document' and model.is_reference(node)
    return isinstance(node, JsMemberExpression) and key_is(node, _DOCUMENTS, model.assumed_keys)


def _writes_markup(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* reads a method that writes markup into a document to call it, where every script
    the markup holds runs: `write`, `writeln`, or `createContextualFragment` of a range.
    """
    return (
        isinstance(node, JsMemberExpression)
        and key_is(node, _MARKUP_WRITERS, model.assumed_keys)
        and _reads_the_method(node)
    )


def _runs_a_string_as_code(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* hands the host a string it runs as code: a string spelling a `javascript:`
    address (`_spells_a_javascript_address`), markup written into an element (`innerHTML`,
    `outerHTML`, `srcdoc`, `insertAdjacentHTML`, `setHTMLUnsafe`), whose handlers run, an
    attribute set under a name that may be one of an event handler, and the `_compile` of a module.
    """
    if isinstance(node, (JsStringLiteral, JsTemplateElement)):
        return node.value is not None and _spells_a_javascript_address(node.value)
    if not isinstance(node, JsMemberExpression):
        return False
    assumptions = model.assumed_keys
    if key_is(node, _MARKUP_PROPERTIES, assumptions):
        return is_member_write_target(node)
    if key_is(node, _CODE_RUNNING_METHODS, assumptions):
        return _reads_the_method(node)
    if key_is(node, _SET_ATTRIBUTE, assumptions):
        return _reads_the_method(node) and _may_be_called_with(node, 0, False, _names_a_handler)
    if key_is(node, _SET_ATTRIBUTE_NS, assumptions):
        return _reads_the_method(node) and _may_be_called_with(node, 1, True, _names_a_handler)
    return False


def _navigates_to_a_computed_address(model: SemanticModel, node: Node) -> bool:
    """
    Whether *node* has the window navigate to an address that is no string literal, which may be
    a `javascript:` address the window runs as code: a store into `location`, into the `location`
    of an object or into the `href` of a location, and a call of the `assign` or `replace` of a
    location. A literal address is read by `_runs_a_string_as_code`.
    """
    assumptions = model.assumed_keys
    if isinstance(node, JsIdentifier):
        return (
            node.name in _LOCATIONS
            and model.is_reference(node)
            and reference_role(node) is not Role.READ
            and ((binding := model.resolve(node)) is None or model.reaches_global_object(binding))
            and _stores_a_computed_value(node)
        )
    if not isinstance(node, JsMemberExpression):
        return False
    if is_member_write_target(node):
        if key_is(node, _LOCATIONS, assumptions):
            return _stores_a_computed_value(node)
        return (
            key_is(node, _ADDRESS_OF_A_LOCATION, assumptions)
            and _is_a_location(model, node.object)
            and _stores_a_computed_value(node)
        )
    return (
        key_is(node, _NAVIGATIONS, assumptions)
        and _is_a_location(model, node.object)
        and _reads_the_method(node)
        and _may_be_called_with(node, 0, False, _is_no_address)
    )


def _is_a_location(model: SemanticModel, node: Node | None) -> bool:
    """
    Whether *node* may be the location of a window: the name `location`, or a member of that name.
    """
    node = strip_parens(node)
    if isinstance(node, JsIdentifier):
        return node.name in _LOCATIONS
    return isinstance(node, JsMemberExpression) and key_is(node, _LOCATIONS, model.assumed_keys)


def _stores_a_computed_value(target: Node) -> bool:
    """
    Whether the store into *target* stores a value that is no string literal: a compound
    assignment or an update computes it, and a plain assignment may store anything but a literal.
    """
    store = enclosing_operator(target)
    if not isinstance(store, JsAssignmentExpression) or strip_parens(store.left) is not target:
        return True
    return store.operator != '=' or _literal_text(store.right) is None


def _is_no_address(text: str) -> bool:
    return False


def _spells_a_javascript_address(text: str) -> bool:
    """
    Whether the string *text* holds a `javascript:` address as a URL parser reads one: in any case,
    and with every tab and line break left out (`_URL_TABS_AND_LINE_BREAKS`).
    """
    return _JAVASCRIPT_SCHEME in text.lower().translate(_URL_TABS_AND_LINE_BREAKS)


def _reads_the_method(member: JsMemberExpression) -> bool:
    """
    Whether *member* reads the method it names to call it: it is no store into the property and no
    `typeof` test of it.
    """
    return not is_member_write_target(member) and not _is_the_operand_of_typeof(member)


def _names_a_script(name: str) -> bool:
    return name.lower() == 'script'


def _names_a_handler(name: str) -> bool:
    return name.lower().startswith('on')


def _may_be_called_with(
    member: JsMemberExpression,
    index: int,
    qualified: bool,
    accepts: Callable[[str], bool],
) -> bool:
    """
    Whether the method *member* reads may be called with a name at *index* that *accepts* takes,
    after the prefix and colon of a name that is *qualified*. Where *member* is the callee of a
    call, that is the argument there: one that is no string literal may be any, and a call that
    passes none there passes no name. Where *member* is read to be handed on, for its `call`,
    `apply` or `bind` or under another name, the method may be called with any name.
    """
    call = enclosing_operator(member)
    if not isinstance(call, JsCallExpression) or strip_parens(call.callee) is not member:
        return True
    argument = call_argument(call, index)
    if argument is None:
        return False
    text = _literal_text(argument)
    if text is None:
        return True
    if qualified:
        text = text.rpartition(':')[2]
    return accepts(text)


def _literal_text(argument: Node | None) -> str | None:
    """
    The text of the string literal *argument*, `None` where it is no string literal or one
    denoting no text.
    """
    literal = strip_parens(argument)
    if not isinstance(literal, JsStringLiteral) or literal.value is None:
        return None
    return literal.value
