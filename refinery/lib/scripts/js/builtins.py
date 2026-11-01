"""
The functions the language installs on the prototypes of the values a fold holds, and the
constructors owning those prototypes. `PROTOTYPE_METHODS` is the one table of them: what a member
read on a string, an array, a number, a boolean or a function is answered by where the value does
not own the key, which keys such a read can never find, and which reads hand out an object the
program may write a built-in through. The analysis that guards a fold and the fold itself both read
it here, so neither states a second answer.
"""
from __future__ import annotations

from refinery.lib.scripts.js.values import BuiltinFunction

PROTOTYPE_METHODS: dict[str, frozenset[str]] = {
    'Object': frozenset({
        '__defineGetter__',
        '__defineSetter__',
        '__lookupGetter__',
        '__lookupSetter__',
        'hasOwnProperty',
        'isPrototypeOf',
        'propertyIsEnumerable',
        'toLocaleString',
        'toString',
        'valueOf',
    }),
    'Function': frozenset({
        'apply',
        'bind',
        'call',
        'toString',
    }),
    'Array': frozenset({
        'at',
        'concat',
        'copyWithin',
        'entries',
        'every',
        'fill',
        'filter',
        'find',
        'findIndex',
        'findLast',
        'findLastIndex',
        'flat',
        'flatMap',
        'forEach',
        'includes',
        'indexOf',
        'join',
        'keys',
        'lastIndexOf',
        'map',
        'pop',
        'push',
        'reduce',
        'reduceRight',
        'reverse',
        'shift',
        'slice',
        'some',
        'sort',
        'splice',
        'toLocaleString',
        'toReversed',
        'toSorted',
        'toSpliced',
        'toString',
        'unshift',
        'values',
        'with',
    }),
    'String': frozenset({
        'anchor',
        'at',
        'big',
        'blink',
        'bold',
        'charAt',
        'charCodeAt',
        'codePointAt',
        'concat',
        'endsWith',
        'fixed',
        'fontcolor',
        'fontsize',
        'includes',
        'indexOf',
        'isWellFormed',
        'italics',
        'lastIndexOf',
        'link',
        'localeCompare',
        'match',
        'matchAll',
        'normalize',
        'padEnd',
        'padStart',
        'repeat',
        'replace',
        'replaceAll',
        'search',
        'slice',
        'small',
        'split',
        'startsWith',
        'strike',
        'sub',
        'substr',
        'substring',
        'sup',
        'toLocaleLowerCase',
        'toLocaleUpperCase',
        'toLowerCase',
        'toString',
        'toUpperCase',
        'toWellFormed',
        'trim',
        'trimEnd',
        'trimLeft',
        'trimRight',
        'trimStart',
        'valueOf',
    }),
    'Number': frozenset({
        'toExponential',
        'toFixed',
        'toLocaleString',
        'toPrecision',
        'toString',
        'valueOf',
    }),
    'Boolean': frozenset({
        'toString',
        'valueOf',
    }),
}
"""
The function-valued own properties of the prototype of each constructor named, `constructor` aside,
enumerated from a real engine rather than from the subset this package can run: `normalize` is a
function whether or not a fold can evaluate it, and a read answering `undefined` for it would
contradict `typeof`. Symbol-keyed members are left out, since no string names them.
"""

ALIASED_METHODS: dict[tuple[str, str], str] = {
    ('String', 'trimLeft')  : 'trimStart',
    ('String', 'trimRight') : 'trimEnd',
}
"""
The prototype keys that hold the same function as another key of the same prototype, mapped to
that other key: `''.trimLeft === ''.trimStart`, and the function's `name` is `trimStart`.
"""

HTML_METHODS: dict[str, tuple[str, str]] = {
    'anchor'    : ('a', 'name'),
    'big'       : ('big', ''),
    'blink'     : ('blink', ''),
    'bold'      : ('b', ''),
    'fixed'     : ('tt', ''),
    'fontcolor' : ('font', 'color'),
    'fontsize'  : ('font', 'size'),
    'italics'   : ('i', ''),
    'link'      : ('a', 'href'),
    'small'     : ('small', ''),
    'strike'    : ('strike', ''),
    'sub'       : ('sub', ''),
    'sup'       : ('sup', ''),
}
"""
The methods of `String.prototype` ECMA-262 B.2.2.2 to B.2.2.14 define, each mapped to the tag it
wraps the string in and to the attribute it writes its argument into, or the empty string where it
writes none.
"""

ITERATOR_METHODS = frozenset({'entries', 'keys', 'values'})
"""
The methods of `Array.prototype` that return an iterator over the array.
"""

PROTOTYPE_CHAIN_PROPERTIES = frozenset({'__proto__', 'constructor'})
"""
The two properties that expose the prototype chain itself. Both exist on every value, so answering
`undefined` for them is wrong, and a read of either hands out an object whose properties are the
built-ins every value of a type inherits.
"""

OBJECT_PROTOTYPE_MEMBERS = PROTOTYPE_METHODS['Object'] | PROTOTYPE_CHAIN_PROPERTIES
"""
The members every plain object inherits from `Object.prototype`. An access of one of these names on
an object that does not own it resolves through the prototype rather than to `undefined`, so a fold
that treats an absent own-property as `undefined` must leave these intact.
"""

BUILTIN_MEMBER_NAMES = frozenset().union(*PROTOTYPE_METHODS.values()) | PROTOTYPE_CHAIN_PROPERTIES
"""
Every key a read off a value of a built-in type may find on its prototype chain. A read of one hands
out a built-in object, whose properties a write through the read replaces for every value.
"""

CONSTRUCTORS: dict[str, BuiltinFunction] = {
    owner: BuiltinFunction(owner, is_constructor=True) for owner in (*PROTOTYPE_METHODS, 'RegExp')
}
"""
The constructor owning each prototype of `PROTOTYPE_METHODS`, and `RegExp`, by the global name
holding it. The methods of `RegExp.prototype` are left out of `PROTOTYPE_METHODS`: `exec` and
`test` are names a program reads off many objects no regular expression is, such as the module
`child_process`, and `BUILTIN_MEMBER_NAMES` would count every such read as one off a built-in.
"""


def _prototype_functions() -> dict[tuple[str, str], BuiltinFunction]:
    functions: dict[tuple[str, str], BuiltinFunction] = {}
    for owner, methods in PROTOTYPE_METHODS.items():
        for key in methods:
            name = ALIASED_METHODS.get((owner, key), key)
            function = functions.get((owner, name))
            if function is None:
                function = functions[owner, name] = BuiltinFunction(name, is_constructor=False)
            functions[owner, key] = function
    return functions


PROTOTYPE_FUNCTIONS = _prototype_functions()
"""
The function each prototype of `PROTOTYPE_METHODS` holds under each of its keys, by the name of the
constructor owning the prototype and the key. The keys `ALIASED_METHODS` pairs hold one function.
"""

RECEIVER_WRITING_METHODS = frozenset({
    '__defineGetter__',
    '__defineSetter__',
    'copyWithin',
    'fill',
    'pop',
    'push',
    'reverse',
    'shift',
    'sort',
    'splice',
    'unshift',
})
"""
The methods in `PROTOTYPE_METHODS` that write a property of the object they are called on: the
accessor installers of `Object.prototype` and the mutators of `Array.prototype`. Called on a
prototype, `[].__proto__.push(5)` stores an element every array then inherits.
"""
