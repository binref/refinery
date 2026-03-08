# Style Guide for Binary Refinery

This document is the style guide for all code in Binary Refinery.

## Compatibility

All refinery code must support **Python 3.8** and later versions.
For example, this means that the `match` statement is currently not supported.

## Code Style

### Flake8 Specification

First and foremost, all code should pass [flake8], with the following tests disabled:

- Disabled to allow command line argument annotations to work:
  - `F821` (undefined name)
  - `F722` (syntax error in forward annotation)
- Disabled because the maintainer doesn't like them:
  - `E128` (continuation line is under-indented for a visual indentation)
  - `E203` (colons should not have any space before them)
  - `E261` (at least two spaces before inline comment)
  - `W503` (line break occurred before a binary operator)

### Type Hints

The refinery code base uses modern type hints, i.e.:
- `int | None` instead of `Optional[int]`,
- `int | bool` instead of `Union[int, bool]`,
- `list[bool]` instead of `List[bool]`.

To facilitate this and ensure backwards compatibility with Python 3.8, we prefix all code with
```
from __future__ import annotations
```
In rare cases where a modern type hint would have to be resolved at runtime however,
 it is permissible to import from `typing` and define types compatible with Python 3.8.
On the other hand, this is very often avoidable by making such definitions only when `TYPE_CHECKING` is true,
 since development happens using a modern Python environment.

### Comments

Comments should be avoided wherever it is possible and used only when important information about the code cannot be communicated otherwise.
Prioritize expressive, well-structured code and comprehensive naming of variables and functions.

### Line Breaks

All code in refinery uses LF line breaks exclusively, never CR/LF.

### Line Length

All lines should wrap at **100** characters.
This is a hard limit for docstrings and comments, and a soft limit for code.
The hard limit for code is at **140** characters to allow for occasional long lines.

When a function call or definition becomes too long for the line width limit, it should be split like so:
```python
result = function_call(
    argument_1,
    argument_2,
    keyword_parameter_1=keyword_argument_1,
    keyword_parameter_2=keyword_argument_2,
)
```
And for function definitions:
```python
def function_call(
    argument_1: int,
    argument_2: int,
    keyword_parameter_1: str = '',
    keyword_parameter_2: str = '',
):
  ...
```
In other words, each positional and keyword argument as well as the closing parenthesis are on one separate line respectively.
Indentation is increased by one for the arguments, the closing parenthesis is not indented.
The same rule applies to other comma-separated list, tuple, or set literals.

The following style is only permitted for function calls, and only if the line is broken exactly once:
```python
result = function_call(argument_1, argument_2, argument_3,
    argument_4, keyword_parameter_1=keyword_argument_1, keyword_parameter_2=keyword_argument_2)
```

### Docstrings

Docstrings use three double quotes `"""` as separators. Always write docstrings like this:
```python
class cls:
    """
    [docstring]
    """
```
and **never** like this:
```python
class cls:
    """[docstring]"""
```
The docstrings for refinery units should be written with keyword search in mind.
A short paragraph at the beginning should give a quick overview of what the unit does,
followed by a lengthy explanation including the possible keywords that would help users discover it.

### Dictionaries

When typing large dictionaries, the omission of `E203` is to allow you to write them like so:
```python
data = {
    'key1'         : 'data1',
    'a-longer-key' : 'data2',
    'other-key'    : 'data3',
}
```
This can make large dictionaries with somewhat tabular data easier to read in the code.

## Paradigms

### Minimizing Copies

All code in binary refinery aims to minimize the number of byte copy operations. To this end:

- Make functions as flexible as possible when it comes to what they accept as input; 
  allow `bytes | bytearray | memoryview` whenever possible and work on memory views whenever that is sufficient.
- When binary buffers have to be sliced, a `memoryview` is the best choice since slicing it has no memory cost.
- Building output should always be done in a `bytearray`, never by concatenating `bytes` objects.
- Returning `bytearray` objects rather than `bytes` is always acceptable; the two types expose the same API.


[flake8]: https://pypi.org/project/flake8/