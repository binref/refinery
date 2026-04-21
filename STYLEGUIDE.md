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

We use `pyflakes` for checking compliance and run the following `isort` command to normalize imports
inside the refinery code package (tests are not subject to this):
```
isort --py=38 refinery
```

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

The goal for refinery is to be fully typed.
Use the `pyright` type checker for newly written code and ensure that it reports no problems.

### Comments

Comments should be avoided wherever it is possible and used only when important information about the code cannot be communicated otherwise. Prioritize expressive, well-structured code and comprehensive naming of variables and functions. Especially undesired
are plate comments that intend to separate a source file into sections or merely announce the code that will follow.

### Line Breaks

All code in refinery uses LF line breaks exclusively, never CR/LF.

### Line Length

The line length for refinery code is **100** characters.
This is a hard limit for docstrings and comments, and a soft limit for code.
Note also that lines should **not** wrap at less than 100 characters.
Do not wrap at 80 characters.
The hard limit for code is at **140** characters to allow occasional code lines that exceed 100 characters.

### Lists

This section applies to frozenset, set, tuple, and list definitions as well as function argument lists.

When a function call or definition becomes too long for the line width limit,
it should be split up with exactly one item on each line, like so:
```python
result = function_call(
    argument_1,
    argument_2,
    keyword_parameter_1=keyword_argument_1,
    keyword_parameter_2=keyword_argument_2,
)
```
Similarly for function definitions:
```python
def function_call(
    argument_1: int,
    argument_2: int,
    keyword_parameter_1: str = '',
    keyword_parameter_2: str = '',
):
  ...
```
The following style is permitted when the line is broken exactly once:
```python
result = function_call(
    argument_1, argument_2, argument_3, keyword_parameter=value
)
```
Do **not** use bracket-aligned indentation like this:
```python
for kw in ['if', 'elseif', 'else',
           'while', 'for', 'foreach']:
```
Do **not** split a sequence up into multiple lines and simultaneously define multiple items one the same line. The following is wrong:
```python
list = [
  'foo', 'bar', 'baz',
  'bam', 'goo', 'bor',
]
```
Similarly, for lists, tuples, sets, there are only two valid formatting strategies.
Either, all items fit on one line:
```python
literal = [value1, value2, value3]
```
or similarly:
```python
long_or_heavily_indented_literal = [
  value1, value2, value3, value4, value5, value6, value7
]
```
When more than one line is required to fit the values within the 120 character limit, 
each item must be on a separate line, with trailing comma in the last line:
```python
literal = [
  value1,
  value2,
  value3,
]
```
Notably: **No** property makes items exempt from the one item per line rule.
For absolutely no reason may items be grouped on one line when there are multiple lines in a sequence definition.

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

For generating documentation, we use pdoc3.
You can include references to other functions or classes in the project by using their full module path in backticks.
For example:
```python
def parse_foo_header(data: bytes):
  """
  Uses `refinery.lib.structures.StructReader` to parse the FOO header.
  """
```

When referencing code elements or showcasing code in a docstring, the following rules apply:
- Inline code fragments should not exceed 25 characters in length.
- Inline code fragments are placed in **single** backticks. Do not use more unless you have to encode a backtick.
- Code that spans multiple lines or exceeds 25 characters is indented by 4 space characters.

An example for a larger code reference in a docstring:
```python
def parse_foo_header(data: bytes):
  """
  Uses `refinery.lib.structures.StructReader` to parse the FOO header. The header has the following
  structure:

    [ VERSION ]
    [ FOOTYPE ]
    [  CODEC  ]
    [ CONTENT ]
  
  Each of these items is a 32-bit unsigned integer.
  """
```

### Dictionaries

When typing large dictionaries, the omission of `E203` is to allow you to align the values;
this is done by aligning the colons to the same character depth:
```python
data = {
    'key1'         : 'data1',
    'a-longer-key' : 'data2',
    'other-key'    : 'data3',
}
```
This can make large dictionaries with somewhat tabular data easier to read in the code.
When aligning values like this, do **not** place the colon right after the key;
that would generate a linter error. Instead, align the colons as shown above.

### Multi-Line Conditions

For multi-line conditions, always use this pattern:
```python
if (
  condition1
  and condition2
  and condition3
):
  ...
```
To summarize:

1. A parenthesis opens directly after the control-flow statement (`if`, `elif`, `while`).
2. Conditions are indented exactly one level and lead with the logical operator.
3. The end of the condition is only the closing parenthesis and a colon, not indented.

Do **not** use this style:
```python
if (condition1
    and condition2):
  ...
```
where separate lines of the condition are indented further than one level. 

## Paradigms

### Minimizing Copies

All code in binary refinery aims to minimize the number of byte copy operations. To this end:

- Make functions as flexible as possible when it comes to what they accept as input;
  Allow `memoryview` inputs wherever possible.
  You can use `codecs.decode` to decode `memoryview` objects to strings,
  and the `refinery.lib.id` module contains methods `buffer_offset` and `buffer_contains` 
  which allow you to search within `memoryview` objects.
- For the top-level entry points of an API, allow `bytes | bytearray | memoryview` as input 
  and pass on `memoryview` objects to subroutines when possible.
- When binary buffers have to be sliced, a `memoryview` is the best choice since slicing it has no memory cost.
- Building output should always be done in a `bytearray`, never by concatenating `bytes` objects.
- Returning `bytearray` objects rather than `bytes` is always acceptable; the two types expose the same API.

When accepting `bytes | bytearray | memoryview` but only requiring a `memoryview` internally,
 cast your input to `memoryview` unconditionally at the start of your function:
```python
def _input_agnostic_function(data: bytes | bytearray | memoryview):
    view = memoryview(data)
    # work only with view
```
Never use the following pattern:
```python
  view = memoryview(data) if not isinstance(data, memoryview) else data
```
Producing a `memoryview` from an existing `memoryview` is cheap. 
Doing it unconditionally helps the type checker and any human reader.

### Structured Data

Data transfer object should not be stored in Python dictionaries.
It should use a `dataclass` or `NamedTuple` with clear type hints instead.
Do not use opaque string or integer literal constants for what can be captured by an `Enum`. 

For parsing structured data, the standard interface is `Struct[memoryview]` from `refinery.lib.structures`.
This should usually be preferred over manual parsing using offset calculations and the `struct` module.

### Format Strings and String Format

All strings use single quotes, except for docstrings, which use three double quotes.
When possible, strings should not be concatenated with string literals,
 F-Strings should be used instead.
Note that f-strings use an uppercase `F` prefix, not lowercase `f`.
For example, the code 
```python
message = 'Hello, ' + world + '\n'
```
should be replaced with:
```python
message = F'Hello, {world}\n'
```

[flake8]: https://pypi.org/project/flake8/