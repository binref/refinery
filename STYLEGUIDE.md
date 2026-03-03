# Style Guide for Binary Refinery

This document is the style guide for all code in Binary Refinery.

## Flake8 Specification

First and foremost, all code should pass [flake8], with the following tests disabled:

- Disabled to allow command line argument annotations to work:
  - `F821` (undefined name)
  - `F722` (syntax error in forward annotation)
- Disabled because the maintainer doesn't like them:
  - `E128` (continuation line is under-indented for a visual indentation)
  - `E203` (colons should not have any space before them)
  - `E261` (at least two spaces before inline comment)
  - `W503` (line break occurred before a binary operator)

## Rules and Paradigms

### Comments

Comments should be avoided wherever it is possible and used only when important information about the code cannot be communicated otherwise.
Prioritize expressive, well-structured code and comprehensive naming of variables and functions.

### Line Breaks

All code in refinery uses LF line breaks exclusively, never CR/LF.

### Line Length

All lines should wrap at **100** characters.
This is a hard limit for docstrings and comments, and a soft limit for code.
The hard limit for code is at **140** characters to allow for occasional long lines.

When a function call becomes too long for the line width limit, it should be split like so:
```python
result = function_call(
  argument_1,
  argument_2,
  keyword_parameter_1=keyword_argument_1,
  keyword_parameter_2=keyword_argument_2,
)
```
Or like this, but only when two lines are sufficient:
```python
result = function_call(argument_1, argument_2, argument_3,
  argument_4, keyword_parameter_1=keyword_argument_1, keyword_parameter_2=keyword_argument_2)
```
In either case, the indentation after a line break is increased by exactly one block width,
not up to the opening parenthesis in the line above.

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
  
[flake8]: https://pypi.org/project/flake8/