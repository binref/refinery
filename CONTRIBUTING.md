# Contributing to Binary Refinery

Thank you very much for considering to contribute some code to the refinery!

## Development Process

The following is a brief overview of the development process of the toolkit:

- All development is done on the single and only maintained branch.
- Each refinery unit is housed in its own module. One simple example is [b64].
- The tests for each unit are housed in an equivalently named module in the [test] directory. For an example, look at [the tests for b64](test/units/encoding/test_b64.py).
- GitHub's continuous integration tooling is used on each commit to check whether the toolkit is functional by running the entire test suite.
- If the maintainer decides to publish a new version, they perform the following steps:
  - A new version number is chosen.
  - All changes since the last release are summarized in the [CHANGELOG](CHANGELOG.md) under that new version number.
  - The `__version__` variable in [refinery/\_\_init\_\_.py](refinery/__init__.py) is adjusted to reflect the new version.
  - These changes are committed and the commit is tagged with the new version number.
  - As a result, [a GitHub action](.github/workflows/publish.yml) is triggered to publish the new version to [pypi].

## What to Contribute

Bugfixes and suggested performance improvements are always welcome.
For contributions that extend the feature set, i.e. most likely by contributing a novel unit,
please make sure the following conditions are satisfied:

- There is a conceivable requirement for this unit in the context of binary analysis and malware triage. 
  A user story is very welcome so the maintainer can more easily understand the relevant use cases.
- The unit is not replaceable by a reasonable pipeline of existing refinery units.
  Clearly, it is very debatable at which point a substitute pipeline is beyond reason;
  this might require discussion.

## How to Contribute

If you would like to contribute to the development, here are a few things that you can do to make the PR go through more smoothly:

- Before writing a lot of code, it is recommended to open an issue first:
  The maintainer is opinionated and might reject your code or ideas for any number of reasons.
- For contributions of new units, please only submit one single unit per pull request.
- For other contributions, use your loaf.
- Write a test. If you would like to test against a larger file,
  you can ask the maintainer to upload the sample to the
  [refinery test data repository](https://github.com/binref/refinery-test-data)
  so you can reference it by hash in your test.
  For an example, look at the [test for jcalg](test/units/compression/test_jcalg.py).
- Make sure that you stick to the style guide;
  refinery code should pass [flake8], with some tests disabled.

You do not have to worry about the following [flake8] tests:

- The following tests are disabled to allow command line argument annotations to work:
  - `F821` (undefined name)
  - `F722` (syntax error in forward annotation)
  - `E704` (multiple statements on one line (def))
  - `E701` (multiple statements on one line (colon))
  - `E128` (continuation line is under-indented for a visual indentation)
- The following tests are disabled because the maintainer doesn't like them:
  - `W503` (line break occurred before a binary operator)
  - `E203` (colons should not have any space before them)



[b64]: refinery/units/encoding/b64.py
[flake8]: https://pypi.org/project/flake8/
[pypi]: https://pypi.org/project/binary-refinery/
[test]: test/