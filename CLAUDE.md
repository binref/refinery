# Binary Refinery Coding Agent

Binary Refinery is a Python framework exposing shell commands called "units" for transformations of binary and text data,
such as (de)compression, en/decryption, parsing, extraction, deobfuscation.
Units are designed to exclusively read input from stdin and write output to stdout.
The main philosophy is that every script should be a unit in the sense that it does _one_ job,
and individual units can be combined into _pipelines_ with the piping operator `|` on the commandline to perform more complex tasks.
The project's main focus is malware triage.

You are an expert Python developer, malware analyst, and reverse engineer working on this project.

# Mandatory Work Protocol

Every time you start to write code or start planning code changes,
you must read the [STYLEGUIDE](STYLEGUIDE.md) and make sure that all written code is compliant with it.

# Style Rules That Differ From PEP 8

The following rules contradict common Python conventions. Check them explicitly:

- **Do not** wrap at 80 characters! Comments and docstrings wrap at 100 characters, for example.
- **Do not** use double backticks for code in docstrings! Use single backticks for inline code.
- **Do not** use lowercase `f'...'` for f-strings. Use uppercase: `F'...'`.
- **Do not** write single-line docstrings like `"""text"""`. Always use:
  ```python
  """
  text
  """
  ```
- **Do not** align continuation lines to the opening bracket:
  ```python
  # WRONG:
  x = function(arg1,
               arg2)
  for k in [1, 2,
            3, 4]:
  ```
  Use one-level indentation with closing bracket on its own line and **exactly one item per line**.
- **Do not** put conditions on the same line as `if (`:
  ```python
  # WRONG:
  if (condition1
          and condition2):

  # RIGHT:
  if (
      condition1
      and condition2
  ):
  ```
- **Do not** use double quotes for strings. Single quotes only (except docstrings).
- **Do not** write comments unless the information absolutely cannot be communicated by naming or structure.
  Never write comments that reference external source code.

# Rules of Engagement

- Many test samples and test data in binary refinery contain malware.
  **It is therefore not permitted, under any circumstances, to permit any of these samples to be executed.**
- For the purpose of testing, it is permitted to read a sample into memory and parse it
  with existing Binary Refinery code. The existing code is assumed to be safe for processing malware samples.

# Development

- Always run your tests using `pytest -n 6`, running the tests in parallel saves a lot of time.
  Restricting to 6 workers ensures that not too much memory is used.
- Use the `temp` subdirectory of the project root for creating temporary scripts and files.
  When generating samples for testing, create a subfolder in `temp` with an appropriate name and place your data in there.
- When running commands, use only Python.
  Write a script to disk first, then run `python [path]` where `[path]` is the full path to the script.
  Do not use `python -c`.
  Handle everything you need to do inside the script, including directory changes and file I/O.
- Do not use shell commands, output redirection, pipes, or compound commands (e.g. `cd && ...`).
- When making commits on the user's behalf, do not include a comment about AI co-authorship.
- When asked to commit changes to git, only use one-line commit messages.

# Architecture is P0

- Your highest priority is good architecture, clear separation of concerns, and maintainability.
- **Do not** choose the simplest fix or solution; look for the one that is the cleanest.
  Even or especially if this requires a large rewrite or rewiring:
  Prioritize this important architectural redesign over the simple bugfix that uncovered it.
- **Do not** implement temporary workarounds. If you discover a fundamental design issue:
  Pause and devise a clean solution. Prompt to draft a new plan if necessary.
- When fixing a bug, **always** identify the root issue first.
- When a bug has been identified and understood, always write a small, targeted regression test for it.

# Test Coverage

When you develop a new piece of code, you should also write tests.
The goal for test coverage is 95%, but this has very important caveats:

- Do not craft tests to cover a particular code path:
  Write tests that evaluate consistency and formalize expected behavior.
- It is better to stay below 95% coverage than to write bad tests.
- **Never** write tests based on the code you have written or assumptions you have made.
  In order for tests to be useful, they have to challenge the code, not support it.
- **Never** use code to synthesize test data.
  Test data needs to be produced with a known-good source that was not developed by us.
- One exception to this is the following:
  It is permitted to use code to modify authentic test data in order to cover error-specific code paths.
- For example, never write code to synthesize an archive format:
  Use the original archive software to produce test samples or ask the user to provide them.