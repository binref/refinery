# Agent Checklist

- Read [README](README.md) to understand the project goal and design.
- Read the [STYLEGUIDE](STYLEGUIDE.md) and make sure that all written code is compliant with it.

## Style Rules That Differ From PEP 8

The following rules contradict common Python conventions. Check them explicitly:

- **DO NOT** use lowercase `f'...'` for f-strings. Use uppercase: `F'...'`.
- **DO NOT** write single-line docstrings like `"""text"""`. Always use:
  ```python
  """
  text
  """
  ```
- **DO NOT** align continuation lines to the opening bracket:
  ```python
  # WRONG:
  x = function(arg1,
               arg2)
  for k in [1, 2,
            3, 4]:
  ```
  Use one-level indentation with closing bracket on its own line.
- **DO NOT** put conditions on the same line as `if (`:
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
- **DO NOT** use double quotes for strings. Single quotes only (except docstrings).
- **DO NOT** use `Optional`, `Union`, or `List` from `typing` in annotations. Use `X | None`, `X | Y`, `list[X]`.
- **DO NOT** write comments unless the information absolutely cannot be communicated by naming or structure. Never write comments that reference external source code.

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
- **Important.** The following rule is **essential**:
  When running commands, use only Python.
  Run only `python [path]` where `[path]` is the full path to your (temporary) script.
  Do **not** run other shell commands, do **not** use output redirection, and do **not** use compound commands
  where, e.g. you first run `cd` to change the working directory.
  Handle everything you need to do inside the script.
- When making commits on the user's behalf, do not include a comment about AI co-authorship.
- When asked to commit changes to git, only use one-line commit messages.

# Bug Fixing

When fixing bugs, always prioritize overall code quality and architecture:

- Never choose a quick or simple fix that is overly focused on the specific bug.
- Always take the time to identify root issues.
- Make structural changes by refactoring code if this allows you to fix bugs in a cleaner way.
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