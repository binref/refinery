# Agent Checklist

- Read [README](README.md) to understand the project goal and design.
- Read the [STYLEGUIDE](STYLEGUIDE.md) and make sure that all written code is compliant with it.

# Development

- Always run your tests using `pytest -n auto`, the development machine has a lot of CPU cores and running the
  tests in parallel saves a lot of time.
- Use the `temp` subdirectory of the project root for creating temporary scripts and files.
  When generating samples for testing, create a subfolder in `temp` with an appropriate name and place your data in there.