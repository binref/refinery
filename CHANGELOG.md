# Binary Refinery Changelog

## Current Build
- The `rex` unit can now apply an arbitrary number of transformations to each match and return the results as separate outputs.

## Version 0.0.6
- Processing of data in frames is no longer interrupted by errors in one unit.
- The global `--lenient` (or `-L`) flag has been added: It allows refinery units to return partial results. This behavior is disabled by default because it usually means that an error occurred during processing.
- The virtual environment setup script has received bug fixes for problems with absolute paths.

## Version 0.0.5
- This changelog was added.
- The unit `jsonfmt` has been renamed to `ppjson` (for **p**retty-**p**rint **json**).
- The unit `ppxml` (**p**retty-**p**rint **xml**) was added.
- The unit `carve-pe` (carve PE files) was added.
- The unit `winreg` (read windows registry hives) was added, also adding a dependency on the [python-registry][] package (also [on GitHub][python-registry-gh]).
- .NET managed resource extraction was improved, although it is still not perfect.
- The unit `sorted` now only sorts the chunks of the input stream that are in scope.
- The unit `dedup` can no longer sort the input stream because `sorted` can do this.
- PowerShell deobfuscation and their test coverage was improved.
- Cryptographic units have been refactored; the `salsa` and `chacha` units now take a `--nonce` parameter rather than an `--iv` parameter, as they should.


[python-registry]: https://pypi.org/project/python-registry/
[python-registry-gh]: https://github.com/williballenthin/python-registry