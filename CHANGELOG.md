# Binary Refinery Changelog

## Current Build
- This changelog was added.
- The unit `jsonfmt` has been renamed to `ppjson` (for **p**retty-**p**rint **json**).
- The unit `ppxml` (**p**retty-**p**rint **xml**) was added.
- The unit `carve-pe` (carve PE files) was added.
- The unit `winreg` (read windows registry hives) was added, also adding a dependency on the [python-registry][] package (also [on GitHub][python-registry-gh]).
- .NET managed resource extraction was improved, although it is still not perfect.
- The unit `sorted` now only sorts the chunks of the input stream that are in scope.
- The unit `dedup` can no longer sort the input stream because `sorted` can do this.
- PowerShell deobfuscation and their test coverage was improved.


[python-registry]: https://pypi.org/project/python-registry/
[python-registry-gh]: https://github.com/williballenthin/python-registry