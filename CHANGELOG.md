# Binary Refinery Changelog

## Version 0.3.7
- Removes the `--install-option` capability introduced in 0.3.5, see [pip/#8748](https://github.com/pypa/pip/issues/8748) for more information.
- The `xttar` unit was added.
- The `lzma` unit can now return partial results for buffers with junk bytes at the end.

## Version 0.3.6
- The `ifrex` unit was added.
- The `jvstr` unit was added.
- A source distribution manifest was added to fix errors that occurred during source installs.

## Version 0.3.5
- Using `pip install --install-option=library binary-refinery` or a `REFINERY_PREFIX` environment variable with value `!` will now install the binary refinery without any command line scripts, only as a library.

## Version 0.3.4 - bugfix release

## Version 0.3.3 - bugfix release

## Version 0.3.2
- It is now possible to use local refinery units (i.e. a Python script in the current director which contains a refinery unit that is not abstract) for multibin prefixes and in any other situation where units are dynamically loaded.
- The `pesect` unit was added.
- The `resub` and `resplit` units no longer offer options that have no bearing on their behavior.
- The `lz4` unit was added with a pure Python implementation of LZ4 decompression.
- The `jvdasm` unit for disassembling Java class files was added.

## Version 0.3.1 - bugfix release

## Version 0.3.0
- The `autoxor` unit was added.
- The `cfmt` unit was added.
- The License of Binary Refinery was changed to 3-Clause BSD.

## Version 0.2.1
- The `netbios` unit was added.
- The `stretch` unit was added.
- The `hc128` cipher unit was added.
- The unit `dnrc` was split into `dnrc` for extracting .NET resources and `dnmr` for unpacking managed .NET resources.
- Several units that extract items from container formats have received a unified interface. So far, this interface applies to `xtmail`, `xtzip`, `winreg`, `dnfields`, `dnrc`, and `dnmr`.
- When using named match groups for the `rex` unit, these matches are now forwarded as metadata within frames.
- The `xtzip` unit was given an optional archive password parameter.
- The `xtmail` unit can now extract headers in text and json format.

## Version 0.2.0
- Test coverage was increased
- The `recode` unit can now autodetect input encoding.
- Several bugfixes were performed on the `vbe` unit.
- More bandaids were added to PowerShell deobfuscation.
- The `pestrip` and `peoverlay` units were added.
- Interface retrofitting was completed.

## Version 0.1.9
- Fixes a tiny bug in the PyPI display of the readme file, and completes changelog from previous version.

## Version 0.1.8
- The `rsa` unit was improved and can handle the Microsoft blob format now.
- PowerShell deobfuscation was improved, but that doesn't change the fact that this would be much better with a proper parser.
- The `b32` for base32 encoding and decoding was added.
- Preliminary support for meta variables has been added with the `mpush`, `mpop`, and `mput` units. This feature is experimental and not well documented yet.
- The `--squeeze`/`-Z` option was added to all units that produce multiple outputs: It disables the default separation of these outputs by line breaks.
- Pattern extraction units such as `rex` will now preserve the order of extracted strings, even when the `--longest` option is used.
- The suggested `PATH` environment variabe modification from the Linux installer script was corrected; The previous variant would make the refinery virtual environment take precedence over the global python executables.

## Version 0.1.7
- The `dump` unit has been refactored to make it easier to use; Formatting of file names is done automatically now unless the flag `-p` or `--plain` is specified to prevent string formatting.
- The `snip` unit can now remove bytes from the input.
- The `dnfields` unit was added.
- The `ppjson` unit can now minify json by specifying `0` as the desired indentation width.
- The `dsjava` unit was improved, although it remains a work in progress.
- The `fread` unit received a linewise mode.

## Version 0.1.6
- After some incomplete attempts to improve backwards compatibility, the package now simply requires Python 3.7.

## Version 0.1.5
- Units can now be written with a Python `__init__` constructor and deduce the command line interface from this constructor. A decorator class was added to help enriching the parameter list of the constructor with information on how to translate these into command line parameters. The goal is to eventually retrofit all units to follow this standard.
- The `pemeta` unit has more features now.
- The `couple` unit was added; it is an adapter to turn any stdin/stdout based command line tool into a refinery unit.
- The `carve-xml` unit was added.
- The `dnstr` unit was added.

## Version 0.1.4
- All hashing prefixes for multibin expressions have been implemented as separate units, i.e. `sha256` and `md5` are now units that output the corresponding hash of the input data.
- The `xtmail` unit was added which can extract the body and attachments of email documents, both Outlook and MIME formats.
- The framed format was extended with rudimentary support for metadata in framed chunks. This is currently used by the `xtzip` and `xtmail` units to attach a `name` property to emitted chunks which contains the file name information from the parsed data. The `dump` unit now has a `--meta` option to read this `name` property and use it as the file name for dumping. The `--meta` options defaults to using the SHA256 hash of the data as the file name if no corresponding metadata is present.
- The `pemeta` unit was added.
- The `carve-json` unit was added.
- The `peslice` and `elfslice` units were given a unified interface.
- The `b85` for base 85 encoding an decoding was added.

## Version 0.1.3
- Fixes a bug in the .NET header parser where the tables were sometimes parsed in the wrong order.

## Version 0.1.2
- The `xtzip` unit has been added, which can extract data from zip archives.
- The `carve-zip` unit has been added. It can carve ZIP files from buffers, similar to `carve-pe` for PE files.
- The `rsa` unit has finally been added.
- The `rncrypt` unit has been added.
- The `dncfx` unit has been added; it extracts the strings from ConfuserEx obfuscated .NET binaries.
- Adds support for TrendMicro Clicktime URL guards in the `urlguards` unit.

## Version 0.1.1
- Several tests were added, testing now uses [malshare][] to test units against real world samples. To properly execute tests, the environment variable `MALSHARE_API` needs to contain a valid [malshare][] API key.
- A `numpy` import that always occured during any unit load was moved into the `peek` unit code to reduce import time of other units.
- Issues with wheel installation on Windows were fixed.

## Version 0.1.0
- It is now possible to instantiate units in code with arguments of type `bytes` and have it work as expected, i.e. `xor(B's3cr3t')` will construct a `xor` unit that decrypts using the byte string key `s3cr3t`.
- The `rex` unit can now apply an arbitrary number of transformations to each match and return the results as separate outputs.
- The `urlguards` unit now supports ProofPoint V3 guarded URLs.
- Thanks to the recent fix of [#29][javaobj-issue-29] in [javaobj][], the `dsjava` (deserialize Java serialized data) unit should now work. However, since there are currently no tests, bugs should be expected.

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
[javaobj-issue-29]: https://github.com/tcalmant/python-javaobj/issues/29
[javaobj]: https://pypi.org/project/javaobj-py3/
[malshare]: https://www.malshare.com/