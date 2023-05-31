# Binary Refinery Changelog

## Version 0.6.8
- The `pestrip` unit has received some improvements and bugfixes; it should work more reliably now against bloated sections and resources.
- All stream cipher units have been given the `--discard` option which allows you to discard an arbitrary number of initial bytes from the keystream.
- Call tracing has been removed from `vstack`; it never really worked in practice and would require a lot more effort to do properly.

## Version 0.6.7
- The `pack` unit can now also pack lists of floating-point numbers.
- The unit `chaskey` was added to support this cipher; it is used by the Donut framework.

## Version 0.6.6
- A minor bug was fixed in `pemeta` that prevented some signatures from being parsed correctly.
- Archive extraction utilities now escalate fuzziness in 3 stages rather than just 2.

## Version 0.6.5
- Slightly improves the script extraction and formatting in `xtmsi`.

## Version 0.6.4
- The `xtdoc` unit now demangles file names in MSI archives correctly.
- The `xtmsi` unit was added for extracting MSI files and also stream metadata in a synthesized JSON document.
- The `csv` unit now has a reverse operation to convert simple JSON documents back to CSV format.
- Thanks to [@larsborn][], the `tnetmtm` unit was added for parsing MITMProxy traffic capture files.

## Version 0.6.3
- The `xtnode` unit was added for extracting the contents of Node.js executables created with `pkg` or `nexe`.
- The `xtzip` unit now supports AES-encrypted archives via the `pyzipper` module.

## Version 0.6.2 - bugfix release

## Version 0.6.1 - bugfix release

## Version 0.6.0
- The AutoIt decompiler unit `a3x` was added.
- Path extractor units have been reworked to be more consistent about when and when they do not use fuzzy matching on paths. Switches have been added to control this behavior.

## Version 0.5.10
- The `tea` and `xtea` units now have a `--swap` switch which allows to switch them from little endian to big endian mode.
- The `xxtea` unit was re-worked to support being used as a proper block cipher. This is enabled by specifying the block size using the `--block-size` argument. By default, `xxtea` will continue to operate on the input as a single block: This is how XXTEA is often used in malicious samples.
- The `rc5` and `rc6` units have been updated to support the `--segment-size` option for CFB mode.

## Version 0.5.9 - bugfix release

## Version 0.5.8 - bugfix release

## Version 0.5.7
- The `pestrip` and `peoverlay` default settings are the same again.

## Version 0.5.6
- The `pestrip` unit has been extended with the capability to strip bloated resources and sections.
- The `xtone` unit was added to extract embedded files from OneNote documents.
- The color legend of the `iemap` unit is now optional and can be enabled with a switch.

## Version 0.5.5
- Bugfix to account for changes in MacOS libmagic which lead to not correctly identifying `exe` and `dll` extensions.
- Importing refinery no longer changes the names of log levels globally.

## Version 0.5.4
- The `xthtml` unit can now extract attributes of HTML tags.
- The `rijndael` cipher unit was added.

## Version 0.5.3 - bugfix release

## Version 0.5.2
- The `lzg` unit was added.
- The `lzf` unit received several bugfixes and now supports the chunked format produced by the command-line `lzf` tool.
- The `ntlm` hash unit was added (thanks to @m0rv4i for the contribution)
- The `vmemref` and `vstack` units were added; both are still experimental and not thoroughly tested.
- The `min` and `max` units were added to simplify the pattern `sorted [| pick 0 ]` to a single unit.

## Version 0.5.1 - bugfix release

## Version 0.5.0
This release changes the way in which meta variables are handled, they now have a scope:
- By default, variables cease to exist when the frame ends in which they were defined.
- Variables remain visible in child frames.
- When a variable is re-defined in a child frame, this definition shadows the previous one: When the child frame ends, the variable is restored to the value it had in the parent frame.
- Some units like `pop` can propagate variables to the parent scope as well.
- The units `mvg` and `mvc` were introduced to manage scoping of variables, the unit `wm` was removed.

Changes unrelated to meta variable redesign:
- The unit `vaddr` was added to convert integer meta variables from virtual address to file offset and vice versa.

## Version 0.4.49
- The `pkcs7sig` unit was added.
- The `pemeta` unit now also displays the module name stored in the export directory.
- The `dedup` unit now uses MD5 instead of Python's built-in hash function because of the high risk of collisions.

## Version 0.4.48
- Block cipher unit backed by [pycryptodome][] (i.e. `aes`, `des`, `des3`) now support additional arguments for some of the less commonly used block cipher modes.
- The `rsa` and `rsakey` unit now also support a simple key format of the form `[modulus]:[exponent]` where both `modulus` and `exponent` are hex-encoded numbers in big endian representation for a textbook RSA round.
- The `perc` unit now has the `--pretty` option to fix bitmap and icon resources by adding the necessary headers (which are missing from the raw resource data).
- The `pcap` and `pcap-http` unit now sort streams by the occurrence of the first packet.

## Version 0.4.47
- By default, the `ef` unit does no longer use glob-patterns on posix systems. The behavior can be explicitly adjusted using new command-line flags.
- Adds the `queue` unit.
- The names of urlencode patterns for `carve` were shortened.
- Adds the `xtnsis` unit to the units used in `xt`.
- The `pemeta` unit has improved RICH header data and displays RICH header counts.

## Version 0.4.46 - bugfix release

## Version 0.4.45 - bugfix release

## Version 0.4.44
- Adds the `lzf` unit for LZF compression and decompression.

## Version 0.4.43
- Adds the `qlz` unit for QuickLZ decompression.

## Version 0.4.42 - bugfix release

## Version 0.4.41
- Adds the `carve-lnk` unit to carve Windows Shortcut files.
- Adds the `carve-rtf` unit to carve RTF documents.
- Adds the `subfiles` unit which unifies all structured file format carvers.
- The `b64` unit now automatically detects and switches to the urlsafe encoding variant.
- Adds the `xtnsis` unit which can extract files from NSIS archives and provide a rudimentary disassembly of the setup script.
- Adds the `ifps` and `ifpsstr` units to disassemble and extract strings from compiled Pascal script files.

## Version 0.4.40 - bugfix release

## Version 0.4.39
- Adds the `vbapc` and `vbastr` units which can extract (decompiled) VBA p-code and VBA strings from (potentially stomped) Word documents.
- Adds the somewhat experimental `xkey` and `autoxor` units that can (sometimes) automatically decrypt XOR-encrypted files using frequency analysis. These units are still work in progress, though.
- Adds the `mscf` unit which implements part of the Microsoft Compression API formats, with LZMS currently missing.
- Adds the `b58` unit which does base58 encoding (used to encode Bitcoin addresses, for example). Simultaneously, the `base` unit was adjusted to no longer strip leading zero bytes unless explicitly instructed to do so.
- Adds variable conversions to `pop`: It is now possible to prefix a variable with a sequence of multibin handlers to convert input data before storing it in the variable.
- When executing the `put` unit without a second argument, it now stores the contents of the current chunk in the specified variable.

## Version 0.4.38
Fixes a critical bug in the meta variable propagation logic.

## Version 0.4.37
- Adds the `jcalg` unit.
- Adds the `byteswap` unit.

## Version 0.4.36 - bugfix release

## Version 0.4.35
- Adds the `lzip` unit.
- Reworks the `serpent` unit to work with real-world examples and adds a `--swap` option to change the block byte order to become compatible with other implementations.
- Changes the `peek` design and fixes problems with colored output on Windows.

## Version 0.4.34 - bugfix release

## Version 0.4.33 - bugfix release

## Version 0.4.32 - bugfix release

## Version 0.4.31
- The (still somewhat experimental) `xt` unit was added which attempts to extract data from known archive formats.
- The `xtasar` unit was added which can extract data from ASAR files.
- The `lnk` unit was added which is a thin wrapper around the LnkParse3 library which extracts metadata from Windows shortcut files.
- The `urlfix` unit was added which can strip URL indicators of fragments and query strings.
- The `iff` unit has gained several new features.
- The `xjl` unit was added, it converts JSON-lists to a sequence of JSON chunks.
- The `xvar:` handler was renamed to `eat:` (it is similar to `var:`, except that it removes the variable after use).
- The `xlxtr` unit now supports XLSB format by virtue of the pyxlsb2 library.
- The `base32` unit was made more robust against invalid paddings.
- The `peek` unit design was changed yet again and colorization was added to the hexdump preview. It can be disabled through the `-g` switch.

## Version 0.4.30 - bugfix release

## Version 0.4.29
- Unit execution time has been improved significantly.
- The `rc5`, `rc6`, and `xxtea` cipher units were added.

## Version 0.4.28
- Adds the option to completely disable the PowerShell band-aid introduced in 0.4.27 to allow using the `Use-RawPipeline` module.

## Version 0.4.27
- Adds several VBA/VBS deobfuscation units and a `deob-vba` unit that applies all of them, similar to `deob-ps1`.
- Adds the `camellia` cipher unit.
- Adds the new `struct` unit format character `w` for decoded wide strings.
- The `dnfields` unit was extended and now also extracts string fields which are assigned a unique value.
- Implements a better PowerShell band-aid and displays a warning message.

## Version 0.4.26
Adds various convenience output options in the Python REPL and adds documentation for those.

## Version 0.4.25 - bugfix release

## Version 0.4.24
- Adds the `szdd` decompression unit.
- Adds the `lzjb` decompression unit.
- Adds an option to the `iff` unit to check for the existence of a certain meta variable.
- The `xtpyi` unit now uses both `uncompyle6` and `decompyle3`, even though they currently appear to have feature parity at best - there is some hope that one of them will support Python 3.9 in the future.
- Adds the `groupby` unit.
- Adds the `isaac` cipher unit.
- Adds the `bat` unit for deobfuscating batch scripts.

## Version 0.4.23 - bugfix release

## Version 0.4.22
- Adds the `ripemd160` and `ripemd128` units.
- Adds the `xtw` unit for extracting cryptocurrency wallet addresses.
- Adds the `iemap` unit to display a colored entropy heatmap.
- Introduces new syntax to the `struct` unit for handling byte alignment.
- The `rsakey` unit supports a new option to output the public key portion of a private key.
- The `pemeta` unit now computes the size of the PE file based on header information.
- Several switches for comparison operators were added to the `iff` unit.

## Version 0.4.21
- Thanks to [@baderj][], the unit `xlmdeobf` was added which wraps the extremely useful [XLMMacroDeobfuscator][] tool for extracting and deobfuscating Excel V4 macros.
- Adds the `carve-7z` unit for carving 7zip archives from blobs.

## Version 0.4.20
- Renames the `blockop` unit to `alu`.
- Removes the shortcut unit `carveb64z`.
- Renames a number of command-line switches for `carve`, `xtp`, and other pattern extraction units.
- Adds a default argument to `resub` that makes it strip whitespace from the input by default.

## Version 0.4.19
Improves performance by replacing an import of `pkg_resources` with equivalent functionality from `importlib`. On a test machine, this removes between 250 and 500 milliseconds from the execution time of any single unit.

## Version 0.4.18
Changes the format for the binary formatter used in `struct`, `rex`, `resub`, and `cfmt`. It now uses a reverse multibin handler instead of parsing the modifier like a command-line pipeline.

## Version 0.4.17 - bugfix release

## Version 0.4.16 - bugfix release

## Version 0.4.15 
- Adds the `lzo` unit

## Version 0.4.14
- The `winreg` unit is now able to extract data from Windows registry editor exports (i.e. `.reg` files).
- The key derivation units `pbkdf2` and `pbkdf1` use a more forgiving decoder to better cover the `Rfc2898DeriveBytes` class, which offers a call signature that receives an arbitrary byte string as password.
- The `string` regular expression pattern now excludes literal line breaks within the string.

## Version 0.4.13
- Base64 regular expression patterns were improved to account for correct character counts.
- The `dexstr` unit was added.
- The `index` meta variable is now automatically populated within frames.
- The `n40` string decryption unit was added.
- The `xtpyi` unit now extracts Python disassembly when decompilation fails.
- The `lzma` unit now correctly decompresses output produced by PyLZMA.

## Version 0.4.12 - bugfix release

## Version 0.4.11
- The `doctxt` unit was added; courtesy of [@baderj][]

## Version 0.4.10 - bugfix release

## Version 0.4.9 - bugfix release

## Version 0.4.8
- Adds the `serpent` unit.

## Version 0.4.7
- Adds the `xtpdf` unit for extracting embedded objects from PDF documents.
- The `accu:` handler now supports pre-configured finite state machines for well-known `rand()` implementations.

## Version 0.4.6
- The `officectypt` unit now supports the Excel default password `VelvetSweatshop`.
- The `ci` property has been removed from the output of `peek --meta`.
- The following units were added: `xj0`, `evtx`
- The `hexdmp` unit was renamed once more to `hexload`, and its pattern matching was improved.
- The `asm` unit was completely redesigned using an Angr-based fallback to produce better disassembly.
- The `pcap-http` unit now extracts the URL from whence the data was downloaded.
- The `rep` unit received some performance improvements.
- The refinery dependencies were cleaned up considerably.
- Blockwise operations no longer require numpy to be reasonably fast by implementing a dynamic inlining step.

## Version 0.4.5
- Adds the `cswap` unit.
- The index counter of `blockop` now starts at zero.
- An option was added to the `swap` unit to swap the contents of two meta variables. This can also be used to rename a meta variable.
- An option was added to `xtpyi` to unpack, but not decompile the contents of a PYZ.
- Adds the `--bare` option to `esc` and uses it in `peek`.
- Adds the `--meta` option to `ef`. The `ef` unit now also descends into dot-directories and lists dot-files.
- The `__init__.pkl` file containing the unit lookup cache was moved into the distribution.

## Version 0.4.4
- Adds the `xtvba` unit to extract Office document macros.
- Adds the `pcap` unit to extract TCP streams from packet capture files.
- Adds the `xthtml` unit to extract components of HTML documents.
- The `htm` unit has been renamed to `htmlesc`.
- The default sort order of `sorted` has been changed to descending.
- The `pemeta` and `pkcs7` units now also extract certificate thumbprints.

## Version 0.4.3
- Fixes an issue with applying `ppjscript` to obfuscated JavaScript files.
- Adds Murmur Hash units
- Adds `xtpyi` unit to extract PyInstaller-packed archives.
- Logging now uses the Python `logging` module.

## Version 0.4.2 - bugfix release
## Version 0.4.1
- Significantly improves unit loading time which had regressed due to the changes in 0.4.0.

## Version 0.4.0
This release removes the `setup-venv` helper scripts and instead uses a slightly less ugly hack to resolve dependencies before running the refinery setup by declaring every dependency a build dependency in `pyproject.toml`. Any kind of installation should work seamlessly through `pip`.

## Version 0.3.38 - bugfix release
Updates build system.

## Version 0.3.37 - bugfix release

## Version 0.3.36 - bugfix release

## Version 0.3.35 - bugfix release
## Version 0.3.34
- Fixes critical bug in deployment.
- Adds the `msgpack` unit.
- Adds the `cull` unit and changes the behaviour of conditional units to make filtered chunks invisible instead of removing them. Conditional units have been renamed to `iff`, `iffs`, `iffx`, and `iifp`.

## Version 0.3.33
- Adds the `xfcc` unit, which replaces the `intersection` unit.
- The `cm` unit can now be used to remove meta variables.
- JSON dumps no longer use hex encoding for big integers as JSON has no size limit on integer expressions.
- The `struct` unit was significantly redesigned and the `lprefix` unit removed because it can now be trivially implemented with `struct`.
- The `ifexpr` unit has been renamed to `iff` and the `iffp` unit was added.
- The field names in `dnfields` have been altered to more closely resemble file names.
- Adds a list of default passwords to archive units.

## Version 0.3.32
- Renames the `fread` unit to `ef`.
- Metadata / Format string expression parsing is now more flexible.

## Version 0.3.31
- Adds the `intersection` unit.

## Version 0.3.30
- Adds the `xtjson` and `xtxml` units for extracting data from JSON and XML files.
- Slight redesigns of `lprefix`, `peek`, `xtmail`, and `cfmt`.
- Refinery now has (very weak) support for PowerShell.
- Adds the `--tabular` option to `ppjson` to produce a flattened jason output.
- Changes to the in-code pipe syntax:
  - `data | unit | unit`  is an iterable over output chunks
  - `data | unit | unit | callable` invokes `callable` with a bytearray containign all concatenated chunks
  - connected pipelines (`data | unit | ... | unit`) can be passed to `str` and `bytes`
- Path extraction units (like `fread`, `xtzip`) offer better control over the path variable.
- Variable merging was added to the `pop` unit.
- The `cm` unit only populates `size` and `index` by default, never performing a full scan unless explicitly requested.

## Version 0.3.29
- Meta variables are now allowed in `struct` formats, and `struct` assumes no alignment by default.
- The `pemeta` unit now has support for RICH header data.
- The `rsakey` unit was added.
- The `pop` unit was extended by an option to discard chunks.
- Several new archive extractors are now available: `xt7z`, `xtace`, `xtiso`, and `xtcpio`.
- The `xlxtr` unit was refactored and generates more metadata.
- The `sorted` unit can sort by metadata variables now.
- The `swap` unit can now swap with an empty variable, which will empty the chunk body.

## Version 0.3.28
- The `trivia` unit was renamed to `cm` for _"common meta"_.
- The `pemeta` unit can now display PE header information, .NET header flags, and supports a table view instead of the JSON output.
- Python expressions all across multibin arguments no longer restrict the operators that can be used.  
- The domain regular expression was updated with new TLDs and the artificial TDLs `.coin` and `.bazar`.
- The `terminate` unit was added.
- The `struct` unit was added.

## Version 0.3.27
- Adds the `ifexpr` and `ifstr` units for filtering framed data.
- The `pemeta` unit now also extracts the `EntryPointToken` field from the .NET header.

## Version 0.3.26
- The `hexview` unit was removed, instead the `hexdmp` unit was created. By default, this unit converts hexdumps back to binary, the previous functionality of `hexview` is now available as the reverse operation of `hexdmp`.
- Adds the `dnblob` unit.
- The `drp` unit underwent major refactoring with the goal to improve both speed and quality of results. Two options were added to help control these new settings.

## Version 0.3.25 - bugfix release
## Version 0.3.24
- Adds the `xtrtf` unit to extract embedded objects from RTF documents.
- Adds the `officecrypt` unit to decode password-protected Office documents.
- Improves PKCS7 parsing and fixes some cases where `pemeta` did not display the details of the digital signature.
- Adds brieflz support to the universal `decompress` unit.

## Version 0.3.23
- Unification of (nearly) all multibin handlers. Only the `yara:` and `escape:` handlers remain to regular expression type arguments.
- Adds the multibin handlers `accu`, `reduce`, `cycle`, and `take`.
- Alters the `le` and `be` handlers to support both conversion from integer to byte string and vice versa.
- Renames the `unpack` handler to `btoi` and adds the `btoi` handler which performs the inverse operation.
- Command line switches for the `lprefix` unit changed.
- Adds the global `--lenient` option which is now required to admit partial results as output.

## Version 0.3.22
- Adds the `blz` unit for BriefLZ compression and decompression.

## Version 0.3.21
- Adds the `xtdoc` unit which can extract more files from Office documents than `xtzip`.
- Adds the `trivia` unit which can be used to attach certain meta variables. Moving forward, this will be the preferred way to access simple invariants of a binary chunk. For now, it can attach the integer variables `size` and `index`, containing the size of the data in bytes and the chunk index within the current frame, respectively. The `eval:` handler for numeric multibin values no longer accepts the special variable `N` to represent the chunk size as this functionality can be recovered by preprocessing each chunk with `trivia` and using the variable `size` instead of `N`.
- The `carve-pe` unit is now a path extractor unit (TL/DR: More command line options).

## Version 0.3.20 - documentation

## Version 0.3.19 - bufgfix release

## Version 0.3.18
- Changes the interface for the frame squeeze mechanic
- Adds option to `pefile` to compute carve size based on virtual section sizes & offsets.

## Version 0.3.17
- Using hex escape sequences in the replacement string for `resub` now works as expected.
- The `yara:` modifier for regular expression based units now accepts lowercase hex characters.
- The `imphash` unit's performance was improved slightly.
- Additional options for the `pecarve` unit.
- Adds the `ppjscript` unit (wrapper around [jsbeautifier][]).
- The `vsnip` unit can now extract more than one memory region.
- Adds a count restriction to the `resplit` and `resub` units.

## Version 0.3.16
- The interface for cipher units has been changed; the encryption mode is no longer a mandatory argument. Better handling of various cipher block chaining modes has been implemented.
- Conservative option added to `peoverlay` and `pestrip`.

## Version 0.3.15
- The `salsa` and `chacha` cipher units now have pure Python implementations that allow you to specify the number of rounds. The PyCryptodome interfaces still exist, now as units `salsa20` and `chacha20`.
- The `HMAC` unit was added to support simple HMAC based key derivation.
- The `dump` unit stream mode has been adjusted so that it is possible to write consecutive data to a file inside a nested frame.

## Version 0.3.14
- The `cfmt` unit has been reworked to support more common modern Python format string syntax.
- The output of `crc32` and `adler32` checksum hashes has been altered to use the correct byte order.
- The `rabbit` unit was added which implements the RABBIT stream cipher.

## Version 0.3.13
- The `mpush`, `mpop`, and `mput` units have been renamed to simply `push`, `pop`, and `put`.
- The `autoxor` unit has been transformed into the `drp` unit, the behavior of `autoxor` can be achieved using `xor drp:copy:all`.
- Data types of .NET fields are better detected by `dnfields` now, but a proper parser for type signatures is still missing.

## Version 0.3.12
- The `gz` unit was deprecated because the `zl` unit covers its usecase (and does a better job at it).
- The `lprefix` unit for parsing length-prefixed data was added.
- Parsing of managed .NET string resources via the `dnmr` unit was fixed, these would previously be returned unparsed.
- The `binpng` unit has been improved and renamed to `stego`, a more flexible unit to extract data from images.

## Version 0.3.11
- The `peslice`, `elfslice`, and `pesect` units have been removed.
- In their place, the cross-format units `vsnip` and `vsect` can now be used to extract data from virtual addresses and sections of PE, ELF, and MachO files.

## Version 0.3.10 - bugfix release

## Version 0.3.9 
- adds `md2` and `md4` hashing algorithms
- the `CryptDeriveKey` unit now also mirrors the API call for SHA2 based hashing algorithms
- message type attachments in Outlook email formats are now supported by `xtmail`

## Version 0.3.8
- The interface of the memory slicing units `peslice` and `elfslice` has changed.
- Python expression parser and numeric arguments have been refactored.

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


[@baderj]: https://github.com/baderj
[@larsborn]: https://github.com/larsborn
[XLMMacroDeobfuscator]: https://github.com/DissectMalware/XLMMacroDeobfuscator
[javaobj-issue-29]: https://github.com/tcalmant/python-javaobj/issues/29
[javaobj]: https://pypi.org/project/javaobj-py3/
[jsbeautifier]: https://pypi.org/project/jsbeautifier/
[malshare]: https://www.malshare.com/
[python-registry-gh]: https://github.com/williballenthin/python-registry
[python-registry]: https://pypi.org/project/python-registry/
[pycryptodome]: https://www.pycryptodome.org/