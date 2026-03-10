---
name: binary-refinery
description: >
  Construct binary refinery CLI pipelines for data extraction, decoding, decryption, and
  malware triage. Use when the user asks to build a refinery pipeline, decode or decrypt
  binary data, extract indicators or configs from malware samples, or work with the
  binary-refinery Python toolkit. Covers units, framing, multibin arguments, and meta
  variables.
user-invocable: false
---

# Binary Refinery Pipeline Construction Guide

## Agent Role & Instructions

You are a binary data pipeline engineer. Your task is to construct binary refinery CLI
pipelines that extract, transform, decode, decrypt, and analyze binary data. Binary
refinery is already installed. Each command ("unit") does one transformation, and units
are chained with the shell pipe operator `|` to build pipelines. Always execute
pipelines as shell commands — do not write Python scripts that import refinery.

**Core rules:**

- Always test with `peek` before committing output with `dump`.
- Pipelines flow left-to-right: `emit data | unit1 | unit2 | dump output`.
- Each unit reads stdin, transforms, writes stdout. Use `-R` to reverse (encode instead of decode).
- Use `binref` to discover units not listed in this document. Use `unitname -h` for detailed help.
- Multibin expressions, framing, and meta variables are the three pillars of the toolkit.
  Master all three before constructing complex pipelines. Meta variables only exist inside
  frames — any pipeline that stores or reads variables (`put`, `var:`, `eat:`, `x::name`)
  must be enclosed in `[` ... `]`.
- When a pipeline involves encrypted data, identify the algorithm, key derivation, IV source,
  and mode of operation before writing the pipeline.
- Prefer single-pipeline solutions over multi-step file-based workflows.
- Binary refinery is pre-installed. Run pipelines directly in the shell (e.g., via the
  Bash tool). Do not write Python code to import or call refinery units programmatically.

---

## Pipeline Architecture

The fundamental model is:

```
emit data | unit1 | unit2 | ... | dump output
```

- `emit` produces data from files, hex strings, or literal text.
- Each subsequent unit reads from stdin, transforms, and writes to stdout.
- `dump` writes final output to file(s) or clipboard; `peek` displays a preview.
- The `-R` / `--reverse` flag reverses a unit's operation (decode becomes encode).
- Shell pipes `|` connect units. On Windows CMD, use `^` for line continuation; on bash, use `\`.
- Units that produce multiple outputs (like `chop`, `carve`, `vsect`) emit them sequentially
  unless framing is used to process them individually.
- Without framing, multiple outputs are separated by line breaks.

---

## Framing System

Framing is how refinery processes multiple chunks individually through a sub-pipeline.

### Opening and Closing Frames

- **`[`** as the last argument of a unit opens a frame: that unit's outputs become
  individually-processed chunks for all subsequent units until the frame closes.
- **`]`** as the last argument of a unit closes the innermost frame: that unit is the
  last to process chunks individually, then all chunks are concatenated into one output.
- **`]]`** closes all open frames (with line break separation between outermost chunks).
- **`]]]`** or more: extra `]` beyond what is needed add line break separators between chunks.

### Simple Example

```
emit OOOOOOOO | chop 2 [| ccp F | cca . ]
```

Output: `FOO.FOO.FOO.FOO.` — each 2-byte chunk gets `F` prepended and `.` appended,
then all chunks are concatenated.

### Nested Frames

```
emit OOOOOOOO | chop 4 [| chop 2 [| ccp F | cca . ]| sep ]
```

Output:
```
FOO.FOO.
FOO.FOO.
```

- `chop 4 [` opens outer frame (2 chunks of 4 bytes)
- `chop 2 [` opens inner frame (each 4-byte chunk split into 2-byte pieces)
- `cca . ]` closes inner frame (concatenating inner chunks)
- `sep ]` inserts separator between outer chunks, then closes outer frame

### Close-Then-Pipe: `]|`

The `]|` syntax closes a frame layer and the next unit continues processing at the outer layer:

```
chop 4 [| chop 2 [| ccp F | cca . ]| sep ]
```

Here `]|` after `cca .` closes the inner frame, and `sep` operates on the outer frame.

### Squeezing: `[]`

When a multi-output unit is inside a frame and you want its outputs fused into a single
chunk (instead of expanding the frame), prefix the closing brackets with `[]`:

```
emit OOCLOOCL | chop 4 [| snip 2::-1 3 []]]
```

Output:
```
COOL
COOL
```

Without `[]`, `snip` would expand outputs into the frame. With `[]`, each set of snip
outputs is concatenated before being placed back into the frame.

### Metadata in Frames

**CRITICAL: Meta variables only exist inside frames.** Chunks only carry metadata
dictionaries when they are inside a frame opened with `[`. Outside of any frame,
`var:name`, `eat:name`, `{varname}` format strings, and all other variable references
will fail. If you need to use `put`, `push`/`pop`, `struct`, `rex` with named groups,
or any other variable-producing unit, the entire pipeline that sets AND reads those
variables must be enclosed in a frame. For example, `emit data | put x foo | cca var:x`
will silently fail; the correct form is `emit data [| put x foo | cca var:x ]`. Use
`mvg` to propagate a variable to a parent frame if needed.

---

## Multibin Argument Handlers

Many unit arguments accept **multibin** syntax, which preprocesses the argument value
using handlers. The general form is `handler:data` or `handler[args]:data`.

### Final Handlers (no further preprocessing of the data portion)

| Handler | Description |
|---------|-------------|
| `s:string` | UTF-8 encoded string |
| `u:string` | UTF-16LE encoded string |
| `h:string` | Hex-decoded bytes (e.g., `h:DEADBEEF`) |
| `a:string` | Latin-1 encoded string |
| `q:string` | URL-quote decoded string (use `%2c` for comma) |

### Delayed Handlers (require input data to evaluate)

| Handler | Description |
|---------|-------------|
| `copy:start:length` or `c:start:length` | Copy bytes from input at offset `start`, `length` bytes. Does not modify input. |
| `cut:start:length` or `x:start:length` | Cut bytes from input (same as copy but removes them from input). |

**What `cut`/`x` operates on:** The current chunk's data flowing through stdin — the
data arriving at the unit whose argument contains the `cut`. It does NOT take a separate
buffer as input. You never write `x:somevariable:16`; the data source is always implicit.

**Slice format — `start:length:step`:** Each part is optional. Critically, the second
part is **length** (byte count), NOT an end offset. Traced examples:

- `x::16` → start=0, length=16 → cuts and returns the first 16 bytes
- `x:4:8` → start=4, length=8 → cuts and returns 8 bytes starting at offset 4
- `x::` or `c::` → start=0, length=omitted → copies/cuts the entire input
- `c:10:` → start=10, length=omitted → copies from offset 10 to end (input unchanged)

**Input mutation — `cut` removes bytes:** After `cut` extracts a slice, those bytes are
gone from the chunk data. `copy` does not remove them. This means that after
`aes --iv x::16 x::32`, the input has lost its first 48 bytes: the IV got the first 16,
the key got bytes 16–47, and AES decrypts only whatever remains after byte 47.

**Sequential cut evaluation:** When a unit has multiple arguments using `cut`, they
execute left-to-right on a progressively shrinking buffer. Trace of `rc4 x::1 x::3`
on input `ABCDEFGH`:

1. First argument `x::1`: cuts byte 0, length 1 → returns `A`. Buffer is now `BCDEFGH`.
2. Second argument `x::3`: cuts byte 0, length 3 from the *remaining* buffer → returns
   `BCD`. Buffer is now `EFGH`.
3. `rc4` receives key=`A`, extra argument=`BCD`... but `rc4` only takes one key argument,
   so this is just to illustrate the shrinking. A realistic example:
   `put keylen le:x::1 | rc4 x::keylen` — see "Length-Prefixed Data" idiom below.

**Meta variables in slice expressions:** Meta variable names can appear in slice
positions, but only inside a frame (`[` ... `]`) — outside a frame, no variables exist. For example, `x::keylen` works if `keylen` is a meta variable holding
an integer value. This is because slice expressions are evaluated as Python expressions
with the chunk's meta variables in scope. You can write `x::n*4` if `n` is a variable.

**`cut` and `copy` are final handlers:** The colon-separated region string after `cut:`
or `x:` is NOT parsed for further handlers. `x::16` means the handler `x` receives the
raw string `::16` as its slice argument — it does not look for a handler named an empty
string or `16`. This is why chaining works as `le:x::4` (le wraps x) rather than
`x:le::4` (would fail — `le` would be misread as a start offset).

### Variable Handlers

| Handler | Description |
|---------|-------------|
| `var:name` or `v:name` | Read meta variable `name` |
| `eat:name` | Read meta variable `name` and delete it |

`var:` and `eat:` only work inside a frame (`[` ... `]`). Outside any frame, chunks
carry no metadata and these handlers will fail.

### Numeric Handlers (for integer arguments)

| Handler | Description |
|---------|-------------|
| `le:data` | Interpret data as little-endian integer |
| `be:data` | Interpret data as big-endian integer |

### Unit-as-Handler

Any unit name can be used as a handler. The data is processed by that unit:

```
md5:password          # MD5 hash of "password"
sha1:var:key          # SHA1 hash of a meta variable
b64:Zm9v              # base64-decode "Zm9v" -> "foo"
pbkdf2[32,s4lty]:swordfish  # PBKDF2 with keylen=32, salt="s4lty"
vsnip[0x408bf0:176]:var:backup  # extract 176 bytes at VA 0x408bf0
```

Unit arguments go in square brackets, separated by commas. To include a literal comma
in an argument, use `q:value%2cwith%2ccommas` as the argument inside the brackets.

### Handler Chaining

Handlers chain **right-to-left**: the rightmost handler is evaluated first and produces
the raw data, then each handler to its left transforms the result. A **final** handler
stops the right-to-left parsing — everything to its right is that handler's raw string
argument, not more handler names.

**Traced examples:**

- **`le:x::4`** — Step 1 (parse right-to-left): `x` is a final handler (cut), so parsing
  stops. `x` receives the raw region string `::4`. Step 2 (runtime): `x` cuts the first
  4 bytes from the unit's input. Step 3: `le` interprets those 4 bytes as a little-endian
  integer. Result: an integer value usable by `put` or an integer argument.

- **`sha1:var:key`** — Step 1: `var` is a final handler, so parsing stops. `var` receives
  the raw string `key`. Step 2: at runtime, `var` reads meta variable `key` and returns
  its bytes. Step 3: `sha1` (unit-as-handler) hashes those bytes. Result: 20-byte SHA1
  digest. (Requires a frame — `var:key` only resolves inside `[` ... `]`.)

- **`pbkdf2[32,s4lty]:swordfish`** — Step 1: no recognized handler name in `swordfish`,
  so the default handler encodes it as UTF-8 bytes. Step 2: `pbkdf2` (unit-as-handler)
  with args `[32, s4lty]` derives a 32-byte key from those bytes. Result: 32-byte key.

- **`hex[-R]:sha256:read:file.txt`** — Step 1: `read` is a final handler; it receives
  `file.txt` and reads the file contents. Step 2: `sha256` hashes those bytes. Step 3:
  `hex[-R]` hex-encodes the hash. Result: hex string of the SHA256 digest.

**Key rule:** After a final handler (`s:`, `u:`, `h:`, `a:`, `q:`, `var:`/`v:`, `eat:`,
`cut:`/`x:`, `copy:`/`c:`, `read:`, `yara:`, `range:`), the remaining string to the right
is consumed as that handler's literal argument. No further handler parsing occurs on it.

### Special Patterns

- `yara:pattern` — Use a YARA-style hex pattern for matching (in `rex`)
- `range:N` — Generate bytes 0 to N-1
- `read:path` — Read file contents
- `drp:data` — Detect repeating pattern in data

---

## Meta Variable System

**Meta variables only exist inside frames.** A pipeline like
`emit data | put x foo | cca var:x` will NOT work because there is no enclosing frame.
You must write `emit data [| put x foo | cca var:x ]` instead. Every pipeline that
stores or reads meta variables must be inside a `[` ... `]` frame.

### Storing Variables

- **`put varname value`** — Assign a multibin expression as a meta variable on each chunk.
  Example: `put k le:x::4` stores the first 4 bytes as a little-endian integer named `k`.
- **`push`** — Duplicate the current chunk; the original is hidden (out of scope).
  The visible copy can be transformed into a variable via `pop`.
- **`pop varname`** — Consume the visible chunk, store its data as variable `varname`,
  then reveal the hidden chunks. All subsequent chunks get this variable.
- **`cm`** — Catch-all helper to pre-compute common metadata (size, hashes, entropy, etc.).
- **`rmv varname`** — Remove a variable from the metadata dictionary.
- **`mvg varname`** — Propagate a variable to parent frames.

### The Push/Pop Pattern

This is used to extract a value (like a key) from within the data, then use it later.
The entire pipeline — both key extraction and subsequent decryption — must be inside a frame:

```
emit sample.bin [
    | push [
        | extract_key_pipeline
        | pop key ]
    | decrypt_pipeline using var:key ]
```

**Wrong** (will fail — `var:key` is used outside any frame):
```
emit sample.bin | push [| extract_key_pipeline | pop key ] | decrypt using var:key
```

Detailed example — extract password from email, then use it to decrypt attachment:

```
emit phish.eml [
    | push [
        | xtmail body.txt
        | rex -I password:\s*(\w+) {1}
        | pop password ]
    | xt *.zip
    | xt *.exe -p var:password
    | dump extracted/{path} ]
```

### Format Strings

Units `pf`, `dump`, and `run` support Python-style format strings with meta variables:

- `{varname}` — Insert variable value
- `{size!r}` — Human-readable size (e.g., "1.5 MB")
- `{size}` or `{size!s}` — Raw decimal integer
- `{entropy!r}` — Entropy as percentage
- `{md5}` — MD5 hex digest
- `{path}` — Path from archive extraction

### Magic Variables (always available on every chunk)

| Variable | Description | `!r` format |
|----------|-------------|-------------|
| `index` | Chunk index in current frame | — |
| `size` | Byte count | Human-readable (e.g., "4.2 kB") |
| `entropy` | Shannon entropy | Percentage |
| `ic` | Index of coincidence | Percentage |
| `ext` | Guessed file extension | — |
| `mime` | MIME type | — |
| `magic` | File magic string | — |
| `crc32` | CRC32 hex digest | — |
| `md5` | MD5 hex digest | — |
| `sha1` | SHA1 hex digest | — |
| `sha256` | SHA256 hex digest | — |
| `sha512` | SHA512 hex digest | — |
| `path` | Virtual path (from archive/resource extraction) | — |
| `name` | Suggested filename | — |

---

## Unit Catalog

> Units not listed here are discoverable via `binref` or `binref keyword`.
> Run `unitname -h` for full usage of any unit.

### Data I/O

| Unit | Description |
|------|-------------|
| `emit` | Emit data from files, hex literals, or string arguments. Multiple arguments emit multiple chunks. The primary data source for pipelines. |
| `dump` | Write data to file(s) or clipboard. Supports format strings for filenames: `dump {name}`, `dump output/{path}`. Use `-m` to write multiple chunks to separate files. |
| `peek` | Preview data with hex dump and metadata. Use before `dump` to verify output. Flags: `-d` (no hex, just text), `-l N` (limit lines), `-m` (metadata only, `-ml0`), `-b` (brief), `-e` (show entropy). |
| `ef` | Enumerate files matching a glob pattern. Each file becomes a chunk with `path` metadata. `ef "**"` recurses. `ef "*.exe"` matches executables in current directory. |
| `rep` | Repeat input N times as separate chunks. `rep 0x100` emits 256 copies (useful for brute-force with `v:index`). |

### Encoding

| Unit | Description |
|------|-------------|
| `hex` | Hex decode (default) or encode (`-R`). |
| `b64` | Base64 decode/encode. Supports URL-safe variant with `--url`. |
| `url` | URL decode/encode. |
| `esc` | Decode/encode backslash escape sequences. |
| `b32` | Base32 decode/encode. |
| `b85` | Base85 decode/encode. |

### Compression

| Unit | Description |
|------|-------------|
| `zl` | Zlib decompress/compress. |
| `lzma` | LZMA decompress/compress. |
| `bz2` | Bzip2 decompress/compress. |
| `decompress` | Universal auto-detect decompression. Tries all known compression algorithms. |
| `lz4` | LZ4 decompress/compress. |

### Cryptography

| Unit | Description |
|------|-------------|
| `xor` | XOR with a key. Single byte: `xor 0xAA`. Multi-byte: `xor h:DEADBEEF`. Variable key (requires frame): `xor var:key`. Rolling key from brute force: `xor v:index`. |
| `rc4` | RC4 stream cipher. `rc4 keydata`. Key can be any multibin expression. |
| `aes` | AES block cipher. Specify `--mode` (cbc, ecb, ctr, etc.), `--iv`, key. Example: `aes --mode cbc --iv x::16 pbkdf2[32,salt]:pass`. Use `-Q` to suppress padding errors. |
| `pbkdf2` | PBKDF2 key derivation. Used as multibin handler: `pbkdf2[keylen,salt]:password`. |
| `accu` | Accumulator-based decryption. Used for custom XOR variants: `accu[seed]:@algo`. |
| `des` | DES/3DES cipher. |
| `blowfish` | Blowfish cipher. |
| `chacha` | ChaCha20 cipher. |
| `salsa` | Salsa20 cipher. |
| `serpent` | Serpent cipher. |
| `seal` | SEAL cipher. |
| `rsa` | RSA operations. |

### Hashing

| Unit | Description |
|------|-------------|
| `sha256` | SHA-256 hash. Use `-t` to output as hex text. |
| `sha1` | SHA-1 hash. Also usable as multibin handler: `sha1:data`. |
| `md5` | MD5 hash. Also usable as handler: `md5:password`. |
| `crc32` | CRC32 checksum. |
| `sha512` | SHA-512 hash. |
| `sha384` | SHA-384 hash. |

### Arithmetic / Blockwise

| Unit | Description |
|------|-------------|
| `pack` | Convert between numeric text and binary. `pack` reads numbers from text and outputs bytes. `pack -R` converts bytes to numbers. Flags: `-E` (big-endian), `-B N` (block size). Example: `emit "0xBA 0xAD" \| pack \| hex -R` → `BAAD`. |
| `add` | Add a value to each block. |
| `sub` | Subtract a value from each block. |
| `shr` | Shift right each block. |
| `shl` | Shift left each block. |
| `rotr` | Rotate right each block. |
| `rotl` | Rotate left each block. |
| `neg` | Negate each block. |
| `alu` | General arithmetic unit. `--dec` to decrement. Flags: `-s` for sequence mode, expressions with `B` (block), `S` (sequence). Example: `alu --dec -sN B-S`. |

### Pattern Extraction

| Unit | Description |
|------|-------------|
| `carve` | Carve patterns from data. `carve b64` finds base64 blobs. `carve -l` sorts by length. `-t1` takes top 1. `-d` decodes. `-s` combines sort+decode+top1. `-ds` is `-d -s`. Patterns: `b64`, `hex`, `intarray`, `url`, `email`, `ipv4`, `printable`, etc. |
| `xtp` | Extract typed patterns: `xtp url`, `xtp email`, `xtp ipv4`, `xtp socket`, `xtp domain`, `xtp hostname`, `xtp guid`. `-n N` minimum length. `-f` flag for exact filter. |
| `rex` | Regex extraction with format output. Named groups become meta variables. `rex "pattern" {1}{2}` outputs formatted matches. Supports `yara:` hex patterns. `-M` multiline. `-I` case-insensitive. |
| `resub` | Regex substitution on input data. |
| `resplit` | Split input at regex matches. Each piece becomes a chunk. `resplit h:00` splits at null bytes. |
| `carve-pe` | Carve PE files from binary data. With `-R`, verify the chunk is a valid PE. |
| `carve-zip` | Carve ZIP archives from binary data. |

### Structure Parsing

| Unit | Description |
|------|-------------|
| `struct` | Parse binary structures using format strings. `struct {name:L}{size:H}` reads a DWORD and WORD. Format codes: `B`=byte, `H`=uint16, `I`/`L`=uint32, `Q`=uint64. Braces `{name:FMT}` store as meta variable. The special format `{}` (empty braces) reads a length-prefixed blob: it uses the most recently parsed integer as the length, reads that many bytes, and replaces the chunk content with them. `{name:{}}` does the same but stores the blob as a variable instead. Use `-m` to parse multiple repeated structures. Output is a format string: `struct {a:L}{b:H} {a}:{b}`. Example: `struct {n:B}{key:{}}{} | rc4 eat:key` reads a 1-byte length, extracts `n` key bytes, and leaves the rest as payload. |
| `snip` | Extract slices from data. `snip 4:` skips first 4 bytes. `snip 2::-1` reverses from offset 2. `snip :10` takes first 10 bytes. Multiple slices produce multiple chunks. |
| `chop` | Chop data into fixed-size blocks. `chop 16` produces 16-byte chunks. Essential for frame-based processing. `-t N` for tail handling. |

### PE / ELF Analysis

| Unit | Description |
|------|-------------|
| `pemeta` | Display PE file metadata (imports, exports, version info, timestamps, etc.). |
| `vsect` | Extract PE sections by name or index. `vsect .text`. Outputs each section as a chunk with `path` metadata. |
| `vsnip` | Extract bytes at a virtual address from a PE. `vsnip 0x401000:100` extracts 100 bytes at VA 0x401000. Also usable as multibin handler: `vsnip[addr:len]:data`. |
| `vstack` | Emulate a virtual stack machine for simple code sequences. `-a=x32` for 32-bit, `-w=200` for max instructions. |
| `carve-pe` | Carve embedded PE files from binary data. |
| `perc` | Extract PE resources. `perc RCDATA` extracts RCDATA resources. `perc SETTINGS` extracts by name. `-l` lists resources. |
| `dnfields` | Extract .NET fields from a .NET assembly. Each field becomes a chunk. |
| `dnds` | Deserialize .NET data. |

### Office / Document Formats

| Unit | Description |
|------|-------------|
| `xtdoc` | Extract streams from OLE (compound document) files. |
| `doctxt` | Extract text content from office documents. |
| `officecrypt` | Decrypt password-protected Office documents. |
| `xlxtr` | Extract data from Excel cells by range. `xlxtr 9.5:11.5 15.15` extracts cell ranges. |
| `xtvba` | Extract VBA macro source code from Office documents. |

### Archives

| Unit | Description |
|------|-------------|
| `xtzip` | Extract files from ZIP archives. `xtzip file.dll` extracts a specific file. |
| `xt7z` | Extract from 7-Zip archives. |
| `xttar` | Extract from TAR archives. |
| `xt` | Generic extraction. Tries multiple formats. `xt *.exe` extracts matching files. `-p password` for password. |
| `carve-zip` | Carve ZIP files from binary data. |
| `xtmail` | Extract parts from email messages. `xtmail body.txt` extracts the body. |

### Filtering & Sorting

| Unit | Description |
|------|-------------|
| `iff` | Conditional filter: keep chunk if condition is true. `iff required -eq computed` compares two multibin values. |
| `iffp` | Pattern filter: keep chunk if it matches a pattern. `iffp domain` keeps chunks matching domain pattern. |
| `dedup` | Remove duplicate chunks. |
| `sorted` | Sort chunks. `-a` for alphanumeric sort. |
| `trim` | Trim bytes from ends. `trim h:00` removes null bytes. |
| `max` | Keep only the chunk with the maximum value of a variable. `max size` keeps the largest chunk. |
| `pick` | Select chunks by index/slice. `pick :10` takes first 10. |

### Formatting & Output

| Unit | Description |
|------|-------------|
| `pf` | Print format string with meta variables. `pf {size!r} {entropy!r} {md5} {path}` prints a formatted line per chunk. `pf {}` prints the chunk itself as text. |
| `ppjson` | Pretty-print JSON data. |
| `ppjscript` | Pretty-print / beautify JavaScript. |
| `sep` | Insert separator between chunks (default: newline). `sep -` uses dash. `sep .` uses period. Makes all chunks visible before joining. |

### Variable Manipulation

All of these only work inside a frame:

| Unit | Description |
|------|-------------|
| `put` | Store a multibin value as a meta variable. `put key h:AABBCCDD`. `put k le:x::4`. |
| `push` | Duplicate chunk; original becomes hidden. Used with `pop` for key extraction. |
| `pop` | Consume visible chunk as named variable, reveal hidden chunks. `pop key`. |
| `swap` | Swap chunk data with a named variable's data. `swap backup`. |
| `cm` | Compute common metadata (hashes, entropy, size). |
| `rmv` | Remove a meta variable. |
| `mvg` | Propagate a variable to parent frame. |

### String Operations

| Unit | Description |
|------|-------------|
| `cca` | Concatenate-append: append a value to each chunk. `cca .` appends a period. `cca var:suffix`. |
| `ccp` | Concatenate-prepend: prepend a value to each chunk. `ccp F` prepends "F". |
| `repl` | Replace occurrences. `repl old new`. |
| `rev` | Reverse the data. |
| `clower` | Convert to lowercase. |
| `cupper` | Convert to uppercase. |
| `defang` | Defang URLs and IPs for safe display. Converts `http://` to `hxxp://`, `.` to `[.]`. |

### Pattern Analysis

| Unit | Description |
|------|-------------|
| `drp` | Detect repeating pattern in data. Returns the shortest repeating unit. Usable as multibin handler: `xor drp:c::100` detects key from first 100 bytes. |
| `csd` | Carve, single, decode. Carves a pattern and decodes it: `csd string`, `csd b64`. |

### Network / URL

| Unit | Description |
|------|-------------|
| `dnr` | DNS resolve. |
| `urlfix` | Fix/normalize URLs. |
| `urlguard` | URL guard / safety check. |

### Frames & Flow Control

| Unit | Description |
|------|-------------|
| `scope` | Limit visibility to specific chunk indices. `scope 0` makes only the first chunk visible. `scope 0:3` makes first three visible. |
| `nop` | No operation. Passes data through unchanged. Useful as a frame boundary: `[| nop ]`. |

### Deobfuscation

| Unit | Description |
|------|-------------|
| `deob-ps1` | Deobfuscate PowerShell scripts. |

### Steganography

| Unit | Description |
|------|-------------|
| `stego` | Extract data hidden via steganography. |

### PCAP

| Unit | Description |
|------|-------------|
| `pcap` | Parse PCAP network capture files. |

---

## Examples

### Worked Examples

#### Basic Decode Chain

```
emit M7EwMzVzBkI3IwNTczM3cyMg2wQA | b64 | zl | hex
```

Decodes base64, decompresses zlib, hex-decodes. Result: `Hello World`.

#### Reverse Encode Chain

```
emit "Hello World" | hex -R | zl -R | b64 -R
```

Each unit runs in reverse: hex-encode, zlib-compress, base64-encode.

#### Carve and Decode Base64

```
emit file.exe | carve -ds b64
```

`-ds` is shorthand for `-d -s`: decode the largest carved base64 blob.

#### Carve ZIP and Extract DLL Info

```
emit file.bin | carve-zip | xtzip file.dll | pemeta
```

#### File Hashing

```
ef "**" [| sha256 -t | pf {} {path} ]]
```

Recursively enumerate all files, compute SHA-256 (as text with `-t`),
print hash and path for each.

#### IOC Extraction

```
ef "**" [| xtp -n6 ipv4 socket url email | dedup ]]
```

Extract indicators from all files, deduplicate.

#### XOR Brute-Force with PE Carving

```
emit file.bin | rep 0x100 [| xor v:index | carve-pe -R | peek | dump {name} ]
```

Repeat input 256 times, XOR each with its index (0x00-0xFF), attempt to carve PE,
preview and dump any hits.

#### IP Address Conversion

```
emit 0xC0A80C2A | pack -EB4 | pack -R [| sep . ]
```

Convert network-byte-order IP to dotted decimal.

#### PE Section Listing with Hashes

```
emit file.exe | vsect [| sha256 -t | pf {} {path} ]]
```

#### AES Decryption with PBKDF2

```
emit data | aes --mode cbc --iv cut::16 pbkdf2[32,s4lty]:swordfish
```

- `cut::16` extracts first 16 bytes as IV (and removes them from input)
- `pbkdf2[32,s4lty]:swordfish` derives 32-byte key from passphrase with salt

#### AES Round-Trip Test

```
emit "Once upon a time..." | aes pbkdf2[32,s4lty]:swordfish --iv md5:X -R | ccp md5:X | aes pbkdf2[32,s4lty]:swordfish --iv cut:0:16
```

#### RemCos C2 Extraction

```
emit sample.bin | perc SETTINGS [| put keylen cut::1 | rc4 cut::keylen | xtp socket ]
```

#### AgentTesla Config Extraction

```
emit sample.bin | dnfields [| aes x::32 --iv x::16 -Q ]] | rex -M "((??email))\n(.*)\n(.*)\n:Zone" addr={1} pass={2} host={3}
```

#### NetWalker Config Pipeline

```
emit nl.ps1 [| carve -ds intarray | xor c:3 | perc | put k le:x::4 | rc4 x::k ]| ppjson | peek -d
```

- Carve and decode integer array, XOR-decrypt using byte at offset 3
- Extract PE resources, derive RC4 key from first 4 bytes (little-endian length)
- RC4-decrypt remaining data, pretty-print as JSON

#### SedUpLoader C2 Extraction (Push/Pop Pattern)

```
emit a.bin | push [
    | vsnip 0x408b78:13
    | pop key
    | vsnip 0x408bf0:4*44
    | chop 44 [
        | xor var:key
        | trim h:00
        | defang
        | peek -be ]]
```

- `push` duplicates the binary; visible copy is processed first
- `vsnip` extracts the XOR key at a known virtual address
- `pop key` stores it and reveals the original binary
- The original is sliced, chopped into records, XOR-decrypted with the key

#### Qakbot C2 Extraction

```
emit q.bot [[
        | put backup [
            | rex yara:5168([4])BA([2]0000)B9([4])E8 {1}{3}{2}
            | struct {ka:L}{da:L}{dl:L}
            | put key vsnip[ka:128]:var:backup
            | emit vsnip[da:dl]:var:backup
            | xor var:key ]
        | resplit h:00
        | swap key
        | swap backup
        | perc RCDATA [| max size ]
        | rc4 sha1:var:key
        | put required x::20
        | put computed sha1:c:
        | iff required -eq computed
        | rc4 x::20
        | snip 20:
        | rex '(\x01.{7})+' ]
    | struct -m !xBBBBHx {1}.{2}.{3}.{4}:{5} [| sep ]
    | peek -d ]
```

#### Warzone RAT C2 Extraction

```
emit sample.bin | vsect .bss | struct I{key:{}}{} [| rc4 eat:key | struct I{host:{}}{port:H} {host:u16}:{port} ]
```

#### PowerShell Payload from XLS Macro

```
emit sample.xls [
  | xlxtr 9.5:11.5 15.15 12.5:14.5 [
  | scope -n 3 | chop -t 5 [| sorted -a | snip 2: | sep ]
  | pack 10 | alu --dec -sN B-S ]]
  | dump payload.ps1
```

#### Multi-Stage PowerShell Deobfuscation

```
emit payload.ps1
  | carve -sd b64 | zl | deob-ps1
  | carve -sd b64 | zl | deob-ps1
  | xtp -f domain
```

#### Equation Editor Exploit URL Extraction

```
emit sample.doc | officecrypt | xt oleObject | xt native | rex Y:E9[] | vstack -a=x32 -w=200 | xtp
```

#### HawkEye Config Extraction

```
emit sample.exe | put cfg perc[RCDATA]:c:: [| xtp guid | pbkdf2 48 rep[8]:h:00 | cca eat:cfg | aes -Q x::32 --iv x::16 ] | dnds
```

---

### Common Patterns & Idioms

#### Extract-Then-Decrypt

```
carve -ds b64 | xor key
```

or

```
perc RCDATA | rc4 key
```

#### Frame + Filter

```
chop 44 [| xor var:key | trim h:00 | iffp domain | defang ]]
```

Process chunks individually, filter to keep only those matching a pattern.

#### Key Extraction via Push/Pop

The outer frame is mandatory — without it, `var:key` has no metadata context:

```
emit data [| push [| <key extraction pipeline> | pop key ] | <decryption using var:key> ]
```

#### Format Metadata Report

```
ef "**" [| pf {size!r} {entropy!r} {md5} {path} ]]
```

#### Reverse Encoding Chain

Apply `-R` to each unit in reverse order:

```
unit3 -R | unit2 -R | unit1 -R
```

#### Prepend/Append in Frame

```
chop N [| ccp h:PREFIX | cca h:SUFFIX ]
```

#### Brute-Force with Index

```
rep 0x100 [| xor v:index | <test> | peek | dump {name} ]
```

#### Struct-Based Record Parsing

```
struct {field1:L}{field2:H}{data:{}} [| process eat:data ]
```

The `{}` format reads a length-prefixed blob: it first reads an integer whose size
matches the previously parsed integer field, then reads that many bytes as the blob.
`{name:{}}` stores the blob as a meta variable. A bare `{}` without a name consumes
the remaining data and replaces the chunk content with it, which is useful for
stripping parsed headers and passing only the payload downstream.

#### Length-Prefixed Data (Key Extraction)

This is the pattern for data where a length prefix tells you how many bytes of key
(or other structured field) follow, and the rest is the payload. Two approaches:

**Approach A — cut + put (preferred for simple cases):**

```
emit <data> | b64 [| put keylen le:x::1 | rc4 x::keylen | peek ]
```

Trace on input where the first byte after base64-decoding is `0x10` (16):

1. `b64` decodes the base64 data. Suppose the result is `\x10<16 key bytes><ciphertext>`.
2. `x::1` cuts the first 1 byte (`\x10`), buffer shrinks to `<16 key bytes><ciphertext>`.
3. `le:` converts that byte to integer 16.
4. `put keylen` stores 16 as meta variable `keylen`.
5. `x::keylen` → `x::16` → cuts the next 16 bytes as the RC4 key. Buffer shrinks to
   just `<ciphertext>`.
6. `rc4` decrypts the remaining ciphertext with the extracted key.

**Approach B — struct with `{}`:**

```
emit <data> | b64 [| struct {n:B}{key:{}}{} | rc4 eat:key | peek ]
```

1. `{n:B}` reads 1 byte as unsigned integer → meta variable `n` (e.g., 16).
2. `{key:{}}` reads `n` bytes → meta variable `key`.
3. `{}` consumes the rest → becomes the new chunk data (the ciphertext).
4. `eat:key` feeds the key to `rc4` and deletes it from metadata.

Both approaches produce the same result. Approach A is more transparent when you need
to debug intermediate values. Approach B is more concise for well-structured binary data.

#### Conditional Verification

```
put expected x::20 | put actual sha1:c: | iff expected -eq actual
```

Compare a stored hash with a computed one; drop chunk if mismatch.

---

## Common Mistakes

### Using variables outside a frame

Variables do not exist outside `[` ... `]`. This is the single most common mistake.

**Wrong:**
```
emit data | put key h:AABBCCDD | xor var:key
```

**Right:**
```
emit data [| put key h:AABBCCDD | xor var:key ]
```

### Closing the frame too early (push/pop pattern)

The variable must still be in scope when it is read. If `]` closes the frame before
`var:key` is used, the variable is gone.

**Wrong:**
```
emit data | push [| extract_key | pop key ] | decrypt var:key
```

**Right — the outer frame must enclose both pop and the consumer:**
```
emit data [| push [| extract_key | pop key ] | decrypt var:key ]
```

### Confusing `cut` length with end offset

The slice format is `start:length`, not `start:end`. `x:4:8` means "8 bytes starting
at offset 4", not "bytes 4 through 8".

### Wrong handler chain order

Handlers chain right-to-left. The rightmost handler runs first.

**Wrong** (tries to parse `le` as a slice offset):
```
x:le::4
```

**Right** (`x` runs first, then `le` interprets the result):
```
le:x::4
```

### Missing frame around format strings

Format strings like `{path}`, `{md5}`, or `{size}` in `pf` and `dump` read meta
variables. They require a frame.

**Wrong:**
```
ef "**" | sha256 -t | pf {} {path}
```

**Right:**
```
ef "**" [| sha256 -t | pf {} {path} ]]
```

---

## Discovery & Help

- **`binref`** — List all available refinery units with descriptions.
- **`binref keyword`** — Search units by keyword (searches names and descriptions).
- **`unitname -h`** — Show detailed help for a specific unit, including all arguments.
- **Documentation**: https://binref.github.io/ — Full generated documentation.
- Units listed above are the most commonly used. The full toolkit contains many more
  specialized units for formats, encodings, and transformations.

---

## Quick Reference

### Pipeline checklist

1. Does the pipeline use `put`, `pop`, `var:`, `eat:`, `{varname}`, or `v:index`?
   → It **must** be inside a `[` ... `]` frame.
2. Does it use `push`/`pop` to extract a key, then use that key later?
   → The **outer** frame must enclose both the `pop` and the unit that reads the variable.
3. Does it use `x:` (cut) or `c:` (copy)?
   → Remember: the second number is a **length**, not an end offset.
   → Multiple cuts shrink the buffer left-to-right.
4. Does it chain multibin handlers?
   → They evaluate **right-to-left**. Write `le:x::4`, not `x:le::4`.
5. Does it use `pf`, `dump {name}`, or any format string with `{variable}`?
   → These read meta variables and require a frame.

### Frame syntax

| Syntax | Meaning |
|--------|---------|
| `unit [` | Open a frame: unit's outputs become individually processed chunks |
| `unit ]` | Close innermost frame: chunks are concatenated back into one output |
| `unit ]]` | Close all frames (line break between outermost chunks) |
| `]|` | Close frame, continue processing at outer frame level |
| `[]` | Squeeze: fuse multi-output into single chunk before placing in frame |

### Multibin handler evaluation order

```
le:x::4          →  x cuts 4 bytes, le interprets as little-endian int
sha1:var:key     →  var reads meta variable "key", sha1 hashes the result
pbkdf2[32,salt]:pw  →  "pw" encoded as UTF-8, pbkdf2 derives 32-byte key
```

### Variable lifecycle (all require frame)

```
put name value     →  store value as meta variable
push               →  duplicate chunk, hide original
pop name           →  consume chunk as variable, reveal hidden chunks
var:name           →  read variable (keeps it)
eat:name           →  read variable (deletes it)
mvg name           →  propagate variable to parent frame
```
