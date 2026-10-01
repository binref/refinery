---
name: update-inno-extraction
description: >
  Use this skill when the task is to extend or update Binary Refinery's Inno Setup extraction code
  to support new Inno Setup versions. Trigger when the user wants to support Inno Setup X.Y.Z,
  update the inno parser/extractor, add a new InnoSetup version, fix parsing of a newer Inno
  installer, or otherwise change code under `refinery/lib/inno/` to track upstream Inno Setup
  format changes. The skill prompts for the local Inno Setup source repository and walks the 
  incremental, diff-per-release methodology.
version: 1.0.0
---
# Updating Inno Setup Extraction Support

Binary Refinery parses Inno Setup installers in
```
refinery/lib/inno/archive.py
```
by replicating the on-disk record layout for each format version.
New Inno Setup releases are supported by diffing the upstream Pascal records and adding **precise per-feature version gates**.
This skill drives that process.

## Step 1 — Prompt For the Inno Setup Source Repository

Before anything else, ask the user for the absolute path to their local Inno Setup source checkout
(the `issrc` repository — the official Pascal/Delphi source). Do not proceed until it is provided.

- The location is environment-specific: Always ask, and do not assume a default.
  The upstream repository is [`jrsoftware/issrc`][issrc]; if the user does not have a local clone, offer to clone it for them.
- Validate the path: It must be a git repo containing this path:
  ```
  Projects/Src/Shared.Struct.pas
  ```
  Confirm this with
  ```
  git -C {path} rev-parse --is-inside-work-tree
  ```
  and that the file exists.
- Note the repo may be checked out at an older tag than its history;
  always reference release **tags** (e.g. `is-7_0_1`), not the working tree.
  List them with `git -C {path} {tag}`.

Refer to the repo as `{issrc}` for the rest of this skill.

## Step 2 — Determine Current Coverage

Read the `_IS_AMBIGUOUS` table in `archive.py`;
its highest entry is the last covered format version.
Each entry is keyed by the version parsed from the embedded `Inno Setup Setup Data (X.Y.Z)` signature
 (a 3- or 4-tuple, e.g. `_I(7, 0, 0, 3, IVF.UTF_16)`).

## Step 3 — Enumerate the Releases to Cover

Run `git -C {issrc} {tag}` to list release tags.
For each tag, record its data-format signature and product version:
```
git -C {issrc} show {tag}:Projects/Src/Shared.Struct.pas | grep -E "SetupVersion =|SetupID:"
```
Multiple releases often share one `SetupID` (e.g. 7.0.0 and 7.0.1 both ship `(7.0.0.3)`);
the `SetupID`-parsed version is the gate/table key, **not** the product version.

## Step 4 — Diff Each Consecutive Release

Do **not** jump to an end-to-end diff.
For each consecutive tag pair, diff every parsed-structure source and reason about it before moving on:
```
git -C {issrc} diff {tagA} {tagB} -- Projects/Src/Shared.Struct.pas
git -C {issrc} diff {tagA} {tagB} -- Projects/Src/Compression.Base.pas
```
The file `Shared.Struct.pas` holds the entry records; `Compression.Base.pas` holds the stream/block header.
A step that only bumps `SetupVersion` has no format change.
A real format change can occur **without** a `SetupID` bump — that is exactly why every step must be diffed
 (trial-parsing later disambiguates same-`SetupID` formats).

## Step 5 — Understand the Serialization Order

`SECompressedBlockRead` (`{issrc}/Projects/Src/Shared.SetupEntFunc.pas`) serializes each record as:
All `String` fields first (declaration order), then `AnsiString`s, then the remaining fixed fields as one packed block.
The parsing classes read inline in this same order,
 so a new record field is read at its declaration position relative to the strings / fixed block.
Match Pascal sizes:

| Pascal Type | Reader Method         |
|-------------|-----------------------|
| `Byte`      | `reader.u8()`         |
| `Word`      | `reader.u16()`        |
| `Cardinal`  | `reader.u32()`        |
| `Integer`   | `reader.u32()`        |
| `Int64`     | `reader.u64()`        |
| `String`    | `self._read_string()` |

A `set of` enum occupies `ceil((max_ordinal + 1) / 8)` bytes;
 the parser reads it bit-by-bit then `byte_align()`s (and, for the file-entry set, pads to its fixed size).
Map Pascal enums to an `enum.IntEnum`.

## Step 6 — Apply Precise Version Gates

For each change, edit the matching class in `archive.py`:

- `TSetupHeader` → `SetupHeader`
- `TSetupFileEntry` → `SetupFile`
- `TSetupFileLocationEntry` → `SetupDataEntry`
- `TSetupRegistryEntry` → `SetupRegistryEntry`, `TSetupRunEntry` → `SetupRunEntry`
- language/type/component/task/dir/icon/ini/delete → corresponding `Setup*` classes
- `TCompressedBlockHeader` → `StreamHeader`
- `TSetupLdrOffsetTable` → `TSetupLdrOffsetTable`

Gate every added read on the version where the field appeared,
 and bound removed reads at the version where they disappeared,
 using the tuple style already in the file, e.g.:

```python
if version >= (7, 0, 0, 3):
    self.NewField = reader.u32()
else:
    self.NewField = 0
...
if (5, 1, 0) <= version < (7, 0, 0, 3):   # a flag that was removed in 7.0.0.3
    flagbit(SomeFlags.Bits32)
```

Use a 4-tuple gate when the signature has four parts (matches existing `(6, 4, 0, 1)` style).
Keep new reads gated so no already-covered version changes behavior.

## Step 7 — Register the Versions

Add one `_IS_AMBIGUOUS` entry per release in the table (keyed by the `SetupID`-parsed version),
 marked `False` unless the format is genuinely indistinguishable from a neighbor by signature alone (then `True`).
Note that `_VERSIONS` derives from this dict automatically.

[issrc]: https://github.com/jrsoftware/issrc