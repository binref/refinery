"""
Sha256 keys of the authentic workbooks of the encrypted test data store, one constant per file;
the bytes come back through `TestBase.download_sample`.

The workbooks originate from the test suites of the `xlrd2` and `pyxlsb2` projects, which
distribute them under the Apache License 2.0; they are produced by a range of authors (Microsoft
Excel, LibreOffice, Apache POI) and collectively cover rich text, shared strings, inline strings,
formula results, date styles, error values, control characters, nonstandard part naming, the BIFF
record format from the worksheet-only BIFF4 stream to BIFF8, a workbook whose OLE container is
defective, a sheet that contains nothing but a picture, and the MS-XLSB record format with both
date epochs.

The XLM_* constants are real Excel 4.0 macro malware samples collected in the wild. They cover
macrosheet formulas as RPN streams with relative cell references and shared-formula members
(BIFF8), a dense defined-name table with assignments and a 3-D reference (BIFF8), name
assignment cells (BIFF8), and macrosheet formulas as OOXML text containing XLM commands (XLSM).

The OPERATOR_ORACLE_* constants are the operator oracle: one workbook per format, produced by
Microsoft Excel itself, whose `Oracle` sheet holds every binary operator of the formula language
applied to every pair of 21 operand spellings, with the result Excel computed cached in the cell.
"""
BINARY_REFINERY = 'ba5e3a3b830a1e15c632fa2a3977546dfd062dba67bc712210a1ade6f86b3b6b'

REVENG1 = 'bdbf1469798c19b8f9ba27919aa2a98bb7a79ce810baac45423c11afc3aa21b7'

LOWER_CASE_CELLNAMES = '188d13459e03bc505e337e1508d440e427cab3dfd71280667bcbe5c1010abf51'

SELF_EVALUATION_REPORT = '82f4ac4a0c88fe023383c1fbaee47df129b28479e92f6ec5a51e4425462d93e2'

SHARED_STRINGS_ALT_LOCATION = '5ad66fb5a66c1e91f853d1aa4dd0b3e3dcc50b3cabccc84eda12aba810c4dc82'

APACHE_POI_52348 = '0021fa21968bb6083b7f58506269cac214faecaf81d79c3091f36d0fca9cae76'

FORMATE_BIFF8 = 'ec916bcdf0df1b98fb9eda822aae06dd1b7bc80b8fbaf8cd93a8c8768e810e0e'

PROFILES_BIFF8 = '6235da262dd2c23d12c95f9a7190f931df6cc16717c968d47359355595ed3803'

FORMULA_TEST_NAMES = '577c00f4750464324ddebc0cda405d931f838b61687bbacc7b717d42d153446e'

FORMULA_TEST_SJMACHIN = '318ce6ee18977add9852993aea79e41a9ddea9131e3f9bcc85febbca3e4059e0'

ISSUE20 = '06be33a16f611910678c43808ce190bcae1e421ecca6be3b28c9c6724441ef4d'

RAGGED = 'a144c284163641c2cb7dfc17d0116006aeffc3dff2b4878f039d4dbab6e2b07e'

PICTURE_IN_CELL = '497fdab68fed04541e4ed7f5284ba1ee0a927290206000158a20fda5efbca80f'

BIFF4_RAW = 'ff5be7a32b8a8f85dba86c7b5ae88069c6ddb4753968f9f5941497e6e207018b'

CORRUPTED_ERROR = '1b079f55d57bcc5c75f892853282c43da2749aa7f740f898006ac13612168dad'

TEST_XLSB = '94e006f195668677170b9e0efb7ba8d443fa6c9c2149ebd78b7a67d77a99c09e'

DATES_XLSB = '6ee82324a6241f59925f16ee37cfbf359a38ff637b672d67ba8d0cc84e72673a'

TEST_1904_XLSB = '872264037e8d34929d2ec564d46d34443c332f7019f87f020f4ef0e9918bd9c8'

XLM_MACRO_RPN_BIFF8 = '152263b91bfcd7473f930ca50fe4bb10938823db11b353f9a29fbeea5a4f4e5b'

XLM_MACRO_NAMES_BIFF8 = '6413be289cf38c2462bd8c6b8bad47f8d953f399e1ccba30126a1fb70d13a733'

XLM_MACRO_ASSIGN_BIFF8 = 'eba7c4994a5cde3da749b4ebdb5e01ba0e675262198217b36f8cfd61daabae43'

XLM_MACRO_TEXT_XLSM = '4e733d150143fe761bb2530446d484022cd45e2930c61dd1439d1da0c9078f65'

XLM_MACRO_FORMULA_XLSM = '7bf40836e37d5f6c5a459583787b39853828f1fe8dcb8b659384e6f3d45e0021'

OPERATOR_ORACLE_XLSX = '1768b72fff3db7742c23f51a4eacaf3647164eb3ff5c62ab59f38e677aa6e82b'

OPERATOR_ORACLE_XLSB = '2fed62b33d6b651564e01671af27d26058f4ecaad11ab3e5fea13c31bd56925e'

OPERATOR_ORACLE_BIFF8 = '8b306d9f70e437689ddee1b7a7b46a524dc041f09308fbf74b923a74fffe9741'
