from __future__ import annotations

import itertools
import re
import string

from refinery.lib.argformats import ParserError, PythonExpression, numseq
from refinery.lib.meta import STRING_FORMAT_HELP, LazyMetaOracle, SizeInt, check_variable_name, metavars
from refinery.lib.structures import StructReaderBits
from refinery.lib.types import Param
from refinery.units import Arg, Chunk, Unit


def identity(x):
    return x


_REST_MARKER = '#'


class _RecordParser:
    """
    Extracts all fields of a single record of structured data, as described by the format
    specification of a `struct` unit.
    """

    def __init__(self, unit: struct, reader: StructReaderBits, meta: LazyMetaOracle, byteorder: str):
        self.unit = unit
        self.reader = reader
        self.meta = meta
        self.byteorder = byteorder
        self.field_format = unit.args.format
        self.args: list = []
        self.field_count = 0
        self.last: object = None

    def parse(self, spec: str) -> tuple[list, object]:
        """
        Parses all fields of one record; returns the list of extracted values and the last byte
        string field that was read, if any.
        """
        for prefix, name, field_spec, conversion in string.Formatter().parse(spec):
            peek = prefix.endswith(':')
            if peek:
                prefix = prefix[:~0]
            if prefix:
                self._read_prefix(prefix)
            if name is not None:
                self._read_field(name, field_spec, conversion, peek)
        return self.args, self.last

    def _fixorder(self, spec: str) -> str:
        if spec[0] not in '<@=!>':
            spec = self.byteorder + spec
        return spec

    def _read_prefix(self, prefix: str) -> None:
        fields = self.reader.read_struct(self._fixorder(prefix))
        if self.field_format:
            codes = re.findall('[?cbBhHiIlLqQnNefdspPauwgk]', prefix)
            if len(codes) != len(fields):
                codes = 'v' * len(fields)
            for code, field in zip(codes, fields):
                code = 'b' if code == '?' else code.lower()
                variable = self.field_format.format_map({'c': code, 'n': self.field_count})
                self.meta[variable] = field
                self.field_count += 1
        self.args.extend(fields)

    def _read_field(self, name: str, field_spec: str | None, conversion: str | None, peek: bool) -> None:
        self.field_count += 1
        if name and not name.isdecimal():
            check_variable_name(name)
        alignment = self._parse_conversion(conversion)
        spec, _, pipeline = (field_spec or '').partition(':')
        if spec:
            spec = self._evaluate_spec(spec)
        if alignment == 0:
            if not isinstance(spec, int) or spec < 0:
                raise ValueError(F'The format of the bit field {name} has to specify a number of bits.')
            value = self.reader.read_integer(spec, peek=peek)
        else:
            value = self._read_value(name, spec, peek)
        if value is None:
            self.unit.log_debug(F'field {name} was empty, ignoring.')
            return
        if pipeline:
            value = numseq(pipeline, reverse=True, seed=value)
        self.args.append(value)
        self._assign(name, value)

    def _parse_conversion(self, conversion: str | None) -> int | None:
        """
        Evaluates the conversion as an alignment expression and moves the cursor accordingly; a value
        of zero requests the field to be read as a bit field.
        """
        if not conversion:
            return None
        alignment = PythonExpression.Evaluate(conversion, self.meta)
        if alignment == 0:
            return 0
        before = self.reader.tell()
        self.reader.byte_align(alignment)
        after = self.reader.tell()
        if before != after:
            self.unit.log_info(F'aligned from 0x{before:X} to 0x{after:X}')
        return alignment

    def _evaluate_spec(self, spec: str) -> str | int:
        spec = self.meta.format_str(spec, self.unit.codec, self.args)
        if not spec:
            return spec
        try:
            return PythonExpression.Evaluate(spec, self.meta)
        except ParserError:
            return spec

    def _read_value(self, name: str, spec: str | int, peek: bool):
        """
        Reads the field data; returns None if the field format produced no data. Whenever the data
        is a byte string, it also becomes the default output of the record.
        """
        if spec == '':
            self.last = value = self.reader.read(peek=peek)
        elif isinstance(spec, int):
            if spec < 0:
                spec += self.reader.remaining_bytes
            if spec < 0:
                raise ValueError(F'The specified negative read offset is {-spec} beyond the cursor.')
            self.last = value = self.reader.read_bytes(spec, peek=peek)
        else:
            value = self.reader.read_struct(self._fixorder(spec), peek=peek)
            if not value:
                return None
            if len(value) > 1:
                self.unit.log_info(F'parsing field {name} produced {len(value)} items reading a tuple')
            else:
                value = value[0]
        return value

    def _assign(self, name: str, value) -> None:
        if name == _REST_MARKER:
            raise ValueError(F'Extracting a field with name {_REST_MARKER} is forbidden.')
        if name.isdecimal():
            index = int(name)
            limit = len(self.args) - 1
            if index > limit:
                self.unit.log_warn(F'cannot assign index field {name}, the highest index is {limit}')
            else:
                self.args[index] = value
        elif name:
            self.meta[name] = value


class struct(Unit):
    """
    Parse structured binary data into meta variables using a parsing language based on the Python
    struct format.

    This unit uses two separate semantics based on format strings: One for parsing the input, and
    another one for parsing the output.

    (1) The input parsing format works as follows: A struct definition can include bare Python
    struct parser letters like L for long integer or B for bytes, but also the following additional
    format characters:

    - `a` for null-terminated ASCII strings,
    - `u` to read encoded, null-terminated UTF16 strings,
    - `w` to read decoded, null-terminated UTF16 strings,
    - `g` to read Microsoft GUID values,
    - `E` to read 7-bit encoded integers.
    - `:` to peek the next value (cursor is not advanced)

    For example, the string `LLxxHaa` will read two unsigned 32bit integers, then skip two bytes,
    then read one unsigned 16bit integer, then two null-terminated ASCII strings. The unit defaults
    to using native byte order with no alignment.

    To extract fields from the struct definition under a name, format specifications are inserted
    into the struct definitions that look like this:

        {name[!alignment]:format}

    The `alignment` parameter is optional. It supports the following values:

    - `0`: the format specifies a number of bits to read; the result is always an integer
    - `a`: the variable `a` must be defined and specifies the alignment
    - `2`: align cursor to a multiple of 2 bytes (equivalently for any positive digit)

    The `format` can either be an integer expression specifying a number of bytes to read, or any
    of the aforementioned format strings. The extracted data is then stored in the meta variable
    with the given name. For example, `LLxxH{foo:a}{bar:a}` would be parsed in the same way as the
    previous example, but the two ASCII strings would also be stored in meta variables under the
    names `foo` and `bar`, respectively. The `format` string of a named field is itself parsed as a
    format string expression, where all the previously parsed fields are already available. For
    example, `I{:{}}` reads a single 32-bit integer length prefix and then reads as many bytes as
    that prefix specifies.

    (2) Conversely, the standard refinery string formatting is used to specify the output. %s

    For example, the struct definition `LLxxH{foo:a}{bar:a}` with the output format `{foo}/{bar}`
    would parse data as before, but the output body would be the concatnation of the field `foo`,
    a forward slash, and the field `bar`. Variables used in the output expression are not included
    as meta variables. As format fields in the output expression, one can also use `{1}`, `{2}` or
    `{-1}` to access extracted fields by index. The value `{0}` represents the entire chunk of
    structured data. By default, the output format `{%s}` is used, which represents either the last
    byte string field that was extracted, or the entire chunk of structured data if none of the
    fields were extracted.
    """

    def __init__(
        self,
        spec: Param[str, Arg.String(help='Structure format as explained above.')],
        *outputs: Param[str, Arg.String(metavar='output', help='Output format as explained above.')],
        multi: Param[bool, Arg.Switch('-m', help=(
            'Read as many pieces of structured data as possible intead of just one.'))] = False,
        count: Param[int, Arg.Number('-c', help=(
            'A limit on the number of chunks to read in multi mode; there is no limit by default.'))] = 0,
        until: Param[str, Arg.String('-u', metavar='E', help=(
            'An expression evaluated on each chunk in multi mode. New chunks will be parsed '
            'only if the result is nonzero.'))] = '',
        format: Param[str, Arg.String('-f', metavar='F', help=(
            'Optionally specify a format string expression to auto-name extracted fields without a '
            'given name. The format string accepts the field {{c}} for the type code and {{n}} for '
            'the variable index.'))] = '',
        name: Param[str, Arg.String('-n', metavar='VAR', group='FIELDS', help=(
            'Equivalent to --format=VAR{{n}}.'))] = '',
        more: Param[bool, Arg.Switch('-M', help=(
            'After parsing the struct, emit one chunk that contains the data that was left '
            'over in the buffer. If no data was left over, this chunk will be empty.'))] = False
    ):
        if name:
            format = format or F'{name}{{n}}'
        outputs = outputs or (F'{{{_REST_MARKER}}}',)
        super().__init__(spec=spec, outputs=outputs, until=until, format=format, count=count, multi=multi, more=more)

    def process(self, data: Chunk):
        until = self.args.until
        until = until and PythonExpression(until, all_variables_allowed=True)
        mainspec = self.args.spec
        byteorder = mainspec[:1]
        count = self.args.count

        if byteorder in '<@=!>':
            mainspec = mainspec[1:]
        else:
            byteorder = '='

        view = memoryview(data)
        reader = StructReaderBits(view, bigendian=byteorder in '>!')
        previously_existing_variables = set(metavars(data).variable_names())

        leftover_start = None
        bit_cursor = 0
        it = itertools.count() if self.args.multi else (0,)
        for index in it:

            if reader.remaining_bits == 0:
                break
            if 0 < count <= index:
                break

            bit_cursor = 8 * reader.tell() - reader.bits_in_buffer
            meta = metavars(data)
            meta.index = index

            self.log_debug(F'starting new read at bit 0x{bit_cursor:X}')

            try:
                parser = _RecordParser(self, reader, meta, byteorder)
                args, last = parser.parse(mainspec)

                if until and until(meta):
                    self.log_info(F'the expression ({until}) evaluated to true; aborting.')
                    break

                end = 8 * reader.tell() - reader.bits_in_buffer
                if self.args.multi and end == bit_cursor:
                    raise ValueError('The record did not consume any data.')

                full = view[bit_cursor // 8:(end + 7) // 8]
                if last is None:
                    last = full

                outputs = self._format_outputs(
                    meta, full, args, last, previously_existing_variables)

                for output in outputs:
                    chunk = Chunk(output)
                    chunk.meta.update(meta)
                    chunk.set_next_batch(index)
                    yield chunk

            except EOFError:
                leftover_start = bit_cursor
                break

        if leftover_start is None:
            leftover_start = 8 * reader.tell() - reader.bits_in_buffer

        leftover = 8 * len(view) - leftover_start

        if not leftover:
            return
        elif self.args.more:
            yield view[leftover_start // 8:]
        else:
            leftover = repr(SizeInt(-(-leftover // 8))).strip()
            self.log_info(F'discarding {leftover} left in buffer')

    def _format_outputs(
        self,
        meta: LazyMetaOracle,
        full: memoryview,
        args: list,
        last: object,
        protected_variables: set[str],
    ) -> list:
        """
        Renders all output templates for one parsed record; meta variables that occur only in the
        output templates are discarded afterwards, the protected ones are kept.
        """
        outputs = []
        symbols = dict(meta)
        symbols[_REST_MARKER] = last
        for template in self.args.outputs:
            used = set()
            outputs.append(meta.format(template, self.codec, [full, *args], symbols, used=used))
            for key in used:
                if key not in protected_variables:
                    meta.discard(key)
        return outputs


if __d := struct.__doc__:
    struct.__doc__ = __d % (STRING_FORMAT_HELP, _REST_MARKER)
