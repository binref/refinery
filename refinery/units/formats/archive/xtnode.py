#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Iterable, Optional, Dict

import re
import json

from refinery.units.formats.archive import Arg, ArchiveUnit, UnpackResult
from refinery.units.encoding.esc import esc
from refinery.lib.structures import EOF, StructReader
from refinery.lib.patterns import formats
from refinery.lib.types import ByteStr, JSON
from refinery.units.pattern.carve_json import JSONCarver


class JSONReader(StructReader):

    def read_string(self) -> Optional[str]:
        quote = self.u8()
        value = bytearray()
        if quote not in B'\"\'':
            raise RuntimeError('trying to read a string, but no quote character was found')
        escaped = False
        while True:
            char = self.u8()
            if escaped:
                escaped = False
            elif char == B'\\':
                escaped = True
            elif char == quote:
                break
            value.append(char)
        return value | esc | str

    def read_json(self) -> Optional[JSON]:
        while self.u8() not in b'[{':
            pass
        self.seekrel(-1)
        end = JSONCarver.find_end(self._data, self._cursor)
        if end is None:
            return None
        data = self._data[self._cursor:end]
        self._cursor = end
        if isinstance(data, memoryview):
            data = bytes(data)
        return json.loads(data)

    def skip_comma(self):
        while self.u8() in b'\n\t\r\f\v\x20,':
            pass
        self.seekrel(-1)
        return self


class xtnode(ArchiveUnit):
    """
    Extracts and decompiles files from compiled Node.Js applications. Supports both nexe and pkg, two
    utilities that are commonly used to generate stand-alone executables.
    """

    _NEXE_SENTINEL = B'<nexe~~sentinel>'
    _PKG_PAYLOAD_P = B'PAYLOAD_POSITION'
    _PKG_PAYLOAD_S = B'PAYLOAD_SIZE'
    _PKG_PRELUDE_P = B'PRELUDE_POSITION'
    _PKG_PRELUDE_S = B'PRELUDE_SIZE'
    _PKG_COMMON_JS = B'sourceMappingURL=common.js.map'

    def __init__(
        self, *paths, entry: Arg.Switch('-u', help='Only extract the entry point.') = False,
        list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False,
        path=b'path', date=b'date',
    ):
        super().__init__(*paths, entry=entry,
            list=list, join_path=join_path, drop_path=drop_path, fuzzy=fuzzy, exact=exact, regex=regex,
            path=path, date=date)

    def unpack(self, data: ByteStr) -> Iterable[UnpackResult]:
        if self._is_nexe(data):
            self.log_info('unpacking as nexe')
            yield from self._unpack_nexe(data)
            return
        if self._is_pkg(data):
            self.log_info('unpacking as pkg')
            yield from self._unpack_pkg(data)
            return

    def _unpack_nexe(self, data: ByteStr):
        try:
            ep = re.compile(
                RB"entry\s*=\s*path\.resolve\(path\.dirname\(process\.execPath\),\s*(%s)\)" % formats.string)
            ep, = ep.finditer(data)
        except Exception:
            ep = None
            self.log_info('could not identify entry point')
        else:
            ep = ep.group(1) | esc(quoted=True) | str
            self.log_info(F'entry point: {ep}')
        view = memoryview(data)
        for marker in re.finditer(re.escape(self._NEXE_SENTINEL), data):
            end = marker.end() + 16
            sizes = data[marker.end():end]
            if sizes.startswith(b"')"):
                continue
            reader = StructReader(sizes)
            code_size = int(reader.f64())
            blob_size = int(reader.f64())
            start = marker.start() - code_size - blob_size
            try:
                reader = StructReader(view[start:end])
                code = reader.read_exactly(code_size)
                blob = reader.read_exactly(blob_size)
            except EOF:
                self.log_debug(F'found marker at 0x{marker.start():X}, but failed to read data')
                continue
            else:
                self.log_debug(F'found marker at 0x{marker.start():X}, data start at {start:X}')
            for rsrc in re.finditer(RB'process\.__nexe\s*=', code):
                rsrc = JSONReader(code[rsrc.end():])
                rsrc = rsrc.read_json()
                if len(rsrc) == 1:
                    _, rsrc = rsrc.popitem()
                for path, (offset, length) in rsrc.items():
                    end = offset + length
                    if ep and self.args.entry and path != ep:
                        continue
                    yield UnpackResult(path, blob[offset:end])

    def _unpack_pkg(self, data: ByteStr):
        def _extract_coordinates(*v):
            for name in v:
                pattern = BR'%s\s{0,3}=\s{0,3}(%s)' % (name, formats.string)
                value, = re.findall(pattern, data)
                yield int((value | esc(quoted=True) | str).strip())

        def _extract_data(*v):
            try:
                offset, length = _extract_coordinates(*v)
            except Exception:
                return None
            return data[offset:offset + length]

        payload = _extract_data(self._PKG_PAYLOAD_P, self._PKG_PAYLOAD_S)
        if not payload:
            raise ValueError('unable to extract payload')
        prelude = _extract_data(self._PKG_PRELUDE_P, self._PKG_PRELUDE_S)
        if not prelude:
            raise ValueError('unable to extract prelude')
        mapping = re.search(re.escape(self._PKG_COMMON_JS) + BR'\s*\},\s*\{', prelude)
        if not mapping:
            raise ValueError('unable to find common.js mapping')

        reader = JSONReader(prelude[mapping.end() - 1:])

        files: Dict[str, dict] = reader.read_json()

        if files is None:
            raise ValueError('failed to read file list')

        entry = reader.skip_comma().read_string()
        links = reader.skip_comma().read_json()

        # _unknown1 = reader.skip_comma().read_json()
        # _unknown2 = reader.skip_comma().read_terminated_array(B')').strip()

        root = next(iter(files))
        skip = 0
        view = memoryview(payload)

        for k in range(len(root) + 1):
            test = root[:k].rstrip('/').rstrip('\\')
            if not all(path.startswith(test) for path in files):
                root = test[:-1]
                skip = k - 1
                break

        entry = entry[skip:]
        self.log_info(F'detected root directory {root}, entry point is {entry}')

        for src, dst in links.items():
            new_files = {}
            self.log_info('link src:', src[skip:])
            self.log_info('link dst:', dst[skip:])
            for path, location in files.items():
                if not path.startswith(src):
                    continue
                new_path = dst + path[len(src):]
                new_files[new_path] = location
                self.log_debug('synthesizing linked file:', new_path)
            files.update(new_files)

        for path, location in files.items():
            path = path[skip:]
            if entry and self.args.entry and path != entry:
                continue
            data = None
            for kind, (offset, length) in location.items():
                stop = offset + length
                if kind == '3':  # metadata
                    continue
                if kind == '2':  # unknown
                    continue
                if kind in '01':
                    data = view[offset:stop]
            if data is not None:
                yield UnpackResult(path, data)

    @classmethod
    def _is_nexe(cls, data: ByteStr) -> bool:
        return cls._NEXE_SENTINEL in data

    @classmethod
    def _is_pkg(cls, data: ByteStr) -> bool:
        if cls._PKG_PAYLOAD_P not in data:
            return False
        if cls._PKG_PAYLOAD_S not in data:
            return False
        if cls._PKG_PRELUDE_P not in data:
            return False
        if cls._PKG_PRELUDE_S not in data:
            return False
        if cls._PKG_COMMON_JS not in data:
            return False
        return True

    @classmethod
    def handles(cls, data: ByteStr) -> Optional[bool]:
        return cls._is_nexe(data) or cls._is_pkg(data)
