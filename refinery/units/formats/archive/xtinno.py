from __future__ import annotations

from refinery.lib import json
from refinery.lib.inno.archive import (
    InnoArchive,
    InvalidPassword,
    SetupFileFlags,
    is_inno_setup,
)
from refinery.lib.mime import FileMagicInfo as magic
from refinery.lib.structures import struct_to_json
from refinery.units.formats.archive import ArchiveUnit


class _ps:
    """
    Note: This unit generates the following synthetic metadata files under the "meta" directory:

    - `setup.bin` contains the raw bytes for the setup metadata
    - `setup.template` contains the raw and unprocessed metadata in JSON format
    - `setup.json` contains the setup metadata with all format fields expanded

    Similarly, there are `files.bin`, `files.template`, and `files.json` that contain the metadata
    of the archived files. The files that are extracted under the "embedded" directory are usually
    parts of the InnoSetup installer and not user data. All archived files are extracted within the
    directory named "data".
    """


class xtinno(ArchiveUnit, _ps, docs='{0} {PathExtractorUnit}{p}{_ps}'):
    """
    Extract files from InnoSetup archives:
    """
    def unpack(self, data: bytearray):
        def post_process_json(doc):
            if isinstance(doc, dict):
                return {key: post_process_json(val) for key, val in doc.items()}
            if isinstance(doc, list):
                return [post_process_json(entry) for entry in doc]
            if not isinstance(doc, str):
                return doc
            try:
                return inno.emulator.reset().expand_constant(doc)
            except Exception:
                return doc

        inno = InnoArchive(data, self)

        _pwd: bytes = self.args.pwd
        password = _pwd.decode(self.codec) if _pwd else None

        if any(file.encrypted for file in inno.files) and password is None:
            self.log_info('some files are password-protected and no password was given')

        if t_setup := inno.streams.TSetup.data:
            yield self._pack('meta/setup.bin', None, t_setup)
            doc = struct_to_json(inno.setup_info)
            yield self._pack('meta/setup.template', None, json.dumps(doc, tojson=json.bytes_as_array))
            doc = post_process_json(doc)
            yield self._pack('meta/setup.json', None, json.dumps(doc, tojson=json.bytes_as_array))

        if t_data := inno.streams.TData.data:
            yield self._pack('meta/files.bin', None, t_data)
            doc = struct_to_json(inno.setup_data)
            yield self._pack('meta/files.template', None, json.dumps(doc, tojson=json.bytes_as_array))
            doc = post_process_json(doc)
            yield self._pack('meta/files.json', None, json.dumps(doc, tojson=json.bytes_as_array))

        def _uninstaller(i=inno):
            return i.read_stream(i.streams.Uninstaller)
        yield self._pack('embedded/uninstaller.exe', None, _uninstaller)

        if license := inno.setup_info.Header.get_license():
            yield self._pack('embedded/license.rtf', None, license.encode(self.codec))

        if script := inno.setup_info.Header.get_script():
            yield self._pack('embedded/script.bin', None, script)
            yield self._pack('embedded/script.ps', None,
                lambda i=inno: ps.disassembly().encode(self.codec) if (ps := i.ifps) else B'')

        if dll := inno.setup_info.get_decompress_dll():
            yield self._pack(F'embedded/decompress.{magic(dll).extension}', None, dll)

        if dll := inno.setup_info.get_decryption_dll():
            yield self._pack(F'embedded/decryption.{magic(dll).extension}', None, dll)

        for size, images in (
            ('small', inno.setup_info.get_wizard_images_small()),
            ('large', inno.setup_info.get_wizard_images_large()),
        ):
            _formatting = len(str(len(images) + 1))
            for k, img in enumerate(images, 1):
                yield self._pack(F'embedded/images/{size}{k:0{_formatting}d}.{magic(img).extension}', None, img)

        for file in inno.files:
            if file.dupe:
                continue

            def _read(inno=inno, file=file, pwd=password):
                if pwd is None:
                    inno.guess_password(10)
                if self.leniency > 0:
                    return inno.read_file(file, pwd)
                try:
                    return inno.read_file_and_check(file, pwd)
                except InvalidPassword:
                    raise
                except Exception as E:
                    raise ValueError(F'{E!s} [ignore this check with -L]') from E

            yield self._pack(file.path, file.date, _read,
                tags=[t.name for t in SetupFileFlags if t & file.tags])

    @classmethod
    def handles(cls, data):
        return is_inno_setup(data)
