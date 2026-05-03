from __future__ import annotations

import re
import zlib

from struct import unpack
from typing import Generator, TYPE_CHECKING

from refinery.units import Unit

if TYPE_CHECKING:
    from refinery.lib.ole.crypto import OleFile


class meow(Unit):
    """
    Extract password hashes from various file types in hashcat format.

    The following file types are supported:

    - PDF (hashcat modes 10400, 10500, 10600, 10700)
    - RAR3 (hashcat mode 12500)
    - RAR5 (hashcat mode 13000)
    - ZIP with WinZip AES encryption (hashcat mode 13600)
    - ZIP with PKZIP traditional encryption (hashcat modes 17200-17230)
    - 7-Zip (hashcat mode 11600)
    - Microsoft Office 2007/2010/2013 (hashcat modes 9400, 9500, 9600)
    - Microsoft Office 97-2003 (hashcat modes 9700, 9800)
    """

    def process(self, data: bytearray) -> bytes | Generator[bytes, None, None]:
        from refinery.lib.ole.crypto import is_ole_file
        from refinery.lib.un7z.headers import SIGNATURE as SZ_SIGNATURE
        from refinery.lib.unrar.headers import RAR_HEADER_V15, RAR_HEADER_V50, RarFormat

        view = memoryview(data)
        if view[:5] == B'%PDF-':
            return self._hash_pdf(data)
        if view[:7] == RAR_HEADER_V15:
            return self._hash_rar(data, RarFormat.RARFMT15)
        if view[:8] == RAR_HEADER_V50:
            return self._hash_rar(data, RarFormat.RARFMT50)
        if view[:2] == B'PK':
            return self._hash_zip(data)
        if view[:6] == SZ_SIGNATURE:
            return self._hash_7z(data)
        if is_ole_file(data):
            return self._hash_office(data)
        raise ValueError('unable to identify an encrypted file format')

    @Unit.Requires('pymupdf', 1)
    def _pymupdf():
        import os
        for setting in ('PYMUPDF_MESSAGE', 'PYMUPDF_LOG'):
            os.environ[setting] = F'path:{os.devnull}'
        import pymupdf
        return pymupdf

    def _hash_pdf(self, data: bytearray) -> bytes:
        doc = self._pymupdf.open(stream=bytes(data), filetype='pdf')
        if not doc.is_encrypted:
            raise ValueError('this PDF is not encrypted')
        trailer_str = doc.pdf_trailer()
        enc_ref_match = re.search(
            r'/Encrypt\s+(\d+)\s+\d+\s+R', trailer_str)
        if enc_ref_match is None:
            raise ValueError('PDF trailer does not contain /Encrypt')
        encrypt_xref = int(enc_ref_match.group(1))
        obj_str = doc.xref_object(encrypt_xref)

        def _int(key: str) -> int | None:
            kind, val = doc.xref_get_key(encrypt_xref, key)
            return int(val) if kind == 'int' else None

        def _hex(key: str) -> bytes | None:
            hit = re.search(F'/{key}\\s*<([0-9A-Fa-f]+)>', obj_str)
            return bytes.fromhex(hit.group(1)) if hit else None

        _V = _int('V')
        _R = _int('R')
        _P = _int('P')
        _O = _hex('O')
        _U = _hex('U')

        keylen = _int('Length') or 40

        if _V is None or _R is None or _P is None or _O is None or _U is None:
            raise ValueError('missing required PDF encryption fields')

        kind, id_val = doc.xref_get_key(-1, 'ID')
        id_hex_values = re.findall(r'<([0-9A-Fa-f]+)>', id_val)
        if not id_hex_values:
            raise ValueError('could not parse /ID array from trailer')
        doc_id = bytes.fromhex(id_hex_values[0])

        enc_meta = 1
        kind, val = doc.xref_get_key(encrypt_xref, 'EncryptMetadata')
        if kind == 'bool' and val.lower() == 'false':
            enc_meta = 0

        parts = [
            F'$pdf${_V}',
            str(_R),
            str(keylen),
            str(_P),
            str(enc_meta),
            str(len(doc_id)),
            doc_id.hex(),
            str(len(_U)),
            _U.hex(),
            str(len(_O)),
            _O.hex(),
        ]
        if _R >= 5:
            OE = _hex('OE')
            UE = _hex('UE')
            if OE is None or UE is None:
                raise ValueError('missing /OE or /UE for R>=5 encryption')
            parts.append(str(len(UE)))
            parts.append(UE.hex())
            parts.append(str(len(OE)))
            parts.append(OE.hex())
        return '*'.join(parts).encode(self.codec)

    def _hash_rar(self, data: bytearray, fmt) -> Generator[bytes, None, None]:
        from refinery.lib.unrar.headers import (
            CryptMethod,
            RarFormat,
            parse_headers,
        )

        view = memoryview(data)
        main, entries, _, crypt_header = parse_headers(view, fmt)

        if fmt == RarFormat.RARFMT15:
            if main is not None and main.is_encrypted and len(data) >= 24:
                tail = bytes(view[-24:])
                salt = tail[:8].hex()
                crypt_data = tail[8:].hex()
                yield F'$RAR3$*0*{salt}*{crypt_data}'.encode(self.codec)
            return

        if crypt_header is not None:
            if crypt_header.use_psw_check and crypt_header.psw_check:
                salt = bytes(crypt_header.salt).hex()
                lg2 = crypt_header.lg2_count
                if crypt_header.header_iv:
                    iv = bytes(crypt_header.header_iv).hex()
                else:
                    iv = (b'\0' * 16).hex()
                pswcheck = bytes(crypt_header.psw_check).hex()
                yield F'$rar5$16${salt}${lg2}${iv}$8${pswcheck}'.encode(self.codec)
                return

        for entry in entries:
            if not entry.is_encrypted:
                continue
            if entry.crypt_method == CryptMethod.CRYPT_RAR50:
                if entry.use_psw_check and entry.psw_check:
                    salt = bytes(entry.salt).hex()
                    lg2 = entry.lg2_count
                    iv = bytes(entry.init_v).hex()
                    pswcheck = bytes(entry.psw_check).hex()
                    yield F'$rar5$16${salt}${lg2}${iv}$8${pswcheck}'.encode(self.codec)
                    return

    def _hash_7z(self, data: bytearray) -> bytes:
        from refinery.lib.structures import StructReader
        from refinery.lib.un7z.coders import CODEC_AES256SHA256, decompress_folder
        from refinery.lib.un7z.headers import (
            ArchiveHeader,
            SIGNATURE_HEADER_SIZE,
            PropertyID,
            parse_encoded_header,
            parse_header,
            parse_signature_header,
        )

        view = memoryview(data)
        sh = parse_signature_header(view)
        header_offset = SIGNATURE_HEADER_SIZE + sh.next_header_offset
        header_end = header_offset + sh.next_header_size
        header_view = view[header_offset:header_end]
        crc = zlib.crc32(header_view) & 0xFFFFFFFF
        if crc != sh.next_header_crc:
            raise ValueError('7z header CRC mismatch')

        reader = StructReader(header_view)
        prop_id = reader.u8()

        if prop_id == PropertyID.ENCODED_HEADER:
            enc = parse_encoded_header(reader)
            if not enc.folders or enc.pack_info is None:
                raise ValueError('7z encoded header has no folders or pack info')
            folder = enc.folders[0]
            pack_offset = SIGNATURE_HEADER_SIZE + enc.pack_info.pack_pos
            if any(c.codec_id == CODEC_AES256SHA256 for c in folder.coders):
                packed = bytes(view[pack_offset:pack_offset + enc.pack_info.sizes[0]])
                return self._hash_7z_folder(folder, packed)
            packed_streams: list[memoryview] = []
            offset = pack_offset
            for size in enc.pack_info.sizes:
                packed_streams.append(view[offset:offset + size])
                offset += size
            header_data = decompress_folder(
                folder, packed_streams, folder.main_unpack_size)
            inner_reader = StructReader(memoryview(header_data))
            inner_prop = inner_reader.u8()
            if inner_prop != PropertyID.HEADER:
                raise ValueError('7z decoded header is not a plain header')
            header: ArchiveHeader = parse_header(inner_reader)
        elif prop_id == PropertyID.HEADER:
            header = parse_header(reader)
        else:
            raise ValueError('7z archive does not appear to be encrypted')

        if header.pack_info is None:
            raise ValueError('7z archive has no pack info')
        pack_offset = SIGNATURE_HEADER_SIZE + header.pack_info.pack_pos
        offset = pack_offset
        pack_starts: list[int] = []
        for size in header.pack_info.sizes:
            pack_starts.append(offset)
            offset += size
        for fi, folder in enumerate(header.folders):
            if any(c.codec_id == CODEC_AES256SHA256 for c in folder.coders):
                pi = sum(
                    len(header.folders[k].packed_indices)
                    for k in range(fi)
                )
                packed = bytes(view[pack_starts[pi]:pack_starts[pi] + header.pack_info.sizes[pi]])
                crc: int | None = folder.crc
                crc_len: int | None = None
                if crc is None and header.substreams and header.substreams.crcs:
                    for sc in header.substreams.crcs:
                        if sc is not None:
                            crc = sc
                            break
                    if header.substreams.unpack_sizes:
                        crc_len = header.substreams.unpack_sizes[0]
                return self._hash_7z_folder(folder, packed, crc, crc_len)

        raise ValueError('7z archive does not appear to be encrypted')

    def _hash_7z_folder(
        self,
        folder,
        packed_data: bytes,
        override_crc: int | None = None,
        override_crc_len: int | None = None,
    ) -> bytes:
        from refinery.lib.un7z.coders import (
            CODEC_AES256SHA256,
            CODEC_ARM,
            CODEC_ARMT,
            CODEC_BCJ_X86,
            CODEC_BZIP2,
            CODEC_COPY,
            CODEC_DEFLATE,
            CODEC_DELTA,
            CODEC_IA64,
            CODEC_LZMA,
            CODEC_LZMA2,
            CODEC_PPC,
            CODEC_PPMD,
            CODEC_SPARC,
        )
        compressor_type = {
            CODEC_COPY    : 0,
            CODEC_LZMA    : 1,
            CODEC_LZMA2   : 2,
            CODEC_PPMD    : 3,
            CODEC_BZIP2   : 6,
            CODEC_DEFLATE : 7,
        }
        filter_type = {
            CODEC_BCJ_X86 : 1,
            CODEC_PPC     : 3,
            CODEC_IA64    : 4,
            CODEC_ARM     : 5,
            CODEC_ARMT    : 6,
            CODEC_SPARC   : 7,
            CODEC_DELTA   : 9,
        }

        aes_props: bytes = b''
        data_type = 0
        coder_attrs = bytearray()

        for coder in folder.coders:
            if coder.codec_id == CODEC_AES256SHA256:
                aes_props = coder.properties
            elif coder.codec_id in compressor_type:
                data_type |= compressor_type[coder.codec_id]
                coder_attrs.extend(coder.properties)
            elif coder.codec_id in filter_type:
                data_type |= filter_type[coder.codec_id] << 4
                coder_attrs.extend(coder.properties)

        if len(aes_props) < 2:
            raise ValueError('7z AES coder has no properties')

        first_byte = aes_props[0]
        num_cycles_power = first_byte & 0x3F
        salt_size = ((first_byte >> 7) & 1) + (aes_props[1] >> 4)
        iv_size = ((first_byte >> 6) & 1) + (aes_props[1] & 0x0F)
        prop_data = aes_props[2:]
        salt = bytes(prop_data[:salt_size])
        iv = bytes(prop_data[salt_size:salt_size + iv_size])
        iv_padded = iv + b'\0' * (16 - len(iv))

        if override_crc is not None:
            crc = override_crc
        elif folder.crc is not None:
            crc = folder.crc
        else:
            crc = 0
        data_len = len(packed_data)
        unpack_size = folder.main_unpack_size

        parts = [
            F'$7z${data_type}',
            str(num_cycles_power),
            str(salt_size),
            salt.hex(),
            str(iv_size),
            iv_padded.hex(),
            str(crc),
            str(data_len),
            str(unpack_size),
            packed_data.hex(),
        ]
        result = '$'.join(parts)
        if data_type > 0:
            crc_len = override_crc_len if override_crc_len is not None else unpack_size
            result += F'${crc_len}${coder_attrs.hex()}'
        return result.encode(self.codec)

    def _hash_zip(self, data: bytearray) -> Generator[bytes, None, None]:
        from refinery.lib.zip import AExCrypto, Zip, ZipCrypto

        archive = Zip(data, read_records=True)
        pkzip_entries: list[tuple] = []

        for entry in archive.directory:
            try:
                record = archive.read(entry)
            except Exception:
                continue
            if not record.flags.Encrypted:
                continue
            enc = record.encryption
            if isinstance(enc, AExCrypto):
                yield self._hash_zip_aes(record, enc)
            elif isinstance(enc, ZipCrypto):
                pkzip_entries.append((record, enc))

        if pkzip_entries:
            yield self._hash_zip_pkzip(pkzip_entries)

    def _hash_zip_aes(self, record, enc) -> bytes:
        salt = bytes(enc.salt).hex()
        pvv = bytes(enc.pvv).hex()
        cdata = record.data
        if cdata is None:
            cdata = B''
        auth_len = enc.auth_size
        if len(cdata) >= auth_len:
            payload = bytes(cdata[:-auth_len])
            auth = bytes(cdata[-auth_len:])
        else:
            payload = bytes(cdata)
            auth = B''
        data_hex = payload.hex()
        auth_hex = auth.hex()
        mode = enc.strength
        return (
            F'$zip2$*0*{mode}*0*{salt}*{pvv}'
            F'*{len(payload):x}*{data_hex}*{auth_hex}*$/zip2$'
        ).encode(self.codec)

    def _hash_zip_pkzip(self, entries: list[tuple]) -> bytes:
        count = len(entries)
        check_bytes = 2
        for record, enc in entries:
            if record.version >= 20:
                check_bytes = 1
                break
        parts = [F'$pkzip2${count}*{check_bytes}']
        for record, enc in entries:
            enc_header = bytes(enc)
            cdata = record.data
            if cdata is None:
                cdata = B''
            full_data = enc_header + bytes(cdata)
            crc = record.crc32
            method = record.method_value
            data_len = len(full_data)
            offex = 30 + len(record.name_bytes) + len(record.xtra_data)
            if record.flags.DataDescriptor:
                cs = F'{(record.mtime >> 8) & 0xFF:02x}{record.mtime & 0xFF:02x}'
            else:
                cs = F'{(crc >> 24) & 0xFF:02x}{(crc >> 16) & 0xFF:02x}'
            tc = F'{(record.mtime >> 8) & 0xFF:02x}{record.mtime & 0xFF:02x}'
            entry_parts = [
                '2',
                '0',
                F'{record.csize:x}',
                F'{record.usize:x}',
                F'{crc:x}',
                '0',
                F'{offex:x}',
                str(method),
                F'{data_len:x}',
                cs,
                tc,
                full_data.hex(),
            ]
            parts.append('*'.join(entry_parts))
        parts.append('$/pkzip2$')
        return '*'.join(parts).encode(self.codec)

    def _hash_office(self, data: bytearray) -> bytes:
        from refinery.lib.ole.crypto import (
            AgileEncryptionInfo,
            EncryptionType,
            OleFile,
            StandardEncryptionInfo,
            _parseinfo,
        )

        ole = OleFile(data)

        if ole.exists('EncryptionInfo'):
            stream = ole.openstream('EncryptionInfo')
            enc_type, info = _parseinfo(stream)
            if enc_type == EncryptionType.STANDARD and isinstance(info, StandardEncryptionInfo):
                h = info.header
                v = info.verifier
                salt = v.salt.hex()
                enc_verifier = v.encrypted_verifier.hex()
                enc_verifier_hash = v.encrypted_verifier_hash.hex()[:64]
                return (
                    F'$office$*2007*{v.verifier_hash_size}*{h.key_size}'
                    F'*{v.salt_size}*{salt}*{enc_verifier}*{enc_verifier_hash}'
                ).encode(self.codec)
            if enc_type == EncryptionType.AGILE and isinstance(info, AgileEncryptionInfo):
                key_bits = info.password_key_bits
                year = 2013 if key_bits >= 256 else 2010
                salt = info.password_salt.hex()
                enc_verifier = info.encrypted_verifier_hash_input.hex()
                enc_verifier_hash = info.encrypted_verifier_hash_value.hex()[:64]
                return (
                    F'$office$*{year}*{info.spin_value}*{key_bits}'
                    F'*{len(info.password_salt)}*{salt}'
                    F'*{enc_verifier}*{enc_verifier_hash}'
                ).encode(self.codec)
            raise ValueError(F'unsupported OOXML encryption type: {enc_type.value}')

        if ole.exists('wordDocument'):
            return self._hash_office_doc97(ole)
        if ole.exists('Workbook'):
            return self._hash_office_xls97(ole)
        if ole.exists('PowerPoint Document'):
            return self._hash_office_ppt97(ole)
        raise ValueError('unable to identify an encrypted Office format')

    def _hash_office_doc97(self, ole: OleFile) -> bytes:
        from refinery.lib.ole.crypto import (
            _parse_header_rc4,
            _parse_header_rc4_cryptoapi,
        )
        from refinery.lib.structures import MemoryFile

        doc = ole.openstream('wordDocument')
        fib_raw = doc.read(32)
        bits = unpack('<H', fib_raw[10:12])[0]
        f_encrypted = (bits >> 8) & 1
        if not f_encrypted:
            raise ValueError('this Word document is not encrypted')
        f_which_tbl = (bits >> 9) & 1
        table_name = '1Table' if f_which_tbl else '0Table'
        with ole.openstream(table_name) as table:
            v_major, v_minor = unpack('<HH', table.read(4))
            if v_major == 1 and v_minor == 1:
                rc4_info = _parse_header_rc4(table)
                return (
                    F'$oldoffice$1*{rc4_info.salt.hex()}'
                    F'*{rc4_info.encrypted_verifier.hex()}'
                    F'*{rc4_info.encrypted_verifier_hash.hex()}'
                ).encode(self.codec)
            elif v_major in (2, 3, 4) and v_minor == 2:
                api_info = _parse_header_rc4_cryptoapi(MemoryFile(table.read()))
                typ = 3 if api_info.key_size <= 40 else 4
                return (
                    F'$oldoffice${typ}*{api_info.salt.hex()}'
                    F'*{api_info.encrypted_verifier.hex()}'
                    F'*{api_info.encrypted_verifier_hash.hex()}'
                ).encode(self.codec)
        raise ValueError('unsupported Word encryption version')

    def _hash_office_xls97(self, ole: OleFile) -> bytes:
        from refinery.lib.ole.crypto import (
            _parse_header_rc4,
            _parse_header_rc4_cryptoapi,
        )
        from refinery.lib.structures import MemoryFile

        with ole.openstream('Workbook') as wb:
            num = unpack('<H', wb.read(2))[0]
            if num != 2057:
                raise ValueError('invalid Workbook stream')
            size = unpack('<H', wb.read(2))[0]
            wb.read(size)
            while True:
                h = wb.read(4)
                if not h or len(h) < 4:
                    raise ValueError('FILEPASS record not found')
                rnum, rsize = unpack('<HH', h)
                if rnum == 47:
                    break
                wb.read(rsize)
            enc_type = unpack('<H', wb.read(2))[0]
            enc_data = MemoryFile(wb.read(rsize - 2))
            if enc_type == 0x0001:
                v_major, v_minor = unpack('<HH', enc_data.read(4))
                if v_major == 1 and v_minor == 1:
                    rc4_info = _parse_header_rc4(enc_data)
                    return (
                        F'$oldoffice$0*{rc4_info.salt.hex()}'
                        F'*{rc4_info.encrypted_verifier.hex()}'
                        F'*{rc4_info.encrypted_verifier_hash.hex()}'
                    ).encode(self.codec)
                elif v_major in (2, 3, 4) and v_minor == 2:
                    api_info = _parse_header_rc4_cryptoapi(enc_data)
                    typ = 3 if api_info.key_size <= 40 else 4
                    return (
                        F'$oldoffice${typ}*{api_info.salt.hex()}'
                        F'*{api_info.encrypted_verifier.hex()}'
                        F'*{api_info.encrypted_verifier_hash.hex()}'
                    ).encode(self.codec)
        raise ValueError('unsupported Excel encryption version')

    def _hash_office_ppt97(self, ole: OleFile) -> bytes:
        from refinery.lib.ole.crypto import (
            _construct_persist_object_directory,
            _parse_current_user_atom,
            _parse_record_header,
            _parse_user_edit_atom,
        )
        from refinery.lib.structures import MemoryFile

        cu_stream = ole.openstream('Current User')
        ppt_stream = ole.openstream('PowerPoint Document')
        pod = _construct_persist_object_directory(cu_stream, ppt_stream)
        cu_stream.seek(0)
        cu = _parse_current_user_atom(cu_stream)
        ppt_stream.seek(cu.offset_to_current_edit)
        uea = _parse_user_edit_atom(ppt_stream)
        if uea.encrypt_session_persist_id_ref is None:
            raise ValueError('this PowerPoint file is not encrypted')
        crypt_offset = pod[uea.encrypt_session_persist_id_ref]
        ppt_stream.seek(crypt_offset)
        rh = _parse_record_header(ppt_stream.read(8))
        crypt_data = ppt_stream.read(rh.rec_len)
        enc_info = MemoryFile(crypt_data)
        v_major, v_minor = unpack('<HH', enc_info.read(4))
        if v_major in (2, 3, 4) and v_minor == 2:
            from refinery.lib.ole.crypto import _parse_header_rc4_cryptoapi
            api_info = _parse_header_rc4_cryptoapi(enc_info)
            typ = 3 if api_info.key_size <= 40 else 4
            return (
                F'$oldoffice${typ}*{api_info.salt.hex()}'
                F'*{api_info.encrypted_verifier.hex()}'
                F'*{api_info.encrypted_verifier_hash.hex()}'
            ).encode(self.codec)
        raise ValueError('unsupported PowerPoint encryption version')
