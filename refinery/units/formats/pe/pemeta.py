#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile
import json
import struct

from asn1crypto import cms
from asn1crypto import x509

from ... import Unit


class pemeta(Unit):
    """
    Extract metadata from PE files, including code signing information.
    """

    def _ensure_string(self, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(self.codec, 'backslashreplace')
        return x

    def _parse_pedict(self, bin):
        return dict((
            self._ensure_string(key),
            self._ensure_string(val)
        ) for key, val in bin.items())

    def _extract_pkcs7(self, pe, data):
        ENTRY_SECURITY = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']

        pe.parse_data_directories(directories=[ENTRY_SECURITY])
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[ENTRY_SECURITY]
        sgnoff = security.VirtualAddress + 8
        sgnend = sgnoff + security.Size

        length, revision, certtype = struct.unpack('<IHH', data[sgnoff - 8:sgnoff])
        signature = data[sgnoff:sgnend]

        self.log_debug('revision:', revision)
        self.log_debug('certtype:', certtype)
        self.log_debug('length:', length)

        if len(signature) + 8 != length:
            raise ValueError(F'Found {len(signature) + 8} bytes of signature, but length should be {length}.')

        return bytes(signature)

    def _parse_signature(self, pe, data):
        cert = self._extract_pkcs7(pe, data)
        info = {}

        try:
            signature = cms.ContentInfo.load(cert)
        except Exception as E:
            raise ValueError(F'PKCS7 parser failed with error: {E!s}')

        def tscrawl(entry, native):
            try:
                if entry['type'] == 'signing_time':
                    return entry['values']
            except KeyError:
                pass
            except TypeError:
                pass

            try:
                keys = list(entry)
                assert all(isinstance(k, str) for k in keys)
            except Exception:
                try:
                    length = len(entry)
                except TypeError:
                    return None

                for k in range(length):
                    try:
                        item = entry[k]
                    except IndexError:
                        continue
                    results = tscrawl(item, native)
                    if results:
                        return results
            else:
                for key in keys:
                    value = entry[key]
                    results = tscrawl(value, native)
                    if isinstance(results, list) and len(results) == 1:
                        result = dict(Timestamp=str(results[0]))
                        try:
                            acc = entry if native else entry.native
                            result['Timestamp Issuer'] = acc['sid']['issuer']['common_name']
                        except Exception:
                            pass
                        return result
                    elif results is not None:
                        return results

            try:
                return tscrawl(entry.native, True)
            except Exception:
                pass

        timestamps = []
        for signer in signature['content']['signer_infos']:
            timestamps.append(tscrawl(signer, False))
        if len(timestamps) == 1:
            info.update(timestamps[0])

        for entry in signature['content']['certificates']:
            cert = x509.Certificate.load(entry.dump())
            if cert.ca: continue
            tbs = cert.native['tbs_certificate']

            for extension in tbs['extensions']:
                if extension['extn_id'] == 'extended_key_usage' and 'code_signing' in extension['extn_value']:
                    tbs = dict(
                        Issuer=tbs['issuer']['common_name'],
                        Subject=tbs['subject']['common_name'],
                        Serial=F"{tbs['serial_number']:x}",
                    )
                    info.update(tbs)
                    return info

    def _parse_file_info(self, pe, data):
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        try:
            FileInfoList = pe.FileInfo
        except AttributeError:
            return None

        for FileInfo in FileInfoList:
            for FileInfoEntry in FileInfo:
                if not hasattr(FileInfoEntry, 'StringTable'):
                    continue
                for StringTableEntry in FileInfoEntry.StringTable:
                    StringTableEntryParsed = self._parse_pedict(StringTableEntry.entries)
                    StringTableEntryParsed['LangID'] = self._ensure_string(StringTableEntry.LangID)
                    return StringTableEntryParsed

    def process(self, data):
        pe = pefile.PE(data=data, fast_load=True)
        result = {}

        try:
            signature = self._parse_signature(pe, data)
        except Exception as E:
            self.log_info(F'could not extract certificate: {E!s}')
        else:
            if signature:
                result['Signature'] = signature

        try:
            file_info = self._parse_file_info(pe, data)
        except Exception as E:
            self.log_info(F'failed to obtain file info resource: {E!s}')
        else:
            if file_info:
                result['FileInfo'] = file_info

        return json.dumps(result, indent=4, ensure_ascii=False).encode(self.codec)
