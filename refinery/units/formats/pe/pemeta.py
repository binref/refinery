#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from functools import lru_cache
from contextlib import suppress
from pefile import PE
from datetime import datetime, timezone
from asn1crypto import cms
from asn1crypto import x509

from ....lib.dotnet.header import DotNetHeader
from ... import arg, Unit


class pemeta(Unit):
    """
    Extract metadata from PE files, including:

    - File version resource
    - Code signature information
    - Timestamps
    - If present, .NET header information
    """
    def __init__(self,
        all : arg('-c', '--custom',
            help='Unless enabled, everything will be extracted.') = True,
        version    : arg('-V', help='Parse the VERSION resource.') = False,
        timestamps : arg('-T', help='Extract time stamps.') = False,
        signatures : arg('-S', help='Parse digital signatures.') = False,
        dotnet     : arg('-D', help='Parse the .NET header.') = False
    ):
        super().__init__(
            timestamps=all or timestamps,
            signatures=all or signatures,
            dotnet=all or dotnet,
            version=all or version
        )

    def _ensure_string(self, x):
        if not isinstance(x, str):
            x = repr(x) if not isinstance(x, bytes) else x.decode(self.codec, 'backslashreplace')
        return x

    def _parse_pedict(self, bin):
        return dict((
            self._ensure_string(key),
            self._ensure_string(val)
        ) for key, val in bin.items() if val)

    @lru_cache(maxsize=1, typed=False)
    def _getpe(self, data: bytearray) -> PE:
        return PE(data=data)

    def parse_signature(self, data: bytearray) -> dict:
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        time stamp and code signing certificates that are attached to the input PE file.
        """
        from .pesig import pesig
        cert, info = pesig()(data), {}

        try:
            signature = cms.ContentInfo.load(cert)
        except Exception as E:
            raise ValueError(F'PKCS7 parser failed with error: {E!s}')

        def tscrawl(entry, native):
            with suppress(KeyError, TypeError):
                if entry['type'] == 'signing_time':
                    return entry['values']
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
                        with suppress(Exception):
                            acc = entry if native else entry.native
                            result['Timestamp Issuer'] = acc['sid']['issuer']['common_name']
                        return result
                    elif results is not None:
                        return results

            with suppress(Exception):
                return tscrawl(entry.native, True)

        timestamps = []
        for signer in signature['content']['signer_infos']:
            timestamps.append(tscrawl(signer, False))
        if len(timestamps) == 1:
            info.update(timestamps[0])

        with suppress(Exception):
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
        return info

    def parse_file_info(self, data: bytearray) -> dict:
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        the version resource of an input PE file, if available.
        """
        try:
            FileInfoList = self._getpe(data).FileInfo
        except AttributeError:
            return None
        for FileInfo in FileInfoList:
            for FileInfoEntry in FileInfo:
                with suppress(AttributeError):
                    for StringTableEntry in FileInfoEntry.StringTable:
                        StringTableEntryParsed = self._parse_pedict(StringTableEntry.entries)
                        LangID = self._ensure_string(StringTableEntry.LangID)
                        StringTableEntryParsed.update(LangID=LangID)
                        return StringTableEntryParsed

    def parse_time_stamps(self, data: bytearray) -> dict:
        """
        Extracts time stamps from the PE header (link time), as well as from the imports,
        exports, debug, and resource directory. The resource time stamp is also parsed as
        a DOS time stamp and returned as the "Delphi" time stamp.
        """
        def dt(ts):
            # parse as UTC but then forget time zone information
            return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)

        pe = self._getpe(data)
        info = {}

        with suppress(AttributeError):
            info.update(Linker=dt(pe.FILE_HEADER.TimeDateStamp))

        with suppress(AttributeError):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                info.update(Import=dt(entry.TimeDateStamp()))

        with suppress(AttributeError):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                info.update(DbgDir=dt(entry.struct.TimeDateStamp))

        with suppress(AttributeError):
            Export = pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
            if Export: info.update(Export=dt(Export))

        with suppress(AttributeError):
            res_timestamp = pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp
            if res_timestamp:
                with suppress(ValueError):
                    from ...misc.datefix import datefix
                    dos = datefix.dostime(res_timestamp)
                    info.update(Delphi=dos)
                    info.update(RsrcTS=dt(res_timestamp))

        return {key: str(value) for key, value in info.items()}

    def parse_dotnet(self, data):
        """
        Extracts a JSON-serializable and human readable dictionary with information about
        the .NET metadata of an input PE file.
        """
        header = DotNetHeader(data, pe=self._getpe(data))
        tables = header.meta.Streams.Tables
        info = dict(
            RuntimeVersion=F'{header.head.MajorRuntimeVersion}.{header.head.MinorRuntimeVersion}',
            Version=F'{header.meta.MajorVersion}.{header.meta.MinorVersion}',
            VersionString=header.meta.VersionString
        )

        if len(tables.Assembly) == 1:
            assembly = tables.Assembly[0]
            info.update(
                AssemblyName=assembly.Name,
                Release='{}.{}.{}.{}'.format(
                    assembly.MajorVersion,
                    assembly.MinorVersion,
                    assembly.BuildNumber,
                    assembly.RevisionNumber
                )
            )

        if len(tables.Module) == 1:
            module = tables.Module[0]
            info.update(ModuleName=module.Name)

        return info

    def process(self, data):
        result = {}

        if self.args.version:
            try:
                file_info = self.parse_file_info(data)
            except Exception as E:
                self.log_info(F'failed to obtain file info resource: {E!s}')
            else:
                if file_info:
                    result['FileInfo'] = file_info
        if self.args.dotnet:
            try:
                dnet_info = self.parse_dotnet(data)
            except Exception as E:
                self.log_info(F'failed to obtain .NET information: {E!s}')
            else:
                if dnet_info:
                    result['DotNet'] = dnet_info

        signature = {}

        if self.args.timestamps or self.args.signatures:
            signature = self.parse_signature(data)

        if self.args.timestamps:
            ts = self.parse_time_stamps(data)
            with suppress(KeyError):
                ts.update(Signed=signature['Timestamp'])
            result.update(TimeStamp=ts)

        if signature and self.args.signatures:
            result['Signature'] = signature

        return json.dumps(result, indent=4, ensure_ascii=False).encode(self.codec)
