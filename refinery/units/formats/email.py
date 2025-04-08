#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import re

from typing import TYPE_CHECKING
from email.parser import Parser
from functools import partial
from collections import defaultdict
from contextlib import suppress

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.pattern.mimewords import mimewords
from refinery.lib.mime import file_extension
from refinery.lib.tools import NoLogging, isbuffer


if TYPE_CHECKING:
    from extract_msg import Message


def _unwrap(method):
    while True:
        try:
            method = method.__wrapped__
        except AttributeError:
            return method


class xtmail(PathExtractorUnit):
    """
    Extract files and body from EMail messages. The unit supports both the Outlook message format
    and regular MIME documents.
    """
    def _get_headparts(self, head: dict[str, str]):
        mw = mimewords()
        mw = partial(_unwrap(mw.process), mw)
        jh: dict[str, list[str]] = defaultdict(list)
        for key, value in head:
            jh[key].append(mw(''.join(re.sub(R'\A\s+', '\x20', t) for t in value.splitlines(False))))
        jh = {k: v[0] if len(v) == 1 else [t for t in v if t] for k, v in jh.items()}
        yield UnpackResult('headers.txt',
            lambda h=head: '\n'.join(F'{k}: {v}' for k, v in h).encode(self.codec))
        received = []
        for recv in jh.get('Received', []):
            if not recv.startswith('from '):
                received = None
                break
            recv = recv[5:]
            src, _, rest = recv.partition(' by ')
            dst, _, rest = rest.partition(' with ')
            received.append({
                'Target': src.partition('\x20')[0],
                'Source': dst.partition('\x20')[0],
            })
        if received:
            received.reverse()
            jh['ReceivedTrace'] = received
        yield UnpackResult('headers.json',
            lambda jsn=jh: json.dumps(jsn, indent=4).encode(self.codec))

    @PathExtractorUnit.Requires('extract-msg<=0.54.0', 'formats', 'office', 'default', 'extended')
    def _extract_msg():
        import extract_msg.enums
        return extract_msg

    def _get_parts_outlook(self, data):
        def ensure_bytes(data: bytes | str):
            return data if isinstance(data, bytes) else data.encode(self.codec)

        def make_message(name, msg: Message):
            bodies = msg.detectedBodies
            BT = self._extract_msg.enums.BodyTypes
            if bodies & BT.HTML:
                def htm(msg=msg):
                    with suppress(Exception), NoLogging():
                        return ensure_bytes(msg.htmlBody)
                yield UnpackResult(F'{name}.htm', htm)
            if bodies & BT.PLAIN:
                def txt(msg=msg):
                    with suppress(Exception), NoLogging():
                        return ensure_bytes(msg.body)
                yield UnpackResult(F'{name}.txt', txt)
            if bodies & BT.RTF:
                def rtf(msg=msg):
                    with suppress(Exception), NoLogging():
                        return ensure_bytes(msg.rtfBody)
                yield UnpackResult(F'{name}.rtf', rtf)

        msgcount = 0

        with NoLogging():
            class ForgivingMessage(self._extract_msg.Message):
                """
                If parsing the input bytes fails early, the "__open" private attribute may not
                yet exist. This hack prevents an exception to occur in the destructor.
                """
                def __getattr__(self, key: str):
                    if key.endswith('_open'):
                        return False
                    raise AttributeError(key)
            msg = ForgivingMessage(bytes(data))

        yield from self._get_headparts(msg.header.items())
        yield from make_message('body', msg)

        def attachments(msg):
            for attachment in getattr(msg, 'attachments', ()):
                yield attachment
                if attachment.type == 'data':
                    continue
                yield from attachments(attachment.data)

        for attachment in attachments(msg):
            at = attachment.type
            if at is self._extract_msg.enums.AttachmentType.MSG:
                msgcount += 1
                yield from make_message(F'attachments/msg_{msgcount:d}', attachment.data)
                continue
            if not isbuffer(attachment.data):
                self.log_warn(F'unknown attachment of type {at}, please report this!')
                continue
            path = attachment.longFilename or attachment.shortFilename
            yield UnpackResult(F'attachments/{path}', attachment.data)

    @PathExtractorUnit.Requires('chardet', 'default', 'extended')
    def _chardet():
        import chardet
        return chardet

    def _get_parts_regular(self, data: bytes):
        try:
            info = self._chardet.detect(data)
            msg = data.decode(info['encoding'])
        except UnicodeDecodeError:
            raise ValueError('This is not a plaintext email message.')
        else:
            msg = Parser().parsestr(msg)

        yield from self._get_headparts(msg.items())

        for k, part in enumerate(msg.walk()):
            path = part.get_filename()
            elog = None
            if path is None:
                extension = file_extension(part.get_content_type(), 'txt')
                path = F'body.{extension}'
            else:
                path = path | mimewords | str
                path = F'attachments/{path}'
            try:
                data = part.get_payload(decode=True)
            except Exception as E:
                try:
                    data = part.get_payload(decode=False)
                except Exception as E:
                    elog = str(E)
                    data = None
                else:
                    from refinery import carve
                    self.log_warn(F'manually decoding part {k}, data might be corrupted: {path}')
                    if isinstance(data, str):
                        data = data.encode('latin1')
                    if isbuffer(data):
                        data = next(data | carve('b64', stripspace=True, single=True, decode=True))
                    else:
                        elog = str(E)
                        data = None
            if not data:
                if elog is not None:
                    self.log_warn(F'could not get content of message part {k}: {elog!s}')
                continue
            yield UnpackResult(path, data)

    def unpack(self, data):
        try:
            yield from self._get_parts_outlook(data)
        except Exception:
            self.log_debug('failed parsing input as Outlook message')
            yield from self._get_parts_regular(data)

    @classmethod
    def handles(cls, data: bytearray) -> bool:
        markers = [
            b'\nReceived:\x20from'
            b'\nSubject:\x20',
            b'\nTo:\x20',
            b'\nFrom:\x20',
            B'\nMessage-ID:\x20',
            b'\nBcc:\x20',
            b'\nContent-Transfer-Encoding:\x20',
            b'\nContent-Type:\x20',
            b'\nReturn-Path:\x20',
        ]
        if data.startswith(B'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
            markers = [marker.decode('latin1').encode('utf-16le') for marker in markers]
        counter = 0
        for marker in markers:
            if re.search(re.escape(marker), data, flags=re.IGNORECASE):
                counter += 1
            if counter >= 3:
                return True
        return False
