from __future__ import annotations

import email.utils
import re

from email.parser import Parser
from typing import TYPE_CHECKING, Iterable

from refinery.lib import json
from refinery.lib.id import is_likely_email
from refinery.lib.mime import file_extension
from refinery.lib.tools import NoLogging, asbuffer, isbuffer
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.pattern.mimewords import mimewords

if TYPE_CHECKING:
    from extract_msg import Message

CDFv2_MARKER = B'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'


class xtmail(PathExtractorUnit):
    """
    Extract files and body from EMail messages. The unit supports both the Outlook message format
    and regular MIME documents.
    """
    def _get_headparts(self, head: Iterable[tuple[str, str]]):
        def normalize_spaces(value: str):
            return ''.join(re.sub(R'\A\s+', '\x20', t) for t in value.splitlines(False))

        _headers: dict[str, list[str]] = {}
        for key, value in head:
            _headers.setdefault(key, []).append(mimewords.convert(normalize_spaces(value)))
        headers = {
            key: value[0] if len(value) == 1 else [t for t in value if t]
            for key, value in _headers.items()}

        yield UnpackResult('headers.txt',
            lambda h=head: '\n'.join(F'{k}: {v}' for k, v in h).encode(self.codec))

        received = []

        for recv in headers.get('Received', []):
            if not recv.startswith('from '):
                received = None
                break
            recv = recv[5:]
            src, _, rest = recv.partition(' by ')
            dst, _, rest = rest.partition(' with ')
            received.append({
                'Source': src.partition('\x20')[0],
                'Target': dst.partition('\x20')[0],
            })

        if received:
            received.reverse()
            headers['ReceivedTrace'] = received

        yield UnpackResult('headers.json', lambda jsn=headers: json.dumps(jsn))

    @PathExtractorUnit.Requires('extract-msg', ['formats', 'office', 'default', 'extended'])
    def _extract_msg():
        import extract_msg.enums
        return extract_msg

    def _get_parts_outlook(self, data):
        def ensure_bytes(data: bytes | str | None):
            if data is None:
                return B''
            elif isinstance(data, str):
                return data.encode(self.codec)
            else:
                return data

        def make_message(name, msg: Message):
            bodies = msg.detectedBodies
            BT = self._extract_msg.enums.BodyTypes
            if bodies & BT.HTML:
                def htm(msg=msg):
                    with NoLogging():
                        try:
                            return ensure_bytes(msg.htmlBody)
                        except Exception:
                            return B''
                yield UnpackResult(F'{name}.htm', htm)
            if bodies & BT.PLAIN:
                def txt(msg=msg):
                    with NoLogging():
                        try:
                            return ensure_bytes(msg.body)
                        except Exception:
                            return B''
                yield UnpackResult(F'{name}.txt', txt)
            if bodies & BT.RTF:
                def rtf(msg=msg):
                    with NoLogging():
                        try:
                            return ensure_bytes(msg.rtfBody)
                        except Exception:
                            return B''
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

        header = dict(msg.header)

        if x := msg.date:
            header['Date'] = email.utils.format_datetime(x)
        if x := msg.sender:
            header['From'] = x
        if x := msg.to:
            header['To'] = x
        if x := msg.cc:
            header['Cc'] = x
        if x := msg.bcc:
            header['Bcc'] = x
        if x := msg.messageId:
            header['Message-Id'] = x
        if x := msg.subject:
            header['Subject'] = x

        for key, val in list(header.items()):
            if val := val.strip().replace('\0', ''):
                header[key] = val
            else:
                del header[key]

        yield from self._get_headparts(header.items())
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
            path = path.rstrip('\0')
            yield UnpackResult(F'attachments/{path}', attachment.data)

    @PathExtractorUnit.Requires('chardet', ['default', 'extended'])
    def _chardet():
        import chardet
        return chardet

    def _get_parts_regular(self, data: bytes):
        try:
            info = self._chardet.detect(data)
            msg = data.decode(str(info['encoding']))
        except UnicodeDecodeError:
            raise ValueError('This is not a plaintext email message.')
        else:
            msg = Parser().parsestr(msg)

        yield from self._get_headparts(msg.items())

        for k, part in enumerate(msg.walk()):
            path = part.get_filename()
            error_message = None
            result = None
            if path is None:
                extension = file_extension(part.get_content_type(), 'txt')
                path = F'body.{extension}'
            else:
                path = path | mimewords | str
                path = F'attachments/{path}'
            try:
                payload = part.get_payload(decode=True)
                if payload is None or isinstance(payload, bytes):
                    result = payload
                else:
                    raise TypeError
            except Exception as E:
                try:
                    payload = part.get_payload(decode=False)
                except Exception as E:
                    error_message = str(E)
                else:
                    from refinery.units.pattern.carve import carve
                    self.log_warn(F'manually decoding part {k}, data might be corrupted: {path}')
                    if isinstance(payload, str):
                        payload = payload.encode('latin1')
                    if payload := asbuffer(payload):
                        result = next(payload | carve('b64', stripspace=True, single=True, decode=True))
                    else:
                        error_message = str(E)
                        result = None
            if not result:
                if error_message is not None:
                    self.log_warn(F'could not get content of message part {k}: {error_message!s}')
                continue
            yield UnpackResult(path, result)

    def unpack(self, data):
        if data[:len(CDFv2_MARKER)] == CDFv2_MARKER:
            yield from self._get_parts_outlook(data)
        else:
            yield from self._get_parts_regular(data)

    @classmethod
    def handles(cls, data) -> bool:
        return is_likely_email(data)
