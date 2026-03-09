from __future__ import annotations

import email.utils
import re

from email.parser import Parser
from typing import Iterable

from refinery.lib import json
from refinery.lib.id import is_likely_email
from refinery.lib.mime import file_extension
from refinery.lib.types import asbuffer, isbuffer
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.pattern.mimewords import mimewords

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

    def _get_parts_outlook(self, data):
        from refinery.lib.outlook import MsgFile

        def make_message(name, msg: MsgFile):
            if msg.html_body is not None:
                yield UnpackResult(F'{name}.htm', msg.html_body)
            if msg.body is not None:
                yield UnpackResult(F'{name}.txt', msg.body.encode(self.codec))
            if msg.rtf_body is not None:
                yield UnpackResult(F'{name}.rtf', msg.rtf_body)

        msg = MsgFile(data)
        header = dict(msg.header.items()) if msg.header else {}

        mc = msg.message_class
        if mc:
            header['X-Message-Class'] = mc

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
        if x := msg.message_id:
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

        item = {}
        mc = msg.message_class or ''
        if 'CONTACT' in mc:
            item['name'] = msg.display_name
            item['company'] = msg.company
            item['title'] = msg.job_title
            phone = {}
            if hp := msg.home_phone:
                phone.update(home=hp)
            if bp := msg.business_phone:
                phone.update(business=bp)
            if mp := msg.mobile_phone:
                phone.update(mobile=mp)
            if phone:
                item['phone'] = phone
        elif 'APPOINTMENT' in mc or 'MEETING' in mc or 'SCHEDULE' in mc:
            if x := msg.start_time:
                item['start'] = x.isoformat(' ', 'seconds')
            if x := msg.end_time:
                item['end'] = x.isoformat(' ', 'seconds')
            if x := msg.location:
                item['location'] = x
        if item:
            yield UnpackResult(F'{mc.lower()}.json', json.dumps(item))

        msgcount = 0

        def walk_attachments(msg: MsgFile):
            for attachment in msg.attachments:
                yield attachment
                if isinstance(ad := attachment.data, MsgFile):
                    yield from walk_attachments(ad)

        for attachment in walk_attachments(msg):
            if isinstance(ad := attachment.data, MsgFile):
                msgcount += 1
                yield from make_message(
                    F'attachments/msg_{msgcount:d}', ad)
                continue
            if not isbuffer(attachment.data):
                self.log_warn('unknown attachment type, please report this!')
                continue
            path = attachment.long_filename or attachment.short_filename or 'unnamed'
            path = path.rstrip('\0')
            yield UnpackResult(F'attachments/{path}', ad)

    @PathExtractorUnit.Requires('chardet', ['default', 'extended'])
    def _chardet():
        import chardet
        return chardet

    def _get_parts_regular(self, data: bytes):
        for codec in ('ascii', 'utf8', ...):
            try:
                if codec is ...:
                    info = self._chardet.detect(data)
                    codec = str(info['encoding'])
                msg = data.decode(codec)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise ValueError('This is not a plaintext email message.')

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
