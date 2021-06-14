#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from email.parser import BytesParser
from extract_msg.message import Message
from functools import partial
from collections import defaultdict

from . import PathExtractorUnit, UnpackResult
from ...lib.mime import file_extension
from ...lib.tools import NoLogging, isbuffer
from ..pattern.mimewords import mimewords


class xtmail(PathExtractorUnit):
    """
    Extract files and body from EMail messages. The unit supports both the Outlook message format
    and regular MIME documents.
    """
    def _get_headparts(self, head):
        mw = mimewords()
        mw = partial(mw.process.__wrapped__.__wrapped__, mw)
        jh = defaultdict(list)
        for key, value in head:
            jh[key].append(mw(''.join(t.lstrip() for t in value.splitlines(False))))
        jh = {k: v[0] if len(v) == 1 else [t for t in v if t] for k, v in jh.items()}
        yield UnpackResult('headers.txt',
            lambda h=head: '\n'.join(F'{k}: {v}' for k, v in h).encode(self.codec))
        yield UnpackResult('headers.json',
            lambda jsn=jh: json.dumps(jsn, indent=4).encode(self.codec))

    def _get_parts_outlook(self, data):
        def ensure_bytes(data):
            return data if isinstance(data, bytes) else data.encode(self.codec)

        def make_message(name, msg):
            if msg.body:
                yield UnpackResult(F'{name}.txt', ensure_bytes(msg.body))
            if msg.htmlBody:
                yield UnpackResult(F'{name}.htm', ensure_bytes(msg.htmlBody))

        msgcount = 0

        with NoLogging:
            with Message(bytes(data)) as msg:
                yield from self._get_headparts(msg.header.items())
                yield from make_message('body', msg)
                for attachment in msg.attachments:
                    if attachment.type == 'msg':
                        msgcount += 1
                        yield from make_message(F'attachments/msg_{msgcount:d}', attachment.data)
                        continue
                    if not isbuffer(attachment.data):
                        self.log_warn(F'unknown attachment of type {attachment.type}, please report this!')
                        continue
                    path = attachment.longFilename or attachment.shortFilename
                    yield UnpackResult(F'attachments/{path}', attachment.data)

    def _get_parts_regular(self, data):
        msg = BytesParser().parsebytes(data)

        yield from self._get_headparts(msg.items())

        for k, part in enumerate(msg.walk()):
            path = part.get_filename()
            elog = None
            if path is None:
                extension = file_extension(part.get_content_type(), 'txt')
                path = F'body.{extension}'
            else:
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
