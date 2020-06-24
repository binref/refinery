#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from email.parser import BytesParser
from extract_msg.message import Message

from . import PathExtractorUnit, UnpackResult
from ...lib.mime import file_extension


class xtmail(PathExtractorUnit):
    """
    Extract files and body from EMail messages. The unit supports both the Outlook message format
    and regular MIME documents.
    """
    def _normalize_names(self, parts, prefix='BODY'):
        unnamed = 0
        for part in parts:
            if not part:
                continue
            if part.path is None:
                unnamed += 1
                part.path = F'{prefix}{unnamed}'
            yield part

    def _get_headparts(self, head):
        yield UnpackResult('HEAD.TXT',
            lambda h=head: '\n'.join(F'{k}: {v}' for k, v in h.items()).encode(self.codec))
        yield UnpackResult('HEAD.JSON',
            lambda h=head: json.dumps(h, indent=4).encode(self.codec))

    def _get_parts_outlook(self, data):
        def ensure_bytes(data):
            return data if isinstance(data, bytes) else data.encode(self.codec)

        with Message(bytes(data)) as msg:
            yield from self._get_headparts(msg.header)
            if msg.body:
                yield UnpackResult('BODY.TXT', ensure_bytes(msg.body))
            if msg.htmlBody:
                yield UnpackResult('BODY.HTM', ensure_bytes(msg.htmlBody))
            for attachment in msg.attachments:
                path = attachment.longFilename or attachment.shortFilename
                yield UnpackResult(path, attachment.data)

    def _get_parts_regular(self, data):
        msg = BytesParser().parsebytes(data)

        yield from self._get_headparts(dict(msg.items()))

        for part in msg.walk():
            path = part.get_filename()
            data = part.get_payload(decode=True)
            if data is None:
                continue
            if path is None:
                path = F'BODY.{file_extension(part.get_content_subtype(), "TXT").upper()}'
            yield UnpackResult(path, data)

    def unpack(self, data):
        try:
            it = list(self._get_parts_outlook(data))
        except Exception as e:
            self.log_debug(F'failed parsing input as Outlook message: {e}')
            it = list(self._get_parts_regular(data))

        yield from self._normalize_names(it)
