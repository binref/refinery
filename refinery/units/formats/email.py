#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from email.parser import BytesParser
from extract_msg.message import Message

from . import PathExtractorUnit


class EmailPart:
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def __bool__(self):
        return bool(self.data)


class xtmail(PathExtractorUnit):
    """
    Extract files and body from EMail messages. The unit supports both the Outlook message format
    and regular MIME documents.
    """
    def _normalize_names(self, parts):
        names = set()
        unnamed = 0
        prefix = 'BODY'

        for part in parts:
            if not part:
                continue
            if part.name is None:
                unnamed += 1
            else:
                names.add(part.name)

        pw = len(str(unnamed))

        while {F'{prefix}{k:0{pw}}' for k in range(1, unnamed + 1)} & names:
            prefix = prefix + '_'

        for part in reversed(parts):
            if part.name is None:
                part.name = F'{prefix}{unnamed:0{pw}}'
                unnamed -= 1

    def _get_parts_outlook(self, data):
        def ensure_bytes(data):
            return data if isinstance(data, bytes) else data.encode(self.codec)
        with Message(bytes(data)) as msg:
            parts = []
            if msg.body:
                parts.append(EmailPart(None, ensure_bytes(msg.body)))
            if msg.htmlBody:
                parts.append(EmailPart(None, ensure_bytes(msg.htmlBody)))
            for attachment in msg.attachments:
                parts.append(EmailPart(attachment.longFilename or attachment.shortFilename, attachment.data))
            return parts

    def _get_parts_regular(self, data):
        msg = BytesParser().parsebytes(data)
        return [EmailPart(part.get_filename(), part.get_payload(decode=True)) for part in msg.walk()]

    def process(self, data):
        try:
            parts = self._get_parts_outlook(data)
        except Exception as e:
            raise
            self.log_debug(F'failed parsing input as Outlook message: {e}')
            parts = self._get_parts_regular(data)

        self._normalize_names(parts)

        for part in parts:
            if part:
                if self._check_path(part.name):
                    self.log_info(part.name)
                    yield dict(data=part.data, path=part.name)
                else:
                    self.log_debug(part.name)
