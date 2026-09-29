from __future__ import annotations

import defusedxml

from refinery.lib.ole import crypto, vba

from ... import TestBase

_ENTITY_DOCUMENT = b'<!DOCTYPE d [<!ENTITY e "x">]><d>&e;</d>'


class TestDefusedXmlParsing(TestBase):
    """
    The Office containers hand untrusted documents to XML parsers; a document that declares
    entities is rejected rather than resolved, so that no expansion happens inside refinery.
    """

    def test_word2003_and_flat_opc_documents(self):
        with self.assertRaises(defusedxml.EntitiesForbidden):
            vba.fromstring(_ENTITY_DOCUMENT)

    def test_encryption_info_documents(self):
        with self.assertRaises(defusedxml.EntitiesForbidden):
            crypto.parseString(_ENTITY_DOCUMENT)
