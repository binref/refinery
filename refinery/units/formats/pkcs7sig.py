from __future__ import annotations

from refinery.units.formats import JSONTableUnit
from refinery.units.formats.pe.pemeta import pemeta


class pkcs7sig(JSONTableUnit):
    """
    Converts PKCS7 encoded signatures into a human-readable JSON representation. This can be used
    to parse authenticode signatures appended to files that are not PE files to get the same output
    that is produced by the pemeta unit. For example, this can be used to parse the code signature
    embedded in MSI files as follows:

        emit sample.msi | xtmsi Meta/DigitalSignature | pkcs7sig
    """
    def json(self, data):
        return pemeta.parse_signature(data)
