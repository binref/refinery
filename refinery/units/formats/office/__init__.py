"""
These units process data formats related to Microsoft Office.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from refinery.lib.frame import Chunk
    from refinery.lib.types import buf
    from refinery.units import Unit
    from refinery.units.formats import PathExtractorUnit


def read_part(
    unit: Unit,
    data: buf,
    extractor: type[PathExtractorUnit],
    name: str,
    exact: bool = False,
) -> Chunk | None:
    """
    Returns the first part of the given document that the extractor selects by the given name, in
    the order of the document, or `None` if it selects none. The given unit warns when the document
    has more than one such part.
    """
    parts = data | extractor(name, exact=exact) | [...]
    if not parts:
        return None
    if (count := len(parts)) > 1:
        unit.log_warn(F'the document has {count} parts named {name}; reading the first one')
    return parts[0]
