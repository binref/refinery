from __future__ import annotations

from typing import Any

_MISSING = object()

BOOLEAN = 1
INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OID = 6
ENUMERATED = 10
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
PRINTABLE_STRING = 19
IA5_STRING = 22
UTC_TIME = 23
GEN_TIME = 24
ANY = object()

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2


class Seq:
    def __init__(self, *fields: F):
        self.fields = fields


class Set:
    def __init__(self, *fields: F):
        self.fields = fields


class SeqOf:
    def __init__(self, element: SchemaType):
        self.element = element


class SetOf:
    def __init__(self, element: SchemaType):
        self.element = element


class Choice:
    def __init__(self, *alternatives: F):
        self.alternatives = alternatives


class Tagged:
    """
    A type wrapped in a single context/application tag, used to represent an inner tag layer that
    survives an outer EXPLICIT tag (e.g. the [1] in `[0] EXPLICIT [1] IMPLICIT INTEGER`). The
    field's own outermost tag is carried on `F`; this wraps the remaining inner tag.
    """
    def __init__(self, inner: SchemaType, tag_num: int, explicit: bool, tag_class: int = CLASS_CONTEXT):
        self.inner = inner
        self.tag_num = tag_num
        self.explicit = explicit
        self.tag_class = tag_class


class F:
    def __init__(
        self,
        name: str,
        type: SchemaType,
        implicit: int | None = None,
        explicit: int | None = None,
        optional: bool = False,
        default: Any = _MISSING,
        tag_class: int = CLASS_CONTEXT,
    ):
        self.name = name
        self.type = type
        self.implicit = implicit
        self.explicit = explicit
        self.optional = optional or default is not _MISSING
        self.default = default
        self.tag_class = tag_class


class ASN1SchemaMismatch(Exception):
    pass


SchemaType = int | Seq | Set | SeqOf | SetOf | Choice | Tagged | object
