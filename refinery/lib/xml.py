#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import uuid

from .structures import MemoryFile
from xml.parsers import expat
from defusedxml.ElementTree import parse as ParseXML, XMLParser, ParseError
from xml.etree.ElementTree import ElementTree


def ForgivingParse(data, entities=None) -> ElementTree:
    entities = entities or {}
    try:
        return ParseXML(MemoryFile(data), parser=ForgivingXMLParser(entities))
    except ParseError as PE:
        raise ValueError from PE


class ForgivingXMLParser(XMLParser):

    def __init__(self, emap):
        class ForgivingEntityResolver(dict):
            def __getitem__(self, key):
                if key in self:
                    return dict.__getitem__(self, key)
                uid = str(uuid.uuid4())
                self[key] = uid
                emap[uid] = key
                return uid

        self.__entity = ForgivingEntityResolver()
        _ParserCreate = expat.ParserCreate

        try:
            def PC(encoding, _):
                parser = _ParserCreate(
                    encoding, namespace_separator=None)
                parser.UseForeignDTD(True)
                return parser
            expat.ParserCreate = PC
            super().__init__()
        finally:
            expat.ParserCreate = _ParserCreate

    @property
    def entity(self):
        return self.__entity

    @entity.setter
    def entity(self, value):
        self.__entity.update(value)
