#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from enum import Enum
from typing import Any, Optional


def makeinstance(cls: Enum, value: Optional[Any]) -> Enum:
    if value is None or isinstance(value, cls):
        return value
    if isinstance(value, str):
        needle = value.upper()
        for item in cls:
            if item.name.upper() == needle:
                return item
        raise ValueError(F'No entry named {value} in {cls.__name__}.')
    try:
        return cls(value)
    except Exception as E:
        raise ValueError(F'Could not transform {value} into a {cls.__name__}.') from E
