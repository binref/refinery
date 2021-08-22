#!/usr/bin/env python3
# -*- coding: utf - 8 -* -
from refinery.units import Unit
from refinery.units.formats.httpresponse import httpresponse
from refinery.units.formats.pcap import pcap


class pcap_http(Unit):
    """
    Extracts HTTP payloads from packet capture (PCAP) files.
    """
    def process(self, data):
        http_parser = httpresponse()
        for stream in data | pcap:
            try:
                data = http_parser.process(stream)
            except Exception:
                continue
            if data:
                yield data
