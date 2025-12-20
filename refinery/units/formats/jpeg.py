from __future__ import annotations

import os
import tempfile

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from refinery.lib import json
from refinery.units.formats.archive import ArchiveUnit, UnpackResult


@dataclass
class _JpegSegment:
    index: int
    marker: int
    name: str
    raw: bytes
    payload: bytes
    length_field: Optional[int]  # value of the 2-byte JPEG length field (includes its own size)


def _marker_name(marker: int) -> str:
    if 0xE0 <= marker <= 0xEF:
        return f'APP{marker - 0xE0}'
    if 0xD0 <= marker <= 0xD7:
        return f'RST{marker - 0xD0}'
    if marker == 0xD8:
        return 'SOI'
    if marker == 0xD9:
        return 'EOI'
    if marker == 0xDA:
        return 'SOS'
    if marker == 0xDB:
        return 'DQT'
    if marker == 0xC4:
        return 'DHT'
    if marker == 0xDD:
        return 'DRI'
    if marker == 0xFE:
        return 'COM'
    if marker == 0x01:
        return 'TEM'

    # Start of Frame markers (not all are commonly used, but this is helpful in listings).
    if 0xC0 <= marker <= 0xCF and marker not in {0xC4, 0xC8, 0xCC}:
        return f'SOF{marker - 0xC0}'

    return f'MARKER_{marker:02X}'


def _encoding_from_sof_marker(marker: int) -> Optional[str]:
    # The names match common terminology (and align with what jpegdata tends to expose).
    return {
        0xC0: 'BaselineDCT',
        0xC1: 'ExtendedSequentialDCT',
        0xC2: 'ProgressiveDCT',
        0xC3: 'Lossless',
        0xC5: 'DifferentialSequentialDCT',
        0xC6: 'DifferentialProgressiveDCT',
        0xC7: 'DifferentialLossless',
        0xC9: 'ExtendedSequentialDCT',
        0xCA: 'ProgressiveDCT',
        0xCB: 'Lossless',
        0xCD: 'DifferentialSequentialDCT',
        0xCE: 'DifferentialProgressiveDCT',
        0xCF: 'DifferentialLossless',
    }.get(marker)


def _u16be(b: bytes) -> int:
    return (b[0] << 8) | b[1]


def _split_jpeg(data: bytes) -> Tuple[List[_JpegSegment], bytes]:
    """Split a JPEG into segments and returns (segments, scandata).

    Segments are returned as strict JPEG segments:
    - For segments with a length field: raw = FF <marker> <len_hi> <len_lo> <payload...>
      and payload excludes the 2-byte length field.
    - For no-length markers (SOI/EOI/RSTn/TEM): raw = FF <marker>, payload empty.

    Scan data (entropy-coded data) is extracted separately into a single byte stream:
    - For each SOS segment, scandata includes the bytes following the SOS payload up to
      the next marker that is not a stuffed 0xFF00 and not a restart marker.
    - Restart markers remain inside scandata.
    """
    if len(data) < 2 or data[0:2] != b'\xFF\xD8':
        raise ValueError('not a JPEG (missing SOI)')

    segments: List[_JpegSegment] = []
    scan_parts: List[bytes] = []

    # SOI
    segments.append(_JpegSegment(0, 0xD8, _marker_name(0xD8), b'\xFF\xD8', b'', None))

    i = 2
    index = 1
    n = len(data)

    def read_marker(pos: int) -> Tuple[int, int, bytes]:
        if pos >= n or data[pos] != 0xFF:
            raise ValueError(f'expected marker at offset 0x{pos:X}')

        start = pos
        pos += 1

        # Skip fill bytes (0xFF). JPEG allows multiple 0xFF bytes before the marker code.
        while pos < n and data[pos] == 0xFF:
            pos += 1

        if pos >= n:
            raise ValueError('truncated marker at end of file')

        marker = data[pos]
        pos += 1

        # Raw marker bytes include any fill bytes and the marker code byte.
        raw_marker = data[start:pos]
        return marker, pos, raw_marker

    while i < n:
        marker, i, raw_marker = read_marker(i)

        # Markers without length fields.
        if marker in {0xD8, 0xD9, 0x01} or (0xD0 <= marker <= 0xD7):
            seg_raw = raw_marker  # usually just b'\xFF' + marker
            segments.append(_JpegSegment(index, marker, _marker_name(marker), seg_raw, b'', None))
            index += 1
            if marker == 0xD9:
                break
            continue

        # All other markers should have a 2-byte length field.
        if i + 2 > n:
            raise ValueError('truncated segment length')

        length = _u16be(data[i:i + 2])
        i += 2

        if length < 2:
            raise ValueError(f'invalid segment length {length} at marker 0x{marker:02X}')

        payload_len = length - 2
        if i + payload_len > n:
            raise ValueError('truncated segment payload')

        payload = data[i:i + payload_len]
        i += payload_len

        seg_raw = raw_marker + length.to_bytes(2, 'big') + payload
        segments.append(_JpegSegment(index, marker, _marker_name(marker), seg_raw, payload, length))
        index += 1

        # After SOS, extract entropy-coded scan data until the next real marker.
        if marker == 0xDA:
            scan_start = i
            j = scan_start
            while j + 1 < n:
                if data[j] != 0xFF:
                    j += 1
                    continue

                nxt = data[j + 1]

                # Stuffed 0xFF byte inside scan data.
                if nxt == 0x00:
                    j += 2
                    continue

                # Fill byte inside scan data.
                if nxt == 0xFF:
                    j += 1
                    continue

                # Restart markers are part of scan data.
                if 0xD0 <= nxt <= 0xD7:
                    j += 2
                    continue

                # Otherwise: start of next segment marker.
                break

            scan_parts.append(data[scan_start:j])
            i = j

    return segments, b''.join(scan_parts)


def _preview_hex(b: bytes, limit: int = 256) -> str:
    return b[:limit].hex()


def _safe_get(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name)
    except Exception:
        return default


def _build_meta_from_jpegdata(jpeg: Any, data: bytes) -> Dict[str, Any]:
    """Build a metadata dictionary from a jpegdata JPEG object, defensively."""
    meta: Dict[str, Any] = {}

    meta['filesize'] = len(data)

    # The jpegdata CLI output uses these names; several versions differ slightly.
    for key, attr in (
        ('byte_order', 'byte_order'),
        ('byte_order', 'byte_oder'),
        ('encoding', 'encoding'),
        ('precision', 'precision'),
        ('width', 'width'),
        ('height', 'height'),
    ):
        if key in meta:
            continue
        value = _safe_get(jpeg, attr, None)
        if value is None:
            continue
        meta[key] = value

    # Normalize encoding value.
    enc = meta.get('encoding')
    if enc is not None and not isinstance(enc, (int, float, str, bool)):
        meta['encoding'] = getattr(enc, 'name', None) or str(enc)

    # Colour block
    colour: Dict[str, Any] = {}
    col = _safe_get(jpeg, 'colour', None) or _safe_get(jpeg, 'color', None)
    if isinstance(col, dict):
        # Some versions may already provide a dict.
        colour.update({k: v for k, v in col.items() if isinstance(k, str)})
    elif col is not None:
        components = _safe_get(col, 'components', None)
        transform = _safe_get(col, 'transform', None)
        if components is not None:
            colour['components'] = components
        if transform is not None:
            colour['transform'] = transform

    if colour:
        meta['colour'] = colour

    # Defaults if absent.
    meta.setdefault('byte_order', 'MSB')

    return meta


def _build_meta_fallback_from_segments(segments: List[_JpegSegment], data: bytes) -> Dict[str, Any]:
    """Fallback metadata extraction without jpegdata."""
    meta: Dict[str, Any] = {
        'filesize': len(data),
        'byte_order': 'MSB',
    }

    # Extract width/height/precision/components from the first SOF marker we find.
    sof_seg = next((s for s in segments if 0xC0 <= s.marker <= 0xCF and s.marker not in {0xC4, 0xC8, 0xCC}), None)
    if sof_seg and len(sof_seg.payload) >= 6:
        payload = sof_seg.payload
        meta['precision'] = payload[0]
        meta['height'] = _u16be(payload[1:3])
        meta['width'] = _u16be(payload[3:5])
        components = payload[5]
        meta['colour'] = {
            'components': components,
        }
        if enc := _encoding_from_sof_marker(sof_seg.marker):
            meta['encoding'] = enc

    return meta


class xtjpg(ArchiveUnit):
    """Extract segments and scan data from JPEG images."""

    @ArchiveUnit.Requires('jpegdata', ['formats', 'default', 'extended'])
    def _jpegdata():
        import jpegdata
        return jpegdata

    def unpack(self, data):
        segments, scandata = _split_jpeg(bytes(data))

        # Emit raw segments.
        for seg in segments:
            suffix = f'_{seg.name}' if seg.name else ''
            yield UnpackResult(f'raw/segment{seg.index:03d}{suffix}', seg.raw)

        # Emit combined scan data.
        yield UnpackResult('raw/scandata', scandata)

        # Build meta.json.
        meta: Dict[str, Any]

        # If jpegdata is missing, accessing any attribute will raise a RefineryImportMissing
        # with the correct installation hint (e.g. "pip install jpegdata").
        try:
            jpegdata = self._jpegdata
        except Exception:
            jpegdata = None

        if jpegdata is not None:
            # jpegdata usually expects a path, so we write a temp file.
            with tempfile.NamedTemporaryFile(prefix='refinery-xtjpg-', suffix='.jpg', delete=False) as tmp:
                tmp.write(data)
                tmp.flush()
                tmp_path = tmp.name
            try:
                jpeg = jpegdata.JPEG(tmp_path)
                meta = _build_meta_from_jpegdata(jpeg, bytes(data))
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        else:
            meta = _build_meta_fallback_from_segments(segments, bytes(data))

        # Segment listing in meta.json should resemble the jpegdata-based script output.
        seg_meta: List[Dict[str, Any]] = []
        for seg in segments:
            entry: Dict[str, Any] = {
                'type': 'Segment',
                'marker': seg.marker,
                'marker_hex': hex(seg.marker),
                'length': seg.length_field or 0,
            }

            if seg.payload:
                entry['payload_len'] = len(seg.payload)
                entry['payload_preview_hex'] = _preview_hex(seg.payload)

            seg_meta.append(entry)

        meta.update({
            'segment_count': len(segments),
            'segments': seg_meta,
        })

        yield UnpackResult('parsed/meta.json', lambda m=meta: json.dumps(m))

    @classmethod
    def handles(cls, data) -> bool | None:
        return len(data) >= 2 and data[:2] == b'\xFF\xD8'
