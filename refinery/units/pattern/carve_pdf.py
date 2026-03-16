from __future__ import annotations

from refinery.units import Unit


class carve_pdf(Unit):
    """
    Extracts anything from the input data that looks like a PDF document.

    The unit searches for the `%PDF-` magic header and the corresponding `%%EOF` trailer to
    determine the boundaries of each embedded PDF. This can be used to carve PDF files from
    disk images, memory dumps, network captures, or compound documents where PDF content is
    embedded in a larger binary stream. Multiple PDF documents embedded in a single input will
    each be extracted separately.
    """
    def process(self, data: bytearray):
        memory = memoryview(data)
        offset = 0
        while True:
            start = data.find(B'%PDF-', offset)
            if start < 0:
                break
            eof_marker = B'%%EOF'
            end = start
            while True:
                end = data.find(eof_marker, end + 1)
                if end < 0:
                    break
                end += len(eof_marker)
                while end < len(data) and data[end:end + 1] in (b'\r', b'\n'):
                    end += 1
                yield self.labelled(memory[start:end], offset=start)
                break
            if end < 0:
                offset = start + 1
            else:
                offset = end
