import sys
import io
import inspect
import contextlib


@contextlib.contextmanager
def errbuf():
    sys_stderr = sys.stderr
    sys.stderr = io.StringIO()
    yield sys.stderr
    sys.stderr.close()
    sys.stderr = sys_stderr


TESTBUFFER_BIN = bytes.fromhex( # start of a notepad.exe
    '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00'
    '40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 00 00 00 00 F8 00 00 00 0E 1F BA 0E 00 B4 09 CD'
    '21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F'
    '74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A'
    '24 00 00 00 00 00 00 00 65 39 D7 74 21 58 B9 27 21 58 B9 27 21 58 B9 27'
    '28 20 2A 27 11 58 B9 27 35 33 BD 26 2B 58 B9 27 35 33 BA 26 22 58 B9 27'
    '35 33 B8 26 28 58 B9 27 21 58 B8 27 0B 5D B9 27 35 33 B1 26 3F 58 B9 27'
    '35 33 BC 26 3E 58 B9 27 35 33 44 27 20 58 B9 27 35 33 46 27 20 58 B9 27'
    '35 33 BB 26 20 58 B9 27 52 69 63 68 21 58 B9 27 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 50 45 00 00 64 86 07 00 18 36 A6 3B 00 00 00 00'
    '00 00 00 00 F0 00 22 00 0B 02 0E 14 00 5E 02 00 00 E6 00 00 00 00 00 00'
    '10 54 02 00 00 10 00 00 00 00 00 40 01 00 00 00 00 10 00 00 00 02 00 00'
    '0A 00 00 00 0A 00 00 00 0A 00 00 00 00 00 00 00 00 90 03 00 00 04 00 00'
    'D3 F1 03 00 02 00 60 C1 00 00 08 00 00 00 00 00 00 10 01 00 00 00 00 00'
    '00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 10 00 00 00'
    '00 00 00 00 00 00 00 00 D8 E6 02 00 44 02 00 00 00 70 03 00 D8 0B 00 00'
    '00 40 03 00 88 11 00 00 00 00 00 00 00 00 00 00 00 80 03 00 E8 02 00 00'
    'A0 BC 02 00 54 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 10 77 02 00 18 01 00 00 00 00 00 00 00 00 00 00'
    '28 78 02 00 10 09 00 00 F0 DF 02 00 E0 00 00 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 00 00 00 00 2E 74 65 78 74 00 00 00 CF 5C 02 00 00 10 00 00'
    '00 5E 02 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60'
    '2E 72 64 61 74 61 00 00 D6 98 00 00 00 70 02 00 00 9A 00 00 00 62 02 00'
    '00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2E 64 61 74 61 00 00 00'
    '88 27 00 00 00 10 03 00 00 0E 00 00 00 FC 02 00 00 00 00 00 00 00 00 00'
    '00 00 00 00 40 00 00 C0 2E 70 64 61 74 61 00 00 88 11 00 00 00 40 03 00'
    '00 12 00 00 00 0A 03 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40'
    '2E 64 69 64 61 74 00 00 78 01 00 00 00 60 03 00 00 02 00 00 00 1C 03 00'
    '00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 72 73 72 63 00 00 00'
)

TESTBUFFER_TXT = inspect.cleandoc(
    """
        Another one got caught today, it's all over the papers.  "Teenager
    Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tampering"...
        Damn kids.  They're all alike.

        But did you, in your three-piece psychology and 1950's technobrain,
    ever take a look behind the eyes of the hacker?  Did you ever wonder what
    made him tick, what forces shaped him, what may have molded him?
        I am a hacker, enter my world...
        Mine is a world that begins with school... I'm smarter than most of
    the other kids, this crap they teach us bores me...
        Damn underachiever.  They're all alike.

        I'm in junior high or high school.  I've listened to teachers explain
    for the fifteenth time how to reduce a fraction.  I understand it.  "No, Ms.
    Smith, I didn't show my work.  I did it in my head..."
        Damn kid.  Probably copied it.  They're all alike.
    """
).encode('utf8')
