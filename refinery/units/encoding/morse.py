from __future__ import annotations

import enum
import io
import re

from refinery.lib.decorators import unicoded
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class MorseLanguage(str, enum.Enum):
    AR = 'Arabic'
    DE = 'German'
    EN = 'English'
    ES = 'Spanish'
    FR = 'French'
    HE = 'Hebrew'
    RU = 'Russian'
    UA = 'Ukrainian'


def _reverse_dictionary(d: dict):
    result = {}
    for key, value in d.items():
        result.setdefault(value, key)
    return result


def _extend_dictionary(d: dict, e: dict):
    for key, value in d.items():
        e.setdefault(key, value)
    return e


class morse(Unit):
    """
    Morse encoding and decoding. All tokens in the input data which consist of dashes and dots are
    replaced by their Morse decoding.
    """
    def __init__(
        self,
        language: Param[str, Arg.Option(choices=MorseLanguage, help=(
            'Optionally choose a language. If none is specified, the unit will attempt to detect '
            'the language automatically. Options are: {choices}'))] = None,
    ):
        super().__init__(language=Arg.AsOption(language, MorseLanguage))

    @classmethod
    def handles(cls, data):
        if re.fullmatch(BR'[-.\s]+', data, re.DOTALL):
            return True

    @unicoded
    def process(self, data: str):
        language: MorseLanguage = self.args.language
        parsed = re.split('(\\s+)', data)
        tokens = {t for t in parsed[::2] if t}
        tables = [
            self._DECODE_SYMBOL,
            self._DECODE_DIGITS,
        ]

        if language is not None:
            tables.append(self._DECODE[language])
        else:
            special = set(self._DECODE_SYMBOL) | set(self._DECODE_DIGITS)
            best_ratio = 1 # number of unused codes
            best_table = None
            for language in MorseLanguage:
                table = self._DECODE[language]
                codes = set(table)
                if not tokens <= codes | special:
                    continue
                if language == MorseLanguage.EN:
                    best_table = table
                    break
                ratio = len(codes - tokens) / len(codes)
                if ratio < best_ratio:
                    best_ratio = ratio
                    best_table = table
            if best_table is None:
                raise LookupError('Unable to determine language, please specify it manually.')
            tables.append(best_table)

        with io.StringIO() as out:
            for k, string in enumerate(parsed):
                if k % 2 == 1:
                    string = string[1:]
                    if len(string) > 1:
                        string = string[:-1]
                    out.write(string)
                    continue
                if not string:
                    continue
                for table in tables:
                    try:
                        out.write(table[string])
                        break
                    except KeyError:
                        continue
                else:
                    raise ValueError(F'invalid token: {string}')
            return out.getvalue()

    @unicoded
    def reverse(self, data: str):
        language: MorseLanguage = self.args.language
        tables = [
            self._ENCODE_SYMBOL,
            self._ENCODE_DIGITS,
        ]
        if language is not None:
            tables.append(self._ENCODE[language])
        else:
            tables.extend(self._ENCODE.values())

        def _encode(letter):
            for table in tables:
                try:
                    return table[letter]
                except KeyError:
                    continue
            else:
                raise ValueError(F'cannot encode letter "{letter}"')

        with io.StringIO() as out:
            for k, word in enumerate(re.split('(\\s+)', data)):
                if k % 2 == 1:
                    out.write(F' {word} ')
                    continue
                out.write(' '.join(_encode(letter) for letter in word.lower()))
            return out.getvalue()

    _ENCODE = {
        MorseLanguage.EN: {
            'a': '.-',
            'b': '-...',
            'c': '-.-.',
            'd': '-..',
            'e': '.',
            'f': '..-.',
            'g': '--.',
            'h': '....',
            'i': '..',
            'j': '.---',
            'k': '-.-',
            'l': '.-..',
            'm': '--',
            'n': '-.',
            'o': '---',
            'p': '.--.',
            'q': '--.-',
            'r': '.-.',
            's': '...',
            't': '-',
            'u': '..-',
            'v': '...-',
            'w': '.--',
            'x': '-..-',
            'y': '-.--',
            'z': '--..',
        }
    }
    _ENCODE[MorseLanguage.ES] = _extend_dictionary(_ENCODE[MorseLanguage.EN], {
        'á': '.--.-',
        'é': '..-..',
        'í': '..',
        'ñ': '--.--',
        'ó': '---.',
        'ú': '..-',
        'ü': '..--',
        '¿': '..-.-',
        '¡': '--...-',
    })
    _ENCODE[MorseLanguage.DE] = _extend_dictionary(_ENCODE[MorseLanguage.EN], {
        'ä': '.-.-',
        'ö': '---.',
        'ü': '..--',
        'ß': '...--..',
    })
    _ENCODE[MorseLanguage.FR] = _extend_dictionary(_ENCODE[MorseLanguage.EN], {
        'à': '.--.-',
        'â': '.--.-',
        'ç': '-.-..',
        'è': '.-..-',
        'é': '..-..',
        'ê': '-..-.',
        'ë': '..-..',
        'î': '..',
        'ï': '-..--',
        'ô': '---',
        'ù': '..-',
        'ü': '..--',
    })
    _ENCODE[MorseLanguage.RU] = {
        'а': '.-',
        'б': '-...',
        'в': '.--',
        'г': '--.',
        'д': '-..',
        'е': '.',
        'ё': '.',
        'ж': '...-',
        'з': '--..',
        'и': '..',
        'й': '.---',
        'к': '-.-',
        'л': '.-..',
        'м': '--',
        'н': '-.',
        'о': '---',
        'п': '.--.',
        'р': '.-.',
        'с': '...',
        'т': '-',
        'у': '..-',
        'ф': '..-.',
        'х': '....',
        'ц': '-.-.',
        'ч': '---.',
        'ш': '----',
        'щ': '--.-',
        'ъ': '--.--',
        'ы': '-.--',
        'ь': '-..-',
        'э': '..-..',
        'ю': '..--',
        'я': '.-.-',
    }
    _ENCODE[MorseLanguage.UA] = _extend_dictionary(_ENCODE[MorseLanguage.RU], {
        'ґ': '--.',
        'и': '-.--',
        'ї': '.---.',
    })
    _ENCODE[MorseLanguage.UA]['є'] = _ENCODE[MorseLanguage.UA].pop('э')
    _ENCODE[MorseLanguage.UA]['і'] = _ENCODE[MorseLanguage.UA].pop('и')

    _ENCODE[MorseLanguage.HE] = {
        'א': '.-',
        'ב': '-...',
        'ג': '--.',
        'ד': '-..',
        'ה': '---',
        'ו': '.',
        'ז': '--..',
        'ח': '....',
        'ט': '..--',
        'י': '..',
        'כ': '-.',
        'ל': '.-..',
        'מ': '--',
        'נ': '--.',
        'ס': '-.-.',
        'ע': '.---',
        'פ': '.--.',
        'צ': '.--',
        'ק': '--.-',
        'ר': '.-.',
        'ש': '...',
        'ת': '-',
    }

    _ENCODE[MorseLanguage.AR] = {
        'ا': '.-',
        'ب': '-...',
        'ت': '-',
        'ث': '-.-.',
        'ج': '.---',
        'ح': '....',
        'خ': '---',
        'د': '-..',
        'ذ': '--..',
        'ر': '.-.',
        'ز': '---.',
        'س': '...',
        'ش': '----',
        'ص': '-..-',
        'ض': '...-',
        'ط': '..-',
        'ظ': '-.--',
        'ع': '.-.-',
        'غ': '--.',
        'ف': '..-.',
        'ق': '--.-',
        'ك': '-.-',
        'ل': '.-..',
        'م': '--',
        'ن': '-.',
        'ه': '..-..',
        'و': '.--',
        'ي': '..',
        'ﺀ': '.',
    }

    _ENCODE_DIGITS = {
        '0': '-----',
        '1': '.----',
        '2': '..---',
        '3': '...--',
        '4': '....-',
        '5': '.....',
        '6': '-....',
        '7': '--...',
        '8': '---..',
        '9': '----.'
    }

    _ENCODE_SYMBOL = {
        '_': '..--.-',
        '-': '-....-',
        ',': '--..--',
        ';': '-.-.-.',
        ':': '---...',
        '!': '-.-.--',
        '?': '..--..',
        '.': '.-.-.-',
        '"': '.-..-.',
        '(': '-.--.',
        ')': '-.--.-',
        '@': '.--.-.',
        '/': '-..-.',
        '\\': '-..-.',
        '&': '.-...',
        '+': '.-.-.',
        '=': '-...-',
        '$': '...-..-',
        "'": '.----.',
    }

    _DECODE = {
        lng: _reverse_dictionary(tbl) for lng, tbl in _ENCODE.items()}
    _DECODE_SYMBOL = _reverse_dictionary(_ENCODE_SYMBOL)
    _DECODE_DIGITS = _reverse_dictionary(_ENCODE_DIGITS)
