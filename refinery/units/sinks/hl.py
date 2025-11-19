from __future__ import annotations

import pathlib

import colorama

if True:
    colorama.init()

from refinery.lib.id import get_text_format
from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class hl(Unit):
    """
    This unit uses the Pygments library for syntax highlighting. It expects plain text code as
    input and outputs ANSI-colored text.
    """
    def __init__(
        self,
        lexer: Param[str | None, Arg.String(
            help='Optionally specify the input language to be highlighted.')] = None,
        style: Param[str | None, Arg.String('-s', group='STYLE',
            help='Optionally specify a color style supported by Pygments.')] = None,
        github: Param[bool, Arg.Switch('-G', group='STYLE',
            help='Use github-flavored styling.')] = False,
        solarized: Param[bool, Arg.Switch('-S', group='STYLE',
            help='Use solarized-flavored styling.')] = False,
        gruvbox: Param[bool, Arg.Switch('-B', group='STYLE',
            help='Use gruvbox-flavored styling.')] = False,
        dark: Param[bool, Arg.Switch('-d',
            help='Assume a dark brackground.')] = False,
        light: Param[bool, Arg.Switch('-l',
            help='Assume a light background.')] = False,
    ):
        if dark and light:
            raise ValueError('The "dark" and "light" options cannot simultaneously be set.')
        if sum(1 for opt in (github, solarized, gruvbox, style) if opt) > 1:
            raise ValueError('More than one styling option was set.')
        return super().__init__(
            lexer=lexer,
            style=style,
            dark=dark,
            light=light,
            github=github,
            solarized=solarized,
            gruvbox=gruvbox,
        )

    @Unit.Requires('Pygments', ['display', 'extended'])
    def _pygments():
        import pygments
        import pygments.formatters
        import pygments.lexers
        import pygments.style
        import pygments.token
        return pygments

    def _style_variant(self):
        return 'light' if self.args.light else 'dark'

    def process(self, data):
        lib = self._pygments
        token = lib.token

        if _lexer := self.args.lexer:
            lexer = lib.lexers.get_lexer_by_name(_lexer)
        else:
            guesses = []
            meta = metavars(data)
            if format := get_text_format(data):
                guesses.append(format.extension)
            guesses.append(str(meta['ext']))
            if path := meta.get('path'):
                guesses.append(pathlib.Path(str(path)).suffix.lstrip('.'))
            for guess in guesses:
                try:
                    lexer = lib.lexers.get_lexer_by_name(guess)
                except Exception:
                    pass
                else:
                    break
            else:
                lexer = lib.lexers.guess_lexer(data)

        self.log_info(F'using lexer for {lexer.name.lower()}')
        t256 = lib.formatters.Terminal256Formatter

        if self.args.github:
            tf = t256(style=F'github-{self._style_variant()}')
        elif self.args.solarized:
            tf = t256(style=F'solarized-{self._style_variant()}')
        elif self.args.gruvbox:
            tf = t256(style=F'gruvbox-{self._style_variant()}')
        elif self.args.light:
            tf = lib.formatters.TerminalFormatter(bg='light')
        elif self.args.dark:
            tf = lib.formatters.TerminalFormatter(bg='dark')
        else:
            if not (style := self.args.style):
                class _style(lib.style.Style):
                    background_color = 'default'
                    R = 'ansibrightred'
                    C = 'ansibrightcyan'
                    W = 'ansiwhite'
                    B = 'ansibrightblack'
                    styles = {
                        token.Comment     : B,
                        token.Text        : R,
                        token.Name        : R,
                        token.Error       : W,
                        token.Keyword     : W,
                        token.String      : W,
                        token.Operator    : C,
                        token.Punctuation : C,
                        token.Number      : C,
                        token.Literal     : C,
                    }
                style = _style
            tf = t256(style=style)

        out = lib.highlight(data, lexer, tf)
        out = F'{out}{colorama.Style.RESET_ALL}'
        return out.encode(self.codec)


class hlg(hl, docs='{0}{s}This variant uses GitHub styling.'):
    def __init__(self, lexer: str | None = None, dark: bool = False, light: bool = False):
        super().__init__(lexer, dark=dark, light=light, github=True)


class hls(hl, docs='{0}{s}This variant uses solarized styling.'):
    def __init__(self, lexer: str | None = None, dark: bool = False, light: bool = False):
        super().__init__(lexer, dark=dark, light=light, solarized=True)


class hlb(hl, docs='{0}{s}This variant uses gruvbox styling.'):
    def __init__(self, lexer: str | None = None, dark: bool = False, light: bool = False):
        super().__init__(lexer, dark=dark, light=light, gruvbox=True)
