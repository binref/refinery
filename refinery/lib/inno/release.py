"""
The release of Inno Setup that built an installer, as far as the installer tells it. Where releases
of Setup behave differently, the emulator asks `SetupRelease.since` whether the release is a given
one or later.
"""
from __future__ import annotations

from typing import Callable

Version = tuple[int, ...]

ReleaseRange = tuple[Version, Version | None]
"""
The releases from the first version up to, not including, the second one; `None` excludes no later
release.
"""

ReleaseSource = Callable[[], ReleaseRange | None]
"""
A part of the installer that names the releases which may have built it, read when asked; `None`
when it does not tell.
"""


def next_release(release: Version) -> Version:
    """
    The release right after the given one.
    """
    major, minor, patch, *_ = (*release, 0, 0, 0)
    return (major, minor, patch + 1)


class SetupRelease:
    """
    The releases of Inno Setup that may have built an installer: from `lowest` up to, not
    including, `below`, which is `None` when no later release is excluded. When this range does not
    tell whether the release is a given one or later, the sources narrow it, each read once and in
    order; a source that contradicts the range is ignored. The current Setup, which runs a bare
    script without a configured version, is later than every release.
    """
    def __init__(self, lowest: Version, below: Version | None, *sources: ReleaseSource):
        self.lowest = lowest[:3]
        self.below = below
        self._sources = list(sources)

    @classmethod
    def exactly(cls, release: Version) -> SetupRelease:
        """
        The given release and no other.
        """
        return cls(release, next_release(release))

    @classmethod
    def of_compiled_code(cls, version: int) -> SetupRelease:
        """
        The release that Inno Setup 7 writes into the header as the version of the compiled code;
        its highest bit marks a 64-bit Setup.
        """
        return cls.exactly((version >> 24 & 0x7F, version >> 16 & 0xFF, version >> 8 & 0xFF))

    @classmethod
    def current(cls) -> SetupRelease:
        """
        The current Setup.
        """
        return cls((0x7FFFFFFF,), None)

    @property
    def is_current(self) -> bool:
        return self.below is None and self.lowest == (0x7FFFFFFF,)

    @property
    def exact(self) -> Version | None:
        """
        The release, when the range holds only one.
        """
        if (below := self.below) is not None and below == next_release(self.lowest):
            return self.lowest
        return None

    def since(self, version: Version) -> bool:
        """
        Whether the release is the given one or later. A question that neither the range nor any
        source answers fails as one whose answer the emulator does not have.
        """
        while True:
            if self.lowest >= version:
                return True
            if (below := self.below) is not None and below <= version:
                return False
            if not self._sources:
                raise NotImplementedError(
                    F'The installer was built by Inno Setup {self}, which does not tell whether it is'
                    F' {_dotted(version)} or later.')
            if (narrowed := self._sources.pop(0)()) is not None:
                self._narrow(*narrowed)

    def _narrow(self, lowest: Version, below: Version | None):
        lowest = max(self.lowest, lowest[:3])
        if below is None or self.below is not None and self.below < below:
            below = self.below
        if below is None or lowest < below:
            self.lowest = lowest
            self.below = below

    def __str__(self):
        if self.is_current:
            return 'current'
        if (release := self.exact) is not None:
            return _dotted(release)
        if (below := self.below) is None:
            return F'{_dotted(self.lowest)} or later'
        return F'{_dotted(self.lowest)} up to {_dotted(below)}, not including it'

    def __repr__(self):
        return F'{self.__class__.__name__}({self!s})'


def _dotted(version: Version) -> str:
    return '.'.join(map(str, version))
