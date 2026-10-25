"""Small, explicit error types.

Messages returned to clients are written by us and never contain exception
reprs, resolved addresses, or other internal connection details.
"""

from __future__ import annotations


class ScanInputError(Exception):
    """The requested target is not acceptable under the scan policy."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class FetchFailure(Exception):
    """A request could not be completed.  Carries a safe, user-facing message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class SSRFBlockedError(Exception):
    """Raised by the network backend if a socket destination is not permitted."""
