from __future__ import annotations

from importlib import import_module
from typing import Protocol, cast

from ...encoding.log_formats import LogicalRecord, Severity, renderNvdaMessage


class _HostLogger(Protocol):
	def debug(self, message: str) -> None: ...

	def info(self, message: str) -> None: ...

	def warning(self, message: str) -> None: ...

	def error(self, message: str) -> None: ...

	def critical(self, message: str) -> None: ...


def _defaultLogger() -> _HostLogger:
	return cast(_HostLogger, getattr(import_module("logHandler"), "log"))


class NvdaLogAdapter:
	__slots__ = ("_logger",)

	def __init__(self, logger: _HostLogger | None = None) -> None:
		super().__init__()
		self._logger = logger if logger is not None else _defaultLogger()

	def emit(self, record: LogicalRecord) -> None:
		message = renderNvdaMessage(record)
		method = {
			Severity.DEBUG: self._logger.debug,
			Severity.INFO: self._logger.info,
			Severity.WARNING: self._logger.warning,
			Severity.ERROR: self._logger.error,
			Severity.CRITICAL: self._logger.critical,
		}[record.severity]
		method(message)
