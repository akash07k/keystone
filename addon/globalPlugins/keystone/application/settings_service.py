from __future__ import annotations

from ..domain.settings import (
	SaveResult,
	SaveStatus,
	SettingsCandidate,
	SettingsSnapshot,
	ValidationIssue,
	validateCandidate,
)
from ..domain.correlation import CorrelationContext
from ..ports.effects import SettingsPort, SettingsWriteRequest


class SettingsService:
	def __init__(self, port: SettingsPort) -> None:
		super().__init__()
		self._port = port

	def save(
		self,
		current: SettingsSnapshot,
		candidate: SettingsCandidate,
		context: CorrelationContext,
	) -> SaveResult:
		if candidate.startingRevision != current.settingsRevision:
			return SaveResult(
				SaveStatus.REJECTED,
				current,
				(ValidationIssue("settingsRevision", "staleRevision"),),
			)
		validation = validateCandidate(candidate)
		if not validation.isValid:
			return SaveResult(SaveStatus.REJECTED, current, validation.issues)
		result = self._port.updateSettings(
			SettingsWriteRequest(
				startingRevision=current.settingsRevision,
				values=candidate.namedValues(),
				context=context,
			),
		)
		expectedRevision = current.settingsRevision + 1
		if result.status.token != "ready":
			code = result.error.code if result.error is not None else "KS.SETTINGS.WRITE_FAILED"
			return SaveResult(SaveStatus.FAILED, current, errorCode=code)
		if result.status.revision != expectedRevision:
			return SaveResult(
				SaveStatus.FAILED,
				current,
				errorCode="KS.SETTINGS.REVISION_MISMATCH",
			)
		snapshot = candidate.toSnapshot(expectedRevision)
		return SaveResult(SaveStatus.UPDATED, snapshot)
