from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from string import Formatter

from ..capability import requireOpaqueId
from ..domain.correlation import CorrelationContext
from ..domain.diagnostics import (
	DIAGNOSTIC_HEAD_LIMIT,
	DIAGNOSTIC_TAIL_LIMIT,
	DiagnosticBundle,
	Severity,
)
from ..domain.status import EvidenceState, OutcomeSummary
from .settings_presenter import LocalizedMessage, TranslationCatalog


_FORMATTER = Formatter()


@dataclass(frozen=True, slots=True)
class StatePresentation:
	state: EvidenceState
	labelMessageId: str
	canonicalToken: EvidenceState


def presentState(state: EvidenceState) -> StatePresentation:
	return StatePresentation(state, f"evidenceState.{state.value}", state)


@dataclass(frozen=True, slots=True)
class StateCountPresentation:
	state: EvidenceState
	labelMessageId: str
	canonicalToken: EvidenceState
	count: int


@dataclass(frozen=True, slots=True)
class StatusDetailPresentation:
	successfulAreas: tuple[str, ...]
	failedAreas: tuple[str, ...]
	errorCode: str | None
	diagnosticId: str | None
	fullCorrelationId: str | None
	generation: int | None


@dataclass(frozen=True, slots=True)
class StatusPresentation:
	outcome: LocalizedMessage
	counts: tuple[StateCountPresentation, ...]
	detail: StatusDetailPresentation
	correlationSuffix: str | None


def presentStatus(
	summary: OutcomeSummary,
	correlation: CorrelationContext | None,
) -> StatusPresentation:
	counts = tuple(
		StateCountPresentation(
			state,
			f"evidenceState.{state.value}",
			state,
			summary.stateCounts.count(state),
		)
		for state in EvidenceState
	)
	applicable = None if correlation is None else correlation.applicableId
	detail = StatusDetailPresentation(
		summary.successfulAreas,
		summary.failedAreas,
		summary.errorCode,
		summary.diagnosticId,
		None if applicable is None else applicable.value,
		None if correlation is None else correlation.generation,
	)
	outcomeArguments: tuple[object, ...] = ()
	if summary.outcomeToken == "completedPartial":
		if applicable is None:
			raise ValueError("partial outcomes require correlation for diagnostic direction")
		outcomeArguments = (
			summary.successfulAreas,
			summary.failedAreas,
			applicable.statusSuffix,
		)
	elif summary.outcomeToken == "failed":
		if applicable is None or not summary.failedAreas or summary.errorCode is None:
			raise ValueError("failed outcomes require an affected area, stable code, and correlation")
		outcomeArguments = (summary.failedAreas[0], summary.errorCode, applicable.statusSuffix)
	return StatusPresentation(
		LocalizedMessage(
			f"outcome.{summary.outcomeToken}",
			outcomeArguments,
		),
		counts,
		detail,
		None if applicable is None else applicable.statusSuffix,
	)


def _formatStateCount(template: object, count: int) -> str:
	try:
		if not isinstance(template, str):
			raise ValueError("localized count template must be text")
		fields: set[str] = set()
		for _literal, fieldName, formatSpec, conversion in _FORMATTER.parse(template):
			if fieldName is None:
				continue
			if fieldName != "count" or formatSpec or conversion:
				raise ValueError("localized count template has an unsafe placeholder")
			fields.add(fieldName)
		if fields != {"count"}:
			raise ValueError("localized count template must use only the count placeholder")
		return template.format_map({"count": count})
	except (AttributeError, IndexError, KeyError, ValueError):
		return f"{count} item" if count == 1 else f"{count} items"


def resolveStateCount(count: StateCountPresentation, catalog: TranslationCatalog) -> str:
	if count.state is EvidenceState.VALUE:
		stateLabel = catalog.pgettext("evidence state", "Available")
	elif count.state is EvidenceState.EMPTY:
		stateLabel = catalog.pgettext("evidence state", "Empty")
	elif count.state is EvidenceState.UNSUPPORTED:
		stateLabel = catalog.pgettext("evidence state", "Unsupported")
	elif count.state is EvidenceState.NOT_APPLICABLE:
		stateLabel = catalog.pgettext("evidence state", "Not applicable")
	elif count.state is EvidenceState.UNAVAILABLE:
		stateLabel = catalog.pgettext("evidence state", "Unavailable")
	elif count.state is EvidenceState.STALE:
		stateLabel = catalog.pgettext("evidence state", "Stale")
	elif count.state is EvidenceState.REJECTED:
		stateLabel = catalog.pgettext("evidence state", "Rejected")
	elif count.state is EvidenceState.REDACTED:
		stateLabel = catalog.pgettext("evidence state", "Redacted")
	elif count.state is EvidenceState.TRUNCATED:
		stateLabel = catalog.pgettext("evidence state", "Truncated")
	elif count.state is EvidenceState.CANCELLED:
		stateLabel = catalog.pgettext("evidence state", "Cancelled")
	elif count.state is EvidenceState.FAILED:
		stateLabel = catalog.pgettext("evidence state", "Failed")
	else:
		stateLabel = catalog.pgettext("evidence state", "Mixed")
	template = catalog.ngettext("{count} item", "{count} items", count.count)
	return f"{_formatStateCount(template, count.count)}: {stateLabel}"


@dataclass(frozen=True, slots=True)
class DiagnosticRowPresentation:
	severity: Severity
	code: str
	fieldPath: str
	safeBreadcrumb: tuple[str, ...]
	sanitizedDetail: str
	correlationId: str
	correlationSuffix: str


@dataclass(frozen=True, slots=True)
class DiagnosticBundlePresentation:
	rows: tuple[DiagnosticRowPresentation, ...]
	total: int
	truncated: bool
	truncationMessage: LocalizedMessage | None


def presentDiagnosticBundle(bundle: DiagnosticBundle) -> DiagnosticBundlePresentation:
	rows = tuple(
		DiagnosticRowPresentation(
			diagnostic.severity,
			diagnostic.code,
			diagnostic.fieldPath,
			diagnostic.safeBreadcrumb,
			diagnostic.sanitizedDetail,
			diagnostic.correlation.applicableId.value,
			diagnostic.correlation.applicableId.statusSuffix,
		)
		for diagnostic in bundle.diagnostics
	)
	truncation = (
		LocalizedMessage(
			"diagnostics.truncated",
			(DIAGNOSTIC_HEAD_LIMIT, DIAGNOSTIC_TAIL_LIMIT, bundle.diagnosticsTotal),
		)
		if bundle.diagnosticsTruncated
		else None
	)
	return DiagnosticBundlePresentation(
		rows,
		bundle.diagnosticsTotal,
		bundle.diagnosticsTruncated,
		truncation,
	)


class OutputCompletionOutcome(StrEnum):
	COMMITTED = "committed"
	COMMITTED_WITH_WARNING = "committedWithWarning"
	FAILED = "failed"
	PARTIAL_WITHOUT_PUBLICATION = "partialWithoutPublication"
	CANCELLED = "cancelled"
	STALE = "stale"
	INVALIDATED = "invalidated"


@dataclass(frozen=True, slots=True)
class ExplicitOutputAction:
	labelMessageId: str
	operation: str
	actionId: str

	def __post_init__(self) -> None:
		requireOpaqueId(self.labelMessageId, "labelMessageId")
		requireOpaqueId(self.operation, "operation")
		requireOpaqueId(self.actionId, "actionId")


@dataclass(frozen=True, slots=True)
class OutputCompletionPresentation:
	outcome: OutputCompletionOutcome
	automaticSpeech: LocalizedMessage
	automaticStatus: LocalizedMessage
	actions: tuple[ExplicitOutputAction, ...]

	def __post_init__(self) -> None:
		if self.outcome is OutputCompletionOutcome.COMMITTED and not self.actions:
			raise ValueError("committed output requires path actions")
		if self.actions and self.outcome not in (
			OutputCompletionOutcome.COMMITTED,
			OutputCompletionOutcome.COMMITTED_WITH_WARNING,
		):
			raise ValueError("path actions are available only for committed output")


def _validatedFolderName(folderName: str) -> str:
	if (
		not folderName
		or len(folderName) > 255
		or folderName.strip() != folderName
		or folderName in (".", "..")
		or any(character in folderName for character in ("/", "\\", ":"))
	):
		raise ValueError("output completion requires a validated short folder name")
	return folderName


def presentOutputCompletion(
	outcome: OutputCompletionOutcome,
	folderName: str | None = None,
	actionId: str | None = None,
	completionCode: str | None = None,
) -> OutputCompletionPresentation:
	if outcome in (OutputCompletionOutcome.COMMITTED, OutputCompletionOutcome.COMMITTED_WITH_WARNING):
		if (folderName is None) != (actionId is None):
			raise ValueError("committed output requires both a folder name and action ID")
		if outcome is OutputCompletionOutcome.COMMITTED and folderName is None:
			raise ValueError("committed output requires a short folder name and opaque action ID")
		if outcome is OutputCompletionOutcome.COMMITTED_WITH_WARNING and completionCode is None:
			raise ValueError("committed output warning requires a stable code")
		if completionCode is not None:
			requireOpaqueId(completionCode, "completionCode")
		if folderName is None:
			message = LocalizedMessage("output.committedWithWarning", (completionCode,))
			return OutputCompletionPresentation(outcome, message, message, ())
		assert actionId is not None
		shortName = _validatedFolderName(folderName)
		requireOpaqueId(actionId, "actionId")
		if outcome is OutputCompletionOutcome.COMMITTED:
			if completionCode is not None:
				raise ValueError("committed output cannot carry a warning code")
			message = LocalizedMessage("output.committed", (shortName,))
		else:
			message = LocalizedMessage("output.committedWithWarning", (shortName, completionCode))
		actions = (
			ExplicitOutputAction("output.copyFullPath", "copyCommittedPath", actionId),
			ExplicitOutputAction("output.openFolder", "openCommittedFolder", actionId),
			ExplicitOutputAction("output.revealFolder", "revealCommittedFolder", actionId),
		)
		return OutputCompletionPresentation(outcome, message, message, actions)
	if folderName is not None or actionId is not None:
		raise ValueError("unpublished output cannot carry a folder name or path action")
	if outcome is OutputCompletionOutcome.FAILED:
		if completionCode is None:
			raise ValueError("failed output requires a stable code")
		requireOpaqueId(completionCode, "completionCode")
		message = LocalizedMessage("output.failed", (completionCode,))
	else:
		if completionCode is not None:
			raise ValueError("unpublished output cannot carry a completion code")
		message = LocalizedMessage(f"output.{outcome.value}")
	return OutputCompletionPresentation(outcome, message, message, ())
