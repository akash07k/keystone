from __future__ import annotations

from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from .document_records import (
	CaptureDocumentKind,
	CaptureMetadata,
	CustomUiaConfigurationRecord,
	DiagnosticRecord,
	DiffChange,
	EventDrops,
	EventRecord,
	JsonArray,
	JsonObject,
	JsonValue,
	NodeRecord,
	PersistedDocumentMetadata,
	PublicationRecord,
	ScreenshotDocumentResult,
	SettingsSnapshotRecord,
	SummaryRecord,
	parseCaptureMetadata,
	parseCustomUiaConfigurationRecord,
	parseDiagnosticRecord,
	parseDiffChange,
	parseDocumentReference,
	parseEventDrops,
	parseEventRecord,
	parseNodeRecord,
	parsePersistedDocumentMetadata,
	parsePublicationRecord,
	parseScreenshotDocumentResult,
	parseSettingsSnapshotRecord,
	parseSummaryRecord,
)
from .settings import SETTING_DEFINITIONS, SettingKind
from .status import EvidenceState


type DocumentKind = Literal[
	"snapshot",
	"navigatorSnapshot",
	"snapshotSummary",
	"navigatorSummary",
	"diff",
	"eventExport",
	"diagnosticBundle",
	"settingsSnapshot",
	"customUiaConfiguration",
	"screenshotResult",
	"publicationReceipt",
]


DOCUMENT_FIELDS: dict[DocumentKind, tuple[str, ...]] = {
	"snapshot": ("roots", "nodes"),
	"navigatorSnapshot": ("root", "nodes"),
	"snapshotSummary": ("summary",),
	"navigatorSummary": ("summary",),
	"diff": ("baseline", "current", "changes", "noChange"),
	"eventExport": ("events", "drops"),
	"diagnosticBundle": ("diagnostics", "diagnosticsTotal", "diagnosticsTruncated"),
	"settingsSnapshot": ("settings",),
	"customUiaConfiguration": ("configuration",),
	"screenshotResult": ("result", "correlationId"),
	"publicationReceipt": ("publication", "correlationId"),
}
METADATA_FIELDS = (
	"capture",
	"environment",
	"limits",
	"counts",
	"duration",
	"projection",
	"redaction",
)


@dataclass(frozen=True, slots=True)
class Document:
	documentKind: DocumentKind
	documentId: str
	metadata: CaptureMetadata | PersistedDocumentMetadata
	content: JsonObject
	captureRoots: tuple[str, ...] = ()
	captureNodes: tuple[NodeRecord, ...] = ()
	navigatorRoot: str | None = None
	summaryRecord: SummaryRecord | None = None
	records: tuple[DiffChange | EventRecord | DiagnosticRecord, ...] = ()
	drops: EventDrops | None = None
	record: (
		SettingsSnapshotRecord
		| CustomUiaConfigurationRecord
		| ScreenshotDocumentResult
		| PublicationRecord
		| None
	) = None
	correlationId: str | None = None

	def __post_init__(self) -> None:
		if self.documentKind not in DOCUMENT_FIELDS:
			raise ValueError("document kind is not in the closed registry")
		try:
			parsed = UUID(self.documentId)
		except (AttributeError, ValueError) as error:
			raise ValueError("document ID must be a UUID") from error
		if self.documentId != str(parsed):
			raise ValueError("document ID must use canonical lowercase UUID text")
		if self.documentKind in CAPTURE_DOCUMENT_KINDS:
			if not isinstance(self.metadata, CaptureMetadata):
				raise ValueError("capture documents require capture metadata")
		elif not isinstance(self.metadata, PersistedDocumentMetadata):
			raise ValueError("non-capture documents require persisted document metadata")
		if tuple(name for name, _value in self.content.items) != DOCUMENT_FIELDS[self.documentKind]:
			raise ValueError("document content must match its exact kind fields")
		self._validateKindInvariants()

	def _validateKindInvariants(self) -> None:
		values = dict(self.content.items)
		if self.documentKind in CAPTURE_DOCUMENT_KINDS:
			self._validateCaptureInvariants()
			return
		if self.documentKind == "diff" and values["noChange"] != (values["changes"] is None):
			raise ValueError("diff noChange must exactly match a null changes value")
		if self.documentKind == "diagnosticBundle":
			diagnostics = values["diagnostics"]
			total = values["diagnosticsTotal"]
			truncated = values["diagnosticsTruncated"]
			if not isinstance(diagnostics, JsonArray):
				raise ValueError("diagnostics must be an array")
			if not isinstance(total, int) or isinstance(total, bool) or total < len(diagnostics.items):
				raise ValueError("diagnostics total is invalid")
			if len(diagnostics.items) > 300 or truncated != (total > len(diagnostics.items)):
				raise ValueError("diagnostic retention evidence is inconsistent")
		if self.documentKind == "screenshotResult":
			if not isinstance(self.record, ScreenshotDocumentResult):
				raise ValueError("screenshot document requires a typed current result")

	def _validateCaptureInvariants(self) -> None:
		if not isinstance(self.metadata, CaptureMetadata):
			raise ValueError("capture documents require substantive typed metadata")
		if self.metadata.counts.emitted != len(self.captureNodes) and self.summaryRecord is None:
			raise ValueError("capture emitted count must agree with admitted nodes")
		if self.documentKind in {"snapshot", "navigatorSnapshot"}:
			keys = tuple(node.key for node in self.captureNodes)
			if not keys or len(set(keys)) != len(keys):
				raise ValueError("capture node keys must be nonempty and unique")
			if any(root not in keys for root in self.captureRoots):
				raise ValueError("every snapshot root must resolve to one node")
			parents = {child: node.key for node in self.captureNodes for child in node.structure.childKeys}
			if len(parents) != sum(len(node.structure.childKeys) for node in self.captureNodes):
				raise ValueError("a capture child must not have multiple structural parents")
			for node in self.captureNodes:
				if any(child not in keys for child in node.structure.childKeys):
					raise ValueError("every structural child must resolve to a node")
				if node.structure.parentKey != parents.get(node.key):
					raise ValueError("node parent and ordered child structure must agree")
			if self.documentKind == "snapshot":
				if not self.captureRoots or set(self.captureRoots) != {
					node.key for node in self.captureNodes if node.structure.parentKey is None
				}:
					raise ValueError("snapshot roots must exactly identify parentless nodes")
			else:
				if (
					self.navigatorRoot is None
					or self.navigatorRoot not in keys
					or {node.key for node in self.captureNodes if node.structure.parentKey is None}
					!= {self.navigatorRoot}
				):
					raise ValueError("navigator root must resolve to the one parentless capture subtree root")
				if self.metadata.capture.containingForeground.status is not EvidenceState.VALUE:
					raise ValueError("navigator capture requires containing-foreground evidence")
		elif self.summaryRecord is None:
			raise ValueError("summary documents require a substantive summary record")
		elif self.metadata.counts.emitted != len(self.summaryRecord.nodes):
			raise ValueError("summary metadata counts must agree with the summary nodes")

	def asObject(self) -> JsonObject:
		metadata = self.metadata.asObject()
		return JsonObject(
			(
				("schemaVersion", JsonObject((("major", 2), ("minor", 0)))),
				("documentKind", self.documentKind),
				("documentId", self.documentId),
				("metadata", metadata),
				*self.content.items,
			),
		)

	@property
	def roots(self) -> tuple[str, ...]:
		if self.documentKind != "snapshot":
			raise AttributeError("roots are available only on snapshot documents")
		return self.captureRoots

	@property
	def nodes(self) -> tuple[NodeRecord, ...]:
		if self.documentKind not in {"snapshot", "navigatorSnapshot"}:
			raise AttributeError("nodes are available only on snapshot documents")
		return self.captureNodes

	@property
	def root(self) -> str:
		if self.documentKind != "navigatorSnapshot" or self.navigatorRoot is None:
			raise AttributeError("root is available only on navigator snapshots")
		return self.navigatorRoot

	@property
	def summary(self) -> SummaryRecord:
		if self.summaryRecord is None:
			raise AttributeError("summary is available only on summary documents")
		return self.summaryRecord


class Snapshot(Document):
	pass


class NavigatorSnapshot(Document):
	pass


class SnapshotSummary(Document):
	pass


class NavigatorSummary(Document):
	pass


class Diff(Document):
	pass


class EventExport(Document):
	pass


class DiagnosticBundleDocument(Document):
	pass


class SettingsSnapshot(Document):
	pass


class CustomUiaConfiguration(Document):
	pass


class ScreenshotResult(Document):
	pass


class PublicationReceipt(Document):
	pass


DOCUMENT_TYPES: dict[DocumentKind, type[Document]] = {
	"snapshot": Snapshot,
	"navigatorSnapshot": NavigatorSnapshot,
	"snapshotSummary": SnapshotSummary,
	"navigatorSummary": NavigatorSummary,
	"diff": Diff,
	"eventExport": EventExport,
	"diagnosticBundle": DiagnosticBundleDocument,
	"settingsSnapshot": SettingsSnapshot,
	"customUiaConfiguration": CustomUiaConfiguration,
	"screenshotResult": ScreenshotResult,
	"publicationReceipt": PublicationReceipt,
}
CAPTURE_DOCUMENT_KINDS = frozenset(
	("snapshot", "navigatorSnapshot", "snapshotSummary", "navigatorSummary"),
)


def buildDocument(
	documentKind: DocumentKind,
	documentId: str,
	metadataValue: JsonObject,
	fields: dict[str, JsonValue],
) -> Document:
	documentType = DOCUMENT_TYPES[documentKind]
	if documentKind not in CAPTURE_DOCUMENT_KINDS:
		metadata = parsePersistedDocumentMetadata(metadataValue)
		if documentKind == "diff":
			baseline = parseDocumentReference(fields["baseline"])
			current = parseDocumentReference(fields["current"])
			changeValue = fields["changes"]
			changes = (
				()
				if changeValue is None
				else tuple(parseDiffChange(item) for item in _arrayItems(changeValue, "diff changes"))
			)
			noChange = fields["noChange"]
			if not isinstance(noChange, bool) or noChange != (changeValue is None):
				raise ValueError("diff noChange must exactly match a null changes value")
			if not noChange and not changes:
				raise ValueError("changed diff requires at least one substantive change")
			content = JsonObject(
				(
					("baseline", baseline.asObject()),
					("current", current.asObject()),
					(
						"changes",
						None if noChange else JsonArray(tuple(change.asObject() for change in changes)),
					),
					("noChange", noChange),
				),
			)
			return documentType(documentKind, documentId, metadata, content, records=changes)
		if documentKind == "eventExport":
			events = tuple(parseEventRecord(item) for item in _arrayItems(fields["events"], "events"))
			drops = parseEventDrops(fields["drops"])
			content = JsonObject(
				(
					("events", JsonArray(tuple(event.asObject() for event in events))),
					("drops", drops.asObject()),
				),
			)
			return documentType(documentKind, documentId, metadata, content, records=events, drops=drops)
		if documentKind == "diagnosticBundle":
			diagnostics = tuple(
				parseDiagnosticRecord(item) for item in _arrayItems(fields["diagnostics"], "diagnostics")
			)
			total = fields["diagnosticsTotal"]
			truncated = fields["diagnosticsTruncated"]
			if not isinstance(total, int) or isinstance(total, bool) or total < len(diagnostics):
				raise ValueError("diagnostics total is invalid")
			if not isinstance(truncated, bool) or truncated != (total > len(diagnostics)):
				raise ValueError("diagnostic truncation evidence is inconsistent")
			if len(diagnostics) > 300 or (truncated and len(diagnostics) != 300):
				raise ValueError(
					"diagnostic retention must contain at most 300 or exactly 300 truncated records",
				)
			ids = tuple(item.diagnosticId for item in diagnostics)
			if len(set(ids)) != len(ids):
				raise ValueError("diagnostic IDs must be unique")
			starts = tuple(item.timing.startMilliseconds for item in diagnostics)
			if starts != tuple(sorted(starts)):
				raise ValueError("retained diagnostics must preserve chronological order")
			content = JsonObject(
				(
					("diagnostics", JsonArray(tuple(item.asObject() for item in diagnostics))),
					("diagnosticsTotal", total),
					("diagnosticsTruncated", truncated),
				),
			)
			return documentType(documentKind, documentId, metadata, content, records=diagnostics)
		if documentKind == "settingsSnapshot":
			record = parseSettingsSnapshotRecord(fields["settings"])
			_validateSettingsRecord(record)
			content = JsonObject((("settings", record.asObject()),))
			return documentType(documentKind, documentId, metadata, content, record=record)
		if documentKind == "customUiaConfiguration":
			record = parseCustomUiaConfigurationRecord(fields["configuration"])
			content = JsonObject((("configuration", record.asObject()),))
			return documentType(documentKind, documentId, metadata, content, record=record)
		if documentKind == "screenshotResult":
			record = parseScreenshotDocumentResult(fields["result"])
			correlationId = _nodeKey(fields["correlationId"], "screenshot correlation ID")
			content = JsonObject((("result", record.asObject()), ("correlationId", correlationId)))
			return documentType(
				documentKind,
				documentId,
				metadata,
				content,
				record=record,
				correlationId=correlationId,
			)
		if documentKind == "publicationReceipt":
			record = parsePublicationRecord(fields["publication"])
			correlationId = _nodeKey(fields["correlationId"], "publication correlation ID")
			content = JsonObject((("publication", record.asObject()), ("correlationId", correlationId)))
			return documentType(
				documentKind,
				documentId,
				metadata,
				content,
				record=record,
				correlationId=correlationId,
			)
		content = JsonObject(tuple((name, fields[name]) for name in DOCUMENT_FIELDS[documentKind]))
		return documentType(documentKind, documentId, metadata, content)

	captureKind: CaptureDocumentKind = documentKind
	metadata = parseCaptureMetadata(metadataValue, captureKind)
	if documentKind == "snapshot":
		roots = tuple(_nodeKey(item, "snapshot root") for item in _arrayItems(fields["roots"], "roots"))
		nodes = tuple(parseNodeRecord(item) for item in _arrayItems(fields["nodes"], "nodes"))
		content = JsonObject(
			(
				("roots", JsonArray(roots)),
				("nodes", JsonArray(tuple(node.asObject() for node in nodes))),
			),
		)
		return documentType(documentKind, documentId, metadata, content, roots, nodes)
	if documentKind == "navigatorSnapshot":
		root = _nodeKey(fields["root"], "navigator root")
		nodes = tuple(parseNodeRecord(item) for item in _arrayItems(fields["nodes"], "nodes"))
		content = JsonObject(
			(
				("root", root),
				("nodes", JsonArray(tuple(node.asObject() for node in nodes))),
			),
		)
		return documentType(documentKind, documentId, metadata, content, (), nodes, root)

	sourceKind: Literal["snapshot", "navigatorSnapshot"] = (
		"snapshot" if documentKind == "snapshotSummary" else "navigatorSnapshot"
	)
	summary = parseSummaryRecord(fields["summary"], sourceKind)
	content = JsonObject((("summary", summary.asObject()),))
	return documentType(documentKind, documentId, metadata, content, (), (), None, summary)


def _arrayItems(value: JsonValue, label: str) -> tuple[JsonValue, ...]:
	if not isinstance(value, JsonArray):
		raise ValueError(f"{label} must be an array")
	return value.items


def _nodeKey(value: JsonValue, label: str) -> str:
	if not isinstance(value, str) or not value or value.strip() != value:
		raise ValueError(f"{label} must be a nonempty trimmed string")
	return value


def _validateSettingsRecord(record: SettingsSnapshotRecord) -> None:
	if len(record.values) != len(SETTING_DEFINITIONS):
		raise ValueError("settings snapshot must contain every setting definition")
	for value, definition in zip(record.values, SETTING_DEFINITIONS, strict=True):
		if value.settingId != definition.settingId.value or value.kind != definition.kind.value:
			raise ValueError("settings snapshot must follow the exact registry order")
		if definition.kind is SettingKind.INTEGER:
			if (
				not isinstance(value.value, int)
				or isinstance(value.value, bool)
				or definition.minimum is None
				or definition.maximum is None
				or not definition.minimum <= value.value <= definition.maximum
			):
				raise ValueError("integer setting snapshot value is invalid")
		elif definition.kind in {SettingKind.BOOLEAN, SettingKind.HELD_CLOSED_BOOLEAN}:
			if not isinstance(value.value, bool):
				raise ValueError("boolean setting snapshot value is invalid")
		elif not isinstance(value.value, str) or value.value not in definition.choices:
			raise ValueError("choice setting snapshot value is invalid")
