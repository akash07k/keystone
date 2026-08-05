from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from time import monotonic_ns
from typing import Literal, Protocol, cast

from ..adapters.providers.common import ProviderSectionData
from ..adapters.providers.custom_uia import CustomUiaBudget, CustomUiaCaptureMode
from ..adapters.windows.publication import PublicationPackage, PublicationPolicy
from ..capability import PlainValue, requireOpaqueId
from ..domain.correlation import CorrelationContext
from ..domain.custom_uia_values import CustomValueLimits
from ..domain.document_records import (
	COMMON_NODE_FIELDS,
	PROVIDER_SECTIONS,
	CaptureCounts,
	CaptureDetails,
	CaptureDuration,
	CaptureLimits,
	CaptureMetadata,
	DiagnosticMetadata,
	EnvironmentMetadata,
	JsonArray,
	JsonObject,
	NodeRecord,
	NodeStructure,
	ProjectionMetadata,
	ProviderSectionRecord,
	ProviderSections,
	RedactionMetadata,
	ScreenshotMetadata,
	StandaloneConventions,
	SummaryCounts,
	SummaryNode,
	SummaryRecord,
)
from ..domain.documents import (
	NavigatorSnapshot,
	NavigatorSummary,
	Snapshot,
	SnapshotSummary,
)
from ..domain.snapshot_bundle import (
	BundlePackage,
	prepareBundle,
	projectSnapshotTopics,
)
from ..domain.evidence import ErrorReference, EvidenceEnvelope, PrivacyReference, Projection, Source
from ..domain.privacy import (
	FieldGroup,
	ObservedValue,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	UNREDACTED_SCREENSHOT_WARNING,
	transformValue,
)
from ..domain.provider_measurement import BackendId
from ..domain.settings import SettingsSnapshot
from ..domain.state import CaptureLifecycle, CaptureState
from ..domain.status import Confidence, EvidenceState
from ..domain.traversal import (
	CaptureMode,
	IterativeTraversal,
	TraversalLimits,
	TraversalProgress,
	TraversalResult,
)
from ..ports.effects import ScreenshotAttempt, ScreenshotPort, ScreenshotResult, ScreenshotTarget
from ..ports.providers import (
	IdentityComparisonPort,
	IdentityComparisonRequest,
	ProviderMetadataRequest,
	ProviderReadResult,
	ReadBudget,
	ReadOnlyNodePort,
)
from ..presentation.status_presenter import OutputCompletionOutcome, OutputCompletionPresentation
from .bundle_service import toPublicationPackage
from .lifecycle import LifecycleAdmission, LifecycleService


class CaptureTargetKind(str):
	FOREGROUND = "foreground"
	NAVIGATOR = "navigator"


class CaptureOutputPort(Protocol):
	def publish(
		self,
		package: PublicationPackage,
		*,
		lifecycleGeneration: int,
		context: CorrelationContext,
		policy: PublicationPolicy | None = None,
	) -> OutputCompletionPresentation: ...


class CustomUiaCapturePort(Protocol):
	def collectCustomUia(
		self,
		nodeRef: object,
		*,
		mode: CustomUiaCaptureMode,
		captureSessionId: str,
		providerProcessId: int,
		budget: CustomUiaBudget,
		privacyPolicy: PrivacyPolicy,
		protection: ProtectionEvidence,
	) -> ProviderSectionData: ...


@dataclass(frozen=True, slots=True)
class CustomUiaCaptureOptions:
	hierarchyPollingEnabled: bool
	maximumNodes: int
	maximumCalls: int
	maximumCandidates: int
	maximumValueReads: int
	maximumTextScalars: int
	maximumTextBytes: int
	maximumElementRuntimeIds: int
	maximumMilliseconds: int

	def __post_init__(self) -> None:
		if type(self.hierarchyPollingEnabled) is not bool:
			raise TypeError("custom UIA hierarchy polling state must be boolean")
		if (
			min(
				self.maximumNodes,
				self.maximumCalls,
				self.maximumCandidates,
				self.maximumValueReads,
				self.maximumTextScalars,
				self.maximumTextBytes,
				self.maximumElementRuntimeIds,
				self.maximumMilliseconds,
			)
			<= 0
		):
			raise ValueError("custom UIA capture limits must be independently positive")

	@classmethod
	def defaults(cls) -> CustomUiaCaptureOptions:
		return cls(False, 25, 256, 128, 32, 4_096, 16_384, 16, 250)

	@property
	def budget(self) -> CustomUiaBudget:
		return CustomUiaBudget(
			self.maximumNodes,
			self.maximumCalls,
			self.maximumCandidates,
			self.maximumValueReads,
			self.maximumMilliseconds,
			CustomValueLimits(
				self.maximumTextScalars,
				self.maximumTextBytes,
				self.maximumElementRuntimeIds,
			),
		)

	def shouldCollect(self, *, detailCollection: bool, depth: int, collectedNodes: int) -> bool:
		if depth < 0 or collectedNodes < 0:
			raise ValueError("custom UIA collection position must be nonnegative")
		if collectedNodes >= self.maximumNodes:
			return False
		return depth == 0 if detailCollection else self.hierarchyPollingEnabled


@dataclass(frozen=True, slots=True)
class CaptureRequest:
	targetKind: Literal["foreground", "navigator"]
	rootRef: str
	containingForeground: ScreenshotTarget
	executable: str
	processId: int
	mode: CaptureMode = "bounded"
	providerScope: str = "nvda-selected"
	processScope: str = "selected-process"
	backend: BackendId = "nvdaSelected"
	detailCollection: bool = False
	inspectionTargetRef: str | None = None
	includeRootNameInOutput: bool = False

	def __post_init__(self) -> None:
		if self.targetKind not in (CaptureTargetKind.FOREGROUND, CaptureTargetKind.NAVIGATOR):
			raise ValueError("capture target kind is not supported")
		if not self.rootRef or not self.executable or self.processId < 0:
			raise ValueError("capture request target identity is incomplete")
		if type(self.detailCollection) is not bool:
			raise TypeError("detail collection state must be boolean")
		if type(self.includeRootNameInOutput) is not bool:
			raise TypeError("includeRootNameInOutput must be boolean")
		if self.inspectionTargetRef is not None:
			requireOpaqueId(self.inspectionTargetRef, "inspectionTargetRef")


@dataclass(frozen=True, slots=True)
class CaptureWorkItem:
	request: CaptureRequest
	admission: LifecycleAdmission
	limits: TraversalLimits


@dataclass(frozen=True, slots=True)
class CaptureResult:
	lifecycle: CaptureLifecycle
	context: CorrelationContext
	traversal: TraversalResult
	snapshot: Snapshot | NavigatorSnapshot | None
	summary: SnapshotSummary | NavigatorSummary | None
	screenshot: ScreenshotResult | None
	publication: OutputCompletionPresentation | None
	committed: bool
	errorCode: str | None = None
	inspectionTargetKey: str | None = None
	bundle: BundlePackage | None = None


def _clockMilliseconds() -> int:
	return monotonic_ns() // 1_000_000


class CaptureService:
	def __init__(
		self,
		lifecycle: LifecycleService,
		provider: ReadOnlyNodePort,
		identity: IdentityComparisonPort,
		output: CaptureOutputPort,
		screenshot: ScreenshotPort,
		*,
		settings: SettingsSnapshot,
		privacyPolicy: PrivacyPolicy,
		documentIdFactory: Callable[[], str],
		publicationIdFactory: Callable[[], str],
		screenshotAttemptIdFactory: Callable[[], str],
		now: Callable[[], datetime] | None = None,
		clockMilliseconds: Callable[[], int] = _clockMilliseconds,
		yieldControl: Callable[[int], None] | None = None,
		customUia: CustomUiaCapturePort | None = None,
		customUiaOptions: CustomUiaCaptureOptions | None = None,
	) -> None:
		super().__init__()
		self._lifecycleService = lifecycle
		self._provider = provider
		self._identity = identity
		self._output = output
		self._screenshot = screenshot
		self._settings = settings
		self._privacyPolicy = privacyPolicy
		self._documentIdFactory = documentIdFactory
		self._publicationIdFactory = publicationIdFactory
		self._screenshotAttemptIdFactory = screenshotAttemptIdFactory
		self._now = now or (lambda: datetime.now(timezone.utc))
		self._clock = clockMilliseconds
		self._yieldControl = yieldControl
		self._customUia = customUia
		self._customUiaOptions = customUiaOptions or CustomUiaCaptureOptions.defaults()
		self._cancelRequested = False
		self._activeLifecycle: CaptureLifecycle | None = None
		self._stagedConfiguration: tuple[SettingsSnapshot, PrivacyPolicy] | None = None
		self._fullCaptureBaseline: Snapshot | None = None
		self._fullCaptureBaselineRequest: CaptureRequest | None = None

	@property
	def fullCaptureBaseline(self) -> Snapshot | None:
		return self._fullCaptureBaseline

	@property
	def fullCaptureBaselineRequest(self) -> CaptureRequest | None:
		return self._fullCaptureBaselineRequest

	@property
	def activeLifecycle(self) -> CaptureLifecycle | None:
		return self._activeLifecycle

	def requestCancellation(self) -> None:
		self._cancelRequested = True
		current = self._activeLifecycle
		if (
			current is not None
			and not current.isTerminal
			and current.state
			not in (
				CaptureState.CANCELLATION_REQUESTED,
				CaptureState.COMMITTING,
			)
		):
			self._activeLifecycle = current.requestCancellation()

	def _ensureCurrent(self, admission: LifecycleAdmission, lifecycle: CaptureLifecycle) -> None:
		if not self._lifecycleService.precommit(admission):
			self._activeLifecycle = lifecycle.fail()
			raise RuntimeError("KS.CAPTURE.STALE_GENERATION")

	def _cooperate(
		self,
		work: CaptureWorkItem,
		sliceStarted: int,
		*,
		force: bool = False,
	) -> int:
		if self._yieldControl is None:
			return sliceStarted
		now = self._clock()
		if not force and now - sliceStarted < work.limits.workSliceMilliseconds:
			return sliceStarted
		self._yieldControl(work.limits.yieldMilliseconds)
		return self._clock()

	def _cancelledResult(
		self,
		lifecycle: CaptureLifecycle,
		context: CorrelationContext,
		traversal: TraversalResult,
	) -> CaptureResult:
		cancelled = lifecycle.requestCancellation().finishCancellation()
		self._activeLifecycle = cancelled
		return CaptureResult(
			cancelled,
			context,
			traversal,
			None,
			None,
			None,
			None,
			False,
			"KS.CAPTURE.CANCELLED",
		)

	def _inspectionTargetKey(
		self,
		work: CaptureWorkItem,
		traversal: TraversalResult,
	) -> str | None:
		"""Resolve an Inspector-only retained object to one captured traversal key."""

		targetRef = work.request.inspectionTargetRef
		if targetRef is None:
			return None
		context = work.admission.context
		if context is None:
			return None
		budget = ReadBudget(
			max(1, min(work.limits.maximumNodes, 2_147_483_647)),
			max(1, min(work.limits.maximumTextScalars, 2_147_483_647)),
			max(1, min(work.limits.maximumMilliseconds, 2_147_483_647)),
		)
		matches: list[str] = []
		sliceStarted = self._clock()
		for node in traversal.nodes:
			if self._cancelRequested:
				raise RuntimeError("KS.CAPTURE.CANCELLED")
			comparison = self._identity.compareIdentity(
				IdentityComparisonRequest(
					targetRef,
					node.nodeRef,
					work.request.providerScope,
					work.request.processScope,
					budget,
					context,
				),
			)
			if comparison.status == "value" and comparison.decision == "same":
				matches.append(node.key)
			sliceStarted = self._cooperate(work, sliceStarted)
			if self._cancelRequested:
				raise RuntimeError("KS.CAPTURE.CANCELLED")
		return matches[0] if len(matches) == 1 else None

	def _envelope(
		self,
		result: ProviderReadResult,
		fieldId: str,
		diagnosticId: str,
		*,
		group: FieldGroup = FieldGroup.NODE,
		protection: ProtectionEvidence | None = None,
	) -> EvidenceEnvelope:
		source = Source("nvdaSelected", "CaptureService", fieldId)
		projection = Projection("normalNvda")
		if result.status == "value":
			sink = (
				SinkId.SCREENSHOT
				if group is FieldGroup.SCREENSHOT
				else SinkId.CUSTOM
				if group is FieldGroup.CUSTOM
				else SinkId.RELATION
				if group is FieldGroup.RELATION
				else SinkId.TEXT
				if group is FieldGroup.TEXT
				else SinkId.NODE
			)
			transformed = transformValue(
				ObservedValue(
					group,
					result.value,
					PrivacyClass.PUBLIC,
					protection or ProtectionEvidence.allClear(),
					f"provider-{fieldId}",
				),
				sink,
				self._privacyPolicy,
			)
			privacy = PrivacyReference(
				group.value,
				transformed.effectiveClass.value,
				transformed.action.value,
				self._privacyPolicy.policyRevision,
			)
			if transformed.action in (TransformAction.REDACT, TransformAction.OMIT):
				return EvidenceEnvelope(
					EvidenceState.REDACTED,
					source,
					projection,
					Confidence.DIRECT,
					privacy,
				)
			return EvidenceEnvelope(
				EvidenceState.VALUE,
				source,
				projection,
				Confidence.DIRECT,
				privacy,
				cast(object, transformed.value),  # pyright: ignore[reportArgumentType]
			)
		privacy = PrivacyReference(group.value, "unknown", "retain", self._privacyPolicy.policyRevision)
		if result.status == "empty":
			return EvidenceEnvelope(EvidenceState.EMPTY, source, projection, Confidence.DIRECT, privacy)
		status = {
			"unsupported": EvidenceState.UNSUPPORTED,
			"unavailable": EvidenceState.UNAVAILABLE,
			"stale": EvidenceState.STALE,
			"failed": EvidenceState.FAILED,
		}[result.status]
		error = (
			ErrorReference(result.errorCode or "KS.PROVIDER.UNKNOWN", diagnosticId)
			if status in (EvidenceState.FAILED, EvidenceState.UNAVAILABLE, EvidenceState.STALE)
			else None
		)
		return EvidenceEnvelope(status, source, projection, Confidence.INDETERMINATE, privacy, errorRef=error)

	def _nonvalue(
		self,
		symbol: str,
		*,
		status: EvidenceState = EvidenceState.NOT_APPLICABLE,
	) -> EvidenceEnvelope:
		return EvidenceEnvelope(
			status,
			Source("nvdaSelected", "CaptureService", symbol),
			Projection("normalNvda"),
			Confidence.INDETERMINATE,
			PrivacyReference("node", "unknown", "retain", self._privacyPolicy.policyRevision),
		)

	def _defaultProviderSections(self) -> ProviderSections:
		applicable = ProviderSectionRecord(
			self._envelope(ProviderReadResult("value", "available"), "providerStatus", "provider-status"),
			self._envelope(
				ProviderReadResult("value", "nvdaSelected"),
				"providerIdentity",
				"provider-identity",
			),
			self._envelope(ProviderReadResult("value", ()), "providerProperties", "provider-properties"),
		)
		unavailable = ProviderSectionRecord(
			self._nonvalue("providerStatus"),
			self._nonvalue("providerIdentity"),
			self._nonvalue("providerProperties"),
		)
		return ProviderSections(
			tuple((name, applicable if name == "generic" else unavailable) for name in PROVIDER_SECTIONS),
		)

	@staticmethod
	def _providerResult(value: object) -> ProviderReadResult:
		if type(value) is not tuple:
			raise ValueError("provider result transport must contain four fields")
		parts = cast(tuple[object, ...], value)
		if len(parts) != 4:
			raise ValueError("provider result transport must contain four fields")
		status, resultValue, errorCode, truncated = parts
		if not isinstance(status, str):
			raise ValueError("provider result status must be a string")
		if errorCode is not None and not isinstance(errorCode, str):
			raise ValueError("provider result error code must be a string or null")
		if type(truncated) is not bool:
			raise ValueError("provider result truncation must be a boolean")
		return ProviderReadResult(status, cast(PlainValue, resultValue), errorCode, truncated)

	def _baseProviderSections(
		self,
		nodeRef: str,
		context: CorrelationContext,
		budget: ReadBudget,
		protection: ProtectionEvidence,
	) -> ProviderSections:
		try:
			result = self._provider.readMetadata(
				ProviderMetadataRequest(nodeRef, "providerSections", budget, context),
			)
		except AssertionError:
			raise
		except Exception:
			return self._defaultProviderSections()
		if result.status != "value" or type(result.value) is not tuple:
			return self._defaultProviderSections()
		try:
			sections: list[tuple[str, ProviderSectionRecord]] = []
			for expectedName, rawSection in zip(PROVIDER_SECTIONS, result.value, strict=True):
				if type(rawSection) is not tuple or len(rawSection) != 4:
					raise ValueError("provider section transport must contain four fields")
				name, statusValue, identityValue, propertiesValue = rawSection
				if name != expectedName:
					raise ValueError("provider section transport is out of registry order")
				status = self._providerResult(statusValue)
				identity = self._providerResult(identityValue)
				properties = self._providerResult(propertiesValue)
				sections.append(
					(
						expectedName,
						ProviderSectionRecord(
							self._envelope(
								status,
								f"{expectedName}Status",
								f"{nodeRef}-{expectedName}-status",
								protection=ProtectionEvidence.allClear(),
							),
							self._envelope(
								identity,
								f"{expectedName}Identity",
								f"{nodeRef}-{expectedName}-identity",
								protection=ProtectionEvidence.allClear(),
							),
							self._envelope(
								properties,
								f"{expectedName}Properties",
								f"{nodeRef}-{expectedName}-properties",
								group=FieldGroup.TEXT,
								protection=protection,
							),
						),
					),
				)
			return ProviderSections(tuple(sections))
		except (TypeError, ValueError):
			return self._defaultProviderSections()

	def _customSectionRecord(
		self,
		section: ProviderSectionData,
		nodeRef: str,
		protection: ProtectionEvidence,
	) -> ProviderSectionRecord:
		plain = section.asPlainValue()
		if type(plain) is not tuple or len(plain) != 4:
			raise ValueError("custom UIA section transport must contain four fields")
		name, statusValue, identityValue, propertiesValue = plain
		if name != "customUia":
			raise ValueError("custom UIA collector returned the wrong provider section")
		return ProviderSectionRecord(
			self._envelope(
				self._providerResult(statusValue),
				"customUiaStatus",
				f"{nodeRef}-custom-uia-status",
				protection=ProtectionEvidence.allClear(),
			),
			self._envelope(
				self._providerResult(identityValue),
				"customUiaIdentity",
				f"{nodeRef}-custom-uia-identity",
				protection=ProtectionEvidence.allClear(),
			),
			self._envelope(
				self._providerResult(propertiesValue),
				"customUiaProperties",
				f"{nodeRef}-custom-uia-properties",
				group=FieldGroup.CUSTOM,
				protection=protection,
			),
		)

	def _providerSections(
		self,
		nodeRef: str,
		context: CorrelationContext,
		budget: ReadBudget,
		protection: ProtectionEvidence,
		*,
		collectCustom: bool = False,
		providerProcessId: int = 0,
		customUiaMode: CustomUiaCaptureMode = CustomUiaCaptureMode.NORMAL,
	) -> ProviderSections:
		base = self._baseProviderSections(nodeRef, context, budget, protection)
		if not collectCustom or self._customUia is None:
			return base
		try:
			custom = self._customUia.collectCustomUia(
				nodeRef,
				mode=customUiaMode,
				captureSessionId=context.sessionId.value,
				providerProcessId=providerProcessId,
				budget=self._customUiaOptions.budget,
				privacyPolicy=self._privacyPolicy,
				protection=protection,
			)
			record = self._customSectionRecord(custom, nodeRef, protection)
		except AssertionError:
			raise
		except Exception:
			return base
		return ProviderSections(
			tuple((name, record if name == "customUia" else section) for name, section in base.items),
		)

	@staticmethod
	def _protection(result: ProviderReadResult) -> ProtectionEvidence:
		if result.status == "value" and result.value is False:
			return ProtectionEvidence.allClear()
		if result.status == "value" and result.value is True:
			return ProtectionEvidence(True)
		return ProtectionEvidence()

	def _documents(
		self,
		work: CaptureWorkItem,
		traversal: TraversalResult,
		screenshot: ScreenshotResult,
		started: int,
		*,
		customUiaMode: CustomUiaCaptureMode,
		progress: Callable[[TraversalProgress], None] | None,
	) -> tuple[Snapshot | NavigatorSnapshot, SnapshotSummary | NavigatorSummary]:
		nodeRecords: list[NodeRecord] = []
		customNodesCollected = 0
		sliceStarted = self._clock()
		totalNodes = len(traversal.nodes)
		if progress is not None:
			progress(
				TraversalProgress(
					totalNodes,
					max(0, self._clock() - started),
					totalNodes,
					"preparing",
				),
			)
		for index, node in enumerate(traversal.nodes):
			fieldMap = {field.fieldId: field.result for field in node.fields}
			protectionResult = fieldMap.get("protection")
			protection = (
				self._protection(protectionResult) if protectionResult is not None else ProtectionEvidence()
			)
			assert work.admission.context is not None
			providerBudget = ReadBudget(
				max(1, min(work.limits.maximumRelations, 4_096)),
				max(1, min(work.limits.maximumTextScalars, 16_384)),
				max(1, min(work.limits.maximumMilliseconds, 2_147_483_647)),
			)
			children = ProviderReadResult("value", node.childKeys)
			fields = tuple(
				(
					fieldId,
					self._envelope(
						children if fieldId == "children" else fieldMap[fieldId],
						fieldId,
						f"{node.key}-{fieldId}",
						group=FieldGroup.TEXT
						if fieldId in ("name", "description", "value")
						else FieldGroup.RELATION
						if fieldId == "annotations"
						else FieldGroup.NODE,
						protection=protection
						if fieldId in ("name", "description", "value", "annotations")
						else ProtectionEvidence.allClear(),
					),
				)
				for fieldId in COMMON_NODE_FIELDS
			)
			collectCustom = self._customUiaOptions.shouldCollect(
				detailCollection=work.request.detailCollection,
				depth=node.depth,
				collectedNodes=customNodesCollected,
			)
			if collectCustom:
				customNodesCollected += 1
			nodeRecords.append(
				NodeRecord(
					node.key,
					NodeStructure(
						node.parentKey,
						node.depth,
						node.childKeys,
						node.cycleDetected,
						node.truncated,
						node.childFetchFailed,
					),
					fields,
					self._providerSections(
						node.nodeRef,
						work.admission.context,
						providerBudget,
						protection,
						collectCustom=collectCustom,
						providerProcessId=work.request.processId,
						customUiaMode=customUiaMode,
					),
				),
			)
			sliceStarted = self._cooperate(work, sliceStarted)
			if progress is not None:
				progress(
					TraversalProgress(
						totalNodes,
						max(0, self._clock() - started),
						totalNodes - index - 1,
						"preparing",
					),
				)
			if self._cancelRequested:
				raise RuntimeError("KS.CAPTURE.CANCELLED")
		snapshotId = self._documentIdFactory()
		summaryId = self._documentIdFactory()
		generated = self._now()
		elapsed = max(0, self._clock() - started)
		containing = self._envelope(
			ProviderReadResult("value", work.request.containingForeground.scopeId),
			"containingForeground",
			"containing-foreground",
		)
		screenshotEnvelope = self._envelope(
			ProviderReadResult(
				"value" if screenshot.status == "value" else "failed",
				screenshot.status if screenshot.status == "value" else None,
				screenshot.errorCode,
			),
			"screenshot",
			screenshot.diagnosticId or "screenshot-current",
			group=FieldGroup.SCREENSHOT,
		)

		def metadata(
			kind: Literal["snapshot", "navigatorSnapshot", "snapshotSummary", "navigatorSummary"],
		) -> CaptureMetadata:
			return CaptureMetadata(
				CaptureDetails(
					generated.isoformat(),
					self._nonvalue("sourcePath"),
					self._envelope(
						ProviderReadResult("value", "capture"),
						"outputPath",
						"output-path",
					),
					kind,
					False,
					containing,
					ScreenshotMetadata(True, screenshotEnvelope, UNREDACTED_SCREENSHOT_WARNING),
					DiagnosticMetadata(0, 0, False),
					StandaloneConventions(
						"keystone.capture",
						"2.0",
						"required fields are never omitted",
						"status is independent from value",
						"signed half-open virtual-screen pixels",
						"capture traversal order",
						"provider child order",
					),
				),
				EnvironmentMetadata(
					self._nonvalue("keystoneVersion"),
					self._nonvalue("nvdaVersion"),
					self._nonvalue("windowsVersion"),
					self._nonvalue("architecture"),
					self._nonvalue("dpi"),
					self._nonvalue("monitors"),
					self._envelope(
						ProviderReadResult("value", (work.request.backend,)),
						"backends",
						"backends",
					),
				),
				CaptureLimits(
					work.limits.maximumDepth,
					work.limits.maximumNodes,
					work.limits.maximumTextScalars,
					max(
						work.limits.maximumRanges,
						work.limits.maximumRelations,
						work.limits.maximumHyperlinks,
					),
				),
				CaptureCounts(
					len(traversal.nodes) + sum(node.childFetchFailed for node in traversal.nodes),
					len(traversal.nodes),
					sum(node.childFetchFailed for node in traversal.nodes),
					sum(node.truncated for node in traversal.nodes),
				),
				CaptureDuration(elapsed),
				ProjectionMetadata("normalNvda", 1),
				RedactionMetadata(
					self._privacyPolicy.redactProtectedText,
					"default",
					self._privacyPolicy.policyRevision,
				),
			)

		def summaryProtection(index: int, key: str) -> EvidenceEnvelope:
			protectionResult = next(
				(item.result for item in traversal.nodes[index].fields if item.fieldId == "protection"),
				None,
			)
			return (
				self._envelope(protectionResult, "protection", f"{key}-protection")
				if protectionResult is not None
				else self._nonvalue("protection")
			)

		summaryNodes = tuple(
			SummaryNode(
				node.key,
				node.field("name"),
				node.field("role"),
				node.field("states"),
				summaryProtection(index, node.key),
				node.field("children"),
				node.structure.cycleDetected,
				node.structure.truncated,
				node.structure.childFetchFailed,
			)
			for index, node in enumerate(nodeRecords)
		)
		summaryRecord = SummaryRecord(
			snapshotId,
			"snapshot" if work.request.targetKind == CaptureTargetKind.FOREGROUND else "navigatorSnapshot",
			traversal.rootKeys,
			summaryNodes,
			SummaryCounts(
				len(traversal.rootKeys),
				len(summaryNodes),
				sum(node.cycleDetected for node in summaryNodes),
				sum(node.truncated for node in summaryNodes),
				sum(node.childFetchFailed for node in summaryNodes),
			),
		)
		documentNodes: list[JsonObject] = []
		for index, node in enumerate(nodeRecords):
			documentNodes.append(node.asObject())
			sliceStarted = self._cooperate(work, sliceStarted)
			if progress is not None:
				progress(
					TraversalProgress(
						totalNodes,
						max(0, self._clock() - started),
						totalNodes - index - 1,
						"preparing",
					),
				)
			if self._cancelRequested:
				raise RuntimeError("KS.CAPTURE.CANCELLED")
		if work.request.targetKind == CaptureTargetKind.FOREGROUND:
			snapshot = Snapshot(
				"snapshot",
				snapshotId,
				metadata("snapshot"),
				JsonObject(
					(
						("roots", JsonArray(traversal.rootKeys)),
						("nodes", JsonArray(tuple(documentNodes))),
					),
				),
				traversal.rootKeys,
				tuple(nodeRecords),
			)
			summary = SnapshotSummary(
				"snapshotSummary",
				summaryId,
				metadata("snapshotSummary"),
				JsonObject((("summary", summaryRecord.asObject()),)),
				summaryRecord=summaryRecord,
			)
			return snapshot, summary
		snapshot = NavigatorSnapshot(
			"navigatorSnapshot",
			snapshotId,
			metadata("navigatorSnapshot"),
			JsonObject(
				(
					("root", traversal.rootKeys[0]),
					("nodes", JsonArray(tuple(documentNodes))),
				),
			),
			(),
			tuple(nodeRecords),
			traversal.rootKeys[0],
		)
		summary = NavigatorSummary(
			"navigatorSummary",
			summaryId,
			metadata("navigatorSummary"),
			JsonObject((("summary", summaryRecord.asObject()),)),
			summaryRecord=summaryRecord,
		)
		return snapshot, summary

	@staticmethod
	def _screenshotObject(result: ScreenshotResult) -> dict[str, object]:
		attempt = result.attempt
		image = None
		if result.status == "value":
			assert result.image is not None
			assert result.capturedGeometry is not None
			image = {
				"sha256": hashlib.sha256(result.image).hexdigest(),
				"byteLength": len(result.image),
				"width": result.capturedGeometry[2],
				"height": result.capturedGeometry[3],
				"capturedAt": result.succeededAt,
			}
		context = attempt.context
		assert context.operationId is not None and context.jobId is not None
		return {
			"attempt": {
				"attemptId": attempt.attemptId,
				"generation": attempt.generation,
				"target": {
					"scopeKind": attempt.target.scopeKind,
					"scopeId": attempt.target.scopeId,
					"geometry": list(attempt.target.geometry),
				},
				"correlation": {
					"sessionId": context.sessionId.value,
					"operationId": context.operationId.value,
					"jobId": context.jobId.value,
					"generation": context.generation,
				},
			},
			"status": result.status,
			"image": image,
			"error": (
				None
				if result.status == "value"
				else {"code": result.errorCode, "diagnosticId": result.diagnosticId}
			),
			"warning": result.warning,
		}

	def _bundleTimestamp(self) -> str:
		now = self._now()
		if now.tzinfo is not None:
			now = now.astimezone(timezone.utc).replace(tzinfo=None)
		return now.isoformat(timespec="microseconds") + "Z"

	def _bundle(
		self,
		work: CaptureWorkItem,
		snapshot: Snapshot | NavigatorSnapshot,
		screenshot: ScreenshotResult,
		*,
		customUiaMode: CustomUiaCaptureMode,
		started: int,
		progress: Callable[[TraversalProgress], None] | None,
	) -> BundlePackage:
		sliceStarted = self._clock()

		def cooperate() -> None:
			nonlocal sliceStarted
			sliceStarted = self._cooperate(work, sliceStarted)
			if progress is not None:
				progress(
					TraversalProgress(
						len(snapshot.captureNodes),
						max(0, self._clock() - started),
						0,
						"packaging",
					),
				)

		target = work.request.containingForeground
		screenshotRecord: dict[str, object] = {
			"screenshot": self._screenshotObject(screenshot),
			"containingForeground": {"scopeId": target.scopeId, "geometry": list(target.geometry)},
		}
		captureConfiguration: dict[str, object] = {
			"maximumDepth": work.limits.maximumDepth,
			"maximumNodes": work.limits.maximumNodes,
			"maximumTextScalars": work.limits.maximumTextScalars,
			"customUiaCaptureMode": customUiaMode.value,
		}
		snapshotKind = (
			"snapshot" if work.request.targetKind == CaptureTargetKind.FOREGROUND else "navigatorSnapshot"
		)
		source = projectSnapshotTopics(
			snapshot,
			generatedAt=self._bundleTimestamp(),
			executable=work.request.executable,
			processId=work.request.processId,
			redactionEnabled=self._privacyPolicy.redactProtectedText,
			policyRevision=self._privacyPolicy.policyRevision,
			settingsRevision=self._settings.settingsRevision,
			snapshotKind=snapshotKind,
			captureConfiguration=captureConfiguration,
			screenshot=screenshotRecord,
			screenshotImage=screenshot.image if screenshot.status == "value" else None,
			customUiaDiagnosticExport=customUiaMode is CustomUiaCaptureMode.DIAGNOSTIC_EXPORT,
			cooperate=cooperate,
		)
		return prepareBundle(source, cooperate=cooperate)

	def _publicationPackage(
		self,
		package: BundlePackage,
		snapshot: Snapshot | NavigatorSnapshot,
		*,
		includeRootName: bool,
	) -> PublicationPackage:
		completedAt = self._now()
		if completedAt.tzinfo is not None:
			completedAt = completedAt.astimezone().replace(tzinfo=None)
		rootKey = (
			snapshot.navigatorRoot if isinstance(snapshot, NavigatorSnapshot) else snapshot.captureRoots[0]
		)
		root = next((node for node in snapshot.captureNodes if node.key == rootKey), None)
		subject = None
		if includeRootName and root is not None:
			name = root.field("name")
			role = root.field("role")
			if name.status is EvidenceState.VALUE and isinstance(name.value, str):
				subject = name.value
			elif role.status is EvidenceState.VALUE and isinstance(role.value, str):
				subject = role.value
		return toPublicationPackage(
			package,
			publicationId=self._publicationIdFactory(),
			completedAt=completedAt,
			subject=subject,
		)

	def stageConfiguration(self, settings: SettingsSnapshot, privacyPolicy: PrivacyPolicy) -> None:
		"""Hold a committed settings change until the next capture starts.

		A capture yields to the host while it walks, so a settings dialog can be applied part-way
		through one. Swapping the policy underneath it would produce a single artifact whose fields
		were redacted under two different rules and whose stored provenance describes neither, so the
		change waits at the boundary instead.
		"""

		self._stagedConfiguration = (settings, privacyPolicy)

	def adoptStagedConfiguration(self) -> None:
		"""Adopt a staged change; a no-op when nothing is staged. Called as an operation begins."""

		staged = self._stagedConfiguration
		if staged is None:
			return
		self._stagedConfiguration = None
		self._settings, self._privacyPolicy = staged

	def capture(
		self,
		request: CaptureRequest,
		*,
		progress: Callable[[TraversalProgress], None] | None = None,
	) -> CaptureResult:
		return self._capture(
			request,
			publish=True,
			updateBaseline=True,
			customUiaMode=CustomUiaCaptureMode.NORMAL,
			progress=progress,
		)

	def captureSubtree(
		self,
		request: CaptureRequest,
		*,
		progress: Callable[[TraversalProgress], None] | None = None,
	) -> CaptureResult:
		"""Publish one selected subtree without replacing the full foreground diff baseline."""

		return self._capture(
			request,
			publish=True,
			updateBaseline=False,
			customUiaMode=CustomUiaCaptureMode.NORMAL,
			progress=progress,
		)

	def exportCustomUiaDiagnostics(self, request: CaptureRequest) -> CaptureResult:
		"""Publish an explicitly requested diagnostic capture without mutating the normal baseline."""
		return self._capture(
			request,
			publish=True,
			updateBaseline=False,
			customUiaMode=CustomUiaCaptureMode.DIAGNOSTIC_EXPORT,
		)

	def captureForDiff(self, request: CaptureRequest) -> CaptureResult:
		"""Collect current full evidence without publishing it or replacing the baseline."""
		if request.targetKind != CaptureTargetKind.FOREGROUND:
			raise ValueError("diff current capture must target the foreground")
		return self._capture(
			request,
			publish=False,
			updateBaseline=False,
			customUiaMode=CustomUiaCaptureMode.NORMAL,
		)

	def captureForInspection(self, request: CaptureRequest) -> CaptureResult:
		"""Materialise one in-memory capture for the Inspector without publishing or baselining.

		The Inspector reads a live object by collecting exactly one capture over the same read-only
		provider seam as every other command, then projects it in memory. It never writes a bundle,
		publishes output, or replaces the diff baseline. Both admissible capture targets -- the
		foreground and the navigator object -- are inspectable, because the Inspector opens on
		whichever object the user selected.
		"""
		return self._capture(
			request,
			publish=False,
			updateBaseline=False,
			customUiaMode=CustomUiaCaptureMode.NORMAL,
			packageForInspection=True,
		)

	def _capture(
		self,
		request: CaptureRequest,
		*,
		publish: bool,
		updateBaseline: bool,
		customUiaMode: CustomUiaCaptureMode,
		progress: Callable[[TraversalProgress], None] | None = None,
		packageForInspection: bool = False,
	) -> CaptureResult:
		self.adoptStagedConfiguration()
		admission = self._lifecycleService.admit(f"capture.{request.targetKind}")
		if not admission.accepted or admission.context is None:
			raise RuntimeError(admission.errorCode or "KS.CAPTURE.NOT_ADMITTED")
		context = admission.context
		self._cancelRequested = False
		lifecycle = CaptureLifecycle.start(admission.generation).advance(CaptureState.COLLECTING)
		self._activeLifecycle = lifecycle
		started = self._clock()
		work = CaptureWorkItem(request, admission, TraversalLimits.fromSettings(self._settings, request.mode))
		walker = IterativeTraversal(
			self._provider,
			self._identity,
			clock=self._clock,
			yieldControl=self._yieldControl,
			cancelRequested=lambda: self._cancelRequested,
			generationCurrent=lambda: self._lifecycleService.isCurrent(admission.generation),
		)
		traversal = walker.walk(
			request.rootRef,
			providerScope=request.providerScope,
			processScope=request.processScope,
			backend=request.backend,
			context=context,
			limits=work.limits,
			progress=progress,
		)
		_ = self._cooperate(work, started, force=True)
		if traversal.cancelled or self._cancelRequested:
			return self._cancelledResult(lifecycle, context, traversal)
		if traversal.errorCode is not None or not traversal.nodes:
			self._activeLifecycle = lifecycle.fail()
			raise RuntimeError(traversal.errorCode or "KS.CAPTURE.EMPTY")
		try:
			inspectionTargetKey = self._inspectionTargetKey(work, traversal)
		except RuntimeError as error:
			if str(error) != "KS.CAPTURE.CANCELLED":
				raise
			return self._cancelledResult(lifecycle, context, traversal)
		self._ensureCurrent(admission, lifecycle)
		lifecycle = lifecycle.advance(CaptureState.TRANSFORMING).advance(CaptureState.SCREENSHOT)
		self._activeLifecycle = lifecycle
		attempt = ScreenshotAttempt(
			self._screenshotAttemptIdFactory(),
			admission.generation,
			request.containingForeground,
			context,
		)
		screenshot = self._screenshot.captureScreenshot(attempt)
		if screenshot.attempt is not attempt:
			self._activeLifecycle = lifecycle.fail()
			raise RuntimeError("KS.CAPTURE.SCREENSHOT_ATTEMPT_MISMATCH")
		self._ensureCurrent(admission, lifecycle)
		lifecycle = lifecycle.advance(CaptureState.SERIALIZING)
		self._activeLifecycle = lifecycle
		_ = self._cooperate(work, started, force=True)
		if self._cancelRequested:
			return self._cancelledResult(lifecycle, context, traversal)
		try:
			snapshot, summary = self._documents(
				work,
				traversal,
				screenshot,
				started,
				customUiaMode=customUiaMode,
				progress=progress,
			)
		except RuntimeError as error:
			if str(error) != "KS.CAPTURE.CANCELLED":
				raise
			return self._cancelledResult(lifecycle, context, traversal)
		_ = self._cooperate(work, started, force=True)
		if self._cancelRequested:
			return self._cancelledResult(lifecycle, context, traversal)
		if progress is not None:
			progress(
				TraversalProgress(
					len(traversal.nodes),
					max(0, self._clock() - started),
					0,
					"packaging",
				),
			)
		bundle = (
			self._bundle(
				work,
				snapshot,
				screenshot,
				customUiaMode=customUiaMode,
				started=started,
				progress=progress,
			)
			if publish or packageForInspection
			else None
		)
		_ = self._cooperate(work, started, force=True)
		if self._cancelRequested:
			return self._cancelledResult(lifecycle, context, traversal)
		lifecycle = lifecycle.advance(CaptureState.STAGING)
		lifecycle = lifecycle.advance(CaptureState.VALIDATING).advance(CaptureState.READY_TO_COMMIT)
		self._activeLifecycle = lifecycle
		self._ensureCurrent(admission, lifecycle)
		lifecycle = lifecycle.beginCommit()
		self._activeLifecycle = lifecycle
		publication = None
		if publish:
			assert bundle is not None
			publication = self._output.publish(
				self._publicationPackage(
					bundle,
					snapshot,
					includeRootName=request.includeRootNameInOutput,
				),
				lifecycleGeneration=admission.generation,
				context=context,
				policy=PublicationPolicy(
					cancelled=False,
					secure=False,
					schemaValidated=True,
					privacyValidated=True,
					generationCurrent=self._lifecycleService.isCurrent(admission.generation),
				),
			)
		committed = not publish or (
			publication is not None
			and publication.outcome
			in (OutputCompletionOutcome.COMMITTED, OutputCompletionOutcome.COMMITTED_WITH_WARNING)
		)
		if committed:
			outcome = (
				CaptureState.COMPLETED_TRUNCATED
				if traversal.truncated
				else CaptureState.COMPLETED_PARTIAL_SCREENSHOT
				if screenshot.status != "value"
				else CaptureState.COMPLETED
			)
			lifecycle = lifecycle.finishCommit(outcome)
			if updateBaseline and request.targetKind == CaptureTargetKind.FOREGROUND:
				self._fullCaptureBaseline = cast(Snapshot, snapshot)
				self._fullCaptureBaselineRequest = request
		else:
			lifecycle = lifecycle.fail()
		self._activeLifecycle = lifecycle
		return CaptureResult(
			lifecycle,
			context,
			traversal,
			snapshot,
			summary,
			screenshot,
			publication,
			committed,
			None if committed else "KS.CAPTURE.PUBLICATION_FAILED",
			inspectionTargetKey,
			bundle,
		)
