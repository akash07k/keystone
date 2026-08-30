from __future__ import annotations

import json
import unittest
from dataclasses import dataclass, field, replace
from collections.abc import Callable
from types import SimpleNamespace
from typing import ClassVar, Protocol, cast
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.providers import common as commonProvider
from addon.globalPlugins.keystone.adapters.providers.custom_uia import (
	CustomUiaBudget,
	CustomUiaCaptureMode,
	CustomUiaProviderAdapter,
)
from addon.globalPlugins.keystone.adapters.providers.raw_uia import RawProjectionOutcome, RawUiaAdapter
from addon.globalPlugins.keystone.adapters.nvda import inspector_source as inspectorSourceModule
from addon.globalPlugins.keystone.adapters.nvda.inspector_source import (
	LiveInspectorSource,
	LiveSessionNodeReader,
	OfflineInspectorSource,
	SnapshotNodeReader,
)
from addon.globalPlugins.keystone.adapters.nvda.selected_objects import (
	SelectedObjectSession,
	SelectedTargetKind,
)
from addon.globalPlugins.keystone.application.inspector_service import (
	FollowFocusEvent,
	FollowFocusOutcome,
	InspectorCopyKind,
	InspectorEscape,
	InspectorRegion,
	InspectorService,
)
from addon.globalPlugins.keystone.domain.document_records import NodeStructure
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.evidence import (
	EvidenceEnvelope,
	PrivacyReference,
	Projection,
	Source,
)
from addon.globalPlugins.keystone.domain.inspector import (
	DEFAULT_PROPERTY_INTERVAL_MS,
	AnnotationRecord,
	AnnotationStatus,
	ChildState,
	FocusMatchCandidate,
	FocusMatchDecision,
	FocusMatchEvidence,
	FocusMatchLimits,
	InspectorSourceIdentity,
	InspectorSourceKind,
	NodeFacet,
	PaneCursor,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	QuickPropertyAction,
	StructuredPropertyNode,
	focusMatchLimits,
	matchInspectorTarget,
)
from addon.globalPlugins.keystone.domain.settings import (
	SettingId,
	SettingsSnapshot,
	validateCandidate,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy, ProtectionEvidence
from addon.globalPlugins.keystone.domain.projection import ProjectionBudget, ProjectionRequest
from addon.globalPlugins.keystone.domain.snapshot_bundle import SnapshotView
from addon.globalPlugins.keystone.domain.status import Confidence, EvidenceState, EvidenceValue
from addon.globalPlugins.keystone.ports.inspector import ChildFetch, PropertyFetch
from addon.globalPlugins.keystone.ports.providers import ProviderReadResult, ReadBudget

_SOURCE = Source("generic", "provider", "field")
_PROJECTION = Projection("normalNvda")
_PRIVACY = PrivacyReference("node", "public", "retain", 1)


def _envelope(state: EvidenceState, value: EvidenceValue | None = None) -> EvidenceEnvelope:
	return EvidenceEnvelope(
		status=state,
		value=value,
		source=_SOURCE,
		projection=_PROJECTION,
		confidence=Confidence.DIRECT,
		privacy=_PRIVACY,
	)


def _facet(
	nodeId: str,
	*,
	parent: str | None,
	depth: int,
	role: str,
	name: str = "",
	hint: bool = False,
) -> NodeFacet:
	return NodeFacet(
		nodeId=nodeId,
		parentId=parent,
		depth=depth,
		name=name,
		hasName=bool(name),
		role=role,
		childHint=hint,
	)


def _row(fieldKey: str, value: str) -> PropertyRow:
	return PropertyRow(
		fieldKey=fieldKey,
		name=fieldKey.capitalize(),
		status=PropertyStatus.VALUE,
		value=value,
	)


def _scalar(key: str, value: str) -> StructuredPropertyNode:
	return StructuredPropertyNode(key=key, label=key.capitalize(), status=PropertyStatus.VALUE, value=value)


def _container(key: str, *children: StructuredPropertyNode) -> StructuredPropertyNode:
	return StructuredPropertyNode(
		key=key,
		label=key.capitalize(),
		status=PropertyStatus.VALUE,
		children=children,
	)


def _noStrings() -> list[str]:
	return []


def _noCalls() -> list[tuple[str, PropertyCategory]]:
	return []


def _redactSecret(value: str) -> str:
	return value.replace("secret", "[redacted]")


class _AnnotationPane(Protocol):
	annotations: tuple[AnnotationRecord, ...]


class _AnnotationNavigation(Protocol):
	nodeId: str | None


@dataclass
class _FakeSource:
	"""A fake ``InspectorSource`` recording every read so branch-local fetching is provable."""

	identityValue: InspectorSourceIdentity
	rootFacets: tuple[NodeFacet, ...]
	childrenByNode: dict[str, ChildFetch]
	propertiesByNode: dict[tuple[str, PropertyCategory], PropertyFetch]
	childrenCalls: list[str] = field(default_factory=_noStrings)
	propertyCalls: list[tuple[str, PropertyCategory]] = field(default_factory=_noCalls)
	closed: bool = False

	def identity(self) -> InspectorSourceIdentity:
		return self.identityValue

	def roots(self) -> tuple[NodeFacet, ...]:
		return self.rootFacets

	def children(self, nodeId: str) -> ChildFetch:
		self.childrenCalls.append(nodeId)
		return self.childrenByNode.get(
			nodeId,
			ChildFetch(parentId=nodeId, state=ChildState.EMPTY, note="No children"),
		)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		self.propertyCalls.append((nodeId, category))
		return self.propertiesByNode.get(
			(nodeId, category),
			PropertyFetch(nodeId=nodeId, category=category),
		)

	def close(self) -> None:
		self.closed = True


def _liveIdentity(label: str = "Focus") -> InspectorSourceIdentity:
	return InspectorSourceIdentity(
		kind=InspectorSourceKind.LIVE,
		label=label,
		executable="app.exe",
		processId=4321,
		backend="UIA",
	)


def _spineSource(**props: PropertyFetch) -> _FakeSource:
	roots = (
		_facet("root", parent=None, depth=0, role="window", name="App"),
		_facet("mid", parent="root", depth=1, role="pane"),
		_facet("target", parent="mid", depth=2, role="button", name="OK", hint=True),
	)
	byNode: dict[tuple[str, PropertyCategory], PropertyFetch] = {
		("target", PropertyCategory.QUICK): PropertyFetch(
			nodeId="target",
			category=PropertyCategory.QUICK,
			rows=(_row("name", "OK"), _row("role", "button")),
		),
	}
	for pane in props.values():
		byNode[(pane.nodeId, pane.category)] = pane
	return _FakeSource(
		identityValue=_liveIdentity(),
		rootFacets=roots,
		childrenByNode={},
		propertiesByNode=byNode,
	)


def _discoveredNestedSource() -> _FakeSource:
	source = _spineSource()
	source.childrenByNode["target"] = ChildFetch(
		parentId="target",
		state=ChildState.LOADED,
		children=(_facet("branch", parent="target", depth=3, role="grouping", name="Branch"),),
	)
	source.childrenByNode["branch"] = ChildFetch(
		parentId="branch",
		state=ChildState.LOADED,
		children=(_facet("leaf", parent="branch", depth=4, role="text", name="Leaf"),),
	)
	return source


class InspectorSourceAndPaneTests(unittest.TestCase):
	def test_live_wide_branch_defers_zero_count_child_probes_until_expanded(self) -> None:
		class _Node:
			def __init__(
				self,
				name: str,
				*,
				children: tuple[object, ...] = (),
				firstChild: object | None = None,
			) -> None:
				super().__init__()
				self.name = name
				self.role = "list"
				self.children = children
				self.firstChild = firstChild
				self.childCount = len(children)
				self.isProtected = False
				self.processID = 7
				self.windowHandle = 70

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		class _CountingGetter:
			def __init__(self) -> None:
				super().__init__()
				self.childReads: list[tuple[str, str]] = []

			@staticmethod
			def readAttribute(
				target: object,
				member: str,
				budget: ReadBudget,
			) -> ProviderReadResult:
				return commonProvider.NvdaObjectGetter.readAttribute(target, member, budget)

			def readChildren(self, target: object, budget: ReadBudget) -> commonProvider.ObjectBatch:
				self.childReads.append(("ordinary", cast(_Node, target).name))
				return commonProvider.NvdaObjectGetter.readChildren(target, budget)

			def readLogicalFirstChild(
				self,
				target: object,
				budget: ReadBudget,
			) -> commonProvider.ObjectBatch:
				self.childReads.append(("logical", cast(_Node, target).name))
				return commonProvider.NvdaObjectGetter.readLogicalFirstChild(target, budget)

		logicalChild = _Node("Logical child")
		children = tuple(_Node(f"Child {index}") for index in range(20))
		children[-1].firstChild = logicalChild
		parent = _Node("Parent", children=children)
		getter = _CountingGetter()
		session = SelectedObjectSession(
			_SelectedSource(parent),
			generation=1,
			objectGetter=getter,
		)
		parentRef = session.retain(parent)
		reader = LiveSessionNodeReader(
			session,
			CorrelationFactory().admit(generation=1),
			_liveIdentity(),
			foregroundRef=parentRef,
			targetRef=parentRef,
			focusAncestorRefs=(),
			providerScope="nvda-selected",
			processScope="process-7",
			privacyPolicy=PrivacyPolicy(1, 1, False),
		)

		fetch = reader.children(parentRef)

		self.assertEqual(20, len(fetch.children))
		self.assertEqual([("ordinary", "Parent"), ("logical", "Parent")], getter.childReads)
		lastChild = fetch.children[-1]
		self.assertTrue(lastChild.childHint)

		logicalFetch = reader.children(lastChild.nodeId)

		self.assertEqual(["Logical child"], [child.name for child in logicalFetch.children])
		self.assertEqual(
			[
				("ordinary", "Parent"),
				("logical", "Parent"),
				("ordinary", "Child 19"),
				("logical", "Child 19"),
			],
			getter.childReads,
		)

	def test_raw_fallback_is_a_first_class_other_api_projection_row(self) -> None:
		class _Target:
			name = "Text editor"
			role = "document"
			states: tuple[object, ...] = ()
			isProtected = False
			children: tuple[object, ...] = ()
			firstChild = None
			processID = 9308
			windowHandle = 656034

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		class _FallbackRaw:
			def project(
				self,
				selectedTarget: object,
				targetKind: object,
				request: ProjectionRequest,
			) -> RawProjectionOutcome:
				_ = selectedTarget, targetKind
				return RawUiaAdapter._rejected(  # pyright: ignore[reportPrivateUsage]
					request,
					"KS.RAW_UIA.COM_FAILED",
				)

			@staticmethod
			def owns(nodeRef: str) -> bool:
				_ = nodeRef
				return False

			@staticmethod
			def close() -> None:
				pass

		target = _Target()
		request = ProjectionRequest.explicit("notepad-fallback", ProjectionBudget(8, 64, 500))
		session = SelectedObjectSession(
			_SelectedSource(target),
			generation=1,
			rawUia=cast(RawUiaAdapter, _FallbackRaw()),
		)
		reference = session.acquire("focus", rawRequest=request)
		reader = LiveSessionNodeReader(
			session,
			CorrelationFactory().admit(generation=1),
			_liveIdentity(),
			foregroundRef=reference.rootRef,
			targetRef=reference.rootRef,
			focusAncestorRefs=(),
			providerScope=reference.providerScope,
			processScope=reference.processScope,
			privacyPolicy=PrivacyPolicy(1, 1, True),
		)

		fetch = reader.properties(reference.rootRef, PropertyCategory.OTHER_API)
		projection = next(row for row in fetch.rows if row.fieldKey == "rawUia.projection")

		self.assertIs(PropertyStatus.VALUE, projection.status)
		assert projection.value is not None
		self.assertIn("requested, true", projection.value)
		self.assertIn("applied, false", projection.value)
		self.assertIn("status, rejected", projection.value)
		self.assertIn("method, none", projection.value)
		self.assertIn("evidenceQuality, incomplete", projection.value)

	def test_live_session_reads_facet_property_and_annotation_values(self) -> None:
		class _AnnotationTarget:
			role = "comment"
			summary = "Review live field"

			def __init__(self, targetObject: object) -> None:
				super().__init__()
				self.targetObject = targetObject

		class _Origin:
			roles = ("details",)

			def __init__(self, target: object) -> None:
				super().__init__()
				self.targets = (_AnnotationTarget(target),)

			def __bool__(self) -> bool:
				return True

		class _Target:
			name = "Live field"
			role = "edit"
			states: tuple[object, ...] = ()
			isProtected = False
			children: tuple[object, ...] = ()
			firstChild = None
			processID = 7
			windowHandle = 70

			def __init__(self) -> None:
				super().__init__()
				self.annotations = _Origin(self)

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		target = _Target()
		session = SelectedObjectSession(_SelectedSource(target), generation=1)
		targetRef = session.retain(target)
		context = CorrelationFactory().admit(generation=1)
		reader = LiveSessionNodeReader(
			session,
			context,
			_liveIdentity(),
			foregroundRef=targetRef,
			targetRef=targetRef,
			focusAncestorRefs=(),
			providerScope="nvda-selected",
			processScope="process-7",
			privacyPolicy=PrivacyPolicy(1, 1, True),
		)

		(facet,) = reader.roots()
		self.assertEqual("Live field", facet.name)
		properties = reader.properties(targetRef, PropertyCategory.CORE)
		name = next(row for row in properties.rows if row.fieldKey == "name")
		self.assertIs(PropertyStatus.VALUE, name.status)
		self.assertEqual("Live field", name.value)
		providerMetadata = commonProvider.encodeProviderSections(
			(
				commonProvider.ProviderSectionData(
					"ia2Msaa",
					ProviderReadResult("value", "available"),
					properties=(
						commonProvider.ProviderDatum("ia2.role", ProviderReadResult("value", "editable")),
					),
				),
			),
		)
		with patch.object(
			reader,
			"_providerMetadata",
			return_value=ProviderReadResult("value", providerMetadata),
		):
			providerRows = reader.properties(targetRef, PropertyCategory.IA2_MSAA)
		(providerRow,) = providerRows.rows
		self.assertIs(PropertyStatus.VALUE, providerRow.status)
		self.assertEqual("editable", providerRow.value)
		(record,) = reader.annotations(targetRef)

		self.assertEqual("Review live field", record.summary)
		self.assertTrue(record.targetIdentityProven)
		self.assertEqual(targetRef, record.targetNodeId)

	def test_annotations_load_only_on_selection_and_preserve_nested_records(self) -> None:
		records = (
			AnnotationRecord(
				key="comment",
				status=AnnotationStatus.VALUE,
				typeName="Comment",
				source="NVDA annotations",
				summary="Review this field",
				targetName="App",
				targetRole="window",
				targetIdentity="node=root",
				targetNodeId="root",
				targetIdentityProven=True,
				relationship="details",
				related=(
					AnnotationRecord(
						key="reply",
						status=AnnotationStatus.VALUE,
						typeName="Comment reply",
						source="NVDA annotations",
						summary="Resolved",
					),
				),
			),
		)

		class _AnnotationSource(_FakeSource):
			def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
				return records if nodeId == "target" else ()

		base = _spineSource()
		source = _AnnotationSource(
			base.identityValue,
			base.rootFacets,
			base.childrenByNode,
			base.propertiesByNode,
		)
		service = InspectorService()
		service.openSource(source)
		self.assertEqual(
			(),
			cast(_AnnotationPane, service.pane(PropertyCategory.ANNOTATIONS)).annotations,
		)

		pane = cast(_AnnotationPane, service.selectCategory(PropertyCategory.ANNOTATIONS))

		self.assertEqual(records, pane.annotations)
		self.assertTrue(pane.annotations[0].canNavigate)
		navigate = cast(
			Callable[[str], _AnnotationNavigation],
			getattr(service, "navigateAnnotationTarget"),
		)
		self.assertEqual("root", navigate("comment").nodeId)
		self.assertEqual("root", service.selectedNodeId)

	def test_annotation_collector_preserves_status_nesting_and_privacy(self) -> None:
		collector = cast(
			Callable[..., tuple[AnnotationRecord, ...]],
			getattr(commonProvider, "collectAnnotations"),
		)

		class _Target:
			name = "secret target"
			role = "button"
			annotations: object | None = None

		class _AnnotationTarget:
			role = "comment"
			summary = "secret summary"
			targetObject = _Target()

		class _Origin:
			targets = (_AnnotationTarget(),)
			roles = ("details",)

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()

		records = collector(
			_Source(),
			ReadBudget(maximumItems=20, maximumTextLength=200, maximumMilliseconds=100),
			privacyTransform=_redactSecret,
		)
		self.assertEqual(1, len(records))
		self.assertIs(AnnotationStatus.VALUE, records[0].status)
		self.assertEqual("[redacted] summary", records[0].summary)
		self.assertEqual("[redacted] target", records[0].targetName)

		unsupported = collector(
			object(),
			ReadBudget(maximumItems=20, maximumTextLength=200, maximumMilliseconds=100),
			privacyTransform=str,
		)
		self.assertIs(AnnotationStatus.UNSUPPORTED, unsupported[0].status)

	def test_nested_sibling_annotations_receive_globally_unique_path_keys(self) -> None:
		class _Leaf:
			name = "Leaf"
			role = "note"

		class _Parent:
			name = "Parent"
			role = "grouping"

			def __init__(self, leaf: object) -> None:
				super().__init__()
				self.detailsRelations = (leaf,)

		class _AnnotationTarget:
			role = "comment"
			summary = "Nested"

			def __init__(self, target: object) -> None:
				super().__init__()
				self.targetObject = target

		class _Origin:
			roles = ("details", "details")

			def __init__(self) -> None:
				super().__init__()
				self.targets = (
					_AnnotationTarget(_Parent(_Leaf())),
					_AnnotationTarget(_Parent(_Leaf())),
				)

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()

		records = commonProvider.collectAnnotations(
			_Source(),
			ReadBudget(maximumItems=20, maximumTextLength=200, maximumMilliseconds=100),
			privacyTransform=str,
		)

		def keys(items: tuple[AnnotationRecord, ...]) -> tuple[str, ...]:
			return tuple(key for record in items for key in (record.key, *keys(record.related)))

		allKeys = keys(records)
		self.assertEqual(len(allKeys), len(set(allKeys)))
		self.assertTrue(all("/" in child.key for record in records for child in record.related))

	def test_annotation_text_is_trimmed_collapsed_and_marked_when_truncated(self) -> None:
		class _Target:
			name = " Target \n name "
			role = " comment "

		class _AnnotationTarget:
			role = " Comment \n thread "
			summary = " abcdefghijklmnop "
			targetObject = _Target()

		class _Origin:
			targets = (_AnnotationTarget(),)
			roles = (" details ",)

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()

		(record,) = commonProvider.collectAnnotations(
			_Source(),
			ReadBudget(maximumItems=20, maximumTextLength=8, maximumMilliseconds=100),
			privacyTransform=str,
		)

		self.assertIs(AnnotationStatus.VALUE, record.status)
		self.assertEqual("Comme...", record.typeName)
		self.assertEqual("abcde...", record.summary)
		self.assertEqual("Targe...", record.targetName)
		self.assertEqual("details", record.relationship)

	def test_live_annotation_failure_degrades_to_an_explicit_failed_record(self) -> None:
		class _Target:
			name = "Live field"
			role = "edit"
			states: tuple[object, ...] = ()
			isProtected = False
			children: tuple[object, ...] = ()
			firstChild = None
			processID = 7
			windowHandle = 70

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		target = _Target()
		session = SelectedObjectSession(_SelectedSource(target), generation=1)
		targetRef = session.retain(target)
		diagnostics: list[str] = []
		reader = LiveSessionNodeReader(
			session,
			CorrelationFactory().admit(generation=1),
			_liveIdentity(),
			foregroundRef=targetRef,
			targetRef=targetRef,
			focusAncestorRefs=(),
			providerScope="nvda-selected",
			processScope="process-7",
			privacyPolicy=PrivacyPolicy(1, 1, True),
			diagnostic=diagnostics.append,
		)

		with patch.object(inspectorSourceModule, "collectAnnotations", side_effect=ValueError("bad text")):
			(record,) = reader.annotations(targetRef)

		self.assertIs(AnnotationStatus.FAILED, record.status)
		self.assertEqual("Annotations", record.typeName)
		assert record.errorRef is not None
		self.assertEqual("KS.ANNOTATION.CONVERSION_FAILED", record.errorRef.code)
		self.assertTrue(record.errorRef.diagnosticId.startswith("annotation-conversion-"))
		self.assertNotIn("bad text", "\n".join(diagnostics))
		self.assertIn(record.errorRef.diagnosticId, "\n".join(diagnostics))

	def test_live_annotations_include_uia_text_range_types(self) -> None:
		class _Range:
			def getAttributeValue(self, _attribute: int) -> tuple[int, int]:
				return (60001, 60002)

		class _Target:
			name = "Word document"
			role = "document"
			UIAElement = object()
			states: tuple[object, ...] = ()
			isProtected = False
			children: tuple[object, ...] = ()
			firstChild = None
			processID = 7
			windowHandle = 70

			@staticmethod
			def makeTextInfo(_position: object) -> object:
				return type("_Info", (), {"_rangeObj": _Range()})()

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		target = _Target()
		session = SelectedObjectSession(_SelectedSource(target), generation=1)
		targetRef = session.retain(target)
		reader = LiveSessionNodeReader(
			session,
			CorrelationFactory().admit(generation=1),
			_liveIdentity(),
			foregroundRef=targetRef,
			targetRef=targetRef,
			focusAncestorRefs=(),
			providerScope="nvda-selected",
			processScope="process-7",
			privacyPolicy=PrivacyPolicy(1, 1, False),
		)
		textInfos = type("_TextInfos", (), {"POSITION_CARET": "caret"})()
		uia = type("_Uia", (), {"UIA_AnnotationTypesAttributeId": 40031})()

		def importTextRangeModule(name: str) -> object:
			return textInfos if name == "textInfos" else uia

		with (
			patch.object(inspectorSourceModule, "collectAnnotations", return_value=()),
			patch.object(
				inspectorSourceModule,
				"import_module",
				side_effect=importTextRangeModule,
			),
		):
			records = reader.annotations(targetRef)

		self.assertEqual(("60001", "60002"), tuple(record.typeId for record in records))
		self.assertTrue(all(record.source == "UIA text range" for record in records))

	def test_text_range_annotations_collect_spelling_comment_metadata_and_custom_types(self) -> None:
		class _Array:
			length = 1
			testCase: ClassVar[unittest.TestCase]

			def QueryInterface(self, _interface: object) -> object:
				return self

			def getElement(self, index: int) -> object:
				self.testCase.assertEqual(0, index)
				return _Element()

		class _Element:
			@staticmethod
			def GetCurrentPropertyValue(propertyId: int) -> object:
				return {
					30001: 60001,
					30002: "Review this paragraph",
					30003: "Reviewer",
					30004: "2026-08-01",
				}[propertyId]

		class _Range:
			def __init__(self, kind: str, character: bool = False) -> None:
				super().__init__()
				self.kind = kind
				self.character = character

			def getAttributeValue(self, attribute: int) -> object:
				if attribute == 40031:
					if self.kind == "caret":
						return (60002,) if self.character else ()
					return (60001, 71000)
				if attribute == 40032 and self.kind == "selection":
					return _Array()
				return None

		class _Info:
			testCase: ClassVar[unittest.TestCase]

			def __init__(self, kind: str, character: bool = False) -> None:
				super().__init__()
				self.kind = kind
				self._rangeObj = _Range(kind, character)
				self.text = "mispelled" if kind == "caret" and character else ""

			def copy(self) -> object:
				return _Info(self.kind)

			def expand(self, unit: object) -> None:
				self.testCase.assertEqual("character", unit)
				self._rangeObj.character = True
				self.text = "mispelled" if self.kind == "caret" else ""

		class _Target:
			UIAElement = object()

			@staticmethod
			def makeTextInfo(position: object) -> object:
				return _Info(str(position))

		_Array.testCase = self
		_Info.testCase = self
		textInfos = type(
			"_TextInfos",
			(),
			{
				"POSITION_CARET": "caret",
				"POSITION_SELECTION": "selection",
				"UNIT_CHARACTER": "character",
			},
		)()
		uia = type(
			"_Uia",
			(),
			{
				"UIA_AnnotationTypesAttributeId": 40031,
				"UIA_AnnotationObjectsAttributeId": 40032,
				"IUIAutomationElementArray": object(),
				"UIA_AnnotationAnnotationTypeIdPropertyId": 30001,
				"UIA_NamePropertyId": 30002,
				"UIA_AnnotationAuthorPropertyId": 30003,
				"UIA_AnnotationDateTimePropertyId": 30004,
				"AnnotationType_Comment": 60001,
				"AnnotationType_SpellingError": 60002,
			},
		)()

		def importAnnotationModule(name: str) -> object:
			return textInfos if name == "textInfos" else uia

		with patch.object(
			inspectorSourceModule,
			"import_module",
			side_effect=importAnnotationModule,
		):
			textRangeAnnotations = cast(
				Callable[[object, ReadBudget, Callable[[str], str]], tuple[AnnotationRecord, ...]],
				getattr(inspectorSourceModule, "_textRangeAnnotations"),
			)
			records = textRangeAnnotations(
				_Target(),
				ReadBudget(8, 100, 100),
				lambda text: text,
			)

		commentRecords = [record for record in records if record.typeId == "60001"]
		self.assertEqual(1, len(commentRecords))
		self.assertEqual("Review this paragraph", commentRecords[0].summary)
		self.assertEqual("Reviewer", commentRecords[0].author)
		self.assertEqual("2026-08-01", commentRecords[0].dateTime)
		spelling = next(record for record in records if record.typeId == "60002")
		self.assertEqual("Spelling error", spelling.typeName)
		self.assertEqual("mispelled", spelling.summary)
		custom = next(record for record in records if record.typeId == "71000")
		self.assertEqual("Custom UIA annotation", custom.typeName)
		self.assertFalse(any(record.status is AnnotationStatus.TRUNCATED for record in records))

	def test_text_range_annotation_caps_append_one_truncation_marker(self) -> None:
		class _Element:
			def __init__(self, typeId: int) -> None:
				super().__init__()
				self._typeId = typeId

			def GetCurrentPropertyValue(self, propertyId: int) -> object:
				return {
					30001: self._typeId,
					30002: "secret object",
					30003: None,
					30004: None,
				}[propertyId]

		class _Array:
			def __init__(self, elements: tuple[_Element, ...]) -> None:
				super().__init__()
				self._elements = elements

			@property
			def length(self) -> int:
				return len(self._elements)

			def QueryInterface(self, _interface: object) -> object:
				return self

			def getElement(self, index: int) -> object:
				return self._elements[index]

		class _Range:
			def __init__(self, typeIds: tuple[int, ...], elements: tuple[_Element, ...]) -> None:
				super().__init__()
				self._typeIds = typeIds
				self._elements = elements

			def getAttributeValue(self, attribute: int) -> object:
				if attribute == 40031:
					return self._typeIds
				if attribute == 40032 and self._elements:
					return _Array(self._elements)
				return None

		class _Info:
			text = "secret text"

			def __init__(self, annotationRange: _Range) -> None:
				super().__init__()
				self._rangeObj = annotationRange

			def copy(self) -> object:
				raise NotImplementedError

		class _Target:
			UIAElement = object()

			def __init__(self, ranges: dict[str, _Range]) -> None:
				super().__init__()
				self._ranges = ranges

			def makeTextInfo(self, position: object) -> object:
				return _Info(self._ranges[str(position)])

		textInfos = type(
			"_TextInfos",
			(),
			{
				"POSITION_CARET": "caret",
				"POSITION_SELECTION": "selection",
				"UNIT_CHARACTER": "character",
			},
		)()
		uia = type(
			"_Uia",
			(),
			{
				"UIA_AnnotationTypesAttributeId": 40031,
				"UIA_AnnotationObjectsAttributeId": 40032,
				"IUIAutomationElementArray": object(),
				"UIA_AnnotationAnnotationTypeIdPropertyId": 30001,
				"UIA_NamePropertyId": 30002,
				"UIA_AnnotationAuthorPropertyId": 30003,
				"UIA_AnnotationDateTimePropertyId": 30004,
			},
		)()

		def collectRanges(caret: _Range, selection: _Range) -> tuple[AnnotationRecord, ...]:
			def importAnnotationModule(name: str) -> object:
				return textInfos if name == "textInfos" else uia

			with patch.object(
				inspectorSourceModule,
				"import_module",
				side_effect=importAnnotationModule,
			):
				textRangeAnnotations = cast(
					Callable[[object, ReadBudget, Callable[[str], str]], tuple[AnnotationRecord, ...]],
					getattr(inspectorSourceModule, "_textRangeAnnotations"),
				)
				return textRangeAnnotations(
					_Target({"caret": caret, "selection": selection}),
					ReadBudget(2, 100, 100),
					lambda text: text.replace("secret", "[redacted]"),
				)

		for name, records, retainedTypeId in (
			(
				"annotation object cap",
				collectRanges(
					_Range((), (_Element(1), _Element(2), _Element(3))),
					_Range((), ()),
				),
				"1",
			),
			(
				"annotation type cap",
				collectRanges(_Range((1, 2, 3), ()), _Range((), ())),
				"1",
			),
			(
				"deduplication cap",
				collectRanges(_Range((1, 2), ()), _Range((3, 4), ())),
				"1",
			),
		):
			with self.subTest(cap=name):
				markers = [record for record in records if record.status is AnnotationStatus.TRUNCATED]
				self.assertEqual(1, len(markers))
				self.assertIs(markers[0], records[-1])
				self.assertEqual(
					("uia-text-annotations-truncated", "UIA text annotations", "UIA text range"),
					(markers[0].key, markers[0].typeName, markers[0].source),
				)
				self.assertEqual(
					(AnnotationStatus.VALUE, AnnotationStatus.TRUNCATED),
					tuple(record.status for record in records),
				)
				self.assertEqual(retainedTypeId, records[0].typeId)
				if name == "annotation object cap":
					self.assertEqual("[redacted] object", records[0].summary)
				else:
					self.assertEqual("[redacted] text", records[0].summary)

	def test_live_inspector_includes_registered_custom_uia_values(self) -> None:
		class _CustomUia:
			testCase: ClassVar[unittest.TestCase]

			def __init__(self) -> None:
				super().__init__()
				self.policies: list[PrivacyPolicy] = []
				self.modes: list[CustomUiaCaptureMode] = []

			def collectCustomUia(
				self,
				_target: object,
				*,
				mode: CustomUiaCaptureMode,
				captureSessionId: str,
				providerProcessId: int,
				budget: CustomUiaBudget,
				privacyPolicy: PrivacyPolicy,
				protection: ProtectionEvidence,
			) -> commonProvider.ProviderSectionData:
				self.policies.append(privacyPolicy)
				self.modes.append(mode)
				self.testCase.assertTrue(captureSessionId.startswith("inspector-1-selected-1"))
				self.testCase.assertEqual(7, providerProcessId)
				self.testCase.assertIsNotNone(budget)
				self.testCase.assertIsNotNone(protection)
				return commonProvider.ProviderSectionData(
					"customUia",
					ProviderReadResult("value", "available"),
					properties=(
						commonProvider.ProviderDatum(
							"potentialProperties",
							ProviderReadResult("value", ("internal candidate data",)),
						),
						commonProvider.ProviderDatum(
							"known.word.editor.registration",
							ProviderReadResult(
								"value",
								(
									("displayName", "View type"),
									("enumValues", ((9, "ViewNormal"),)),
								),
							),
						),
						commonProvider.ProviderDatum(
							"known.word.editor.current",
							ProviderReadResult(
								"value",
								(
									("status", "value"),
									("value", 9),
								),
							),
						),
					),
				)

		class _Target:
			name = "Word document"
			role = "document"
			states: tuple[object, ...] = ()
			isProtected = False
			children: tuple[object, ...] = ()
			firstChild = None
			processID = 7
			windowHandle = 70

		class _SelectedSource:
			def __init__(self, target: object) -> None:
				super().__init__()
				self.target = target

			def selectedObject(self, targetKind: SelectedTargetKind) -> object:
				_ = targetKind
				return self.target

		customUia = _CustomUia()
		_CustomUia.testCase = self
		target = _Target()
		session = SelectedObjectSession(
			_SelectedSource(target),
			generation=1,
			customUia=cast(CustomUiaProviderAdapter, customUia),
		)
		targetRef = session.retain(target)
		reader = LiveSessionNodeReader(
			session,
			CorrelationFactory().admit(generation=1),
			_liveIdentity(),
			foregroundRef=targetRef,
			targetRef=targetRef,
			focusAncestorRefs=(),
			providerScope="nvda-selected",
			processScope="process-7",
			privacyPolicy=PrivacyPolicy(3, 3, False),
		)

		result = reader.properties(targetRef, PropertyCategory.UIA)

		customRow = next(row for row in result.rows if row.fieldKey == "customUia.known.word.editor.current")
		self.assertEqual("View type", customRow.name)
		self.assertEqual("ViewNormal (9)", customRow.value)
		self.assertEqual(
			["customUia.known.word.editor.current"],
			[row.fieldKey for row in result.rows if row.fieldKey.startswith("customUia.")],
		)
		self.assertTrue(customUia.policies)
		self.assertTrue(all(policy == PrivacyPolicy(3, 3, False) for policy in customUia.policies))
		self.assertTrue(customUia.modes)
		self.assertTrue(all(mode is CustomUiaCaptureMode.NORMAL for mode in customUia.modes))

	def test_live_custom_uia_uses_display_name_from_definition_metadata(self) -> None:
		renderConfiguredRows = cast(
			Callable[
				[tuple[tuple[str, ProviderReadResult], ...]],
				tuple[PropertyRow, ...],
			],
			getattr(LiveSessionNodeReader, "_configuredCustomUiaRows"),
		)
		rows = renderConfiguredRows(
			(
				(
					"known.custom-f065.definition",
					ProviderReadResult(
						"value",
						(
							"custom-f065",
							"{F065-0000-0000-0000-000000000000}",
							"Readable custom property",
							((1, "ViewSlide"),),
						),
					),
				),
				(
					"known.custom-f065.current",
					ProviderReadResult("value", (("status", "value"), ("value", 1))),
				),
			),
		)

		self.assertEqual(1, len(rows))
		self.assertEqual("Readable custom property", rows[0].name)
		self.assertEqual("ViewSlide (1)", rows[0].value)

	def test_same_source_retarget_preserves_loaded_hierarchy_and_pane_state(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			"target",
			ChildState.LOADED,
			(_facet("old-child", parent="target", depth=3, role="text", name="Old"),),
		)
		source.propertiesByNode[("new-target", PropertyCategory.CORE)] = PropertyFetch(
			"new-target",
			PropertyCategory.CORE,
			(_row("states", "focused"),),
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.expand("target")
		_ = service.selectCategory(PropertyCategory.CORE)
		service.setCursor(PropertyCategory.CORE, PaneCursor(selectedFieldKey="states", topIndex=3))
		generation = service.sourceGeneration

		applied = service.retargetWithinSource(
			(
				_facet("root", parent=None, depth=0, role="window", name="App"),
				_facet("mid", parent="root", depth=1, role="pane"),
				_facet("new-target", parent="mid", depth=2, role="edit", name="Search"),
			),
		)

		self.assertTrue(applied)
		self.assertEqual(generation, service.sourceGeneration)
		self.assertFalse(source.closed)
		self.assertEqual("new-target", service.selectedNodeId)
		self.assertIn("old-child", {row.nodeId for row in service.hierarchy()})
		self.assertIn("new-target", {row.nodeId for row in service.hierarchy()})
		self.assertEqual("states", service.cursor(PropertyCategory.CORE).selectedFieldKey)
		self.assertIn(("new-target", PropertyCategory.CORE), source.propertyCalls)

	def test_initial_hierarchy_shows_only_target_and_ancestors_without_fetching_children(self) -> None:
		source = _spineSource()
		service = InspectorService()
		service.openSource(source)

		rows = service.hierarchy()
		self.assertEqual([row.nodeId for row in rows], ["root", "mid", "target"])
		self.assertEqual(service.selectedNodeId, "target")
		self.assertTrue(rows[-1].selected)
		self.assertEqual(source.childrenCalls, [])

	def test_expanding_a_node_reads_only_that_branch_once(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(
				_facet("child-a", parent="target", depth=3, role="text", name="A"),
				_facet("child-b", parent="target", depth=3, role="text", name="B"),
			),
		)
		service = InspectorService()
		service.openSource(source)

		state = service.expand("target")
		self.assertIs(state, ChildState.LOADED)
		self.assertEqual(source.childrenCalls, ["target"])
		self.assertEqual(
			[row.nodeId for row in service.hierarchy()],
			["root", "mid", "target", "child-a", "child-b"],
		)

		_ = service.expand("target")
		self.assertEqual(source.childrenCalls, ["target"], "a loaded branch is never re-read")

	def test_hierarchy_subtree_rejects_children_when_its_source_generation_changes(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(_facet("child", parent="target", depth=3, role="text", name="Child"),),
		)
		service = InspectorService()
		service.openSource(source)
		children = source.children

		def changeGeneration(nodeId: str) -> ChildFetch:
			fetch = children(nodeId)
			setattr(service, "_sourceGeneration", service.sourceGeneration + 1)
			return fetch

		with patch.object(source, "children", side_effect=changeGeneration):
			self.assertEqual((), service.hierarchySubtree("target"))

		self.assertIs(service.childState("target"), ChildState.HINT)
		self.assertNotIn("child", {row.nodeId for row in service.hierarchy()})

	def test_complete_node_text_rejects_properties_when_its_source_generation_changes(self) -> None:
		source = _spineSource()
		service = InspectorService()
		service.openSource(source)
		properties = source.properties
		changed = False

		def changeGeneration(nodeId: str, category: PropertyCategory) -> PropertyFetch:
			nonlocal changed
			fetch = properties(nodeId, category)
			if not changed:
				changed = True
				setattr(service, "_sourceGeneration", service.sourceGeneration + 1)
			return fetch

		callsBefore = len(source.propertyCalls)
		with patch.object(source, "properties", side_effect=changeGeneration):
			self.assertEqual("", service.completeNodeText("target"))

		self.assertEqual(callsBefore + 1, len(source.propertyCalls))

	def test_expand_rejects_children_when_its_source_generation_changes(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(_facet("child", parent="target", depth=3, role="text", name="Child"),),
		)
		service = InspectorService()
		service.openSource(source)
		children = source.children

		def changeGeneration(nodeId: str) -> ChildFetch:
			fetch = children(nodeId)
			setattr(service, "_sourceGeneration", service.sourceGeneration + 1)
			return fetch

		with patch.object(source, "children", side_effect=changeGeneration):
			self.assertIs(service.expand("target"), ChildState.HINT)

		self.assertNotIn("child", {row.nodeId for row in service.hierarchy()})

	def test_child_enumeration_states_stay_distinct(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(
				_facet("loaded", parent="target", depth=3, role="list", hint=True),
				_facet("empty", parent="target", depth=3, role="list", hint=True),
				_facet("failed", parent="target", depth=3, role="list", hint=True),
				_facet("cut", parent="target", depth=3, role="list", hint=True),
				_facet("cancelled", parent="target", depth=3, role="list", hint=True),
				_facet("rejected", parent="target", depth=3, role="list", hint=True),
			),
		)
		source.childrenByNode["loaded"] = ChildFetch(
			parentId="loaded",
			state=ChildState.LOADED,
			children=(_facet("leaf", parent="loaded", depth=4, role="text", name="Leaf"),),
		)
		source.childrenByNode["empty"] = ChildFetch(
			parentId="empty",
			state=ChildState.EMPTY,
			note="No children",
		)
		source.childrenByNode["failed"] = ChildFetch(
			parentId="failed",
			state=ChildState.FAILED,
			note="Children unavailable",
		)
		source.childrenByNode["cut"] = ChildFetch(
			parentId="cut",
			state=ChildState.TRUNCATED,
			children=(_facet("partial", parent="cut", depth=4, role="text", name="Partial"),),
			note="Some children were not captured",
		)
		source.childrenByNode["cancelled"] = ChildFetch(
			parentId="cancelled",
			state=ChildState.CANCELLED,
			note="Child load cancelled",
		)
		source.childrenByNode["rejected"] = ChildFetch(
			parentId="rejected",
			state=ChildState.REJECTED,
			note="Child load rejected",
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.expand("target")

		self.assertIs(service.expand("loaded"), ChildState.LOADED)
		self.assertIs(service.expand("empty"), ChildState.EMPTY)
		self.assertIs(service.expand("failed"), ChildState.FAILED)
		self.assertIs(service.expand("cut"), ChildState.TRUNCATED)
		self.assertIs(service.expand("cancelled"), ChildState.CANCELLED)
		self.assertIs(service.expand("rejected"), ChildState.REJECTED)
		self.assertFalse(next(row for row in service.hierarchy() if row.nodeId == "empty").node.hasExpander)

		_ = service.expand("loaded")
		_ = service.expand("empty")
		_ = service.hierarchySubtree("empty")
		for nodeId, state in (
			("failed", ChildState.FAILED),
			("cut", ChildState.TRUNCATED),
			("cancelled", ChildState.CANCELLED),
			("rejected", ChildState.REJECTED),
		):
			with self.subTest(nodeId=nodeId):
				self.assertIs(service.expand(nodeId), state)

		self.assertEqual(source.childrenCalls.count("loaded"), 1)
		self.assertEqual(source.childrenCalls.count("empty"), 1)
		self.assertEqual(source.childrenCalls.count("failed"), 2)
		self.assertEqual(source.childrenCalls.count("cut"), 2)
		self.assertEqual(source.childrenCalls.count("cancelled"), 2)
		self.assertEqual(source.childrenCalls.count("rejected"), 2)

	def test_ten_panes_retain_independent_cursor_and_scroll(self) -> None:
		source = _spineSource(
			core=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.CORE,
				rows=(_row("role", "button"), _row("states", "focusable")),
			),
		)
		service = InspectorService()
		service.openSource(source)

		service.setCursor(
			PropertyCategory.QUICK,
			PaneCursor(selectedFieldKey="name", topIndex=2, horizontalOffset=5),
		)
		_ = service.selectCategory(PropertyCategory.CORE)
		service.setCursor(PropertyCategory.CORE, PaneCursor(selectedFieldKey="states", topIndex=7))

		quick = service.selectCategory(PropertyCategory.QUICK).cursor
		core = service.cursor(PropertyCategory.CORE)
		self.assertEqual((quick.selectedFieldKey, quick.topIndex, quick.horizontalOffset), ("name", 2, 5))
		self.assertEqual((core.selectedFieldKey, core.topIndex), ("states", 7))

	def test_inactive_pane_stays_stale_until_its_tab_reloads(self) -> None:
		source = _spineSource(
			core=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.CORE,
				rows=(_row("role", "button"),),
			),
		)
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(_facet("child-a", parent="target", depth=3, role="text", name="A"),),
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.selectCategory(PropertyCategory.CORE)
		_ = service.selectCategory(PropertyCategory.QUICK)
		_ = service.expand("target")

		service.selectNode("child-a")

		stale = service.pane(PropertyCategory.CORE)
		fresh = service.pane(PropertyCategory.QUICK)
		self.assertEqual(stale.nodeId, "target")
		self.assertTrue(stale.stale)
		self.assertEqual(fresh.nodeId, "child-a")
		self.assertFalse(fresh.stale)

	def test_offline_capture_bundle_is_inspected_through_the_same_service(self) -> None:
		view = _FakeSnapshotView(
			captureRoots=("root",),
			captureNodes=(
				_FakeNode(
					key="root",
					structure=NodeStructure(
						parentKey=None,
						depth=0,
						childKeys=("target",),
						cycleDetected=False,
						truncated=False,
						childFetchFailed=False,
					),
					fields=(
						("name", _envelope(EvidenceState.VALUE, "Application")),
						("role", _envelope(EvidenceState.VALUE, "window")),
					),
				),
				_FakeNode(
					key="target",
					structure=NodeStructure(
						parentKey="root",
						depth=1,
						childKeys=(),
						cycleDetected=False,
						truncated=False,
						childFetchFailed=False,
					),
					fields=(
						("name", _envelope(EvidenceState.VALUE, "Submit")),
						("role", _envelope(EvidenceState.VALUE, "button")),
						("states", _envelope(EvidenceState.EMPTY)),
					),
				),
			),
			annotationRecords=(
				AnnotationRecord(
					key="offline-comment",
					status=AnnotationStatus.VALUE,
					typeName="Comment",
					source="capture bundle",
					summary="Stored annotation",
				),
			),
		)
		source = OfflineInspectorSource(cast(SnapshotView, view), "target", label="capture.keystone")
		service = InspectorService()
		service.openSource(source)

		self.assertIs(source.identity().kind, InspectorSourceKind.OFFLINE)
		self.assertEqual([row.nodeId for row in service.hierarchy()], ["root", "target"])
		core = service.selectCategory(PropertyCategory.CORE)
		rendered = {row.fieldKey: (row.status, row.value) for row in core.rows}
		self.assertEqual(rendered["name"], (PropertyStatus.VALUE, "Submit"))
		self.assertEqual(rendered["role"], (PropertyStatus.VALUE, "button"))
		self.assertEqual(rendered["states"][0], PropertyStatus.EMPTY)
		self.assertIs(service.expand("target"), ChildState.EMPTY)
		annotations = service.selectCategory(PropertyCategory.ANNOTATIONS)
		self.assertEqual("Stored annotation", annotations.annotations[0].summary)
		copied = service.completeNodeText("target")
		self.assertIn("Annotations:", copied)
		self.assertIn("Stored annotation", copied)
		self.assertIn("Source: capture bundle", copied)

	def test_offline_hierarchy_uses_uia_display_fields_when_core_fields_are_empty(self) -> None:
		def uiaSection(name: str, role: str) -> object:
			return SimpleNamespace(
				status=_envelope(EvidenceState.VALUE, "available"),
				identity=_envelope(EvidenceState.VALUE, ()),
				properties=_envelope(
					EvidenceState.VALUE,
					(
						("Name", "value", ("value", name), ("noError",), False),
						("LocalizedControlType", "value", ("value", role), ("noError",), False),
						("AccessKey", "value", ("value", ""), ("noError",), False),
					),
				),
			)

		def customUiaSection() -> object:
			return SimpleNamespace(
				status=_envelope(EvidenceState.VALUE, "available"),
				identity=_envelope(
					EvidenceState.VALUE,
					(
						(
							"known.custom-f065.definition",
							"value",
							(
								"value",
								(
									"custom-f065",
									"{F065-0000-0000-0000-000000000000}",
								),
							),
							("noError",),
							False,
						),
					),
				),
				properties=_envelope(
					EvidenceState.VALUE,
					(
						(
							"known.custom-f065.current",
							"value",
							("value", (("status", "value"), ("value", 1))),
							("noError",),
							False,
						),
					),
				),
			)

		view = _FakeSnapshotView(
			captureRoots=("root",),
			captureNodes=(
				_FakeNode(
					key="root",
					structure=NodeStructure(None, 0, ("dock",), False, False, False),
					fields=(
						("name", _envelope(EvidenceState.VALUE, "Presentation1 - PowerPoint")),
						("role", _envelope(EvidenceState.VALUE, "window")),
					),
				),
				_FakeNode(
					key="dock",
					structure=NodeStructure("root", 1, ("workspace",), False, False, False),
					fields=(
						("name", _envelope(EvidenceState.EMPTY)),
						("role", _envelope(EvidenceState.EMPTY)),
					),
					providers=_FakeProviderSections((("uia", uiaSection("MsoDockBottom", "pane")),)),
				),
				_FakeNode(
					key="workspace",
					structure=NodeStructure("dock", 2, (), False, False, False),
					fields=(
						("name", _envelope(EvidenceState.EMPTY)),
						("role", _envelope(EvidenceState.EMPTY)),
					),
					providers=_FakeProviderSections(
						(
							("uia", uiaSection("Workspace", "pane")),
							("customUia", customUiaSection()),
						),
					),
				),
			),
		)
		service = InspectorService()
		service.openSource(OfflineInspectorSource(cast(SnapshotView, view), "root", label="capture"))

		rendered = {
			row.nodeId: (row.node.facet.name, row.node.facet.role) for row in service.hierarchySubtree("root")
		}
		self.assertEqual(rendered["dock"], ("MsoDockBottom", "pane"))
		self.assertEqual(rendered["workspace"], ("Workspace", "pane"))
		self.assertEqual([row.nodeId for row in service.hierarchy()], ["root"])
		service.selectNode("dock")
		uia = service.selectCategory(PropertyCategory.UIA)
		uiaRows = {row.fieldKey: (row.name, row.value) for row in uia.rows}
		self.assertEqual(uiaRows["uia.Name"], ("Name", "MsoDockBottom"))
		self.assertEqual(uiaRows["uia.LocalizedControlType"], ("Localized control type", "pane"))
		self.assertEqual(uiaRows["uia.AccessKey"], ("Access key", None))
		service.selectNode("workspace")
		customRows = {
			row.fieldKey: (row.name, row.value) for row in service.selectCategory(PropertyCategory.UIA).rows
		}
		self.assertEqual(
			customRows["customUia.known.custom-f065.current"],
			("Custom UIA property ({F065-0000-0000-0000-000000000000})", "1"),
		)

	def test_all_properties_expands_exactly_one_structured_level(self) -> None:
		structured = (
			_container(
				"owner",
				_scalar("owner.name", "Ada"),
				_container("owner.address", _scalar("owner.address.city", "Rivertown")),
			),
			_container("roles", _scalar("roles[0]", "button"), _scalar("roles[1]", "menuitem")),
			_scalar("title", "Untitled"),
		)
		source = _spineSource(
			allProps=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.ALL_PROPERTIES,
				structured=structured,
			),
		)
		service = InspectorService()
		service.openSource(source)

		pane = service.selectCategory(PropertyCategory.ALL_PROPERTIES)
		byKey = {node.key: node for node in pane.structured}
		self.assertTrue(byKey["owner"].expanded)
		self.assertTrue(byKey["roles"].expanded)
		self.assertFalse(byKey["title"].expanded)
		nested = next(child for child in byKey["owner"].children if child.key == "owner.address")
		self.assertFalse(nested.expanded, "a grandchild container must remain collapsed")
		self.assertTrue(all(not leaf.expanded for leaf in nested.children))
		self.assertTrue(all(not leaf.expanded for leaf in byKey["roles"].children))

		# Reopening returns to Core and preserves the saved cursor for a later All Properties visit.
		service.setCursor(
			PropertyCategory.ALL_PROPERTIES,
			PaneCursor(selectedFieldKey="owner", topIndex=1),
		)
		service.openSource(source)

		self.assertIs(service.activeCategory, PropertyCategory.CORE)
		self.assertEqual(service.selectedNodeId, "target")
		self.assertEqual(service.cursor(PropertyCategory.ALL_PROPERTIES).selectedFieldKey, "owner")
		restored = {
			node.key: node for node in service.selectCategory(PropertyCategory.ALL_PROPERTIES).structured
		}
		self.assertTrue(restored["owner"].expanded)
		self.assertFalse(
			next(child for child in restored["owner"].children if child.key == "owner.address").expanded,
		)


@dataclass(frozen=True)
class _FakeProviderSections:
	items: tuple[tuple[str, object], ...] = ()


@dataclass(frozen=True)
class _FakeNode:
	key: str
	structure: NodeStructure
	fields: tuple[tuple[str, EvidenceEnvelope], ...]
	providers: _FakeProviderSections = _FakeProviderSections()

	def field(self, name: str) -> EvidenceEnvelope:
		return dict(self.fields)[name]


@dataclass(frozen=True)
class _FakeSnapshotView:
	captureRoots: tuple[str, ...]
	captureNodes: tuple[_FakeNode, ...]
	annotationRecords: tuple[AnnotationRecord, ...] = ()

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		return self.annotationRecords if nodeId == "target" else ()


def _redactedRow(fieldKey: str) -> PropertyRow:
	return PropertyRow(fieldKey=fieldKey, name=fieldKey.capitalize(), status=PropertyStatus.REDACTED)


class InspectorInteractionTests(unittest.TestCase):
	def test_raw_node_without_an_nvda_object_has_no_annotation_surface(self) -> None:
		class _RawOnlyReader:
			_closed = False

			def liveObject(self, _nodeId: str) -> object:
				raise LookupError("KS.PROVIDER.UNKNOWN_NODE_REF")

		reader = cast(LiveSessionNodeReader, _RawOnlyReader())
		self.assertEqual((), LiveSessionNodeReader.annotations(reader, "raw-1-1"))

	def test_f6_cycles_regions_forward_and_reverse_with_wrap(self) -> None:
		service = InspectorService()
		service.openSource(_spineSource())

		self.assertIs(service.activeRegion, InspectorRegion.HIERARCHY)
		self.assertIs(service.cycleRegion(), InspectorRegion.PROPERTIES)
		self.assertIs(service.cycleRegion(), InspectorRegion.SEARCH)
		self.assertIs(service.cycleRegion(), InspectorRegion.HIERARCHY)
		self.assertIs(service.cycleRegion(forward=False), InspectorRegion.SEARCH)

	def test_direct_region_focus_and_escape_when_not_searching_requests_close(self) -> None:
		service = InspectorService()
		service.openSource(_spineSource())

		self.assertIs(service.focusRegion(InspectorRegion.PROPERTIES), InspectorRegion.PROPERTIES)
		self.assertIs(service.activeRegion, InspectorRegion.PROPERTIES)
		self.assertIs(service.escape(), InspectorEscape.CLOSE)

	def test_search_selects_a_loaded_match_without_enumerating_children(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(_facet("child-a", parent="target", depth=3, role="text", name="Alpha"),),
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.expand("target")
		callsBefore = list(source.childrenCalls)

		outcome = service.search("alpha")

		self.assertEqual(outcome.decision, "match")
		self.assertEqual(outcome.nodeId, "child-a")
		self.assertEqual(service.selectedNodeId, "child-a")
		self.assertIs(service.activeRegion, InspectorRegion.SEARCH)
		self.assertEqual(service.searchQuery, "alpha")
		self.assertEqual(source.childrenCalls, callsBefore, "search must not enumerate any branch")

	def test_selecting_a_discovered_descendant_reveals_its_collapsed_ancestors(self) -> None:
		service = InspectorService()
		service.openSource(_discoveredNestedSource())
		_ = service.expand("target")
		_ = service.expand("branch")
		service.collapse("target")

		service.selectNode("leaf")

		rows = service.hierarchy()
		self.assertEqual(["root", "mid", "target", "branch", "leaf"], [row.nodeId for row in rows])
		self.assertTrue(rows[-1].selected)
		self.assertTrue(next(row for row in rows if row.nodeId == "target").expanded)
		self.assertTrue(next(row for row in rows if row.nodeId == "branch").expanded)

		# Selecting a collapsed tree item itself does not disclose it.
		service.collapse("target")
		service.selectNode("target")
		self.assertEqual(["root", "mid", "target"], [row.nodeId for row in service.hierarchy()])
		self.assertFalse(next(row for row in service.hierarchy() if row.nodeId == "target").expanded)

	def test_annotation_navigation_reveals_a_discovered_target_behind_a_collapsed_ancestor(self) -> None:
		class _AnnotationSource(_FakeSource):
			def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
				return (
					(
						AnnotationRecord(
							key="leaf",
							status=AnnotationStatus.VALUE,
							typeName="Comment",
							source="test",
							summary="Navigate to the discovered leaf",
							targetName="Leaf",
							targetRole="text",
							targetIdentity="node=leaf",
							targetNodeId="leaf",
							targetIdentityProven=True,
						),
					)
					if nodeId == "target"
					else ()
				)

		base = _discoveredNestedSource()
		source = _AnnotationSource(
			base.identityValue,
			base.rootFacets,
			base.childrenByNode,
			base.propertiesByNode,
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.expand("target")
		_ = service.expand("branch")
		service.selectNode("target")
		_ = service.selectCategory(PropertyCategory.ANNOTATIONS)
		service.collapse("target")

		outcome = service.navigateAnnotationTarget("leaf")

		self.assertEqual("leaf", outcome.nodeId)
		self.assertEqual("leaf", service.selectedNodeId)
		self.assertEqual(
			["root", "mid", "target", "branch", "leaf"],
			[row.nodeId for row in service.hierarchy()],
		)

	def test_search_never_reaches_an_unexpanded_branch(self) -> None:
		source = _spineSource()
		source.childrenByNode["target"] = ChildFetch(
			parentId="target",
			state=ChildState.LOADED,
			children=(_facet("hidden", parent="target", depth=3, role="text", name="Needle"),),
		)
		service = InspectorService()
		service.openSource(source)

		outcome = service.search("needle")

		self.assertEqual(outcome.decision, "noMatch")
		self.assertEqual(source.childrenCalls, [], "search must not expand to find a match")

	def test_escape_dismisses_an_active_search_and_returns_to_the_tree(self) -> None:
		source = _spineSource()
		service = InspectorService()
		service.openSource(source)
		_ = service.search("nothing-here")
		self.assertIs(service.activeRegion, InspectorRegion.SEARCH)

		self.assertIs(service.escape(), InspectorEscape.DISMISS_SEARCH)
		self.assertIsNone(service.searchQuery)
		self.assertIs(service.activeRegion, InspectorRegion.HIERARCHY)

	def test_copy_routes_by_context_and_never_emits_a_redacted_value(self) -> None:
		source = _spineSource(
			core=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.CORE,
				rows=(_row("role", "button"), _redactedRow("value")),
			),
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.selectCategory(PropertyCategory.CORE)

		self.assertEqual(service.copy(InspectorCopyKind.NODE_PATH), "App > [pane] > OK")

		text = service.copy(InspectorCopyKind.NODE_TEXT)
		self.assertIn("Role: button", text)
		self.assertIn("Value: (redacted)", text)

		markdown = service.copy(InspectorCopyKind.NODE_MARKDOWN)
		self.assertIn("| Value | redacted |  |", markdown)

		payload = cast(dict[str, object], json.loads(service.copy(InspectorCopyKind.NODE_JSON)))
		categories = cast(list[dict[str, object]], payload["categories"])
		core = next(entry for entry in categories if entry["category"] == "core")
		rows = cast(list[dict[str, object]], core["rows"])
		byField = {cast(str, row["field"]): row for row in rows}
		self.assertEqual(byField["role"]["value"], "button")
		self.assertEqual(byField["value"]["status"], "redacted")
		self.assertNotIn("value", byField["value"], "a redacted row must not carry any value key")

	def test_property_copy_follows_the_active_cursor(self) -> None:
		source = _spineSource(
			core=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.CORE,
				rows=(_row("role", "button"), _redactedRow("value")),
			),
		)
		service = InspectorService()
		service.openSource(source)
		_ = service.selectCategory(PropertyCategory.CORE)

		self.assertEqual(service.copy(InspectorCopyKind.PROPERTY), "Role: button")
		service.setCursor(PropertyCategory.CORE, PaneCursor(selectedFieldKey="value"))
		self.assertEqual(service.copy(InspectorCopyKind.PROPERTY), "Value: (redacted)")

	def test_quick_property_layout_digits_and_interval_bounds(self) -> None:
		base = SettingsSnapshot.defaults(settingsRevision=1)
		self.assertEqual(base.propertyIntervalMilliseconds, 1000)
		self.assertEqual(DEFAULT_PROPERTY_INTERVAL_MS, 1000)

		# The shared settings layer accepts the 250 and 5,000 ms boundaries.
		for value in (250, 5000):
			candidate = base.asCandidate().withValue(SettingId.PROPERTY_INTERVAL_MILLISECONDS, value)
			self.assertTrue(validateCandidate(candidate).isValid, value)

		# The shared settings layer rejects values just outside the boundaries.
		for value in (249, 5001):
			candidate = base.asCandidate().withValue(SettingId.PROPERTY_INTERVAL_MILLISECONDS, value)
			result = validateCandidate(candidate)
			self.assertFalse(result.isValid, value)
			self.assertEqual(result.firstInvalidSettingId, SettingId.PROPERTY_INTERVAL_MILLISECONDS)

		# A boundary interval drives the service's independent, layout-tolerant digit cycles.
		settings = base.asCandidate().withValue(SettingId.PROPERTY_INTERVAL_MILLISECONDS, 250).toSnapshot(2)
		service = InspectorService()
		service.openSource(_spineSource(), settings=settings)

		first = service.quickProperty("kb(laptop):numpad3", nowMilliseconds=0)
		assert first is not None
		self.assertEqual(first.digit, 3)
		self.assertIs(first.action, QuickPropertyAction.ANNOUNCE)
		self.assertEqual(first.deadlineMilliseconds, 250)

		second = service.quickProperty("kb:3", nowMilliseconds=100)
		assert second is not None
		self.assertIs(second.action, QuickPropertyAction.BROWSE)

		other = service.quickProperty("kb:control+4", nowMilliseconds=120)
		assert other is not None
		self.assertEqual(other.digit, 4)
		self.assertIs(other.action, QuickPropertyAction.ANNOUNCE)

		self.assertIsNone(service.quickProperty("kb:f4", nowMilliseconds=130))

		# Selecting a node cancels every pending repeat timer.
		service.selectNode("target")
		resumed = service.quickProperty("kb:3", nowMilliseconds=140)
		assert resumed is not None
		self.assertIs(resumed.action, QuickPropertyAction.ANNOUNCE)


def _offlineSource() -> OfflineInspectorSource:
	"""A minimal two-node capture bundle for exercising offline-only lifecycle behaviour."""

	view = _FakeSnapshotView(
		captureRoots=("root",),
		captureNodes=(
			_FakeNode(
				key="root",
				structure=NodeStructure(
					parentKey=None,
					depth=0,
					childKeys=("target",),
					cycleDetected=False,
					truncated=False,
					childFetchFailed=False,
				),
				fields=(
					("name", _envelope(EvidenceState.VALUE, "Application")),
					("role", _envelope(EvidenceState.VALUE, "window")),
				),
			),
			_FakeNode(
				key="target",
				structure=NodeStructure(
					parentKey="root",
					depth=1,
					childKeys=(),
					cycleDetected=False,
					truncated=False,
					childFetchFailed=False,
				),
				fields=(
					("name", _envelope(EvidenceState.VALUE, "Submit")),
					("role", _envelope(EvidenceState.VALUE, "button")),
				),
			),
		),
	)
	return OfflineInspectorSource(cast(SnapshotView, view), "target", label="capture.keystone")


class InspectorLifecycleTests(unittest.TestCase):
	# The live spine identity is app.exe / pid 4321; the service keys applications by that pair
	# joined with the ASCII unit separator, so a same-application focus change coalesces.
	_currentApplicationKey = "app.exe\x1f4321"

	def test_a_committed_settings_change_reaches_the_open_inspector(self) -> None:
		service = InspectorService()
		service.openSource(
			_spineSource(),
			settings=replace(
				SettingsSnapshot.defaults(settingsRevision=1),
				propertyIntervalMilliseconds=1_000,
			),
		)

		first = service.quickProperty("kb:1", nowMilliseconds=0)
		second = service.quickProperty("kb:1", nowMilliseconds=100)
		assert first is not None
		assert second is not None
		self.assertEqual(1_000, first.deadlineMilliseconds)
		self.assertNotEqual(first.action, second.action)

		service.applySettings(
			replace(
				SettingsSnapshot.defaults(settingsRevision=2),
				propertyIntervalMilliseconds=2_500,
			),
		)
		third = service.quickProperty("kb:1", nowMilliseconds=200)

		# The open Inspector uses the new interval at once, and the repeat cycle restarts rather
		# than judging the next press against the rule it was started under.
		assert third is not None
		self.assertEqual(2_700, third.deadlineMilliseconds)
		self.assertEqual(first.action, third.action)

	def test_focus_match_identity_ladder_and_budgets(self) -> None:
		limits = focusMatchLimits()
		self.assertEqual((limits.maximumNodes, limits.maximumDepth), (150, 40))

		def candidate(
			candidateId: str,
			evidence: FocusMatchEvidence,
			*,
			depth: int = 0,
		) -> FocusMatchCandidate:
			return FocusMatchCandidate(candidateId=candidateId, depth=depth, evidence=evidence)

		# Each positive identity layer, in isolation, is enough to match.
		for evidence in (
			FocusMatchEvidence(pythonIdentity=True),
			FocusMatchEvidence(nvdaEquality=True),
			FocusMatchEvidence(providerNative="same"),
			FocusMatchEvidence(stableIdEqual=True, roleAgrees=True),
		):
			result = matchInspectorTarget((candidate("only", evidence),), limits=limits)
			self.assertIs(result.decision, FocusMatchDecision.MATCHED)
			self.assertEqual(result.candidateId, "only")

		# Provider conflicts and a stable id whose role disagrees are rejected, never guessed.
		for evidence in (
			FocusMatchEvidence(providerNative="different"),
			FocusMatchEvidence(providerNative="conflict"),
			FocusMatchEvidence(stableIdEqual=True, roleAgrees=False),
		):
			result = matchInspectorTarget((candidate("candidate", evidence),), limits=limits)
			self.assertIs(result.decision, FocusMatchDecision.REJECTED)
			self.assertIsNone(result.candidateId)

		# Geometry alone can only narrow the neighbourhood; it never returns a match by itself.
		geometryOnly = matchInspectorTarget(
			(candidate("geo", FocusMatchEvidence(geometryCandidate=True)),),
			limits=limits,
		)
		self.assertIs(geometryOnly.decision, FocusMatchDecision.REJECTED)
		self.assertEqual(geometryOnly.reasonCode, "KS.INSPECTOR.FOCUS.GEOMETRY_ONLY")

		# A geometry candidate that also clears an identity layer does match.
		guided = matchInspectorTarget(
			(candidate("guided", FocusMatchEvidence(geometryCandidate=True, nvdaEquality=True)),),
			limits=limits,
		)
		self.assertIs(guided.decision, FocusMatchDecision.MATCHED)
		self.assertEqual(guided.candidateId, "guided")

		# Two positive matches are ambiguous rather than an arbitrary pick.
		ambiguous = matchInspectorTarget(
			(
				candidate("first", FocusMatchEvidence(pythonIdentity=True)),
				candidate("second", FocusMatchEvidence(nvdaEquality=True)),
			),
			limits=limits,
		)
		self.assertIs(ambiguous.decision, FocusMatchDecision.AMBIGUOUS)
		self.assertIsNone(ambiguous.candidateId)

		# A candidate deeper than the depth budget is explicitly unavailable.
		deep = matchInspectorTarget(
			(candidate("deep", FocusMatchEvidence(pythonIdentity=True), depth=limits.maximumDepth + 1),),
			limits=limits,
		)
		self.assertIs(deep.decision, FocusMatchDecision.UNAVAILABLE)
		self.assertEqual(deep.reasonCode, "KS.INSPECTOR.FOCUS.DEPTH_BUDGET")

		# Reaching the node budget stops the walk with an unavailable result and the visited count.
		tight = FocusMatchLimits(maximumNodes=2, maximumDepth=40)
		crowd = tuple(
			candidate(f"crowd-{index}", FocusMatchEvidence(stableIdEqual=True, roleAgrees=False))
			for index in range(3)
		)
		budgeted = matchInspectorTarget(crowd, limits=tight)
		self.assertIs(budgeted.decision, FocusMatchDecision.UNAVAILABLE)
		self.assertEqual(budgeted.reasonCode, "KS.INSPECTOR.FOCUS.NODE_BUDGET")
		self.assertEqual(budgeted.visitedNodes, 2)

	def test_follow_focus_starts_disarmed_and_toggles_on_a_live_source(self) -> None:
		service = InspectorService()
		service.openSource(_spineSource())

		self.assertFalse(service.followFocusEnabled)
		self.assertTrue(service.followFocusAvailable)
		self.assertTrue(service.setFollowFocus(True))
		self.assertTrue(service.followFocusEnabled)
		self.assertFalse(service.setFollowFocus(False))
		self.assertFalse(service.followFocusEnabled)

	def test_offline_capture_can_never_arm_follow_focus(self) -> None:
		service = InspectorService()
		service.openSource(_offlineSource())

		self.assertFalse(service.followFocusAvailable)
		self.assertFalse(service.setFollowFocus(True))
		self.assertFalse(service.followFocusEnabled)

	def test_follow_focus_excludes_self_and_transient_but_retargets_same_application(self) -> None:
		service = InspectorService()
		service.openSource(_spineSource())

		# While disarmed, every focus change is ignored outright.
		self.assertIs(
			service.considerFollowFocus(FollowFocusEvent(applicationKey="other.exe\x1f7")),
			FollowFocusOutcome.IGNORED_DISABLED,
		)

		_ = service.setFollowFocus(True)
		self.assertIs(
			service.considerFollowFocus(
				FollowFocusEvent(applicationKey=self._currentApplicationKey, isInspectorSurface=True),
			),
			FollowFocusOutcome.EXCLUDED_SELF,
		)
		self.assertIs(
			service.considerFollowFocus(
				FollowFocusEvent(applicationKey="menu.exe\x1f9", isTransient=True),
			),
			FollowFocusOutcome.EXCLUDED_TRANSIENT,
		)
		self.assertIs(
			service.considerFollowFocus(FollowFocusEvent(applicationKey=self._currentApplicationKey)),
			FollowFocusOutcome.RETARGET,
		)
		self.assertIs(
			service.considerFollowFocus(FollowFocusEvent(applicationKey="other.exe\x1f7")),
			FollowFocusOutcome.RETARGET,
		)

	def test_resolve_retarget_uses_the_fixed_identity_budgets(self) -> None:
		service = InspectorService()
		service.openSource(_spineSource())

		matched = service.resolveRetarget(
			(
				FocusMatchCandidate(
					candidateId="t",
					depth=0,
					evidence=FocusMatchEvidence(pythonIdentity=True),
				),
			),
		)
		self.assertIs(matched.decision, FocusMatchDecision.MATCHED)
		self.assertEqual(matched.candidateId, "t")

		deep = service.resolveRetarget(
			(
				FocusMatchCandidate(
					candidateId="t",
					depth=41,
					evidence=FocusMatchEvidence(pythonIdentity=True),
				),
			),
		)
		self.assertIs(deep.decision, FocusMatchDecision.UNAVAILABLE)
		self.assertEqual(deep.reasonCode, "KS.INSPECTOR.FOCUS.DEPTH_BUDGET")

	def test_close_invalidates_pending_reads_then_restores_state_on_reopen(self) -> None:
		source = _spineSource(
			core=PropertyFetch(
				nodeId="target",
				category=PropertyCategory.CORE,
				rows=(_row("role", "button"),),
			),
		)
		service = InspectorService()
		service.openSource(source)
		sourceGeneration = service.sourceGeneration
		operationGeneration = service.operationGeneration
		self.assertTrue(
			service.isCurrent(
				sourceGeneration=sourceGeneration,
				operationGeneration=operationGeneration,
			),
		)
		_ = service.selectCategory(PropertyCategory.CORE)
		service.selectNode("mid")
		self.assertTrue(service.setFollowFocus(True))
		lifecycleBefore = service.lifecycleGeneration

		service.close()

		self.assertEqual(service.lifecycleGeneration, lifecycleBefore + 1)
		self.assertFalse(service.followFocusEnabled)
		self.assertTrue(source.closed)
		# A deferred callback tagged with the pre-close generations now refuses to touch anything.
		self.assertFalse(
			service.isCurrent(
				sourceGeneration=sourceGeneration,
				operationGeneration=operationGeneration,
			),
		)

		# Live node references are session-local and can be recycled for different objects.
		# Reopening restores pane state but must always select the newly inspected target.
		service.openSource(
			_spineSource(
				core=PropertyFetch(
					nodeId="target",
					category=PropertyCategory.CORE,
					rows=(_row("role", "button"),),
				),
			),
		)
		self.assertIs(service.activeCategory, PropertyCategory.CORE)
		self.assertEqual(service.selectedNodeId, "target")


class SnapshotNodeReaderTests(unittest.TestCase):
	"""The concrete live reader projects an in-memory capture yet presents a live identity."""

	def _view(self) -> _FakeSnapshotView:
		return _FakeSnapshotView(
			captureRoots=("root",),
			captureNodes=(
				_FakeNode(
					key="root",
					structure=NodeStructure(
						parentKey=None,
						depth=0,
						childKeys=("target",),
						cycleDetected=False,
						truncated=False,
						childFetchFailed=False,
					),
					fields=(
						("name", _envelope(EvidenceState.VALUE, "Reader window")),
						("role", _envelope(EvidenceState.VALUE, "window")),
					),
				),
				_FakeNode(
					key="target",
					structure=NodeStructure(
						parentKey="root",
						depth=1,
						childKeys=(),
						cycleDetected=False,
						truncated=False,
						childFetchFailed=False,
					),
					fields=(
						("name", _envelope(EvidenceState.VALUE, "Submit")),
						("role", _envelope(EvidenceState.VALUE, "button")),
					),
				),
			),
		)

	def _reader(self) -> SnapshotNodeReader:
		return SnapshotNodeReader(
			cast(SnapshotView, self._view()),
			"root",
			label="reader.exe",
			executable="reader.exe",
			processId=4242,
			backend="nvdaSelected",
		)

	def test_reader_reports_a_live_identity_that_keeps_follow_focus_available(self) -> None:
		identity = self._reader().identity()

		self.assertIs(identity.kind, InspectorSourceKind.LIVE)
		self.assertTrue(identity.isLive)
		self.assertTrue(identity.followFocusAvailable)
		self.assertIsNone(identity.nodeCount)
		self.assertEqual("reader.exe", identity.executable)
		self.assertEqual(4242, identity.processId)
		self.assertEqual("nvdaSelected", identity.backend)

	def test_reader_projects_the_captured_spine_and_lazily_enumerates_children(self) -> None:
		reader = self._reader()

		self.assertEqual(["root"], [facet.nodeId for facet in reader.roots()])
		children = reader.children("root")
		self.assertIs(children.state, ChildState.LOADED)
		self.assertEqual(["target"], [facet.nodeId for facet in children.children])
		core = reader.properties("root", PropertyCategory.CORE)
		self.assertIn("Reader window", [row.value for row in core.rows])

	def test_reader_drives_the_service_as_a_live_source_with_follow_focus(self) -> None:
		service = InspectorService()
		service.openSource(LiveInspectorSource(self._reader()))

		identity = service.sourceIdentity()
		assert identity is not None
		self.assertIs(identity.kind, InspectorSourceKind.LIVE)
		self.assertTrue(service.followFocusAvailable)
		self.assertEqual(["root"], [row.nodeId for row in service.hierarchy()])
		_ = service.expand("root")
		self.assertEqual(["root", "target"], [row.nodeId for row in service.hierarchy()])

	def test_reader_close_releases_the_projection(self) -> None:
		reader = self._reader()
		_ = reader.roots()

		reader.close()

		self.assertEqual((), reader.roots())


if __name__ == "__main__":
	_ = unittest.main()
