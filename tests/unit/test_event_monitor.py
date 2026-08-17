from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import json
import threading
from types import SimpleNamespace
from typing import Any, override
import unittest

from addon.globalPlugins.keystone.adapters.nvda.event_sources import NvdaEventSource
from addon.globalPlugins.keystone.adapters.windows.raw_uia_events import (
	RawUiaClient,
	RawUiaEventSource,
	RawUiaNotification,
	RawUiaObjectDescriptor,
)
from addon.globalPlugins.keystone.domain.event_monitor import (
	NVDA_EVENT_TYPES,
	RAW_UIA_FAMILIES,
	BoundaryReason,
	ChangeEvidence,
	DropCounters,
	EventBackend,
	EventExportMetadata,
	EventFilter,
	EventReceipt,
	EventProvenance,
	EventRow,
	MonitorProvenance,
	MonitorScope,
	MonitorScopeKind,
	NvdaEventType,
	RawUiaFamily,
	RetentionPolicy,
	SessionBoundary,
	TargetIdentity,
	applyCeiling,
	applyPositiveCap,
	applyRetention,
	crossedDropMilestones,
	eventFilterChoices,
	filterToSelection,
	monitoringScopeStatus,
	selectionToFilter,
	serializeEventExport,
)
from addon.globalPlugins.keystone.ports.event_sources import EventSink, SubscriptionRequest


def _provenance() -> EventProvenance:
	return EventProvenance(
		backend=EventBackend.NVDA,
		rawEventsEnabled=False,
		redactionEnabled=True,
		settingsRevision=1,
		policyRevision=1,
	)


def _row(sequence: int, *, session: int = 1) -> EventRow:
	return EventRow(
		sequence=sequence,
		session=session,
		backend=EventBackend.NVDA,
		eventType="focus",
		processId=100,
		application="app",
		objectName="name",
		objectRole="role",
		detail="detail",
		timestampText="12:00:00.000 AM",
		wallClockMs=1,
		receiptToProcessingMs=0.0,
		receiptToPropertyReadMs=0.0,
		redacted=False,
		rawEvent=False,
		truncated=False,
		provenance=_provenance(),
	)


def _boundary(
	sequence: int,
	session: int,
	*,
	reason: BoundaryReason = BoundaryReason.STARTED,
) -> SessionBoundary:
	return SessionBoundary(
		sequence=sequence,
		session=session,
		application="app",
		processId=100,
		broad=False,
		reason=reason,
		startTimeText="12:00:00.000 AM",
		wallClockMs=1,
		detail="detail",
	)


class DropMilestoneTests(unittest.TestCase):
	def test_first_drop_is_a_milestone(self) -> None:
		self.assertEqual(crossedDropMilestones(0, 1), (1,))

	def test_no_milestone_when_unchanged(self) -> None:
		self.assertEqual(crossedDropMilestones(5, 5), ())
		self.assertEqual(crossedDropMilestones(11, 12), ())

	def test_decade_milestones(self) -> None:
		self.assertEqual(crossedDropMilestones(0, 10), (1, 10))
		self.assertEqual(crossedDropMilestones(1, 10), (10,))
		self.assertEqual(crossedDropMilestones(9, 11), (10,))
		self.assertEqual(crossedDropMilestones(100, 1_000), (1_000,))

	def test_tenfold_beyond_base_table(self) -> None:
		self.assertEqual(crossedDropMilestones(1_000_000, 10_000_000), (10_000_000,))
		self.assertEqual(crossedDropMilestones(999_999, 1_000_000), (1_000_000,))


class RetentionPolicyTests(unittest.TestCase):
	def test_default_is_two_thousand(self) -> None:
		self.assertEqual(RetentionPolicy.fromSetting(2_000).userCap, 2_000)
		self.assertFalse(RetentionPolicy.fromSetting(2_000).unbounded)

	def test_zero_maps_to_unbounded_million_ceiling(self) -> None:
		policy = RetentionPolicy.fromSetting(0)
		self.assertTrue(policy.unbounded)
		self.assertEqual(policy.processCeiling, 1_000_000)
		self.assertEqual(policy.effectiveCap, 1_000_000)

	def test_invalid_values_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = RetentionPolicy.fromSetting(-1)
		with self.assertRaises(ValueError):
			_ = RetentionPolicy.fromSetting(1_000_001)

	def test_boolean_rejected(self) -> None:
		with self.assertRaises(TypeError):
			_ = RetentionPolicy.fromSetting(True)


class PositiveCapRetentionTests(unittest.TestCase):
	def test_boundary_1999_2000_2001(self) -> None:
		policy = RetentionPolicy.fromSetting(2_000)

		items1999 = tuple(_row(index) for index in range(1_999))
		_, drops = applyRetention(items1999, DropCounters(), policy)
		self.assertEqual(drops.retainedRowDrops, 0)

		items2000 = tuple(_row(index) for index in range(2_000))
		kept2000, drops2000 = applyRetention(items2000, DropCounters(), policy)
		self.assertEqual(drops2000.retainedRowDrops, 0)
		self.assertEqual(len(kept2000), 2_000)

		items2001 = tuple(_row(index) for index in range(2_001))
		kept2001, drops2001 = applyRetention(items2001, DropCounters(), policy)
		self.assertEqual(drops2001.retainedRowDrops, 1)
		self.assertEqual(len(kept2001), 2_000)
		self.assertIsInstance(kept2001[0], EventRow)
		self.assertEqual(kept2001[0].sequence, 1)

	def test_positive_cap_keeps_boundaries(self) -> None:
		items = (_boundary(0, 1), _row(1), _row(2), _row(3))
		kept, drops = applyPositiveCap(items, DropCounters(), 2)
		self.assertEqual(drops.retainedRowDrops, 1)
		self.assertEqual(kept[0], items[0])
		rows = [item for item in kept if isinstance(item, EventRow)]
		self.assertEqual([row.sequence for row in rows], [2, 3])

	def test_default_cap_bounds_repeated_session_boundaries(self) -> None:
		policy = RetentionPolicy.fromSetting(2_000)
		items = tuple(
			item
			for session in range(1, 2_001)
			for item in (_boundary(session * 2, session), _row(session * 2 + 1, session=session))
		)

		kept, drops = applyRetention(items, DropCounters(), policy)

		self.assertLessEqual(len(kept), policy.effectiveCap)
		self.assertGreater(drops.retainedRowDrops, 0)
		self.assertTrue(
			all(
				any(
					isinstance(candidate, EventRow) and candidate.session == boundary.session
					for candidate in kept
				)
				for boundary in kept
				if isinstance(boundary, SessionBoundary)
			),
		)


class CeilingRetentionTests(unittest.TestCase):
	def test_ceiling_evicts_oldest_row_and_unneeded_boundary(self) -> None:
		items = (_boundary(0, 1), _row(1, session=1), _row(2, session=1), _boundary(3, 2), _row(4, session=2))

		keptFour, dropsFour = applyCeiling(items, DropCounters(), 4)
		self.assertEqual(dropsFour.retainedRowDrops, 1)
		self.assertEqual(
			[type(item).__name__ for item in keptFour],
			["SessionBoundary", "EventRow", "SessionBoundary", "EventRow"],
		)

		keptThree, dropsThree = applyCeiling(items, DropCounters(), 3)
		self.assertEqual(dropsThree.retainedRowDrops, 2)
		sessions = {item.session for item in keptThree if isinstance(item, SessionBoundary)}
		self.assertEqual(sessions, {2})
		rows = [item for item in keptThree if isinstance(item, EventRow)]
		self.assertEqual([row.sequence for row in rows], [4])

	def test_boundary_heavy_ceiling_prunes_evicted_sessions_directly(self) -> None:
		items = tuple(
			item
			for session in range(1, 1_501)
			for item in (_boundary(session * 2, session), _row(session * 2 + 1, session=session))
		)

		kept, drops = applyCeiling(items, DropCounters(), 2_000)

		self.assertEqual(drops.retainedRowDrops, 500)
		self.assertEqual(kept, items[1_000:])

	def test_orphan_boundary_sweep_discards_boundary_only_input(self) -> None:
		items = tuple(_boundary(sequence, sequence) for sequence in range(10))

		kept, drops = applyCeiling(items, DropCounters(), 3)

		self.assertEqual(0, drops.retainedRowDrops)
		self.assertEqual((), kept)


class EventFilterTests(unittest.TestCase):
	def test_default_selects_all_eleven_nvda_events(self) -> None:
		default = EventFilter.default()
		self.assertEqual(len(default.nvdaTypes), 11)
		self.assertEqual(len(NVDA_EVENT_TYPES), 11)
		self.assertFalse(default.rawEnabled)
		self.assertEqual(default.selectedCount, 11)

	def test_empty_filter_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = EventFilter(nvdaTypes=frozenset(), rawFamilies=frozenset())

	def test_summary_is_canonically_ordered(self) -> None:
		selective = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.CARET, NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.ALERT}),
		)
		self.assertEqual(selective.summary(), ("focus", "caret", "rawUia.alert"))
		self.assertTrue(selective.rawEnabled)

	def test_admits_by_backend(self) -> None:
		selective = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS}),
			rawFamilies=frozenset({RawUiaFamily.NOTIFICATION}),
		)
		self.assertTrue(selective.admits(EventBackend.NVDA, "focus"))
		self.assertFalse(selective.admits(EventBackend.NVDA, "caret"))
		self.assertTrue(selective.admits(EventBackend.RAW_UIA, "notification"))
		self.assertFalse(selective.admits(EventBackend.RAW_UIA, "alert"))

	def test_ten_raw_families(self) -> None:
		self.assertEqual(len(RAW_UIA_FAMILIES), 10)


class EventFilterChoiceTests(unittest.TestCase):
	def test_choices_cover_all_types_in_canonical_order(self) -> None:
		choices = eventFilterChoices()
		self.assertEqual(len(choices), len(NVDA_EVENT_TYPES) + len(RAW_UIA_FAMILIES))
		self.assertEqual(
			tuple(choice.nvdaType for choice in choices[: len(NVDA_EVENT_TYPES)]),
			NVDA_EVENT_TYPES,
		)
		self.assertEqual(
			tuple(choice.rawFamily for choice in choices[len(NVDA_EVENT_TYPES) :]),
			RAW_UIA_FAMILIES,
		)
		self.assertTrue(choices[0].label.startswith("NVDA: "))
		self.assertTrue(choices[-1].label.startswith("Raw UIA: "))

	def test_selection_round_trips_through_active_filter(self) -> None:
		choices = eventFilterChoices()
		original = EventFilter(
			nvdaTypes=frozenset({NvdaEventType.FOCUS, NvdaEventType.CARET}),
			rawFamilies=frozenset({RawUiaFamily.ALERT}),
		)
		rebuilt = selectionToFilter(choices, filterToSelection(choices, original))
		self.assertEqual(rebuilt, original)

	def test_empty_selection_keeps_current_filter(self) -> None:
		self.assertIsNone(selectionToFilter(eventFilterChoices(), ()))

	def test_out_of_range_indices_ignored(self) -> None:
		choices = eventFilterChoices()
		built = selectionToFilter(choices, (0, len(choices) + 5, -1))
		assert built is not None
		self.assertEqual(built.nvdaTypes, frozenset({NvdaEventType.FOCUS}))
		self.assertEqual(built.rawFamilies, frozenset())

	def test_scope_status_reports_pinned_broad_and_raw(self) -> None:
		pinned = monitoringScopeStatus(MonitorScope.pinned("firefox", 4242), EventFilter.default())
		self.assertIn("firefox", pinned)
		self.assertIn("4242", pinned)
		self.assertIn("raw UIA off", pinned)

		broad = monitoringScopeStatus(
			MonitorScope.broadScope(),
			EventFilter(nvdaTypes=frozenset(), rawFamilies=frozenset({RawUiaFamily.ALERT})),
		)
		self.assertIn("broad scope", broad)
		self.assertIn("raw UIA included", broad)
		self.assertIn("broad scope", monitoringScopeStatus(None, EventFilter.default()))


class MonitorScopeTests(unittest.TestCase):
	@staticmethod
	def _identity(
		*,
		processId: int = 4242,
		windowHandle: int = 101,
		evidence: tuple[tuple[str, str], ...] = (("automationId", "submit"),),
	) -> TargetIdentity:
		return TargetIdentity(
			processId=processId,
			windowHandle=windowHandle,
			providerEvidence=evidence,
		)

	def test_pinned_accepts_only_matching_pid(self) -> None:
		scope = MonitorScope.pinned("firefox", 4242)
		self.assertEqual(scope.kind, MonitorScopeKind.APPLICATION)
		self.assertTrue(scope.accepts(4242, "firefox"))
		self.assertFalse(scope.accepts(4243, "firefox"))
		self.assertIn("4242", scope.scopeText)

	def test_excludes_nvda_processes(self) -> None:
		scope = MonitorScope.pinned("firefox", 4242)
		self.assertFalse(scope.accepts(4242, "nvda.exe"))
		self.assertFalse(scope.accepts(4242, "nvda"))

	def test_broad_rejects_pinned_pid(self) -> None:
		scope = MonitorScope.broadScope()
		self.assertEqual(scope.kind, MonitorScopeKind.BROAD)
		self.assertTrue(scope.broad)
		self.assertIsNone(scope.processId)
		self.assertTrue(scope.accepts(999, "anything"))
		self.assertFalse(scope.accepts(999, "nvda.exe"))

	def test_broad_scope_cannot_pin_pid(self) -> None:
		with self.assertRaises(ValueError):
			_ = MonitorScope(application="x", processId=5, broad=True)

	def test_element_requires_exact_frozen_cross_backend_identity(self) -> None:
		frozen = self._identity()
		scope = MonitorScope.element("firefox", 4242, frozen)

		self.assertEqual(scope.kind, MonitorScopeKind.ELEMENT)
		self.assertTrue(
			scope.accepts(
				4242,
				"firefox",
				candidateIdentity=self._identity(),
			),
		)
		self.assertFalse(
			scope.accepts(
				4242,
				"firefox",
				candidateIdentity=self._identity(evidence=(("automationId", "other"),)),
			),
		)
		self.assertFalse(
			scope.accepts(
				4243,
				"firefox",
				candidateIdentity=self._identity(processId=4243),
			),
		)

	def test_subtree_accepts_frozen_root_in_bounded_ancestor_chain(self) -> None:
		root = self._identity(evidence=(("ia2UniqueId", "root-7"),))
		scope = MonitorScope.subtree("firefox", 4242, root)
		unrelated = tuple(
			self._identity(evidence=(("ia2UniqueId", f"ancestor-{index}"),)) for index in range(40)
		)

		self.assertEqual(scope.kind, MonitorScopeKind.SUBTREE)
		self.assertTrue(
			scope.accepts(
				4242,
				"firefox",
				candidateIdentity=self._identity(evidence=(("ia2UniqueId", "child"),)),
				ancestorIdentities=(*unrelated[:39], root),
			),
		)
		self.assertFalse(
			scope.accepts(
				4242,
				"firefox",
				candidateIdentity=self._identity(evidence=(("ia2UniqueId", "child"),)),
				ancestorIdentities=(*unrelated, root),
			),
		)


class _EventApp:
	appName = "firefox"


class _IdentityEventObject:
	def __init__(
		self,
		identifier: str,
		*,
		processId: int = 4242,
		parent: _IdentityEventObject | None = None,
	) -> None:
		super().__init__()
		self.processID = processId
		self.windowHandle = 101
		self.UIAAutomationId = identifier
		self.parent = parent
		self.name = identifier
		self.role = "button"
		self.appModule = _EventApp()
		self.UIAElement: object | None = None
		self.isProtected = False
		self.value: str = ""
		self.description: str | None = ""
		self.states: tuple[object, ...] = ()
		self.makeTextInfo: Callable[[object], object] | None = None


class _CrossProcessEventObject(_IdentityEventObject):
	@property
	@override
	def parent(self) -> object:
		raise AssertionError("cross-process events must not read ancestry")

	@parent.setter
	def parent(self, _value: object) -> None:
		pass


class _StalePropertyEventObject(_IdentityEventObject):
	def __init__(self, identifier: str, failingAttribute: str) -> None:
		super().__init__(identifier)
		self._failingAttribute = failingAttribute

	@override
	def __getattribute__(self, attribute: str) -> Any:
		failingAttribute = object.__getattribute__(self, "__dict__").get("_failingAttribute")
		if attribute == failingAttribute:
			raise RuntimeError(f"stale {attribute} property")
		return super().__getattribute__(attribute)


class _CurrentParentOnlyElement:
	def __init__(self, parent: object) -> None:
		super().__init__()
		self._parent = parent
		self.currentParentReads = 0

	@property
	def GetCachedParent(self) -> None:
		return None

	@property
	def CurrentParent(self) -> object:
		self.currentParentReads += 1
		return self._parent


class _FlakyProtectionEventObject(_IdentityEventObject):
	def __init__(
		self,
		identifier: str,
		*,
		protection: object,
		failOnFirstRead: bool = False,
		failAfterFirstRead: bool = False,
	) -> None:
		self._protection = protection
		self._failOnFirstRead = failOnFirstRead
		self._failAfterFirstRead = failAfterFirstRead
		self.protectionReads = 0
		super().__init__(identifier)

	@property
	@override
	def isProtected(self) -> object:
		self.protectionReads += 1
		if self._failOnFirstRead or (self._failAfterFirstRead and self.protectionReads > 1):
			raise RuntimeError("isProtected must be read exactly once")
		return self._protection

	@isProtected.setter
	def isProtected(self, _value: object) -> None:
		return


class ScopedEventSourceTests(unittest.TestCase):
	def test_nvda_subtree_matches_new_descendant_through_live_ancestry(self) -> None:
		root = _IdentityEventObject("root")
		child = _IdentityEventObject("child", parent=root)
		identity = TargetIdentity(4242, 101, (("providerIdentifier", "root"),))
		source = NvdaEventSource()
		sink = _CollectingSink()
		source.subscribe(
			sink,
			SubscriptionRequest(
				scope=MonitorScope.subtree("firefox", 4242, identity),
				activeFilter=EventFilter.default(),
				generation=1,
			),
		)

		self.assertTrue(source.forward(NvdaEventType.FOCUS, child))
		self.assertEqual(len(sink.receipts), 1)

	def test_nvda_subtree_matches_through_uia_current_parent_when_cached_parent_is_absent(self) -> None:
		root = _IdentityEventObject("root")
		child = _IdentityEventObject("child")
		element = _CurrentParentOnlyElement(root)
		child.UIAElement = element
		identity = TargetIdentity(4242, 101, (("providerIdentifier", "root"),))
		source = NvdaEventSource()
		sink = _CollectingSink()
		source.subscribe(
			sink,
			SubscriptionRequest(
				scope=MonitorScope.subtree("firefox", 4242, identity),
				activeFilter=EventFilter.default(),
				generation=1,
			),
		)

		self.assertTrue(source.forward(NvdaEventType.FOCUS, child))
		self.assertEqual(1, element.currentParentReads)
		self.assertEqual(len(sink.receipts), 1)

	def test_nvda_scope_rejects_cross_process_before_ancestry_read(self) -> None:
		identity = TargetIdentity(4242, 101, (("providerIdentifier", "root"),))
		source = NvdaEventSource()
		sink = _CollectingSink()
		source.subscribe(
			sink,
			SubscriptionRequest(
				scope=MonitorScope.subtree("firefox", 4242, identity),
				activeFilter=EventFilter.default(),
				generation=1,
			),
		)

		self.assertFalse(
			source.forward(
				NvdaEventType.FOCUS,
				_CrossProcessEventObject("foreign", processId=4243),
			),
		)
		self.assertEqual(sink.receipts, [])


class ChangedValueEvidenceTests(unittest.TestCase):
	def _subscribed(self) -> tuple[NvdaEventSource, _CollectingSink]:
		source = NvdaEventSource()
		sink = _CollectingSink()
		source.subscribe(
			sink,
			SubscriptionRequest(
				scope=MonitorScope.pinned("firefox", 4242),
				activeFilter=EventFilter.default(),
				generation=1,
			),
		)
		return source, sink

	def test_a_first_value_change_is_reported_as_a_reading_and_the_next_as_a_delta(self) -> None:
		source, sink = self._subscribed()
		target = _IdentityEventObject("search-box")
		target.value = "one"

		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))
		target.value = "two"
		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))

		first, second = sink.receipts
		self.assertEqual(ChangeEvidence.READ_AFTER_EVENT, first.changeEvidence)
		self.assertEqual("one", first.changedValue)
		self.assertEqual(ChangeEvidence.PRIOR_OBSERVATION_DELTA, second.changeEvidence)
		self.assertEqual("one changed to two", second.changedValue)

	def test_protection_is_read_once_and_reliable_false_preserves_unprotected_event_content(self) -> None:
		source, sink = self._subscribed()
		target = _FlakyProtectionEventObject("search-box", protection=False, failAfterFirstRead=True)
		target.value = "visible"

		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))

		receipt = sink.receipts[0]
		self.assertEqual(1, target.protectionReads)
		self.assertFalse(receipt.protectedName)
		self.assertFalse(receipt.protectedDetail)
		self.assertFalse(receipt.protectedChangedValue)
		self.assertEqual("value=visible", receipt.detail)
		self.assertEqual("visible", receipt.changedValue)

	def test_unknown_protection_is_conservatively_marked_protected(self) -> None:
		source, sink = self._subscribed()
		target = _FlakyProtectionEventObject("search-box", protection=None)
		target.value = "secret"

		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))

		receipt = sink.receipts[0]
		self.assertEqual(1, target.protectionReads)
		self.assertTrue(receipt.protectedName)
		self.assertTrue(receipt.protectedDetail)
		self.assertTrue(receipt.protectedChangedValue)

	def test_unavailable_protection_is_conservatively_marked_protected(self) -> None:
		source, sink = self._subscribed()
		target = _FlakyProtectionEventObject("search-box", protection=False, failOnFirstRead=True)
		target.value = "secret"

		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))

		receipt = sink.receipts[0]
		self.assertEqual(1, target.protectionReads)
		self.assertTrue(receipt.protectedName)
		self.assertTrue(receipt.protectedDetail)
		self.assertTrue(receipt.protectedChangedValue)

	def test_a_delta_needs_a_stable_identity(self) -> None:
		source, sink = self._subscribed()
		anonymous = SimpleNamespace(
			processID=4242,
			appModule=_EventApp(),
			name="unnamed",
			role="button",
			isProtected=False,
			value="one",
		)

		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, anonymous))
		anonymous.value = "two"
		self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, anonymous))

		for receipt in sink.receipts:
			self.assertEqual(ChangeEvidence.READ_AFTER_EVENT, receipt.changeEvidence)
		self.assertEqual("two", sink.receipts[1].changedValue)

	def test_prior_observations_are_bounded_and_cleared_at_session_boundaries(self) -> None:
		source, _sink = self._subscribed()
		for index in range(600):
			target = _IdentityEventObject(f"control-{index}")
			target.value = "one"
			self.assertTrue(source.forward(NvdaEventType.VALUE_CHANGE, target))

		self.assertLessEqual(source.observedValueCount, 512)

		source.unsubscribe()
		self.assertEqual(0, source.observedValueCount)

	def test_an_event_with_no_value_concept_says_so_instead_of_going_blank(self) -> None:
		source, sink = self._subscribed()

		self.assertTrue(source.forward(NvdaEventType.FOCUS, _IdentityEventObject("button")))

		receipt = sink.receipts[0]
		self.assertEqual(ChangeEvidence.NOT_APPLICABLE, receipt.changeEvidence)
		self.assertEqual("", receipt.changedValue)

	def test_a_missing_field_is_reported_as_not_exposed(self) -> None:
		source, sink = self._subscribed()
		target = _IdentityEventObject("plain")
		target.description = None

		self.assertTrue(source.forward(NvdaEventType.DESCRIPTION_CHANGE, target))

		self.assertEqual(ChangeEvidence.NOT_EXPOSED, sink.receipts[0].changeEvidence)

	def test_stale_content_properties_do_not_drop_their_events(self) -> None:
		for eventType, attribute in (
			(NvdaEventType.NAME_CHANGE, "name"),
			(NvdaEventType.VALUE_CHANGE, "value"),
			(NvdaEventType.DESCRIPTION_CHANGE, "description"),
		):
			with self.subTest(eventType=eventType):
				source, sink = self._subscribed()
				target = _StalePropertyEventObject("control", attribute)

				self.assertTrue(source.forward(eventType, target))

				self.assertEqual(source.forwardCount, 1)
				self.assertEqual(len(sink.receipts), 1)
				receipt = sink.receipts[0]
				self.assertEqual(receipt.objectName, "" if attribute == "name" else "control")
				self.assertEqual(receipt.detail, "")
				self.assertEqual(receipt.changeEvidence, ChangeEvidence.UNAVAILABLE)
				self.assertEqual(receipt.changedValue, "")

	def test_state_changes_report_which_states_were_added_and_removed(self) -> None:
		source, sink = self._subscribed()
		target = _IdentityEventObject("checkbox")
		target.states = (SimpleNamespace(name="focusable"), SimpleNamespace(name="checked"))

		self.assertTrue(source.forward(NvdaEventType.STATE_CHANGE, target))
		target.states = (SimpleNamespace(name="focusable"), SimpleNamespace(name="focused"))
		self.assertTrue(source.forward(NvdaEventType.STATE_CHANGE, target))

		first, second = sink.receipts
		self.assertEqual(ChangeEvidence.READ_AFTER_EVENT, first.changeEvidence)
		self.assertEqual("checked, focusable", first.changedValue)
		self.assertEqual(ChangeEvidence.PRIOR_OBSERVATION_DELTA, second.changeEvidence)
		self.assertEqual("added focused; removed checked", second.changedValue)

	def test_a_caret_event_reports_its_position_and_never_its_text(self) -> None:
		source, sink = self._subscribed()
		target = _IdentityEventObject("document")
		target.makeTextInfo = lambda _position: SimpleNamespace(
			bookmark=SimpleNamespace(startOffset=12, endOffset=12),
			text="secret line",
		)

		self.assertTrue(source.forward(NvdaEventType.CARET, target))

		receipt = sink.receipts[0]
		self.assertEqual(ChangeEvidence.CARET_METADATA, receipt.changeEvidence)
		self.assertEqual("caret offset 12", receipt.changedValue)
		self.assertFalse(receipt.protectedChangedValue)

	def test_an_opaque_bookmark_is_reported_as_not_exposed(self) -> None:
		source, sink = self._subscribed()
		target = _IdentityEventObject("uia-document")
		target.makeTextInfo = lambda _position: SimpleNamespace(bookmark=object())

		self.assertTrue(source.forward(NvdaEventType.CARET, target))

		self.assertEqual(ChangeEvidence.NOT_EXPOSED, sink.receipts[0].changeEvidence)

	def test_a_row_states_every_outcome_rather_than_leaving_the_cell_blank(self) -> None:
		stated = {
			ChangeEvidence.NOT_APPLICABLE: "Not applicable",
			ChangeEvidence.NOT_EXPOSED: "Not exposed",
			ChangeEvidence.UNAVAILABLE: "Unavailable",
			ChangeEvidence.REDACTED: "(redacted)",
		}
		for evidence, expected in stated.items():
			with self.subTest(evidence=evidence):
				row = replace(_row(1), changedValue=None, changeEvidence=evidence)
				self.assertEqual(expected, row.changedValueText)

		observed = replace(_row(1), changedValue="hello", changeEvidence=ChangeEvidence.READ_AFTER_EVENT)
		self.assertEqual("hello", observed.changedValueText)
		empty = replace(_row(1), changedValue="", changeEvidence=ChangeEvidence.READ_AFTER_EVENT)
		self.assertEqual("(empty)", empty.changedValueText)
		trimmed = replace(
			_row(1),
			changedValue="",
			changeEvidence=ChangeEvidence.READ_AFTER_EVENT,
			truncated=True,
			changedValueTruncated=True,
		)
		self.assertEqual("(truncated)", trimmed.changedValueText)

	def test_a_detail_that_was_shortened_does_not_make_an_empty_value_look_truncated(self) -> None:
		row = replace(
			_row(1),
			detail="shortened",
			changedValue="",
			changeEvidence=ChangeEvidence.READ_AFTER_EVENT,
			# Only the detail hit the size limit; the changed value was read and found empty.
			truncated=True,
			changedValueTruncated=False,
		)

		self.assertEqual("(empty)", row.changedValueText)

	def test_a_row_cannot_claim_a_truncation_it_has_no_value_for(self) -> None:
		with self.assertRaises(ValueError):
			_ = replace(
				_row(1),
				changedValue=None,
				changeEvidence=ChangeEvidence.NOT_EXPOSED,
				changedValueTruncated=True,
			)

	def test_a_row_cannot_claim_evidence_it_does_not_carry(self) -> None:
		with self.assertRaises(ValueError):
			_ = replace(_row(1), changedValue=None, changeEvidence=ChangeEvidence.READ_AFTER_EVENT)
		with self.assertRaises(ValueError):
			_ = replace(_row(1), changedValue="ghost", changeEvidence=ChangeEvidence.NOT_EXPOSED)


class ExportSerializationTests(unittest.TestCase):
	def test_serialize_export_round_trips_metadata_and_rows(self) -> None:
		provenance = MonitorProvenance(
			scope=MonitorScope.pinned("firefox", 4242),
			rawEventsEnabled=False,
			redactionEnabled=True,
			settingsRevision=3,
			policyRevision=5,
			queueCapacity=1_000,
			drainLimit=100,
			retention=RetentionPolicy.fromSetting(2_000),
			detailCharacters=100,
			filterSummary=("focus",),
		)
		metadata = EventExportMetadata.build(
			provenance,
			exportedEventCount=1,
			drops=DropCounters(pendingQueueDrops=2, retainedRowDrops=3),
			truncated=True,
			boundaries=(_boundary(0, 1),),
		)
		payload = json.loads(serializeEventExport(metadata, (_row(1),)).decode("utf-8"))
		self.assertEqual(payload["schema"], "keystone.events.export.v1")
		self.assertEqual(payload["metadata"]["exportedEventCount"], 1)
		self.assertEqual(payload["metadata"]["pendingQueueDrops"], 2)
		self.assertEqual(payload["metadata"]["retainedRowDrops"], 3)
		self.assertTrue(payload["metadata"]["truncated"])
		self.assertEqual(len(payload["metadata"]["sessionBoundaries"]), 1)
		self.assertEqual(len(payload["events"]), 1)
		self.assertEqual(payload["events"][0]["event"], "focus")


class _CollectingSink:
	def __init__(self) -> None:
		super().__init__()
		self.receipts: list[EventReceipt] = []

	def deliver(self, receipt: EventReceipt) -> None:
		self.receipts.append(receipt)


class _FakeRawUiaClient:
	def __init__(self) -> None:
		super().__init__()
		self.focus: Callable[[], None] | None = None
		self.removed = 0
		self.released = 0

	def addFocusHandler(self, onFocus: Callable[[], None]) -> None:
		self.focus = onFocus

	def removeAllHandlers(self) -> None:
		self.removed += 1

	def release(self) -> None:
		self.released += 1

	def rootProcessId(self) -> int:
		return 4242


class _FakeClientFactory:
	def __init__(self, client: RawUiaClient) -> None:
		super().__init__()
		self.client = client
		self.created = 0

	def create(self) -> RawUiaClient:
		self.created += 1
		return self.client


class _FailingClientFactory:
	def create(self) -> RawUiaClient:
		raise RuntimeError("no COM host available")


class _RecoveringClientFactory:
	def __init__(self, client: RawUiaClient) -> None:
		super().__init__()
		self._client = client
		self.created = 0

	def create(self) -> RawUiaClient:
		self.created += 1
		if self.created == 1:
			raise RuntimeError("no COM host available")
		return self._client


def _rawFilter() -> EventFilter:
	return EventFilter(nvdaTypes=frozenset(NVDA_EVENT_TYPES), rawFamilies=frozenset(RAW_UIA_FAMILIES))


def _rawDescriptor(
	*,
	pid: int = 4242,
	app: str = "explorer.exe",
	name: str = "Cell",
) -> RawUiaObjectDescriptor:
	return RawUiaObjectDescriptor(processId=pid, executable=app, name=name, role="dataItem")


def _subscribeRaw(
	source: RawUiaEventSource,
	sink: EventSink,
	*,
	pid: int = 4242,
	app: str = "explorer.exe",
	generation: int = 1,
) -> SubscriptionRequest:
	request = SubscriptionRequest(
		scope=MonitorScope.pinned(app, pid),
		activeFilter=_rawFilter(),
		generation=generation,
	)
	source.subscribe(sink, request)
	return request


class RawUiaEventSourceUnitTests(unittest.TestCase):
	def test_backend_and_families_are_the_ten_raw_families(self) -> None:
		source = RawUiaEventSource()
		self.assertEqual(source.backend, EventBackend.RAW_UIA)
		self.assertEqual(source.families, tuple(family.value for family in RAW_UIA_FAMILIES))
		self.assertEqual(len(source.families), 10)

	def test_ten_families_route_once_each_for_pinned_process(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)
		for family in RAW_UIA_FAMILIES:
			self.assertTrue(
				source.observe(family, _rawDescriptor(), issuedGeneration=request.generation),
			)
		self.assertEqual(source.forwardCount, 10)
		self.assertEqual(len(sink.receipts), 10)
		observed = {receipt.eventType for receipt in sink.receipts}
		self.assertEqual(observed, {family.value for family in RAW_UIA_FAMILIES})
		self.assertTrue(all(receipt.backend == EventBackend.RAW_UIA for receipt in sink.receipts))

	def test_a_notification_reports_the_display_string_the_provider_sent(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)
		notification = RawUiaNotification(
			notificationKind=4,
			notificationProcessing=2,
			displayString="Download complete",
			activityId="downloads",
		)

		self.assertTrue(
			source.observe(
				RawUiaFamily.NOTIFICATION,
				_rawDescriptor(),
				issuedGeneration=request.generation,
				notification=notification,
			),
		)

		receipt = sink.receipts[0]
		self.assertEqual(ChangeEvidence.PROVIDER_REPORTED, receipt.changeEvidence)
		self.assertEqual("Download complete", receipt.changedValue)

	def test_a_notification_without_a_display_string_says_it_was_not_exposed(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)

		self.assertTrue(
			source.observe(
				RawUiaFamily.NOTIFICATION,
				_rawDescriptor(),
				issuedGeneration=request.generation,
				notification=RawUiaNotification(notificationKind=4),
			),
		)

		self.assertEqual(ChangeEvidence.NOT_EXPOSED, sink.receipts[0].changeEvidence)

	def test_an_active_text_position_reports_the_range_without_reading_it(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)

		class _Range:
			def GetText(self, _maximum: int) -> str:
				raise AssertionError("a text range must never be read across the process boundary")

		self.assertTrue(
			source.observe(
				RawUiaFamily.ACTIVE_TEXT_POSITION,
				_rawDescriptor(),
				issuedGeneration=request.generation,
				activeTextRange=_Range(),
			),
		)

		receipt = sink.receipts[0]
		self.assertEqual(ChangeEvidence.CARET_METADATA, receipt.changeEvidence)
		self.assertEqual("active text position range reported", receipt.changedValue)

	def test_families_without_a_value_concept_say_not_applicable(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)
		valueless = tuple(
			family
			for family in RAW_UIA_FAMILIES
			if family not in (RawUiaFamily.NOTIFICATION, RawUiaFamily.ACTIVE_TEXT_POSITION)
		)

		for family in valueless:
			self.assertTrue(
				source.observe(family, _rawDescriptor(), issuedGeneration=request.generation),
			)

		for receipt in sink.receipts:
			self.assertEqual(ChangeEvidence.NOT_APPLICABLE, receipt.changeEvidence)

	def test_mismatched_process_is_dropped_before_retention(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink, pid=4242)
		result = source.observe(
			RawUiaFamily.NOTIFICATION,
			_rawDescriptor(pid=4242 + 7919),
			issuedGeneration=request.generation,
		)
		self.assertFalse(result)
		self.assertEqual(source.pidDropped, 1)
		self.assertEqual(source.forwardCount, 0)
		self.assertEqual(sink.receipts, [])

	def test_stale_descriptor_properties_degrade_without_losing_events(self) -> None:
		class _StaleRawObject:
			def __init__(self, failingAttribute: str) -> None:
				super().__init__()
				self._failingAttribute = failingAttribute
				self.processID = 4242
				self.appModule = SimpleNamespace(appName="explorer.exe")
				self.name = "Cell"
				self.role = "dataItem"
				self.value = "Current value"
				self.isProtected = True

			@override
			def __getattribute__(self, attribute: str) -> object:
				if attribute == object.__getattribute__(self, "_failingAttribute"):
					raise RuntimeError(f"stale {attribute} property")
				return object.__getattribute__(self, attribute)

		for attribute, field, expected in (
			("appModule", "executable", ""),
			("name", "objectName", ""),
			("role", "objectRole", ""),
			("value", "detail", ""),
			("isProtected", "protectedName", False),
		):
			with self.subTest(attribute=attribute):
				sink = _CollectingSink()
				source = RawUiaEventSource()
				_ = _subscribeRaw(source, sink)

				self.assertTrue(source.forward(RawUiaFamily.ALERT, _StaleRawObject(attribute)))

				self.assertEqual(source.forwardCount, 1)
				self.assertEqual(len(sink.receipts), 1)
				self.assertEqual(getattr(sink.receipts[0], field), expected)

	def test_stale_process_property_is_refused_without_raising(self) -> None:
		class _StaleProcessObject:
			@property
			def processID(self) -> int:
				raise RuntimeError("stale processID property")

		sink = _CollectingSink()
		source = RawUiaEventSource()
		_ = _subscribeRaw(source, sink)

		self.assertFalse(source.forward(RawUiaFamily.ALERT, _StaleProcessObject()))
		self.assertEqual(source.pidDropped, 1)
		self.assertEqual(sink.receipts, [])

	def test_excluded_executable_is_dropped_even_for_pinned_pid(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink, pid=4242)
		result = source.observe(
			RawUiaFamily.ALERT,
			_rawDescriptor(pid=4242, app="nvda.exe"),
			issuedGeneration=request.generation,
		)
		self.assertFalse(result)
		self.assertEqual(source.pidDropped, 1)
		self.assertEqual(sink.receipts, [])

	def test_unselected_family_is_refused_without_provider_access(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = SubscriptionRequest(
			scope=MonitorScope.pinned("explorer.exe", 4242),
			activeFilter=EventFilter(
				nvdaTypes=frozenset(NVDA_EVENT_TYPES),
				rawFamilies=frozenset({RawUiaFamily.NOTIFICATION}),
			),
			generation=1,
		)
		source.subscribe(sink, request)
		self.assertFalse(source.observe(RawUiaFamily.ALERT, _rawDescriptor(), issuedGeneration=1))
		self.assertEqual(source.providerAccesses, 0)
		self.assertTrue(source.observe(RawUiaFamily.NOTIFICATION, _rawDescriptor(), issuedGeneration=1))
		self.assertEqual(source.providerAccesses, 1)

	def test_unselected_family_does_not_read_the_forwarded_object(self) -> None:
		class _UnreadableRawObject:
			@override
			def __getattribute__(self, attribute: str) -> object:
				raise AssertionError(f"unselected raw event read {attribute}")

		sink = _CollectingSink()
		source = RawUiaEventSource()
		source.subscribe(
			sink,
			SubscriptionRequest(
				scope=MonitorScope.pinned("explorer.exe", 4242),
				activeFilter=EventFilter(
					nvdaTypes=frozenset(NVDA_EVENT_TYPES),
					rawFamilies=frozenset({RawUiaFamily.NOTIFICATION}),
				),
				generation=1,
			),
		)

		self.assertFalse(source.forward(RawUiaFamily.ALERT, _UnreadableRawObject()))
		self.assertEqual(source.providerAccesses, 0)
		self.assertEqual(sink.receipts, [])

	def test_forward_timestamps_receipt_at_callback_entry(self) -> None:
		timeline: list[str] = []
		timestamps = iter((10.0, 20.0))

		def monotonic() -> float:
			timeline.append("clock")
			return next(timestamps)

		class _TimedRawObject(_IdentityEventObject):
			def __init__(self) -> None:
				super().__init__("control")
				self._timeline = timeline

			@override
			def __getattribute__(self, attribute: str) -> Any:
				if attribute != "_timeline":
					object.__getattribute__(self, "_timeline").append("provider")
				return super().__getattribute__(attribute)

		sink = _CollectingSink()
		source = RawUiaEventSource(monotonicMs=monotonic)
		_ = _subscribeRaw(source, sink)

		self.assertTrue(source.forward(RawUiaFamily.ALERT, _TimedRawObject()))

		receipt = sink.receipts[0]
		self.assertEqual(receipt.receivedAtMs, 10.0)
		self.assertEqual(receipt.readAtMs, 20.0)
		self.assertEqual(timeline[0], "clock")
		self.assertEqual(timeline[-1], "clock")
		self.assertIn("provider", timeline[1:-1])

	def test_hundred_receipt_burst_forwards_each_once(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink)
		for _ in range(100):
			self.assertTrue(
				source.observe(RawUiaFamily.SELECTION, _rawDescriptor(), issuedGeneration=request.generation),
			)
		self.assertEqual(source.forwardCount, 100)
		self.assertEqual(len(sink.receipts), 100)
		sequences = [receipt.sequence for receipt in sink.receipts]
		self.assertEqual(sequences, sorted(set(sequences)))

	def test_stale_generation_is_refused(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink, generation=3)
		self.assertFalse(
			source.observe(RawUiaFamily.WINDOW, _rawDescriptor(), issuedGeneration=request.generation - 1),
		)
		self.assertEqual(source.staleRefused, 1)
		self.assertEqual(sink.receipts, [])

	def test_secure_transition_flip_refuses_pre_transition_callbacks(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource()
		request = _subscribeRaw(source, sink, generation=1)
		staleGeneration = request.generation
		source.invalidate()
		self.assertFalse(
			source.observe(RawUiaFamily.RELATION, _rawDescriptor(), issuedGeneration=staleGeneration),
		)
		self.assertEqual(source.forwardCount, 0)
		self.assertEqual(source.staleRefused, 1)

	def test_late_callbacks_after_teardown_never_accepted(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		source = RawUiaEventSource(clientFactory=_FakeClientFactory(client))
		request = _subscribeRaw(source, sink)
		self.assertTrue(source.active)
		source.unsubscribe()
		self.assertFalse(source.active)
		self.assertEqual(source.subscriptionCount, 0)
		self.assertEqual(client.removed, 1)
		self.assertEqual(client.released, 1)
		for _ in range(25):
			self.assertFalse(
				source.observe(
					RawUiaFamily.NOTIFICATION,
					_rawDescriptor(),
					issuedGeneration=request.generation,
				),
			)
		self.assertEqual(source.lateCallbacksAccepted, 0)
		self.assertEqual(source.providerAccesses, 0)
		self.assertEqual(sink.receipts, [])

	def test_real_focus_subscription_records_liveness(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		source = RawUiaEventSource(clientFactory=_FakeClientFactory(client))
		_ = _subscribeRaw(source, sink)
		self.assertIsNotNone(client.focus)
		if client.focus is not None:
			client.focus()
		self.assertEqual(source.realFocusEvents, 1)
		self.assertIsNone(source.disableReason)

	def test_successful_client_reacquisition_clears_the_prior_disable_reason(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		factory = _RecoveringClientFactory(client)
		source = RawUiaEventSource(clientFactory=factory)
		_ = _subscribeRaw(source, sink, generation=1)
		self.assertEqual(source.disableReason, "RuntimeError: no COM host available")

		source.unsubscribe()
		_ = _subscribeRaw(source, sink, generation=2)

		self.assertEqual(factory.created, 2)
		self.assertIsNone(source.disableReason)
		self.assertIsNotNone(client.focus)

	def test_client_acquisition_failure_disables_raw_safely(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource(clientFactory=_FailingClientFactory())
		request = _subscribeRaw(source, sink)
		self.assertIsNotNone(source.disableReason)
		self.assertTrue(source.active)
		self.assertTrue(
			source.observe(RawUiaFamily.TOOLTIP, _rawDescriptor(), issuedGeneration=request.generation),
		)

	def test_client_factory_none_leaves_production_raw_routing_unchanged(self) -> None:
		sink = _CollectingSink()
		source = RawUiaEventSource(clientFactory=None)
		request = _subscribeRaw(source, sink)

		self.assertTrue(source.active)
		self.assertFalse(source.clientCleanupPending)
		self.assertIsNone(source.disableReason)
		self.assertTrue(
			source.observe(RawUiaFamily.TOOLTIP, _rawDescriptor(), issuedGeneration=request.generation),
		)

		source.unsubscribe()

		self.assertFalse(source.active)
		self.assertFalse(source.clientCleanupPending)
		self.assertEqual(source.ownershipViolations, 0)
		self.assertEqual(len(sink.receipts), 1)

	def test_wrong_thread_unsubscribe_retains_client_for_owner_thread_cleanup(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		factory = _FakeClientFactory(client)
		source = RawUiaEventSource(clientFactory=factory)
		_ = _subscribeRaw(source, sink)

		worker = threading.Thread(target=source.unsubscribe)
		worker.start()
		worker.join()

		self.assertFalse(source.active)
		self.assertTrue(source.clientCleanupPending)
		self.assertEqual(source.ownershipViolations, 1)
		self.assertEqual(factory.created, 1)
		self.assertEqual(client.removed, 0)
		self.assertEqual(client.released, 0)

		source.unsubscribe()

		self.assertFalse(source.clientCleanupPending)
		self.assertEqual(client.removed, 1)
		self.assertEqual(client.released, 1)

	def test_wrong_thread_subscribe_refuses_pending_client_cleanup(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		factory = _FakeClientFactory(client)
		source = RawUiaEventSource(clientFactory=factory)
		_ = _subscribeRaw(source, sink)

		worker = threading.Thread(target=source.unsubscribe)
		worker.start()
		worker.join()
		worker = threading.Thread(target=_subscribeRaw, args=(source, sink), kwargs={"generation": 2})
		worker.start()
		worker.join()

		self.assertFalse(source.active)
		self.assertEqual(source.subscriptionCount, 0)
		self.assertTrue(source.clientCleanupPending)
		self.assertEqual(source.ownershipViolations, 2)
		self.assertEqual(factory.created, 1)
		self.assertEqual(client.removed, 0)
		self.assertEqual(client.released, 0)

		source.unsubscribe()

		self.assertFalse(source.clientCleanupPending)
		self.assertEqual(client.removed, 1)
		self.assertEqual(client.released, 1)

	def test_original_owner_subscribe_cleans_up_then_reacquires_pending_client(self) -> None:
		sink = _CollectingSink()
		client = _FakeRawUiaClient()
		factory = _FakeClientFactory(client)
		source = RawUiaEventSource(clientFactory=factory)
		_ = _subscribeRaw(source, sink)

		worker = threading.Thread(target=source.unsubscribe)
		worker.start()
		worker.join()
		_ = _subscribeRaw(source, sink, generation=2)

		self.assertTrue(source.active)
		self.assertFalse(source.clientCleanupPending)
		self.assertEqual(factory.created, 2)
		self.assertEqual(client.removed, 1)
		self.assertEqual(client.released, 1)

		source.unsubscribe()

		self.assertEqual(client.removed, 2)
		self.assertEqual(client.released, 2)


if __name__ == "__main__":
	_ = unittest.main()
