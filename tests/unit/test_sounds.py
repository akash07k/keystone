from __future__ import annotations

import unittest
from typing import cast

from addon.globalPlugins.keystone.domain.sounds import (
	CUE_GRAMMAR,
	SOUND_ASSETS,
	CueAtomId,
	CueEventId,
	CuePriority,
	DispatchDecision,
	SoundOwner,
	SoundOwnerKind,
	SoundRequest,
	SoundScheduler,
	soundRequestFor,
)
from tests.tools.build_sound_theme import EXPECTED_INVENTORY


def _owner(kind: SoundOwnerKind, generation: int) -> SoundOwner:
	return SoundOwner(kind, generation)


def _drain(scheduler: SoundScheduler, token: int, *, now: int = 0) -> None:
	dispatch = scheduler.completeAtom(token, nowMilliseconds=now)
	while dispatch.plays:
		dispatch = scheduler.completeAtom(dispatch.token, nowMilliseconds=now)


class CueGrammarTests(unittest.TestCase):
	def test_grammar_defines_every_event_with_valid_atoms(self) -> None:
		self.assertEqual(set(CUE_GRAMMAR), set(CueEventId))
		for event, composition in CUE_GRAMMAR.items():
			with self.subTest(event=event):
				self.assertIsInstance(composition.priority, CuePriority)
				self.assertIsInstance(composition.primaryAtom, CueAtomId)
				if composition.familyAtom is not None:
					self.assertIsInstance(composition.familyAtom, CueAtomId)
					self.assertNotEqual(composition.familyAtom, composition.primaryAtom)
				if composition.activeFamily:
					self.assertIsNone(composition.familyAtom)
				if composition.startsProgress:
					self.assertIsNotNone(composition.familyAtom)

	def test_priorities_match_the_feedback_grammar_tiers(self) -> None:
		self.assertEqual(CUE_GRAMMAR[CueEventId.SECURE_DESKTOP_DENIAL].priority, CuePriority.CRITICAL)
		self.assertEqual(CUE_GRAMMAR[CueEventId.CAPTURE_FAILURE].priority, CuePriority.CRITICAL)
		self.assertEqual(CUE_GRAMMAR[CueEventId.CAPTURE_SUCCESS].priority, CuePriority.URGENT)
		self.assertEqual(CUE_GRAMMAR[CueEventId.INSPECTOR_READY].priority, CuePriority.URGENT)
		self.assertEqual(CUE_GRAMMAR[CueEventId.START_BOUNDED_FULL].priority, CuePriority.URGENT)
		self.assertEqual(CUE_GRAMMAR[CueEventId.OUTPUT_PATH_COPY].priority, CuePriority.STANDARD)
		self.assertEqual(CUE_GRAMMAR[CueEventId.CAPTURE_PROGRESS].priority, CuePriority.AMBIENT)

	def test_start_events_compose_family_then_start_state_and_bear_progress(self) -> None:
		composition = CUE_GRAMMAR[CueEventId.START_BOUNDED_FULL]
		self.assertEqual(composition.familyAtom, CueAtomId.BOUNDED_FULL_FAMILY)
		self.assertEqual(composition.primaryAtom, CueAtomId.START_STATE)
		self.assertTrue(composition.startsProgress)

	def test_warnings_share_one_atom_but_keep_distinct_identities(self) -> None:
		# Distinct warnings remain distinct despite reusing the shared warning atom.
		for event in (
			CueEventId.RAW_UIA_FALLBACK,
			CueEventId.SECURE_DESKTOP_DENIAL,
			CueEventId.BROAD_EVENT_SCOPE,
			CueEventId.REDACTION_DISABLED,
		):
			with self.subTest(event=event):
				self.assertEqual(CUE_GRAMMAR[event].primaryAtom, CueAtomId.SHARED_WARNING)
		keys = {
			soundRequestFor(event, _owner(SoundOwnerKind.CAPTURE, 1)).coalescingKey
			for event in (
				CueEventId.RAW_UIA_FALLBACK,
				CueEventId.BROAD_EVENT_SCOPE,
				CueEventId.REDACTION_DISABLED,
			)
		}
		self.assertEqual(len(keys), 3)

	def test_builder_requires_active_family_only_for_active_events(self) -> None:
		request = soundRequestFor(
			CueEventId.CAPTURE_SUCCESS,
			_owner(SoundOwnerKind.CAPTURE, 2),
			activeFamilyAtom=CueAtomId.DIFF_FAMILY,
		)
		self.assertEqual(request.familyAtom, CueAtomId.DIFF_FAMILY)
		self.assertEqual(request.primaryAtom, CueAtomId.SUCCESS_OUTCOME)
		with self.assertRaises(ValueError):
			_ = soundRequestFor(CueEventId.CAPTURE_SUCCESS, _owner(SoundOwnerKind.CAPTURE, 2))
		with self.assertRaises(ValueError):
			_ = soundRequestFor(
				CueEventId.LAYER_ENTERED,
				_owner(SoundOwnerKind.LAYER, 1),
				activeFamilyAtom=CueAtomId.DIFF_FAMILY,
			)

	def test_builder_rejects_coalescing_keys_on_noncoalescing_events(self) -> None:
		with self.assertRaises(ValueError):
			_ = soundRequestFor(
				CueEventId.LAYER_ENTERED,
				_owner(SoundOwnerKind.LAYER, 1),
				coalescingKey="nope",
			)


class SoundRequestValidationTests(unittest.TestCase):
	def test_atoms_property_orders_family_before_primary(self) -> None:
		request = soundRequestFor(CueEventId.START_DIFF, _owner(SoundOwnerKind.CAPTURE, 1))
		self.assertEqual(request.atoms, (CueAtomId.DIFF_FAMILY, CueAtomId.START_STATE))
		layer = soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1))
		self.assertEqual(layer.atoms, (CueAtomId.LAYER_ENTERED,))

	def test_request_rejects_progress_interval_that_is_not_a_nonnegative_integer(self) -> None:
		for invalid in (-1, True, 1.5, "1", None):
			with self.subTest(interval=invalid), self.assertRaises((ValueError, TypeError)):
				_ = SoundRequest(
					event=CueEventId.START_DIFF,
					owner=_owner(SoundOwnerKind.CAPTURE, 1),
					priority=CuePriority.STANDARD,
					primaryAtom=CueAtomId.START_STATE,
					familyAtom=CueAtomId.DIFF_FAMILY,
					startsProgress=True,
					progressIntervalMilliseconds=cast(int, invalid),
				)

	def test_request_rejects_identical_family_and_primary_atoms(self) -> None:
		with self.assertRaises(ValueError):
			_ = SoundRequest(
				event=CueEventId.LAYER_ENTERED,
				owner=_owner(SoundOwnerKind.LAYER, 1),
				priority=CuePriority.STANDARD,
				primaryAtom=CueAtomId.START_STATE,
				familyAtom=CueAtomId.START_STATE,
			)

	def test_owner_generation_must_be_a_nonnegative_integer(self) -> None:
		for invalid in (-1, True, 1.5, "1", None):
			with self.subTest(generation=invalid), self.assertRaises((ValueError, TypeError)):
				_ = SoundOwner(SoundOwnerKind.CAPTURE, cast(int, invalid))


class SoundSchedulerArbitrationTests(unittest.TestCase):
	def test_idle_voice_plays_and_occupies(self) -> None:
		scheduler = SoundScheduler()
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.PLAY)
		self.assertEqual(dispatch.atom, CueAtomId.LAYER_ENTERED)
		self.assertTrue(scheduler.state.occupied)

	def test_critical_replaces_lower_priority_work(self) -> None:
		# P0 replaces any lower-priority voice.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.SECURE_DESKTOP_DENIAL, _owner(SoundOwnerKind.SYSTEM, 1)),
			nowMilliseconds=0,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.REPLACE)
		self.assertEqual(dispatch.atom, CueAtomId.SHARED_WARNING)

	def test_urgent_replaces_opening_from_the_same_source(self) -> None:
		# Inspector ready (P1) replaces the opening sequence (P2) from the same source.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 3)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.INSPECTOR_READY, _owner(SoundOwnerKind.INSPECTOR, 3)),
			nowMilliseconds=0,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.REPLACE)

	def test_capture_start_defers_behind_a_still_playing_transient_layer_cue(self) -> None:
		# Product policy: the short (225ms) layerEntered cue is preserved rather than cut off
		# mid-play when a capture-start command follows it immediately.
		scheduler = SoundScheduler()
		layer = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=1,
		)

		self.assertEqual(dispatch.decision, DispatchDecision.DEFER)
		self.assertIsNone(dispatch.atom)
		# The layer-enter cue is still the occupying voice; nothing has stopped it.
		self.assertTrue(scheduler.state.occupied)
		self.assertEqual(scheduler.state.activeToken, layer.token)

	def test_deferred_capture_start_begins_the_instant_the_layer_cue_completes(self) -> None:
		scheduler = SoundScheduler()
		layer = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		deferred = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=1,
		)
		self.assertEqual(deferred.decision, DispatchDecision.DEFER)

		promoted = scheduler.completeAtom(layer.token, nowMilliseconds=225)

		self.assertEqual(promoted.decision, DispatchDecision.PLAY)
		self.assertEqual(promoted.atom, CueAtomId.BOUNDED_FULL_FAMILY)
		self.assertTrue(promoted.hasFollowOn)
		self.assertNotEqual(promoted.token, layer.token)
		self.assertTrue(scheduler.state.occupied)
		self.assertEqual(scheduler.state.activeToken, promoted.token)

		# The promoted request still runs its own family-then-primary sequence normally.
		primary = scheduler.completeAtom(promoted.token, nowMilliseconds=255)
		self.assertEqual(primary.decision, DispatchDecision.PLAY)
		self.assertEqual(primary.atom, CueAtomId.START_STATE)
		final = scheduler.completeAtom(promoted.token, nowMilliseconds=1_000)
		self.assertEqual(final.decision, DispatchDecision.IDLE)
		self.assertFalse(scheduler.state.occupied)

	def test_warnings_and_critical_cues_still_replace_the_transient_layer_cue_immediately(self) -> None:
		# The deferral is scoped to capture-start alone: urgent preemption for warnings and
		# other critical cues must not weaken.
		for label, event, owner in (
			("warning", CueEventId.RAW_UIA_FALLBACK, _owner(SoundOwnerKind.SYSTEM, 1)),
			("critical", CueEventId.SECURE_DESKTOP_DENIAL, _owner(SoundOwnerKind.SYSTEM, 1)),
		):
			with self.subTest(case=label):
				scheduler = SoundScheduler()
				_ = scheduler.dispatch(
					soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
					nowMilliseconds=0,
				)
				dispatch = scheduler.dispatch(soundRequestFor(event, owner), nowMilliseconds=1)
				self.assertEqual(dispatch.decision, DispatchDecision.REPLACE)
				self.assertEqual(dispatch.atom, CueAtomId.SHARED_WARNING)

	def test_deferral_is_scoped_to_the_transient_layer_cue_not_any_standard_active_voice(self) -> None:
		# A non-layer STANDARD cue is still replaced immediately by capture-start, unchanged.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 1)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=1,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.REPLACE)
		self.assertEqual(dispatch.atom, CueAtomId.BOUNDED_FULL_FAMILY)

	def test_invalidating_the_capture_owner_cancels_a_pending_deferral(self) -> None:
		scheduler = SoundScheduler()
		layer = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		captureOwner = _owner(SoundOwnerKind.CAPTURE, 1)
		deferred = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, captureOwner),
			nowMilliseconds=1,
		)
		self.assertEqual(deferred.decision, DispatchDecision.DEFER)

		scheduler.invalidate(captureOwner)

		promoted = scheduler.completeAtom(layer.token, nowMilliseconds=225)
		self.assertEqual(promoted.decision, DispatchDecision.IDLE)
		self.assertFalse(scheduler.state.occupied)

	def test_global_invalidation_also_clears_a_pending_deferral(self) -> None:
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1)),
			nowMilliseconds=0,
		)
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=1,
		)

		scheduler.invalidate()
		self.assertFalse(scheduler.state.occupied)

		# A fresh, unrelated layer-enter cue must not resurrect the discarded deferral.
		freshLayer = scheduler.dispatch(
			soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 2)),
			nowMilliseconds=10,
		)
		final = scheduler.completeAtom(freshLayer.token, nowMilliseconds=235)
		self.assertEqual(final.decision, DispatchDecision.IDLE)
		self.assertFalse(scheduler.state.occupied)

	def test_equal_priority_newer_generation_replaces_older(self) -> None:
		# A newer same-kind generation supersedes the older cue.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 1)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 2)),
			nowMilliseconds=0,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.REPLACE)

	def test_equal_priority_same_or_older_or_foreign_owner_skips(self) -> None:
		# Deterministic ties: an occupied voice is not disturbed by an equal peer.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 2)),
			nowMilliseconds=0,
		)
		for label, request in (
			(
				"sameGeneration",
				soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 2)),
			),
			(
				"olderGeneration",
				soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 1)),
			),
			(
				"foreignKind",
				soundRequestFor(CueEventId.EVENT_MONITOR_START, _owner(SoundOwnerKind.MONITOR, 9)),
			),
		):
			with self.subTest(case=label):
				dispatch = scheduler.dispatch(request, nowMilliseconds=0)
				self.assertEqual(dispatch.decision, DispatchDecision.SKIP)

	def test_ambient_progress_skips_while_voice_is_occupied(self) -> None:
		# P3 progress is dropped, not queued, while the voice is busy.
		scheduler = SoundScheduler()
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.OPEN_FOCUS_INSPECTOR, _owner(SoundOwnerKind.INSPECTOR, 1)),
			nowMilliseconds=0,
		)
		dispatch = scheduler.dispatch(
			soundRequestFor(
				CueEventId.CAPTURE_PROGRESS,
				_owner(SoundOwnerKind.CAPTURE, 1),
				activeFamilyAtom=CueAtomId.BOUNDED_FULL_FAMILY,
			),
			nowMilliseconds=0,
		)
		self.assertEqual(dispatch.decision, DispatchDecision.SKIP)


class SoundSchedulerSequenceTests(unittest.TestCase):
	def test_two_atom_sequence_plays_family_then_primary_without_interleaving(self) -> None:
		# Composition is a strict two-atom sequence.
		scheduler = SoundScheduler()
		first = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=0,
		)
		self.assertEqual(first.atom, CueAtomId.BOUNDED_FULL_FAMILY)
		self.assertTrue(first.hasFollowOn)
		self.assertEqual(first.gapMilliseconds, 30)
		second = scheduler.completeAtom(first.token, nowMilliseconds=30)
		self.assertEqual(second.decision, DispatchDecision.PLAY)
		self.assertEqual(second.atom, CueAtomId.START_STATE)
		self.assertFalse(second.hasFollowOn)
		self.assertEqual(second.gapMilliseconds, 0)
		final = scheduler.completeAtom(first.token, nowMilliseconds=60)
		self.assertEqual(final.decision, DispatchDecision.IDLE)
		self.assertFalse(scheduler.state.occupied)

	def test_gap_is_inside_the_validated_window(self) -> None:
		for gap in (20, 30, 40):
			with self.subTest(gap=gap):
				scheduler = SoundScheduler(interAtomGapMilliseconds=gap)
				dispatch = scheduler.dispatch(
					soundRequestFor(CueEventId.START_DIFF, _owner(SoundOwnerKind.CAPTURE, 1)),
					nowMilliseconds=0,
				)
				self.assertEqual(dispatch.gapMilliseconds, gap)
		for gap in (19, 41, 0):
			with self.subTest(rejected=gap), self.assertRaises(ValueError):
				_ = SoundScheduler(interAtomGapMilliseconds=gap)

	def test_stale_completion_cannot_start_the_second_atom(self) -> None:
		# A preempted sequence never emits its second atom.
		scheduler = SoundScheduler()
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=0,
		)
		replaced = scheduler.dispatch(
			soundRequestFor(CueEventId.SECURE_DESKTOP_DENIAL, _owner(SoundOwnerKind.SYSTEM, 1)),
			nowMilliseconds=5,
		)
		self.assertEqual(replaced.decision, DispatchDecision.REPLACE)
		stale = scheduler.completeAtom(start.token, nowMilliseconds=30)
		self.assertEqual(stale.decision, DispatchDecision.IDLE)
		self.assertIsNone(stale.atom)

	def test_invalidation_before_second_atom_frees_the_voice(self) -> None:
		# Synchronous invalidation cancels the queued second atom.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.CAPTURE, 1)
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, owner),
			nowMilliseconds=0,
		)
		scheduler.invalidate(owner)
		self.assertFalse(scheduler.state.occupied)
		stale = scheduler.completeAtom(start.token, nowMilliseconds=30)
		self.assertEqual(stale.decision, DispatchDecision.IDLE)

	def test_completion_on_empty_voice_is_idle(self) -> None:
		# Completing when nothing plays is a safe no-op.
		scheduler = SoundScheduler()
		self.assertEqual(scheduler.completeAtom(7, nowMilliseconds=0).decision, DispatchDecision.IDLE)


class SoundSchedulerProgressTests(unittest.TestCase):
	def test_first_progress_waits_two_seconds_then_uses_the_interval(self) -> None:
		# First eligibility is 2000 ms; later eligibility is the configured interval.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.CAPTURE, 1)
		start = scheduler.dispatch(
			soundRequestFor(owner=owner, event=CueEventId.START_BOUNDED_FULL),
			nowMilliseconds=1_000,
		)
		_drain(scheduler, start.token, now=1_100)
		self.assertEqual(scheduler.tick(2_999).decision, DispatchDecision.IDLE)
		firstPulse = scheduler.tick(3_000)
		self.assertEqual(firstPulse.decision, DispatchDecision.PLAY)
		self.assertEqual(firstPulse.atom, CueAtomId.BOUNDED_FULL_FAMILY)
		self.assertEqual(scheduler.state.activePriority, CuePriority.AMBIENT)
		_drain(scheduler, firstPulse.token, now=3_100)
		self.assertEqual(scheduler.tick(4_999).decision, DispatchDecision.IDLE)
		self.assertEqual(scheduler.tick(5_000).decision, DispatchDecision.PLAY)

	def test_configured_interval_overrides_the_minimum_floor(self) -> None:
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.CAPTURE, 1)
		start = scheduler.dispatch(
			soundRequestFor(
				CueEventId.START_UNLIMITED_FULL,
				owner,
				progressIntervalMilliseconds=5_000,
			),
			nowMilliseconds=0,
		)
		_drain(scheduler, start.token, now=10)
		firstPulse = scheduler.tick(2_000)
		self.assertEqual(firstPulse.decision, DispatchDecision.PLAY)
		_drain(scheduler, firstPulse.token, now=2_010)
		self.assertEqual(scheduler.tick(6_999).decision, DispatchDecision.IDLE)
		self.assertEqual(scheduler.tick(7_000).decision, DispatchDecision.PLAY)

	def test_progress_is_skipped_not_queued_while_occupied(self) -> None:
		# A tick during an occupied voice does not consume the pending pulse.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.CAPTURE, 1)
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, owner),
			nowMilliseconds=0,
		)
		self.assertEqual(scheduler.tick(3_000).decision, DispatchDecision.IDLE)
		_drain(scheduler, start.token, now=3_000)
		self.assertEqual(scheduler.tick(3_000).decision, DispatchDecision.PLAY)

	def test_terminal_outcome_removes_pending_progress(self) -> None:
		# Completion and cancellation remove pending progress for their generation.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.CAPTURE, 1)
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, owner),
			nowMilliseconds=0,
		)
		_drain(scheduler, start.token, now=10)
		success = scheduler.dispatch(
			soundRequestFor(
				CueEventId.CAPTURE_SUCCESS,
				owner,
				activeFamilyAtom=CueAtomId.BOUNDED_FULL_FAMILY,
			),
			nowMilliseconds=20,
		)
		self.assertEqual(success.decision, DispatchDecision.PLAY)
		_drain(scheduler, success.token, now=30)
		self.assertEqual(scheduler.tick(100_000).decision, DispatchDecision.IDLE)
		self.assertEqual(scheduler.state.progressOwners, ())

	def test_stale_terminal_does_not_clear_a_newer_generation_progress(self) -> None:
		# A late terminal from an old generation cannot silence the new job.
		scheduler = SoundScheduler()
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 2)),
			nowMilliseconds=0,
		)
		_drain(scheduler, start.token, now=10)
		late = scheduler.dispatch(
			soundRequestFor(
				CueEventId.CAPTURE_SUCCESS,
				_owner(SoundOwnerKind.CAPTURE, 1),
				activeFamilyAtom=CueAtomId.BOUNDED_FULL_FAMILY,
			),
			nowMilliseconds=20,
		)
		_drain(scheduler, late.token, now=30)
		self.assertEqual(scheduler.tick(2_010).decision, DispatchDecision.PLAY)


class SoundSchedulerCoalescingTests(unittest.TestCase):
	def test_repeated_warning_coalesces_until_a_new_generation(self) -> None:
		# Identical warnings coalesce per operation; a new generation re-emits.
		scheduler = SoundScheduler()
		first = scheduler.dispatch(
			soundRequestFor(CueEventId.RAW_UIA_FALLBACK, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=0,
		)
		self.assertEqual(first.decision, DispatchDecision.PLAY)
		_drain(scheduler, first.token, now=10)
		repeat = scheduler.dispatch(
			soundRequestFor(CueEventId.RAW_UIA_FALLBACK, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=20,
		)
		self.assertEqual(repeat.decision, DispatchDecision.COALESCE)
		fresh = scheduler.dispatch(
			soundRequestFor(CueEventId.RAW_UIA_FALLBACK, _owner(SoundOwnerKind.CAPTURE, 2)),
			nowMilliseconds=30,
		)
		self.assertEqual(fresh.decision, DispatchDecision.PLAY)

	def test_distinct_drop_milestones_each_emit(self) -> None:
		# Distinct drop milestones and distinct drop events never coalesce,
		# even when a caller reuses a milestone key across pending and retained drops.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.MONITOR, 1)
		pending = scheduler.dispatch(
			soundRequestFor(CueEventId.PENDING_QUEUE_DROP, owner, coalescingKey="pendingDrop:10"),
			nowMilliseconds=0,
		)
		self.assertEqual(pending.decision, DispatchDecision.PLAY)
		_drain(scheduler, pending.token, now=10)
		milestone = scheduler.dispatch(
			soundRequestFor(CueEventId.PENDING_QUEUE_DROP, owner, coalescingKey="pendingDrop:100"),
			nowMilliseconds=20,
		)
		self.assertEqual(milestone.decision, DispatchDecision.PLAY)
		self.assertEqual(milestone.atom, CueAtomId.PENDING_QUEUE_DROP)
		_drain(scheduler, milestone.token, now=30)
		retained = scheduler.dispatch(
			soundRequestFor(CueEventId.RETAINED_ROW_DROP, owner, coalescingKey="pendingDrop:100"),
			nowMilliseconds=40,
		)
		self.assertEqual(retained.decision, DispatchDecision.PLAY)
		self.assertEqual(retained.atom, CueAtomId.RETAINED_ROW_DROP)

	def test_invalidation_resets_coalescing(self) -> None:
		# Invalidation lets the next identical warning speak again.
		scheduler = SoundScheduler()
		owner = _owner(SoundOwnerKind.SETTINGS, 1)
		first = scheduler.dispatch(
			soundRequestFor(CueEventId.REDACTION_DISABLED, owner),
			nowMilliseconds=0,
		)
		_drain(scheduler, first.token, now=10)
		scheduler.invalidate(owner)
		again = scheduler.dispatch(
			soundRequestFor(CueEventId.REDACTION_DISABLED, owner),
			nowMilliseconds=20,
		)
		self.assertEqual(again.decision, DispatchDecision.PLAY)


class SoundSchedulerInvalidationTests(unittest.TestCase):
	def test_global_invalidation_clears_all_state(self) -> None:
		scheduler = SoundScheduler()
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=0,
		)
		_drain(scheduler, start.token, now=10)
		_ = scheduler.dispatch(
			soundRequestFor(CueEventId.RAW_UIA_FALLBACK, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=20,
		)
		scheduler.invalidate()
		state = scheduler.state
		self.assertFalse(state.occupied)
		self.assertEqual(state.progressOwners, ())
		self.assertEqual(state.coalescedKeys, ())

	def test_targeted_invalidation_only_clears_the_named_owner(self) -> None:
		scheduler = SoundScheduler()
		other = _owner(SoundOwnerKind.MONITOR, 1)
		start = scheduler.dispatch(
			soundRequestFor(CueEventId.START_BOUNDED_FULL, _owner(SoundOwnerKind.CAPTURE, 1)),
			nowMilliseconds=0,
		)
		_drain(scheduler, start.token, now=10)
		scheduler.invalidate(other)
		self.assertEqual(len(scheduler.state.progressOwners), 1)


class SoundSchedulerClockTests(unittest.TestCase):
	def test_scheduler_clocks_require_nonnegative_integers(self) -> None:
		scheduler = SoundScheduler()
		request = soundRequestFor(CueEventId.LAYER_ENTERED, _owner(SoundOwnerKind.LAYER, 1))
		for invalid in (-1, True, 1.5, "1", None):
			with self.subTest(dispatchClock=invalid), self.assertRaises((ValueError, TypeError)):
				_ = scheduler.dispatch(request, nowMilliseconds=cast(int, invalid))
			with self.subTest(tickClock=invalid), self.assertRaises((ValueError, TypeError)):
				_ = scheduler.tick(cast(int, invalid))
			with self.subTest(completeClock=invalid), self.assertRaises((ValueError, TypeError)):
				_ = scheduler.completeAtom(1, nowMilliseconds=cast(int, invalid))

	def test_dispatch_of_nonrequest_is_rejected(self) -> None:
		scheduler = SoundScheduler()
		with self.assertRaises(AttributeError):
			_ = scheduler.dispatch(cast(SoundRequest, object()), nowMilliseconds=0)


class SoundAssetManifestTests(unittest.TestCase):
	def test_manifest_covers_every_atom_once_in_declaration_order(self) -> None:
		self.assertEqual(tuple(atom for atom, _ in SOUND_ASSETS), tuple(CueAtomId))

	def test_manifest_paths_are_unique(self) -> None:
		paths = [path for _, path in SOUND_ASSETS]
		self.assertEqual(len(set(paths)), len(paths))

	def test_manifest_matches_bundled_inventory_order_and_paths(self) -> None:
		self.assertEqual(len(SOUND_ASSETS), len(EXPECTED_INVENTORY))
		for (atom, path), (cueId, expectedPath, _role) in zip(SOUND_ASSETS, EXPECTED_INVENTORY, strict=True):
			with self.subTest(cue=cueId):
				self.assertEqual(atom.value, cueId)
				self.assertEqual(path, expectedPath)

	def test_manifest_entries_are_bare_wav_filenames(self) -> None:
		for atom, path in SOUND_ASSETS:
			with self.subTest(atom=atom):
				self.assertTrue(path.endswith(".wav"))
				self.assertNotIn("/", path)
				self.assertNotIn("\\", path)


if __name__ == "__main__":
	_ = unittest.main()
