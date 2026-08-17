from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import unittest

from addon.globalPlugins.keystone.application.settings_service import SettingsService
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.settings import (
	INTEGER_SETTING_DEFINITIONS,
	SETTING_DEFINITIONS,
	SettingId,
	SettingsSnapshot,
	SaveStatus,
	restoreDefaultCandidate,
	validateCandidate,
)
from addon.globalPlugins.keystone.ports.effects import (
	EffectResult,
	PortError,
	PortOutcome,
	PortStatus,
	SettingsReadRequest,
	SettingsWriteRequest,
)


CONTEXT = CorrelationFactory().admit(generation=1)


EXPECTED_SETTINGS = (
	(SettingId.MAXIMUM_NODES, 6_000, 100, 1_000_000),
	(SettingId.MAXIMUM_DEPTH, 40, 1, 1_000),
	(SettingId.CAPTURE_TIME_SECONDS, 45, 1, 3_600),
	(SettingId.MAXIMUM_TEXT_CHARACTERS, 20_000, 100, 100_000_000),
	(SettingId.PROGRESS_INTERVAL_SECONDS, 3, 1, 30),
	(SettingId.JSON_FULL_TAB_INDENTATION, False, None, None),
	(SettingId.EVENT_DETAIL_CHARACTERS, 100, 0, 1_000_000),
	(SettingId.EVENT_ROWS, 2_000, 0, 1_000_000),
	(SettingId.OFFLINE_FILE_MEGABYTES, 100, 0, 100_000),
	(SettingId.PROPERTY_INTERVAL_MILLISECONDS, 1_000, 250, 5_000),
	(SettingId.SWAP_PROPERTY_ACTIONS, False, None, None),
	(SettingId.REDACT_PROTECTED_TEXT, False, None, None),
	(SettingId.FORCE_RAW_UIA, False, None, None),
	(SettingId.SOUNDS_ENABLED, True, None, None),
)


class RecordingSettingsPort:
	def __init__(self, result: EffectResult | None = None) -> None:
		super().__init__()
		self.requests: list[SettingsWriteRequest] = []
		self.result = result

	def readSettings(self, request: SettingsReadRequest) -> EffectResult:
		raise AssertionError("save must not read settings")

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		self.requests.append(request)
		return self.result or EffectResult(
			PortStatus("ready", request.startingRevision + 1),
			PortOutcome("updated"),
		)


class SettingsRegistryTests(unittest.TestCase):
	def test_registry_owns_exact_defaults_ranges_and_panel_order(self) -> None:
		actual = tuple(
			(definition.settingId, definition.default, definition.minimum, definition.maximum)
			for definition in SETTING_DEFINITIONS
		)
		self.assertEqual(EXPECTED_SETTINGS, actual)
		self.assertEqual(
			(
				("visibleUiaRanges", 50),
				("selectionRanges", 50),
				("uiaElementArrayEntries", 200),
				("ia2Hyperlinks", 200),
				("focusMatchNodes", 150),
				("focusMatchDepth", 40),
				("workSliceMilliseconds", 150),
				("yieldMilliseconds", 10),
			),
			SettingsSnapshot.fixedCaptureLimits(),
		)

	def test_every_integer_boundary_is_accepted_without_coercion(self) -> None:
		defaults = SettingsSnapshot.defaults(settingsRevision=1).asCandidate()
		for definition in INTEGER_SETTING_DEFINITIONS:
			assert definition.minimum is not None
			assert definition.maximum is not None
			for value in (definition.minimum, definition.maximum):
				with self.subTest(setting=definition.settingId, value=value):
					candidate = defaults.withValue(definition.settingId, value)
					result = validateCandidate(candidate)
					self.assertTrue(result.isValid)
					self.assertEqual(value, result.candidate.value(definition.settingId))

	def test_adjacent_missing_noninteger_and_closed_values_are_rejected(self) -> None:
		defaults = SettingsSnapshot.defaults(settingsRevision=1).asCandidate()
		cases: tuple[tuple[SettingId, object], ...] = (
			(SettingId.MAXIMUM_NODES, 99),
			(SettingId.MAXIMUM_DEPTH, 1_001),
			(SettingId.CAPTURE_TIME_SECONDS, None),
			(SettingId.MAXIMUM_TEXT_CHARACTERS, 100.0),
			(SettingId.PROGRESS_INTERVAL_SECONDS, True),
			(SettingId.EVENT_DETAIL_CHARACTERS, -1),
			(SettingId.EVENT_ROWS, 1_000_001),
			(SettingId.OFFLINE_FILE_MEGABYTES, -1),
			(SettingId.PROPERTY_INTERVAL_MILLISECONDS, 5_001),
			(SettingId.JSON_FULL_TAB_INDENTATION, 1),
		)
		for settingId, value in cases:
			with self.subTest(setting=settingId, value=value):
				result = validateCandidate(defaults.withValue(settingId, value))
				self.assertFalse(result.isValid)
				self.assertEqual(settingId, result.issues[0].settingId)

	def test_validation_collects_all_issues_in_focus_order_without_unsafe_values(self) -> None:
		candidate = SettingsSnapshot.defaults(settingsRevision=4).asCandidate()
		for settingId, value in (
			(SettingId.OFFLINE_FILE_MEGABYTES, -1),
			(SettingId.MAXIMUM_NODES, 99),
			(SettingId.CAPTURE_TIME_SECONDS, None),
		):
			candidate = candidate.withValue(settingId, value)
		result = validateCandidate(candidate)
		self.assertEqual(
			(
				SettingId.MAXIMUM_NODES,
				SettingId.CAPTURE_TIME_SECONDS,
				SettingId.OFFLINE_FILE_MEGABYTES,
			),
			tuple(issue.settingId for issue in result.issues),
		)
		self.assertEqual(SettingId.MAXIMUM_NODES, result.firstInvalidSettingId)
		self.assertNotIn("submitted secret", repr(result.issues))

	def test_raw_uia_preference_accepts_true_when_runtime_availability_is_checked_separately(self) -> None:
		candidate = (
			SettingsSnapshot.defaults(settingsRevision=1)
			.asCandidate()
			.withValue(
				SettingId.FORCE_RAW_UIA,
				True,
			)
		)

		result = validateCandidate(candidate)

		self.assertTrue(result.isValid)
		self.assertTrue(result.candidate.forceRawUia)

	def test_restore_defaults_is_an_unsaved_complete_candidate(self) -> None:
		current = replace(
			SettingsSnapshot.defaults(settingsRevision=9),
			maximumNodes=777,
			redactProtectedText=False,
		)
		restored = restoreDefaultCandidate(current)
		self.assertEqual(9, restored.startingRevision)
		self.assertEqual(SettingsSnapshot.defaults(settingsRevision=9).asCandidate(), restored)

	def test_snapshots_and_candidates_are_immutable_and_revision_is_positive(self) -> None:
		snapshot = SettingsSnapshot.defaults(settingsRevision=1)
		candidate = snapshot.asCandidate()
		with self.assertRaises(FrozenInstanceError):
			snapshot.maximumNodes = 10  # type: ignore[misc]
		with self.assertRaises(FrozenInstanceError):
			candidate.maximumNodes = 10  # type: ignore[misc]
		with self.assertRaises(ValueError):
			_ = SettingsSnapshot.defaults(settingsRevision=0)


class SettingsTransactionTests(unittest.TestCase):
	def test_invalid_candidate_has_no_effect_and_keeps_revision(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=3)
		candidate = current.asCandidate().withValue(SettingId.MAXIMUM_NODES, 99)
		port = RecordingSettingsPort()
		result = SettingsService(port).save(current, candidate, CONTEXT)
		self.assertEqual(SaveStatus.REJECTED, result.status)
		self.assertEqual(current, result.snapshot)
		self.assertEqual(3, result.snapshot.settingsRevision)
		self.assertEqual((), tuple(port.requests))

	def test_valid_candidate_commits_once_and_increments_revision_once(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=5)
		candidate = (
			current.asCandidate()
			.withValue(SettingId.MAXIMUM_NODES, 7_000)
			.withValue(SettingId.REDACT_PROTECTED_TEXT, False)
		)
		port = RecordingSettingsPort()
		result = SettingsService(port).save(current, candidate, CONTEXT)
		self.assertEqual(SaveStatus.UPDATED, result.status)
		self.assertEqual(6, result.snapshot.settingsRevision)
		self.assertEqual(7_000, result.snapshot.maximumNodes)
		self.assertFalse(result.snapshot.redactProtectedText)
		self.assertEqual(1, len(port.requests))
		self.assertEqual(5, port.requests[0].startingRevision)
		self.assertEqual(candidate.namedValues(), port.requests[0].values)
		self.assertIs(CONTEXT, port.requests[0].context)

	def test_stale_concurrent_candidate_is_rejected_before_commit(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=8)
		stale = SettingsSnapshot.defaults(settingsRevision=7).asCandidate()
		port = RecordingSettingsPort()
		result = SettingsService(port).save(current, stale, CONTEXT)
		self.assertEqual(SaveStatus.REJECTED, result.status)
		self.assertEqual("staleRevision", result.issues[0].reasonCode)
		self.assertEqual(current, result.snapshot)
		self.assertEqual((), tuple(port.requests))

	def test_unexpected_adapter_revision_fails_closed(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=2)
		port = RecordingSettingsPort(
			EffectResult(PortStatus("ready", 8), PortOutcome("updated")),
		)
		result = SettingsService(port).save(current, current.asCandidate(), CONTEXT)
		self.assertEqual(SaveStatus.FAILED, result.status)
		self.assertEqual(current, result.snapshot)
		self.assertEqual("KS.SETTINGS.REVISION_MISMATCH", result.errorCode)

	def test_adapter_failure_does_not_publish_candidate_as_current(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=2)
		port = RecordingSettingsPort(
			EffectResult(
				PortStatus("failed", 2),
				error=PortError("KS.SETTINGS.ACCESS_DENIED"),
			),
		)
		result = SettingsService(port).save(current, current.asCandidate(), CONTEXT)
		self.assertEqual(SaveStatus.FAILED, result.status)
		self.assertEqual(current, result.snapshot)
		self.assertEqual("KS.SETTINGS.ACCESS_DENIED", result.errorCode)


if __name__ == "__main__":
	_ = unittest.main()
