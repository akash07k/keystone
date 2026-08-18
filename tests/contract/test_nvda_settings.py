from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from types import SimpleNamespace
from typing import Protocol, cast, override
import unittest
from unittest.mock import patch

from addon.globalPlugins.keystone.domain.settings import SettingId, SettingsSnapshot
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.ports.effects import EffectResult, SettingsWriteRequest


class RegistrationResultLike(Protocol):
	available: bool
	errorCode: str | None


class InstallTasksLike(Protocol):
	def registerKeystoneSection(self, api: object) -> RegistrationResultLike: ...

	def unregisterKeystoneSection(self, api: object) -> RegistrationResultLike: ...

	def registerLegacyKeystoneSection(self, manager: object) -> RegistrationResultLike: ...

	def unregisterLegacyKeystoneSection(self, manager: object) -> RegistrationResultLike: ...

	def onInstall(self) -> None: ...


class SettingsLoadResultLike(Protocol):
	status: str
	snapshot: SettingsSnapshot | None
	errorCode: str | None


class RedactionMigrationOutcomeLike(Protocol):
	status: str
	previousValue: bool | None

	@property
	def migrated(self) -> bool: ...


class NvdaSettingsAdapterLike(Protocol):
	def readSnapshot(self) -> SettingsLoadResultLike: ...

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult: ...

	def migrateRedactionPolicy(self) -> RedactionMigrationOutcomeLike: ...


class AdapterFactory(Protocol):
	def __call__(self, manager: object) -> NvdaSettingsAdapterLike: ...


class SettingsModuleLike(Protocol):
	KEYSTONE_SECTION: str
	NVDA_API_EVIDENCE: tuple[tuple[str, str], ...]
	CURRENT_REDACTION_POLICY_GENERATION: int
	NvdaSettingsAdapter: AdapterFactory

	def buildConfigSpec(self) -> dict[str, str]: ...

	def initializeKeystoneBaseSection(self, manager: object) -> RegistrationResultLike: ...

	def initializeLegacyKeystoneBaseSection(self, manager: object) -> RegistrationResultLike: ...


installTasks = cast(InstallTasksLike, cast(object, import_module("addon.installTasks")))
settingsModule = cast(
	SettingsModuleLike,
	cast(object, import_module("addon.globalPlugins.keystone.adapters.nvda.settings")),
)
KEYSTONE_SECTION = settingsModule.KEYSTONE_SECTION
NVDA_API_EVIDENCE = settingsModule.NVDA_API_EVIDENCE
NvdaSettingsAdapter = settingsModule.NvdaSettingsAdapter
buildConfigSpec = settingsModule.buildConfigSpec
CONTEXT = CorrelationFactory().admit(generation=1)


class FakeConfigSections:
	def __init__(self, *, supported: bool = True) -> None:
		super().__init__()
		self.supported = supported
		self.calls: list[tuple[object, ...]] = []
		self.spec: dict[str, object] = {}

	def registerSection(self, name: str, spec: dict[str, str], *, isBaseOnly: bool) -> None:
		if not self.supported:
			raise TypeError("isBaseOnly is unsupported")
		self.calls.append(("register", name, spec, isBaseOnly))

	def unregisterSection(self, name: str) -> None:
		self.calls.append(("unregister", name))


class FakeConfigManager:
	BASE_ONLY_SECTIONS = {KEYSTONE_SECTION}

	def __init__(
		self,
		snapshot: SettingsSnapshot | None,
		*,
		overlays: tuple[dict[str, object], ...] = (),
		baseError: bool = False,
		saveError: Exception | None = None,
	) -> None:
		super().__init__()
		base: dict[str, object] = {}
		if snapshot is not None:
			base[KEYSTONE_SECTION] = _stored(snapshot)
		self.profiles = [base, *deepcopy(overlays)]
		self.baseConfigError = baseError
		self.saveError = saveError
		self.saveCalls = 0

	def __getitem__(self, key: str) -> object:
		return self.profiles[0][key]

	def save(self) -> None:
		self.saveCalls += 1
		if self.saveError is not None:
			raise self.saveError


class FakeConfigSection(dict[str, object]):
	def __init__(self, *args: object, validationResult: object = True, **kwargs: object) -> None:
		super().__init__(*args, **kwargs)
		self.configspec: object | None = None
		self.validationResult = validationResult

	@override
	def __setitem__(self, key: str, value: object) -> None:
		if isinstance(value, dict) and not isinstance(value, FakeConfigSection):
			value = FakeConfigSection(cast(dict[str, object], value))
		super().__setitem__(key, value)

	def validate(self, _validator: object, *, section: object) -> object:
		assert isinstance(section, FakeConfigSection)
		for key, value in _stored(SettingsSnapshot.defaults(settingsRevision=1)).items():
			_ = section.setdefault(key, value)
		return self.validationResult


class FreshRuntimeConfigManager:
	def __init__(self) -> None:
		super().__init__()
		self.BASE_ONLY_SECTIONS = {KEYSTONE_SECTION}
		self.profiles = [
			FakeConfigSection(
				{
					KEYSTONE_SECTION: FakeConfigSection(
						_stored(SettingsSnapshot.defaults(settingsRevision=1)),
					),
				},
			),
		]
		self.baseConfigError = False
		self.saveCalls = 0

	def __getitem__(self, key: str) -> object:
		return self.profiles[0][key]

	def save(self) -> None:
		self.saveCalls += 1


class LegacyRuntimeConfigManager:
	def __init__(
		self,
		*,
		persisted: dict[str, object] | None = None,
		validator: object | None = None,
		validationResult: object = True,
	) -> None:
		super().__init__()
		self.BASE_ONLY_SECTIONS = {"general"}
		self.spec = FakeConfigSection()
		base = FakeConfigSection(validationResult=validationResult)
		if persisted is not None:
			base[KEYSTONE_SECTION] = FakeConfigSection(persisted)
		self.profiles = [base]
		self.validator = object() if validator is None else validator
		self.baseConfigError = False
		self.saveCalls = 0

	def __getitem__(self, key: str) -> object:
		if key in self.BASE_ONLY_SECTIONS:
			return self.profiles[0][key]
		raise KeyError(key)

	def save(self) -> None:
		self.saveCalls += 1


def _stored(snapshot: SettingsSnapshot) -> dict[str, object]:
	return {
		"settingsRevision": snapshot.settingsRevision,
		"redactionPolicyGeneration": settingsModule.CURRENT_REDACTION_POLICY_GENERATION,
		**dict(snapshot.asCandidate().namedValues()),
	}


class RegistrationTests(unittest.TestCase):
	def test_runtime_initialization_accepts_the_registered_base_only_section(self) -> None:
		manager = FreshRuntimeConfigManager()
		initialize = settingsModule.initializeKeystoneBaseSection

		result = initialize(manager)
		loaded = NvdaSettingsAdapter(manager).readSnapshot()

		self.assertTrue(result.available)
		self.assertEqual(SettingsSnapshot.defaults(settingsRevision=1), loaded.snapshot)

	def test_missing_base_only_registration_is_unavailable_without_mutation(self) -> None:
		manager = FreshRuntimeConfigManager()
		manager.BASE_ONLY_SECTIONS.clear()
		before = deepcopy(manager.profiles)

		result = settingsModule.initializeKeystoneBaseSection(manager)

		self.assertFalse(result.available)
		self.assertEqual(before, manager.profiles)

	def test_legacy_2026_1_initialization_registers_and_preserves_the_base_section(self) -> None:
		persisted = _stored(SettingsSnapshot.defaults(settingsRevision=7))
		persisted["maximumNodes"] = 7_777
		manager = LegacyRuntimeConfigManager(persisted=persisted)

		result = settingsModule.initializeLegacyKeystoneBaseSection(manager)
		loaded = NvdaSettingsAdapter(manager).readSnapshot()

		self.assertTrue(result.available)
		self.assertIn(KEYSTONE_SECTION, manager.BASE_ONLY_SECTIONS)
		self.assertEqual(buildConfigSpec(), manager.spec[KEYSTONE_SECTION])
		section = cast(FakeConfigSection, manager.profiles[0][KEYSTONE_SECTION])
		self.assertEqual(buildConfigSpec(), section.configspec)
		self.assertIsNotNone(loaded.snapshot)
		assert loaded.snapshot is not None
		self.assertEqual(7_777, loaded.snapshot.maximumNodes)
		self.assertEqual(7, loaded.snapshot.settingsRevision)

	def test_legacy_initialization_rolls_back_every_partial_registration_on_failure(self) -> None:
		manager = LegacyRuntimeConfigManager()
		manager.validator = None
		beforeSections = set(manager.BASE_ONLY_SECTIONS)
		beforeSpec = deepcopy(manager.spec)
		beforeBase = deepcopy(manager.profiles[0])

		result = settingsModule.initializeLegacyKeystoneBaseSection(manager)

		self.assertFalse(result.available)
		self.assertEqual(beforeSections, manager.BASE_ONLY_SECTIONS)
		self.assertEqual(beforeSpec, manager.spec)
		self.assertEqual(beforeBase, manager.profiles[0])

	def test_legacy_initialization_rolls_back_on_false_or_nested_validation_failure(self) -> None:
		for validationResult in (False, {KEYSTONE_SECTION: {"maximumNodes": False}}):
			with self.subTest(validationResult=validationResult):
				persisted = _stored(SettingsSnapshot.defaults(settingsRevision=7))
				persisted["maximumNodes"] = 7_777
				manager = LegacyRuntimeConfigManager(
					persisted=persisted,
					validationResult=validationResult,
				)
				beforeSections = set(manager.BASE_ONLY_SECTIONS)
				beforeSpec = deepcopy(manager.spec)
				beforeBase = deepcopy(manager.profiles[0])

				result = settingsModule.initializeLegacyKeystoneBaseSection(manager)

				self.assertFalse(result.available)
				self.assertEqual(beforeSections, manager.BASE_ONLY_SECTIONS)
				self.assertEqual(beforeSpec, manager.spec)
				self.assertEqual(beforeBase, manager.profiles[0])

	def test_registers_and_unregisters_one_base_only_section(self) -> None:
		api = FakeConfigSections()

		result = installTasks.registerKeystoneSection(api)
		removed = installTasks.unregisterKeystoneSection(api)

		self.assertTrue(result.available)
		self.assertTrue(removed.available)
		self.assertEqual(
			[
				("register", KEYSTONE_SECTION, buildConfigSpec(), True),
				("unregister", KEYSTONE_SECTION),
			],
			api.calls,
		)
		self.assertEqual(set(buildConfigSpec()), set(_stored(SettingsSnapshot.defaults(settingsRevision=1))))

	def test_unsupported_registration_stays_unavailable_without_spec_mutation(self) -> None:
		api = FakeConfigSections(supported=False)

		result = installTasks.registerKeystoneSection(api)

		self.assertFalse(result.available)
		self.assertEqual(result.errorCode, "KS.SETTINGS.BASE_ONLY_UNAVAILABLE")
		self.assertEqual(api.spec, {})
		self.assertEqual(api.calls, [])

	def test_install_uses_legacy_2026_1_registration_only_when_new_module_is_absent(self) -> None:
		manager = LegacyRuntimeConfigManager()
		config = SimpleNamespace(conf=manager)

		def importHostModule(name: str) -> object:
			if name == "config.configSections":
				error = ModuleNotFoundError(name)
				error.name = name
				raise error
			if name == "config":
				return config
			raise ImportError(name)

		with patch("addon.installTasks.import_module", side_effect=importHostModule):
			installTasks.onInstall()

		self.assertEqual(1, manager.saveCalls)
		self.assertTrue(NvdaSettingsAdapter(manager).readSnapshot().status == "ready")

	def test_install_keeps_the_new_registration_api_when_available(self) -> None:
		api = FakeConfigSections()

		with patch("addon.installTasks.import_module", return_value=api):
			installTasks.onInstall()

		self.assertEqual([("register", KEYSTONE_SECTION, buildConfigSpec(), True)], api.calls)

	def test_install_fails_explicitly_when_the_selected_registration_path_fails(self) -> None:
		api = FakeConfigSections(supported=False)

		with (
			patch("addon.installTasks.import_module", return_value=api),
			self.assertRaises(RuntimeError),
		):
			installTasks.onInstall()

	def test_records_exact_reviewed_nvda_api_sources(self) -> None:
		self.assertEqual(
			NVDA_API_EVIDENCE,
			(
				("source/config/configSections.py", "registerSection"),
				("source/config/configSections.py", "unregisterSection"),
				("source/config/configSections.py", "_addSection"),
				("release-2026.1.1/source/config/__init__.py", "ConfigManager.spec"),
				("release-2026.1.1/source/config/__init__.py", "ConfigManager.profiles[0]"),
				("release-2026.1.1/source/config/__init__.py", "section.configspec"),
				("release-2026.1.1/source/config/__init__.py", "profile.validate"),
				("source/config/__init__.py", "ConfigManager.BASE_ONLY_SECTIONS"),
				("source/config/__init__.py", "ConfigManager.__getitem__"),
				("source/config/__init__.py", "ConfigManager.save"),
			),
		)


class RedactionMigrationTests(unittest.TestCase):
	def _legacyManager(self, *, storedRedaction: bool) -> FakeConfigManager:
		snapshot = SettingsSnapshot.defaults(settingsRevision=5)
		manager = FakeConfigManager(snapshot)
		section = cast(dict[str, object], manager.profiles[0][KEYSTONE_SECTION])
		section["redactProtectedText"] = storedRedaction
		del section["redactionPolicyGeneration"]
		return manager

	def test_a_preference_stored_under_the_old_default_is_retired_once(self) -> None:
		manager = self._legacyManager(storedRedaction=True)
		adapter = NvdaSettingsAdapter(manager)

		outcome = adapter.migrateRedactionPolicy()

		self.assertTrue(outcome.migrated)
		self.assertIs(True, outcome.previousValue)
		section = cast(dict[str, object], manager.profiles[0][KEYSTONE_SECTION])
		self.assertIs(False, section["redactProtectedText"])
		self.assertEqual(
			settingsModule.CURRENT_REDACTION_POLICY_GENERATION,
			section["redactionPolicyGeneration"],
		)
		self.assertEqual(1, manager.saveCalls)

		self.assertEqual("alreadyCurrent", adapter.migrateRedactionPolicy().status)
		self.assertEqual(1, manager.saveCalls)

	def test_a_deliberate_choice_made_after_the_migration_is_kept(self) -> None:
		manager = self._legacyManager(storedRedaction=True)
		adapter = NvdaSettingsAdapter(manager)
		_ = adapter.migrateRedactionPolicy()
		current = adapter.readSnapshot().snapshot
		assert current is not None
		candidate = current.asCandidate().withValue(SettingId.REDACT_PROTECTED_TEXT, True)

		result = adapter.updateSettings(
			SettingsWriteRequest(current.settingsRevision, candidate.namedValues(), CONTEXT),
		)

		self.assertEqual("ready", result.status.token)
		section = cast(dict[str, object], manager.profiles[0][KEYSTONE_SECTION])
		self.assertIs(True, section["redactProtectedText"])
		self.assertEqual(
			settingsModule.CURRENT_REDACTION_POLICY_GENERATION,
			section["redactionPolicyGeneration"],
		)
		self.assertEqual("alreadyCurrent", adapter.migrateRedactionPolicy().status)
		self.assertIs(True, section["redactProtectedText"])

	def test_an_unreadable_configuration_reports_the_migration_as_unavailable(self) -> None:
		manager = FakeConfigManager(SettingsSnapshot.defaults(settingsRevision=1), baseError=True)

		self.assertEqual("unavailable", NvdaSettingsAdapter(manager).migrateRedactionPolicy().status)


class AdapterTests(unittest.TestCase):
	def test_reads_only_the_base_profile_despite_conflicting_overlays(self) -> None:
		base = SettingsSnapshot.defaults(settingsRevision=7)
		overlayValues = _stored(base)
		overlayValues["maximumNodes"] = 999_999
		manager = FakeConfigManager(
			base,
			overlays=(
				{KEYSTONE_SECTION: overlayValues},
				{KEYSTONE_SECTION: {"maximumNodes": 888_888}},
			),
		)

		result = NvdaSettingsAdapter(manager).readSnapshot()

		self.assertEqual(result.snapshot, base)
		self.assertEqual(result.status, "ready")

	def test_obsolete_independent_log_values_do_not_block_loading(self) -> None:
		expected = SettingsSnapshot.defaults(settingsRevision=7)
		manager = FakeConfigManager(expected)
		section = cast(dict[str, object], manager.profiles[0][KEYSTONE_SECTION])
		section.update(
			{
				"independentLogEnabled": True,
				"independentLogFormat": "jsonl",
				"independentLogLevel": "debug",
			},
		)

		result = NvdaSettingsAdapter(manager).readSnapshot()

		self.assertEqual("ready", result.status)
		self.assertEqual(expected, result.snapshot)

	def test_missing_corrupt_or_unreadable_base_is_failed_not_defaulted(self) -> None:
		cases = (
			FakeConfigManager(None),
			FakeConfigManager(SettingsSnapshot.defaults(settingsRevision=1), baseError=True),
			FakeConfigManager(SettingsSnapshot.defaults(settingsRevision=1)),
		)
		cases[2].profiles[0][KEYSTONE_SECTION] = {"settingsRevision": "broken"}

		for manager in cases:
			with self.subTest(manager=manager):
				result = NvdaSettingsAdapter(manager).readSnapshot()
				self.assertEqual(result.status, "failed")
				self.assertIsNone(result.snapshot)
				self.assertEqual(result.errorCode, "KS.SETTINGS.READ_FAILED")

	def test_complete_write_updates_base_once_and_advances_revision(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=3)
		manager = FakeConfigManager(
			current,
			overlays=({KEYSTONE_SECTION: {"maximumNodes": 123}},),
		)
		overlayBefore = deepcopy(manager.profiles[1])
		candidate = current.asCandidate().withValue(SettingId.MAXIMUM_NODES, 8_000)
		request = SettingsWriteRequest(current.settingsRevision, candidate.namedValues(), CONTEXT)

		result = NvdaSettingsAdapter(manager).updateSettings(request)

		self.assertEqual(result.status.token, "ready")
		self.assertEqual(result.status.revision, 4)
		self.assertEqual(manager.saveCalls, 1)
		self.assertEqual(manager.profiles[1], overlayBefore)
		self.assertEqual(manager.profiles[0][KEYSTONE_SECTION]["maximumNodes"], 8_000)  # type: ignore[index]
		self.assertEqual(manager.profiles[0][KEYSTONE_SECTION]["settingsRevision"], 4)  # type: ignore[index]

	def test_failed_save_restores_the_complete_base_snapshot(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=11)
		manager = FakeConfigManager(current, saveError=PermissionError("read only"))
		before = deepcopy(manager.profiles[0][KEYSTONE_SECTION])
		candidate = current.asCandidate().withValue(SettingId.MAXIMUM_DEPTH, 55)

		result = NvdaSettingsAdapter(manager).updateSettings(
			SettingsWriteRequest(current.settingsRevision, candidate.namedValues(), CONTEXT),
		)

		self.assertEqual(result.status.token, "failed")
		self.assertIsNotNone(result.error)
		assert result.error is not None
		self.assertEqual(result.error.code, "KS.SETTINGS.WRITE_FAILED")
		self.assertEqual(manager.profiles[0][KEYSTONE_SECTION], before)
		self.assertEqual(manager.saveCalls, 1)

	def test_stale_or_partial_writes_do_not_mutate_or_save(self) -> None:
		current = SettingsSnapshot.defaults(settingsRevision=5)
		for request in (
			SettingsWriteRequest(4, current.asCandidate().namedValues(), CONTEXT),
			SettingsWriteRequest(5, (("maximumNodes", 4_000),), CONTEXT),
		):
			manager = FakeConfigManager(current)
			before = deepcopy(manager.profiles[0])

			result = NvdaSettingsAdapter(manager).updateSettings(request)

			self.assertIn(result.status.token, ("stale", "failed"))
			self.assertEqual(manager.profiles[0], before)
			self.assertEqual(manager.saveCalls, 0)


if __name__ == "__main__":
	_ = unittest.main()
