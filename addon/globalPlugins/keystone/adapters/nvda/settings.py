from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import cast

from ...domain.settings import (
	SETTING_DEFINITIONS,
	SettingId,
	SettingKind,
	SettingsCandidate,
	SettingsSnapshot,
	validateCandidate,
)
from ...ports.effects import (
	EffectResult,
	PortError,
	PortOutcome,
	PortStatus,
	SettingsReadRequest,
	SettingsWriteRequest,
)


KEYSTONE_SECTION = "keystone"
_REVISION_KEY = "settingsRevision"
_REDACTION_POLICY_KEY = "redactionPolicyGeneration"
# Bumped whenever the shipped redaction default changes. Generation 1 is the move from redacting
# protected values by default to keeping every value visible unless the user opts in.
CURRENT_REDACTION_POLICY_GENERATION = 1
_READ_FAILED = "KS.SETTINGS.READ_FAILED"
_WRITE_FAILED = "KS.SETTINGS.WRITE_FAILED"
_BASE_ONLY_UNAVAILABLE = "KS.SETTINGS.BASE_ONLY_UNAVAILABLE"

NVDA_API_EVIDENCE = (
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
)


@dataclass(frozen=True, slots=True)
class ConfigRegistrationResult:
	available: bool
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.available == (self.errorCode is not None):
			raise ValueError("registration availability and error code are inconsistent")

	@classmethod
	def unavailable(cls) -> ConfigRegistrationResult:
		return cls(False, _BASE_ONLY_UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class RedactionMigrationOutcome:
	"""What happened to a stored redaction preference written before the default changed."""

	status: str
	previousValue: bool | None = None

	def __post_init__(self) -> None:
		if self.status not in ("migrated", "alreadyCurrent", "unavailable"):
			raise ValueError("unknown redaction migration status")
		if self.status != "migrated" and self.previousValue is not None:
			raise ValueError("only a migrated preference carries the value it replaced")

	@property
	def migrated(self) -> bool:
		return self.status == "migrated"


@dataclass(frozen=True, slots=True)
class SettingsLoadResult:
	status: str
	snapshot: SettingsSnapshot | None
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.status not in ("ready", "failed"):
			raise ValueError("unknown settings load status")
		if self.status == "ready" and (self.snapshot is None or self.errorCode is not None):
			raise ValueError("ready settings load requires a snapshot only")
		if self.status == "failed" and (self.snapshot is not None or self.errorCode is None):
			raise ValueError("failed settings load requires an error code only")


def buildConfigSpec() -> dict[str, str]:
	spec = {
		_REVISION_KEY: "integer(default=1, min=1)",
		_REDACTION_POLICY_KEY: "integer(default=0, min=0)",
	}
	for definition in SETTING_DEFINITIONS:
		if definition.kind is SettingKind.INTEGER:
			spec[definition.settingId.value] = (
				f"integer(default={definition.default}, min={definition.minimum}, max={definition.maximum})"
			)
		elif definition.kind in (SettingKind.BOOLEAN, SettingKind.HELD_CLOSED_BOOLEAN):
			spec[definition.settingId.value] = f"boolean(default={definition.default})"
		else:
			options = ", ".join(repr(choice) for choice in definition.choices)
			spec[definition.settingId.value] = f"option({options}, default={definition.default!r})"
	return spec


def initializeKeystoneBaseSection(configManager: object) -> ConfigRegistrationResult:
	if getattr(configManager, "baseConfigError", False) is not False:
		return ConfigRegistrationResult.unavailable()
	baseOnlySections = getattr(configManager, "BASE_ONLY_SECTIONS", ())
	if not isinstance(baseOnlySections, (set, frozenset)) or KEYSTONE_SECTION not in baseOnlySections:
		return ConfigRegistrationResult.unavailable()
	getItem = getattr(configManager, "__getitem__", None)
	if not callable(getItem):
		return ConfigRegistrationResult.unavailable()
	try:
		section = getItem(KEYSTONE_SECTION)
	except (AttributeError, KeyError, TypeError):
		return ConfigRegistrationResult.unavailable()
	if not isinstance(section, MutableMapping):
		return ConfigRegistrationResult.unavailable()
	return ConfigRegistrationResult(True)


def initializeLegacyKeystoneBaseSection(configManager: object) -> ConfigRegistrationResult:
	"""Register Keystone against NVDA 2026.1's base configuration surfaces.

	NVDA 2026.1 exposes ``BASE_ONLY_SECTIONS`` but predates ``config.configSections``. Registration
	therefore mirrors ``ConfigManager._initBaseConf`` for one section: attach the validated spec to the
	base profile, add the section to the public base-only registry, and leave overlay profiles untouched.
	Every partial mutation is rolled back if validation cannot complete.
	"""

	if getattr(configManager, "baseConfigError", False) is not False:
		return ConfigRegistrationResult.unavailable()
	baseOnlySections = getattr(configManager, "BASE_ONLY_SECTIONS", None)
	spec = getattr(configManager, "spec", None)
	profiles = getattr(configManager, "profiles", None)
	validator = getattr(configManager, "validator", None)
	if (
		not isinstance(baseOnlySections, set)
		or not isinstance(spec, MutableMapping)
		or not isinstance(profiles, list)
		or not profiles
		or validator is None
	):
		return ConfigRegistrationResult.unavailable()
	typedBaseOnlySections = cast(set[str], baseOnlySections)
	typedProfiles = cast(list[object], profiles)
	base = typedProfiles[0]
	if not isinstance(base, MutableMapping):
		return ConfigRegistrationResult.unavailable()
	typedSpec = cast(MutableMapping[str, object], spec)
	typedBase = cast(MutableMapping[str, object], base)
	sectionWasBaseOnly = KEYSTONE_SECTION in typedBaseOnlySections
	previousSpec = typedSpec.get(KEYSTONE_SECTION)
	hadSpec = KEYSTONE_SECTION in typedSpec
	createdSection = KEYSTONE_SECTION not in typedBase
	previousSection: dict[str, object] | None = None
	previousSectionSpec: object | None = None
	try:
		typedBaseOnlySections.add(KEYSTONE_SECTION)
		typedSpec[KEYSTONE_SECTION] = buildConfigSpec()
		if createdSection:
			typedBase[KEYSTONE_SECTION] = {}
		section = typedBase[KEYSTONE_SECTION]
		sectionSpec = typedSpec[KEYSTONE_SECTION]
		if not isinstance(section, MutableMapping) or not isinstance(sectionSpec, MutableMapping):
			raise TypeError("Keystone configuration section is unavailable")
		typedSection = cast(MutableMapping[str, object], section)
		previousSection = dict(typedSection)
		previousSectionSpec = getattr(typedSection, "configspec", None)
		setattr(typedSection, "configspec", cast(MutableMapping[str, object], sectionSpec))
		validate = getattr(typedBase, "validate", None)
		if not callable(validate):
			raise TypeError("NVDA base configuration validation is unavailable")
		if validate(validator, section=typedSection) is not True:
			raise ValueError("NVDA base configuration validation failed")
	except (AttributeError, KeyError, TypeError, ValueError):
		if createdSection:
			_ = typedBase.pop(KEYSTONE_SECTION, None)
		elif previousSection is not None:
			section = typedBase.get(KEYSTONE_SECTION)
			if isinstance(section, MutableMapping):
				typedSection = cast(MutableMapping[str, object], section)
				typedSection.clear()
				typedSection.update(previousSection)
				setattr(typedSection, "configspec", previousSectionSpec)
		if hadSpec:
			typedSpec[KEYSTONE_SECTION] = previousSpec
		else:
			_ = typedSpec.pop(KEYSTONE_SECTION, None)
		if not sectionWasBaseOnly:
			typedBaseOnlySections.discard(KEYSTONE_SECTION)
		return ConfigRegistrationResult.unavailable()
	return ConfigRegistrationResult(True)


def unregisterLegacyKeystoneBaseSection(configManager: object) -> ConfigRegistrationResult:
	"""Remove process-local legacy registration while preserving stored user values."""

	baseOnlySections = getattr(configManager, "BASE_ONLY_SECTIONS", None)
	spec = getattr(configManager, "spec", None)
	if not isinstance(baseOnlySections, set) or not isinstance(spec, MutableMapping):
		return ConfigRegistrationResult.unavailable()
	cast(set[str], baseOnlySections).discard(KEYSTONE_SECTION)
	_ = cast(MutableMapping[str, object], spec).pop(KEYSTONE_SECTION, None)
	return ConfigRegistrationResult(True)


class NvdaSettingsAdapter:
	def __init__(self, configManager: object) -> None:
		super().__init__()
		self._configManager = configManager

	def _baseSection(self) -> MutableMapping[str, object] | None:
		if getattr(self._configManager, "baseConfigError", False) is not False:
			return None
		baseOnlySections = getattr(self._configManager, "BASE_ONLY_SECTIONS", ())
		if not isinstance(baseOnlySections, (set, frozenset)) or KEYSTONE_SECTION not in baseOnlySections:
			return None
		getItem = getattr(self._configManager, "__getitem__", None)
		if not callable(getItem):
			return None
		try:
			section = getItem(KEYSTONE_SECTION)
		except (AttributeError, KeyError, TypeError):
			return None
		if not isinstance(section, MutableMapping):
			return None
		return cast(MutableMapping[str, object], section)

	def readSnapshot(self) -> SettingsLoadResult:
		section = self._baseSection()
		if section is None:
			return SettingsLoadResult("failed", None, _READ_FAILED)
		revision = section.get(_REVISION_KEY)
		if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
			return SettingsLoadResult("failed", None, _READ_FAILED)
		values: dict[str, object] = {}
		for definition in SETTING_DEFINITIONS:
			if definition.settingId.value not in section:
				return SettingsLoadResult("failed", None, _READ_FAILED)
			values[definition.attributeName] = section[definition.settingId.value]
		try:
			candidate = SettingsCandidate(startingRevision=revision, **values)
		except TypeError:
			return SettingsLoadResult("failed", None, _READ_FAILED)
		validation = validateCandidate(candidate)
		if not validation.isValid:
			return SettingsLoadResult("failed", None, _READ_FAILED)
		return SettingsLoadResult("ready", candidate.toSnapshot(revision))

	def migrateRedactionPolicy(self) -> RedactionMigrationOutcome:
		"""Retire a redaction preference that was stored under the previous shipped default.

		Keystone used to redact protected values by default. A configuration written back then holds
		``redactProtectedText`` whether or not the user ever chose it, so leaving it alone would keep
		people opted in to hiding evidence without ever having asked for it. The stored value is
		replaced by the current default exactly once, recorded by a generation marker so a later
		deliberate choice is never overwritten, and the caller is told what it replaced so the change
		can be spoken rather than made behind the user's back.
		"""

		section = self._baseSection()
		if section is None:
			return RedactionMigrationOutcome("unavailable")
		generation = section.get(_REDACTION_POLICY_KEY)
		if isinstance(generation, int) and not isinstance(generation, bool):
			if generation >= CURRENT_REDACTION_POLICY_GENERATION:
				return RedactionMigrationOutcome("alreadyCurrent")
		stored = section.get(SettingId.REDACT_PROTECTED_TEXT.value)
		previous = stored if isinstance(stored, bool) else None
		shippedDefault = next(
			definition.default
			for definition in SETTING_DEFINITIONS
			if definition.settingId is SettingId.REDACT_PROTECTED_TEXT
		)
		section[SettingId.REDACT_PROTECTED_TEXT.value] = shippedDefault
		section[_REDACTION_POLICY_KEY] = CURRENT_REDACTION_POLICY_GENERATION
		save = getattr(self._configManager, "save", None)
		if not callable(save):
			return RedactionMigrationOutcome("unavailable")
		try:
			_ = save()
		except Exception:
			return RedactionMigrationOutcome("unavailable")
		return RedactionMigrationOutcome("migrated", previous)

	def readSettings(self, _request: SettingsReadRequest) -> EffectResult:
		result = self.readSnapshot()
		if result.snapshot is None:
			return EffectResult(PortStatus("failed", 0), error=PortError(result.errorCode or _READ_FAILED))
		return EffectResult(
			PortStatus("ready", result.snapshot.settingsRevision),
			PortOutcome(
				"settingsSnapshot",
				(result.snapshot.settingsRevision, result.snapshot.asCandidate().namedValues()),
			),
		)

	def updateSettings(self, request: SettingsWriteRequest) -> EffectResult:
		loadResult = self.readSnapshot()
		current = loadResult.snapshot
		if current is None:
			return EffectResult(PortStatus("failed", 0), error=PortError(_READ_FAILED))
		if request.startingRevision != current.settingsRevision:
			return EffectResult(
				PortStatus("stale", current.settingsRevision),
				error=None,
			)
		names = tuple(name for name, _value in request.values)
		expectedNames = tuple(definition.settingId.value for definition in SETTING_DEFINITIONS)
		if len(names) != len(set(names)) or set(names) != set(expectedNames):
			return EffectResult(
				PortStatus("failed", current.settingsRevision),
				error=PortError(_WRITE_FAILED),
			)
		values = dict(request.values)
		candidate = SettingsCandidate(
			startingRevision=current.settingsRevision,
			**{
				definition.attributeName: values[definition.settingId.value]
				for definition in SETTING_DEFINITIONS
			},
		)
		validation = validateCandidate(candidate)
		if not validation.isValid:
			return EffectResult(
				PortStatus("failed", current.settingsRevision),
				error=PortError(_WRITE_FAILED),
			)
		nextRevision = current.settingsRevision + 1
		nextSnapshot = candidate.toSnapshot(nextRevision)
		section = self._baseSection()
		if section is None:
			return EffectResult(
				PortStatus("failed", current.settingsRevision),
				error=PortError(_READ_FAILED),
			)
		previous = dict(section)
		replacement: dict[str, object] = {
			_REVISION_KEY: nextRevision,
			**dict(nextSnapshot.asCandidate().namedValues()),
		}
		# The redaction generation marker is not a user setting, so a write must carry it forward
		# rather than reset it and migrate a preference the user has already been told about.
		storedGeneration = previous.get(_REDACTION_POLICY_KEY)
		if storedGeneration is not None:
			replacement[_REDACTION_POLICY_KEY] = storedGeneration
		try:
			section.clear()
			section.update(replacement)
			save = getattr(self._configManager, "save", None)
			if not callable(save):
				raise RuntimeError("NVDA configuration save is unavailable")
			_ = save()
		except Exception:
			section.clear()
			section.update(previous)
			return EffectResult(
				PortStatus("failed", current.settingsRevision),
				error=PortError(_WRITE_FAILED),
			)
		return EffectResult(
			PortStatus("ready", nextRevision),
			PortOutcome("settingsUpdated"),
		)
