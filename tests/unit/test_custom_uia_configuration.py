from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from addon.globalPlugins.keystone.adapters.nvda.custom_uia_registry import CustomUiaRegistry
from addon.globalPlugins.keystone.application.custom_uia_service import CustomUiaService
from addon.globalPlugins.keystone.domain.custom_uia import (
	BUILT_IN_CATALOG,
	CATALOG_VERSION,
	CustomUiaConfiguration,
	CustomUiaProperty,
	parseConfiguration,
	serializeConfiguration,
	stableKeyForGuid,
	validateConfiguration,
)


_GUID_A = "{12345678-1234-4ABC-8DEF-1234567890AB}"
_GUID_B = "{22345678-1234-4ABC-8DEF-1234567890AB}"


def _property(**changes: object) -> CustomUiaProperty:
	values: dict[str, object] = {
		"stableKey": "sample.reading-mode",
		"canonicalGuid": _GUID_A,
		"name": "Sample.ReadingMode",
		"propertyType": "string",
		"privacy": "unknown",
		"enabled": True,
		"description": "Sample property.",
		"executableTarget": "sample.exe",
		"frameworkFilter": None,
		"windowClassFilter": None,
		"displayName": "Reading mode",
	}
	values.update(changes)
	return CustomUiaProperty(**values)  # type: ignore[arg-type]


class ConfigurationValidationTests(unittest.TestCase):
	def test_closed_document_round_trips_as_utf8_with_canonical_guid(self) -> None:
		raw = json.dumps(
			{
				"schemaVersion": 1,
				"properties": [
					{
						"stableKey": "sample.reading-mode",
						"canonicalGuid": _GUID_A.lower(),
						"name": "Sample.ReadingMode",
						"displayName": "Reading mode",
						"type": "string",
						"privacy": "unknown",
						"enabled": True,
						"description": "Sample property.",
						"executableTarget": "sample.exe",
					},
				],
			},
		).encode()

		result = parseConfiguration(raw)

		self.assertTrue(result.isValid)
		assert result.configuration is not None
		self.assertEqual(_GUID_A, result.configuration.properties[0].canonicalGuid)
		self.assertEqual(
			result.configuration,
			parseConfiguration(serializeConfiguration(result.configuration)).configuration,
		)
		self.assertEqual("Reading mode", result.configuration.properties[0].displayName)
		self.assertIn(b'\n\t"properties": [', serializeConfiguration(result.configuration))

	def test_missing_definition_id_is_generated_from_the_property_guid(self) -> None:
		raw = json.dumps(
			{
				"schemaVersion": 1,
				"properties": [
					{
						"canonicalGuid": _GUID_A,
						"name": "Sample.ReadingMode",
						"type": "string",
						"privacy": "unknown",
						"enabled": True,
						"executableTarget": "sample.exe",
					},
				],
			},
		).encode()

		result = parseConfiguration(raw)

		self.assertTrue(result.isValid)
		assert result.configuration is not None
		self.assertEqual(stableKeyForGuid(_GUID_A), result.configuration.properties[0].stableKey)

	def test_enum_values_round_trip_and_require_a_nonempty_unique_mapping(self) -> None:
		enumProperty = _property(
			propertyType="enum",
			enumValues=((1, "ViewSlide"), (9, "ViewNormal")),
		)
		result = validateConfiguration(CustomUiaConfiguration(1, (enumProperty,)))

		self.assertTrue(result.isValid)
		assert result.configuration is not None
		self.assertEqual(
			((1, "ViewSlide"), (9, "ViewNormal")),
			result.configuration.properties[0].enumValues,
		)
		self.assertEqual(
			result.configuration,
			parseConfiguration(serializeConfiguration(result.configuration)).configuration,
		)
		for invalid in (
			replace(enumProperty, enumValues=()),
			replace(enumProperty, enumValues=((1, "ViewSlide"), (1, "Duplicate"))),
			replace(_property(), enumValues=((1, "Not an enum"),)),
		):
			with self.subTest(invalid=invalid):
				issues = validateConfiguration(CustomUiaConfiguration(1, (invalid,))).issues
				self.assertIn("KSERR_CUIA_ENUM_VALUES_INVALID", {issue.code for issue in issues})

	def test_validation_matrix_rejects_unsafe_or_open_ended_input(self) -> None:
		base = json.loads(serializeConfiguration(CustomUiaConfiguration(1, (_property(),))))
		cases: tuple[tuple[str, object, str], ...] = (
			("schemaVersion", 2, "KSERR_CUIA_SCHEMA_VERSION"),
			("unknownRoot", True, "KSERR_CUIA_UNKNOWN_FIELD"),
			("entryUnknown", True, "KSERR_CUIA_UNKNOWN_FIELD"),
			("type", "rect", "KSERR_CUIA_TYPE_INVALID"),
			("privacy", "public", "KSERR_CUIA_PRIVACY_INVALID"),
			("stableKey", "Unsafe Key", "KSERR_CUIA_KEY_INVALID"),
			("canonicalGuid", "{00000000-0000-0000-0000-000000000000}", "KSERR_CUIA_GUID_INVALID"),
			("name", "Bad\nName", "KSERR_CUIA_UNSAFE_TEXT"),
			("displayName", "Bad\nName", "KSERR_CUIA_UNSAFE_TEXT"),
			("executableTarget", r"C:\apps\sample.exe", "KSERR_CUIA_EXPANSION_FORBIDDEN"),
			("frameworkFilter", "*", "KSERR_CUIA_EXPANSION_FORBIDDEN"),
			("windowClassFilter", "https://example.invalid", "KSERR_CUIA_EXPANSION_FORBIDDEN"),
		)
		for field, value, code in cases:
			with self.subTest(field=field):
				document = json.loads(json.dumps(base))
				if field == "schemaVersion":
					document[field] = value
				elif field == "unknownRoot":
					document[field] = value
				elif field == "entryUnknown":
					document["properties"][0]["module"] = value
				else:
					document["properties"][0][field] = value
				result = parseConfiguration(json.dumps(document).encode())
				self.assertFalse(result.isValid)
				self.assertIn(code, {issue.code for issue in result.issues})

	def test_json_types_and_duplicate_members_are_rejected_without_exceptions(self) -> None:
		base = json.loads(serializeConfiguration(CustomUiaConfiguration(1, (_property(),))))
		cases: tuple[tuple[str, object], ...] = (
			("stableKey", 7),
			("canonicalGuid", False),
			("name", list[object]()),
			("displayName", list[object]()),
			("type", 1),
			("privacy", None),
			("enabled", 1),
			("description", dict[str, object]()),
			("executableTarget", ["sample.exe"]),
			("frameworkFilter", 2.5),
			("windowClassFilter", True),
		)
		for field, value in cases:
			with self.subTest(field=field):
				document = json.loads(json.dumps(base))
				document["properties"][0][field] = value
				self.assertFalse(parseConfiguration(json.dumps(document).encode()).isValid)
		self.assertFalse(
			parseConfiguration(b'{"schemaVersion":1,"schemaVersion":1,"properties":[]}').isValid,
		)

	def test_size_count_and_string_limits_are_closed_before_side_effects(self) -> None:
		self.assertIn(
			"KSERR_CUIA_FILE_INVALID",
			{i.code for i in parseConfiguration(b"x" * (1024 * 1024 + 1)).issues},
		)
		tooMany = CustomUiaConfiguration(
			1,
			tuple(
				_property(
					stableKey=f"sample.key-{index}",
					canonicalGuid=f"{{12345678-1234-4ABC-8DEF-{index:012X}}}",
				)
				for index in range(257)
			),
		)
		self.assertIn("KSERR_CUIA_COUNT_LIMIT", {i.code for i in validateConfiguration(tooMany).issues})
		tooLong = replace(_property(), description="x" * 513)
		self.assertIn(
			"KSERR_CUIA_STRING_LIMIT",
			{i.code for i in validateConfiguration(CustomUiaConfiguration(1, (tooLong,))).issues},
		)

	def test_collisions_deduplicate_exact_entries_and_reject_identity_conflicts(self) -> None:
		exact = validateConfiguration(CustomUiaConfiguration(1, (_property(), _property())))
		self.assertTrue(exact.isValid)
		assert exact.configuration is not None
		self.assertEqual(1, len(exact.configuration.properties))
		self.assertIn("KS_CUIA_EXACT_DUPLICATE", {warning.code for warning in exact.warnings})

		cases = (
			(replace(_property(), name="Other.Name"), "KSERR_CUIA_GUID_CONFLICT"),
			(replace(_property(), canonicalGuid=_GUID_B), "KSERR_CUIA_KEY_CONFLICT"),
			(
				replace(
					_property(),
					canonicalGuid=BUILT_IN_CATALOG[0].canonicalGuid,
					name="Invented.Name",
				),
				"KSERR_CUIA_CATALOG_CONFLICT",
			),
		)
		for conflicting, code in cases:
			with self.subTest(code=code):
				result = validateConfiguration(CustomUiaConfiguration(1, (_property(), conflicting)))
				self.assertFalse(result.isValid)
				self.assertIn(code, {issue.code for issue in result.issues})

		nameOnly = replace(_property(), stableKey="sample.second", canonicalGuid=_GUID_B)
		accepted = validateConfiguration(CustomUiaConfiguration(1, (_property(), nameOnly)))
		self.assertTrue(accepted.isValid)
		self.assertIn("KS_CUIA_NAME_COLLISION", {warning.code for warning in accepted.warnings})

	def test_catalog_is_exact_source_validated_and_non_required(self) -> None:
		self.assertEqual(1, CATALOG_VERSION)
		self.assertEqual(11, len(BUILT_IN_CATALOG))
		self.assertEqual(11, len({(entry.stableKey, entry.canonicalGuid) for entry in BUILT_IN_CATALOG}))
		self.assertEqual({"sourceValidated"}, {entry.maturity for entry in BUILT_IN_CATALOG})
		self.assertFalse(any(entry.required for entry in BUILT_IN_CATALOG))
		self.assertIn("Word.MathML", {entry.name for entry in BUILT_IN_CATALOG})
		self.assertIn("AreGridlinesVisible", {entry.name for entry in BUILT_IN_CATALOG})
		configuration = CustomUiaConfiguration(
			1,
			tuple(
				CustomUiaProperty(
					entry.stableKey,
					entry.canonicalGuid,
					entry.name,
					entry.propertyType,
					entry.privacy,
					False,
					None,
					"catalog.exe",
					None,
					None,
				)
				for entry in BUILT_IN_CATALOG
			),
		)
		self.assertTrue(validateConfiguration(configuration).isValid)


class RecordingRegistrar:
	def __init__(
		self,
		outcomes: dict[str, int | Exception] | None = None,
		*,
		available: bool = True,
		availabilityError: Exception | None = None,
	) -> None:
		super().__init__()
		self.outcomes = outcomes or {}
		self.available = available
		self.availabilityError = availabilityError
		self.calls: list[tuple[bytes, str, int]] = []

	def isAvailable(self) -> bool:
		if self.availabilityError is not None:
			raise self.availabilityError
		return self.available

	def registerProperty(self, guidBytes: bytes, name: str, propertyType: int) -> int:
		self.calls.append((guidBytes, name, propertyType))
		outcome = self.outcomes.get(name, len(self.calls) + 40_000)
		if isinstance(outcome, Exception):
			raise outcome
		return outcome


class RegistryAndServiceTests(unittest.TestCase):
	def test_registry_is_lazy_deterministic_idempotent_and_failure_isolated(self) -> None:
		registrar = RecordingRegistrar(
			{
				"First": 0,
				"Second": RuntimeError("private provider detail"),
				"Third": 40_123,
			},
		)
		registry = CustomUiaRegistry(registrar)
		configuration = CustomUiaConfiguration(
			1,
			(
				_property(
					stableKey="sample.third",
					canonicalGuid="{33333333-0000-4000-8000-000000000003}",
					name="Third",
				),
				_property(
					stableKey="sample.first",
					canonicalGuid="{11111111-0000-4000-8000-000000000001}",
					name="First",
				),
				_property(
					stableKey="sample.second",
					canonicalGuid="{22222222-0000-4000-8000-000000000002}",
					name="Second",
				),
			),
		)
		self.assertEqual((), registry.statuses)

		statuses = registry.register(configuration)

		self.assertEqual(["First", "Second", "Third"], [call[1] for call in registrar.calls])
		self.assertEqual(["failed", "failed", "registered"], [status.status for status in statuses])
		self.assertEqual(["idZero", "registrationFailed", None], [status.errorCode for status in statuses])
		self.assertEqual(40_123, statuses[2].runtimeId)
		self.assertEqual(statuses, registry.register(configuration))
		self.assertEqual(3, len(registrar.calls))
		changed = CustomUiaConfiguration(
			1,
			configuration.properties
			+ (
				_property(
					stableKey="sample.after-reload",
					canonicalGuid="{44444444-0000-4000-8000-000000000004}",
					name="AfterReload",
				),
			),
		)
		self.assertEqual(statuses, registry.register(changed))
		self.assertEqual(3, len(registrar.calls))

	def test_unavailable_registration_is_explicit_and_save_never_hot_registers(self) -> None:
		registrar = RecordingRegistrar(available=False)
		registry = CustomUiaRegistry(registrar)
		configuration = CustomUiaConfiguration(1, (_property(),))
		status = registry.register(configuration)[0]
		self.assertEqual("unavailable", status.status)
		self.assertEqual("nativeRegistrationUnavailable", status.errorCode)

		with tempfile.TemporaryDirectory() as temporary:
			service = CustomUiaService(Path(temporary), registry=registry)
			result = service.save(configuration)
			self.assertTrue(result.accepted)
			self.assertTrue(result.restartRequired)
			self.assertEqual([], registrar.calls)

	def test_availability_failure_does_not_start_the_registry(self) -> None:
		registrar = RecordingRegistrar(availabilityError=RuntimeError("temporary availability failure"))
		registry = CustomUiaRegistry(registrar)
		configuration = CustomUiaConfiguration(1, (_property(),))

		with self.assertRaisesRegex(RuntimeError, "temporary availability failure"):
			_ = registry.register(configuration)

		registrar.availabilityError = None
		statuses = registry.register(configuration)

		self.assertEqual(1, len(statuses))
		self.assertEqual(1, len(registrar.calls))

	def test_import_rejection_has_no_partial_persistence(self) -> None:
		with tempfile.TemporaryDirectory() as temporary:
			root = Path(temporary)
			service = CustomUiaService(root)
			self.assertTrue(service.save(CustomUiaConfiguration(1, (_property(),))).accepted)
			before = service.storagePath.read_bytes()
			badImport = root / "bad.json"
			_ = badImport.write_text(
				'{"schemaVersion":1,"properties":[{"module":"bad.dll"}]}',
				encoding="utf-8",
			)

			result = service.importFrom(badImport)

			self.assertFalse(result.accepted)
			self.assertEqual(before, service.storagePath.read_bytes())


if __name__ == "__main__":
	_ = unittest.main()
