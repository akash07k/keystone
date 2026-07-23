from __future__ import annotations

from dataclasses import dataclass
import json
import re
import unicodedata
from typing import cast
from uuid import UUID


SCHEMA_VERSION = 1
CATALOG_VERSION = 1
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_PROPERTIES = 256
ALLOWED_PROPERTY_TYPES = ("int", "bool", "string", "double", "point", "element", "enum")
ALLOWED_PRIVACY = ("unknown", "sensitive", "protected")

_ROOT_FIELDS = frozenset(("schemaVersion", "properties"))
_ENTRY_FIELDS = frozenset(
	(
		"stableKey",
		"canonicalGuid",
		"name",
		"displayName",
		"enumValues",
		"type",
		"privacy",
		"enabled",
		"description",
		"executableTarget",
		"frameworkFilter",
		"windowClassFilter",
	),
)
_REQUIRED_ENTRY_FIELDS = frozenset(
	(
		"canonicalGuid",
		"name",
		"type",
		"privacy",
		"enabled",
		"executableTarget",
	),
)
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_GUID_PATTERN = re.compile(
	r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-" + r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$",
)
_EXECUTABLE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FRAMEWORK_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BIDI_CONTROLS = frozenset(
	(
		"\u061c",
		"\u200e",
		"\u200f",
		"\u202a",
		"\u202b",
		"\u202c",
		"\u202d",
		"\u202e",
		"\u2066",
		"\u2067",
		"\u2068",
		"\u2069",
	),
)
_TYPE_CODES = {
	"int": 1,
	"bool": 2,
	"string": 3,
	"double": 4,
	"point": 5,
	"element": 7,
	"enum": 1,
}


@dataclass(frozen=True, slots=True)
class CustomUiaProperty:
	stableKey: str
	canonicalGuid: str
	name: str
	propertyType: str
	privacy: str
	enabled: bool
	description: str | None
	executableTarget: str
	frameworkFilter: str | None
	windowClassFilter: str | None
	displayName: str | None = None
	enumValues: tuple[tuple[int, str], ...] = ()

	@property
	def typeCode(self) -> int:
		return _TYPE_CODES[self.propertyType]

	@property
	def guidBytes(self) -> bytes:
		return UUID(self.canonicalGuid[1:-1]).bytes_le

	@property
	def identityBytes(self) -> bytes:
		return UUID(self.canonicalGuid[1:-1]).bytes

	@property
	def userVisibleName(self) -> str:
		return self.displayName or self.name


@dataclass(frozen=True, slots=True)
class CustomUiaConfiguration:
	schemaVersion: int
	properties: tuple[CustomUiaProperty, ...]

	@classmethod
	def empty(cls) -> CustomUiaConfiguration:
		return cls(SCHEMA_VERSION, ())


@dataclass(frozen=True, slots=True)
class CustomUiaIssue:
	field: str
	code: str
	severity: str = "error"

	def __post_init__(self) -> None:
		if self.severity not in ("error", "warning"):
			raise ValueError("custom UIA issue severity is invalid")


@dataclass(frozen=True, slots=True)
class CustomUiaValidationResult:
	configuration: CustomUiaConfiguration | None
	issues: tuple[CustomUiaIssue, ...] = ()
	warnings: tuple[CustomUiaIssue, ...] = ()

	@property
	def isValid(self) -> bool:
		return self.configuration is not None and not self.issues

	@property
	def firstInvalidField(self) -> str | None:
		return None if not self.issues else self.issues[0].field


@dataclass(frozen=True, slots=True)
class CatalogProperty:
	stableKey: str
	canonicalGuid: str
	name: str
	propertyType: str
	privacy: str
	productFamily: str
	applicationTarget: str
	maturity: str = "sourceValidated"
	required: bool = False

	def __post_init__(self) -> None:
		if self.maturity != "sourceValidated" or self.required:
			raise ValueError("built-in custom UIA catalog entries must remain non-required source records")


BUILT_IN_CATALOG = (
	CatalogProperty(
		"CAT-COMMON-ITEM-INDEX",
		"{92A053DA-2969-4021-BF27-514CFC2E4A69}",
		"ItemIndex",
		"int",
		"unknown",
		"NVDA common",
		"all UIA providers",
	),
	CatalogProperty(
		"CAT-COMMON-ITEM-COUNT",
		"{ABBF5C45-5CCC-47B7-BB4E-87CB87BBD162}",
		"ItemCount",
		"int",
		"unknown",
		"NVDA common",
		"all UIA providers",
	),
	CatalogProperty(
		"CAT-WORD-MATHML",
		"{FA170AB3-3229-4E7C-827F-DD05EE0481D9}",
		"Word.MathML",
		"string",
		"unknown",
		"MathML/Word",
		"Microsoft Word build 14326+",
	),
	CatalogProperty(
		"CAT-EXCEL-CELL-FORMULA",
		"{E244641A-2785-41E9-A4A7-5BE5FE531507}",
		"CellFormula",
		"string",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-CELL-NUMBER-FORMAT",
		"{626CF4A0-A5AE-448B-A157-5EA4D1D057D7}",
		"CellNumberFormat",
		"string",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-HAS-DATA-VALIDATION",
		"{29F2E049-5DE9-4444-8338-6784C5D18ADF}",
		"HasDataValidation",
		"bool",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-HAS-DATA-VALIDATION-DROPDOWN",
		"{1B93A5CD-0956-46ED-9BBF-016C1B9FD75F}",
		"HasDataValidationDropdown",
		"bool",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-DATA-VALIDATION-PROMPT",
		"{7AAEE221-E14D-4DA4-83FE-842AAF06A9B7}",
		"DataValidationPrompt",
		"string",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-HAS-CONDITIONAL-FORMATTING",
		"{DFEF6BBD-7A50-41BD-971F-B5D741569A2B}",
		"HasConditionalFormatting",
		"bool",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-COMMENT-REPLY-COUNT",
		"{312F7536-259A-47C7-B192-AA16352522C4}",
		"CommentReplyCount",
		"int",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
	CatalogProperty(
		"CAT-EXCEL-GRIDLINES-VISIBLE",
		"{4BB56516-F354-44CF-A5AA-96B52E968CFD}",
		"AreGridlinesVisible",
		"bool",
		"unknown",
		"Excel",
		"Microsoft Excel",
	),
)


def _issue(field: str, code: str) -> CustomUiaIssue:
	return CustomUiaIssue(field, code)


def _warning(field: str, code: str) -> CustomUiaIssue:
	return CustomUiaIssue(field, code, "warning")


def _isNoncharacter(character: str) -> bool:
	value = ord(character)
	return 0xFDD0 <= value <= 0xFDEF or (value & 0xFFFF) in (0xFFFE, 0xFFFF)


def _hasUnsafeText(value: str, *, separators: bool) -> bool:
	for character in value:
		category = unicodedata.category(character)
		if (
			category in ("Cc", "Cs")
			or character in _BIDI_CONTROLS
			or _isNoncharacter(character)
			or (separators and category.startswith("Z"))
		):
			return True
	return False


def _canonicalGuid(value: str) -> str | None:
	if not _GUID_PATTERN.fullmatch(value):
		return None
	try:
		guid = UUID(value[1:-1])
	except ValueError:
		return None
	if int(guid.hex, 16) == 0:
		return None
	return "{" + str(guid).upper() + "}"


def stableKeyForGuid(value: str) -> str:
	"""Return the managed configuration identity for a custom property GUID."""

	guid = _canonicalGuid(value)
	return f"custom-{guid[1:-1].lower()}" if guid is not None else "custom-pending"


def _stringValue(value: object) -> str | None:
	return value if isinstance(value, str) else None


def _optionalStringValue(value: object) -> tuple[bool, str | None]:
	if value is None:
		return True, None
	if isinstance(value, str):
		return True, unicodedata.normalize("NFC", value)
	return False, None


def _normalizedEnumValues(value: object) -> tuple[tuple[tuple[int, str], ...] | None, bool]:
	if not isinstance(value, tuple):
		return None, False
	values: list[tuple[int, str]] = []
	seen: set[int] = set()
	for item in cast(tuple[object, ...], value):
		if not isinstance(item, tuple):
			return None, False
		pair = cast(tuple[object, ...], item)
		if len(pair) != 2:
			return None, False
		number, nameInput = pair
		if type(number) is not int or not -2_147_483_648 <= number <= 2_147_483_647:
			return None, False
		if not isinstance(nameInput, str):
			return None, False
		name = unicodedata.normalize("NFC", nameInput).strip()
		if not name or len(name) > 256 or _hasUnsafeText(name, separators=False) or number in seen:
			return None, False
		seen.add(number)
		values.append((number, name))
	return tuple(sorted(values)), True


def _booleanValue(value: object) -> bool | None:
	return value if isinstance(value, bool) else None


def _schemaVersionIsValid(value: object) -> bool:
	return isinstance(value, int) and not isinstance(value, bool) and value == SCHEMA_VERSION


def _validateProperty(
	property: CustomUiaProperty,
	index: int,
) -> tuple[CustomUiaProperty | None, tuple[CustomUiaIssue, ...]]:
	prefix = f"properties[{index}]"
	issues: list[CustomUiaIssue] = []
	stableKey = _stringValue(property.stableKey)
	if stableKey is None or not _KEY_PATTERN.fullmatch(stableKey):
		issues.append(_issue(f"{prefix}.stableKey", "KSERR_CUIA_KEY_INVALID"))
	guidInput = _stringValue(property.canonicalGuid)
	guid = None if guidInput is None else _canonicalGuid(guidInput)
	if guid is None:
		issues.append(_issue(f"{prefix}.canonicalGuid", "KSERR_CUIA_GUID_INVALID"))
	nameInput = _stringValue(property.name)
	name = "" if nameInput is None else unicodedata.normalize("NFC", nameInput)
	if nameInput is None or not 1 <= len(name) <= 256:
		issues.append(_issue(f"{prefix}.name", "KSERR_CUIA_STRING_LIMIT"))
	elif _hasUnsafeText(name, separators=True):
		issues.append(_issue(f"{prefix}.name", "KSERR_CUIA_UNSAFE_TEXT"))
	displayNameValid, displayName = _optionalStringValue(property.displayName)
	if not displayNameValid:
		issues.append(_issue(f"{prefix}.displayName", "KSERR_CUIA_ENTRY_INVALID"))
	elif displayName == "":
		displayName = None
	elif displayName is not None:
		if len(displayName) > 256:
			issues.append(_issue(f"{prefix}.displayName", "KSERR_CUIA_STRING_LIMIT"))
		elif _hasUnsafeText(displayName, separators=False):
			issues.append(_issue(f"{prefix}.displayName", "KSERR_CUIA_UNSAFE_TEXT"))
	propertyType = _stringValue(property.propertyType)
	if propertyType not in ALLOWED_PROPERTY_TYPES:
		issues.append(_issue(f"{prefix}.type", "KSERR_CUIA_TYPE_INVALID"))
	enumValues, enumValuesValid = _normalizedEnumValues(property.enumValues)
	if (
		not enumValuesValid
		or (propertyType == "enum" and not enumValues)
		or (propertyType != "enum" and enumValues)
	):
		issues.append(_issue(f"{prefix}.enumValues", "KSERR_CUIA_ENUM_VALUES_INVALID"))
	privacy = _stringValue(property.privacy)
	if privacy not in ALLOWED_PRIVACY:
		issues.append(_issue(f"{prefix}.privacy", "KSERR_CUIA_PRIVACY_INVALID"))
	enabled = _booleanValue(property.enabled)
	if enabled is None:
		issues.append(_issue(f"{prefix}.enabled", "KSERR_CUIA_ENABLED_INVALID"))
	descriptionValid, description = _optionalStringValue(property.description)
	if not descriptionValid:
		issues.append(_issue(f"{prefix}.description", "KSERR_CUIA_ENTRY_INVALID"))
	elif description is not None:
		if len(description) > 512:
			issues.append(_issue(f"{prefix}.description", "KSERR_CUIA_STRING_LIMIT"))
		elif _hasUnsafeText(description, separators=False):
			issues.append(_issue(f"{prefix}.description", "KSERR_CUIA_UNSAFE_TEXT"))
	executable = _stringValue(property.executableTarget)
	if (
		executable is None
		or not _EXECUTABLE_PATTERN.fullmatch(executable)
		or not executable.lower().endswith(".exe")
	):
		issues.append(_issue(f"{prefix}.executableTarget", "KSERR_CUIA_EXPANSION_FORBIDDEN"))
	frameworkValid, framework = _optionalStringValue(property.frameworkFilter)
	if not frameworkValid:
		issues.append(_issue(f"{prefix}.frameworkFilter", "KSERR_CUIA_ENTRY_INVALID"))
	elif framework is not None and not _FRAMEWORK_PATTERN.fullmatch(framework):
		issues.append(_issue(f"{prefix}.frameworkFilter", "KSERR_CUIA_EXPANSION_FORBIDDEN"))
	windowClassValid, windowClass = _optionalStringValue(property.windowClassFilter)
	if not windowClassValid:
		issues.append(_issue(f"{prefix}.windowClassFilter", "KSERR_CUIA_ENTRY_INVALID"))
	elif windowClass is not None:
		if not 1 <= len(windowClass) <= 128:
			issues.append(_issue(f"{prefix}.windowClassFilter", "KSERR_CUIA_STRING_LIMIT"))
		elif _hasUnsafeText(windowClass, separators=False) or any(
			token in windowClass
			for token in ("*", "+", "?", "^", "$", "|", "[", "]", "(", ")", "{", "}", "\\", "/", "://", "%")
		):
			issues.append(_issue(f"{prefix}.windowClassFilter", "KSERR_CUIA_EXPANSION_FORBIDDEN"))
	if (
		issues
		or stableKey is None
		or guid is None
		or nameInput is None
		or propertyType is None
		or enumValues is None
		or privacy is None
		or enabled is None
		or executable is None
	):
		return None, tuple(issues)
	return (
		CustomUiaProperty(
			stableKey,
			guid,
			name,
			propertyType,
			privacy,
			enabled,
			description,
			executable,
			framework,
			windowClass,
			displayName,
			enumValues,
		),
		(),
	)


def validateConfiguration(configuration: CustomUiaConfiguration) -> CustomUiaValidationResult:
	issues: list[CustomUiaIssue] = []
	warnings: list[CustomUiaIssue] = []
	if not _schemaVersionIsValid(configuration.schemaVersion):
		issues.append(_issue("schemaVersion", "KSERR_CUIA_SCHEMA_VERSION"))
	if len(configuration.properties) > MAX_PROPERTIES:
		issues.append(_issue("properties", "KSERR_CUIA_COUNT_LIMIT"))

	normalized: list[CustomUiaProperty] = []
	for index, property in enumerate(configuration.properties):
		normalizedProperty, propertyIssues = _validateProperty(property, index)
		issues.extend(propertyIssues)
		if normalizedProperty is not None:
			normalized.append(normalizedProperty)
	if issues:
		return CustomUiaValidationResult(None, tuple(issues))

	catalogByGuid = {entry.canonicalGuid: entry for entry in BUILT_IN_CATALOG}
	catalogByKey = {entry.stableKey: entry for entry in BUILT_IN_CATALOG}
	byGuid: dict[str, CustomUiaProperty] = {}
	byKey: dict[str, CustomUiaProperty] = {}
	byName: dict[str, CustomUiaProperty] = {}
	deduplicated: list[CustomUiaProperty] = []
	for index, property in enumerate(normalized):
		catalog = catalogByGuid.get(property.canonicalGuid) or catalogByKey.get(property.stableKey)
		if catalog is not None and (
			property.canonicalGuid != catalog.canonicalGuid
			or property.stableKey != catalog.stableKey
			or property.name != catalog.name
			or property.propertyType != catalog.propertyType
		):
			issues.append(_issue(f"properties[{index}]", "KSERR_CUIA_CATALOG_CONFLICT"))
		previousGuid = byGuid.get(property.canonicalGuid)
		previousKey = byKey.get(property.stableKey)
		if previousGuid is not None:
			if previousGuid == property:
				warnings.append(_warning(f"properties[{index}]", "KS_CUIA_EXACT_DUPLICATE"))
				continue
			issues.append(_issue(f"properties[{index}].canonicalGuid", "KSERR_CUIA_GUID_CONFLICT"))
		if previousKey is not None and previousKey != property:
			issues.append(_issue(f"properties[{index}].stableKey", "KSERR_CUIA_KEY_CONFLICT"))
		previousName = byName.get(property.name)
		if (
			previousName is not None
			and previousName.canonicalGuid != property.canonicalGuid
			and previousName.stableKey != property.stableKey
		):
			warnings.append(_warning(f"properties[{index}].name", "KS_CUIA_NAME_COLLISION"))
		_ = byGuid.setdefault(property.canonicalGuid, property)
		_ = byKey.setdefault(property.stableKey, property)
		_ = byName.setdefault(property.name, property)
		deduplicated.append(property)
	if issues:
		return CustomUiaValidationResult(None, tuple(issues), tuple(warnings))
	return CustomUiaValidationResult(
		CustomUiaConfiguration(SCHEMA_VERSION, tuple(deduplicated)),
		(),
		tuple(warnings),
	)


def _propertyFromObject(
	value: object,
	index: int,
) -> tuple[CustomUiaProperty | None, tuple[CustomUiaIssue, ...]]:
	field = f"properties[{index}]"
	if not isinstance(value, dict):
		return None, (_issue(field, "KSERR_CUIA_ENTRY_INVALID"),)
	entry = cast(dict[str, object], value)
	keys = set(entry)
	if keys - _ENTRY_FIELDS:
		return None, (_issue(field, "KSERR_CUIA_UNKNOWN_FIELD"),)
	if any(required not in keys for required in _REQUIRED_ENTRY_FIELDS):
		return None, (_issue(field, "KSERR_CUIA_ENTRY_INVALID"),)
	if any(
		entry.get(optional) is None
		for optional in ("description", "displayName", "frameworkFilter", "windowClassFilter")
		if optional in entry
	):
		return None, (_issue(field, "KSERR_CUIA_ENTRY_INVALID"),)
	stableKey = (
		entry["stableKey"]
		if "stableKey" in entry
		else stableKeyForGuid(entry["canonicalGuid"])
		if isinstance(entry["canonicalGuid"], str)
		else "custom-pending"
	)
	enumValuesInput = entry.get("enumValues", {})
	if isinstance(enumValuesInput, dict):
		rawEnumValues = cast(dict[object, object], enumValuesInput)
		parsedEnumValues: object = tuple(
			(int(number), name)
			for number, name in rawEnumValues.items()
			if isinstance(number, str) and number.lstrip("-").isdigit()
		)
		if len(parsedEnumValues) != len(rawEnumValues):
			parsedEnumValues = None
	else:
		parsedEnumValues = enumValuesInput
	try:
		property = CustomUiaProperty(
			stableKey=stableKey,  # type: ignore[arg-type]
			canonicalGuid=entry["canonicalGuid"],  # type: ignore[arg-type]
			name=entry["name"],  # type: ignore[arg-type]
			propertyType=entry["type"],  # type: ignore[arg-type]
			privacy=entry["privacy"],  # type: ignore[arg-type]
			enabled=entry["enabled"],  # type: ignore[arg-type]
			description=entry.get("description"),  # type: ignore[arg-type]
			executableTarget=entry["executableTarget"],  # type: ignore[arg-type]
			frameworkFilter=entry.get("frameworkFilter"),  # type: ignore[arg-type]
			windowClassFilter=entry.get("windowClassFilter"),  # type: ignore[arg-type]
			displayName=entry.get("displayName"),  # type: ignore[arg-type]
			enumValues=parsedEnumValues,  # type: ignore[arg-type]
		)
	except (KeyError, TypeError):
		return None, (_issue(field, "KSERR_CUIA_ENTRY_INVALID"),)
	return property, ()


class _DuplicateFieldError(ValueError):
	pass


def _closedObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
	result: dict[str, object] = {}
	for key, value in pairs:
		if key in result:
			raise _DuplicateFieldError
		result[key] = value
	return result


def parseConfiguration(data: bytes) -> CustomUiaValidationResult:
	if len(data) > MAX_DOCUMENT_BYTES:
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_FILE_INVALID"),))
	if data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00")):
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_FILE_INVALID"),))
	try:
		text = data.decode("utf-8-sig")
		loaded: object = json.loads(text, object_pairs_hook=_closedObject)
	except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateFieldError):
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_FILE_INVALID"),))
	if not isinstance(loaded, dict):
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_ROOT_INVALID"),))
	root = cast(dict[str, object], loaded)
	keys = set(root)
	if keys - _ROOT_FIELDS:
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_UNKNOWN_FIELD"),))
	if keys != set(_ROOT_FIELDS):
		return CustomUiaValidationResult(None, (_issue("document", "KSERR_CUIA_ROOT_INVALID"),))
	version = root.get("schemaVersion")
	properties = root.get("properties")
	if not isinstance(version, int) or isinstance(version, bool) or version != SCHEMA_VERSION:
		return CustomUiaValidationResult(None, (_issue("schemaVersion", "KSERR_CUIA_SCHEMA_VERSION"),))
	if not isinstance(properties, list):
		return CustomUiaValidationResult(None, (_issue("properties", "KSERR_CUIA_PROPERTIES_INVALID"),))
	typedProperties = cast(list[object], properties)
	if len(typedProperties) > MAX_PROPERTIES:
		return CustomUiaValidationResult(None, (_issue("properties", "KSERR_CUIA_COUNT_LIMIT"),))
	parsed: list[CustomUiaProperty] = []
	issues: list[CustomUiaIssue] = []
	for index, value in enumerate(typedProperties):
		property, entryIssues = _propertyFromObject(value, index)
		issues.extend(entryIssues)
		if property is not None:
			parsed.append(property)
	if issues:
		return CustomUiaValidationResult(None, tuple(issues))
	return validateConfiguration(CustomUiaConfiguration(version, tuple(parsed)))


def configurationObject(configuration: CustomUiaConfiguration) -> dict[str, object]:
	validation = validateConfiguration(configuration)
	if not validation.isValid or validation.configuration is None:
		raise ValueError("invalid custom UIA configuration cannot be serialized")
	properties: list[dict[str, object]] = []
	for property in validation.configuration.properties:
		entry: dict[str, object] = {
			"stableKey": property.stableKey,
			"canonicalGuid": property.canonicalGuid,
			"name": property.name,
			"type": property.propertyType,
			"privacy": property.privacy,
			"enabled": property.enabled,
			"executableTarget": property.executableTarget,
		}
		if property.description is not None:
			entry["description"] = property.description
		if property.displayName is not None:
			entry["displayName"] = property.displayName
		if property.enumValues:
			entry["enumValues"] = {str(number): name for number, name in property.enumValues}
		if property.frameworkFilter is not None:
			entry["frameworkFilter"] = property.frameworkFilter
		if property.windowClassFilter is not None:
			entry["windowClassFilter"] = property.windowClassFilter
		properties.append(entry)
	return {"schemaVersion": SCHEMA_VERSION, "properties": properties}


def serializeConfiguration(configuration: CustomUiaConfiguration) -> bytes:
	return (
		json.dumps(
			configurationObject(configuration),
			ensure_ascii=False,
			indent="\t",
			sort_keys=True,
		)
		+ "\n"
	).encode("utf-8")
