from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import ntpath
from pathlib import Path
import unicodedata


_INVALID_COMPONENT_CHARACTERS = frozenset('<>:"/\\|?*')
_RESERVED_COMPONENTS = frozenset(
	(
		"CON",
		"PRN",
		"AUX",
		"NUL",
		*(f"COM{index}" for index in range(1, 10)),
		*(f"LPT{index}" for index in range(1, 10)),
	),
)
_DEFAULT_COMPONENT_LENGTH = 80
_MAXIMUM_PROCESS_ID = (1 << 32) - 1


def fixedOutputRoot(environment: Mapping[str, str] | None = None) -> Path:
	values = environment if environment is not None else __import__("os").environ
	temp = values.get("TEMP")
	if temp is None or not ntpath.isabs(temp):
		raise ValueError("Keystone requires an absolute local TEMP directory")
	normalized = ntpath.normpath(temp)
	drive = ntpath.splitdrive(normalized)[0]
	if drive.startswith("\\\\?\\"):
		drive = drive[4:]
	elif normalized.startswith("\\\\"):
		raise ValueError("Keystone requires an absolute local TEMP directory")
	if normalized in (".", "\\") or len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha():
		raise ValueError("Keystone requires a drive-qualified TEMP directory")
	return Path(normalized) / "Keystone"


def snapshotOutputRoot(environment: Mapping[str, str] | None = None) -> Path:
	return fixedOutputRoot(environment) / "snapshots"


def sanitizeComponent(value: object, maximumLength: int = _DEFAULT_COMPONENT_LENGTH) -> str:
	if isinstance(maximumLength, bool) or maximumLength <= 0:
		raise ValueError("maximumLength must be a positive integer")
	text = unicodedata.normalize("NFC", str(value) if value is not None else "").strip()
	sanitized = "".join(
		"_" if character in _INVALID_COMPONENT_CHARACTERS or ord(character) < 32 else character
		for character in text
	)
	sanitized = sanitized.rstrip(" .")[:maximumLength].rstrip(" .")
	if not sanitized or sanitized in (".", ".."):
		sanitized = "unknown"[:maximumLength]
	stem = sanitized.split(".", 1)[0].upper()
	if stem in _RESERVED_COMPONENTS:
		sanitized = f"_{sanitized}"[:maximumLength].rstrip(" .")
	if not sanitized:
		raise ValueError("maximumLength cannot represent a safe component")
	return sanitized


def applicationDirectoryName(executable: object, processId: int) -> str:
	if type(processId) is not int or processId < 0 or processId > _MAXIMUM_PROCESS_ID:
		raise ValueError("processId must be a nonnegative 32-bit integer")
	return f"{sanitizeComponent(executable)}-{processId}"


def captureDirectoryName(
	capturedAt: datetime,
	captureKind: object,
	*,
	subject: str | None = None,
	collisionIndex: int = 0,
) -> str:
	if capturedAt.tzinfo is not None:
		raise ValueError("capture timestamps must already be local wall-clock values")
	if type(collisionIndex) is not int or collisionIndex < 0 or collisionIndex == 1:
		raise ValueError("collisionIndex must be zero or at least two")
	milliseconds = capturedAt.microsecond // 1000
	base = f"{capturedAt:%Y%m%d-%H%M%S}.{milliseconds:03d}-{sanitizeComponent(captureKind, maximumLength=32)}"
	subjectPrefix = "" if subject is None else f"{sanitizeComponent(subject, maximumLength=80)}-"
	name = f"{subjectPrefix}{base}"
	return name if collisionIndex == 0 else f"{name}-{collisionIndex:02d}"
