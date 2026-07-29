from __future__ import annotations

import re


_INVALID_FILENAME_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_UNKNOWN_APPLICATIONS = frozenset({"unknown", "unknown.exe"})
_WINDOWS_RESERVED_COMPONENTS = frozenset(
	{
		"con",
		"prn",
		"aux",
		"nul",
		*(f"com{index}" for index in range(1, 10)),
		*(f"lpt{index}" for index in range(1, 10)),
	},
)


def defaultExportFilename(
	executable: str | None,
	artifact: str,
	suffix: str,
	*,
	subject: str | None = None,
) -> str:
	"""Return a safe filename qualified by its source application and selected subject."""

	application = _applicationStem(executable)
	prefix = "" if application is None else f"{application}-"
	subjectStem = _filenameStem(subject)
	subjectPrefix = "" if subjectStem is None else f"{subjectStem}-"
	return f"{subjectPrefix}{prefix}keystone-{artifact}{suffix}"


def _applicationStem(executable: str | None) -> str | None:
	if not isinstance(executable, str):
		return None
	name = executable.strip().replace("\\", "/").rsplit("/", 1)[-1]
	if name.lower().endswith(".exe"):
		name = name[:-4]
	name = _filenameStem(name)
	if name is None:
		return None
	if not name or name.lower() in _UNKNOWN_APPLICATIONS:
		return None
	return name


def _filenameStem(value: str | None) -> str | None:
	if not isinstance(value, str):
		return None
	name = _INVALID_FILENAME_CHARACTERS.sub("-", value).strip(" .-")[:120]
	if not name or name.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_COMPONENTS:
		return None
	return name
