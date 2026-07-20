from __future__ import annotations

from pathlib import Path


def nextLocalBuildVersion(baseVersion: str, counterPath: Path) -> str:
	"""Advance a local development build number without changing a release version."""

	parts = baseVersion.split(".")
	if len(parts) != 3 or not all(part.isdecimal() for part in parts):
		raise ValueError("base version must contain three decimal components")
	major, minor, patch = (int(part) for part in parts)
	try:
		stored = counterPath.read_text(encoding="utf-8").strip()
	except FileNotFoundError:
		counter = patch
	else:
		if not stored.isdecimal():
			raise ValueError("local build counter must be a nonnegative integer")
		counter = max(patch, int(stored))
	counter += 1
	counterPath.write_text(f"{counter}\n", encoding="utf-8")
	return f"{major}.{minor}.{counter}"
