from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Protocol

from ..domain.custom_uia import (
	CustomUiaConfiguration,
	CustomUiaIssue,
	CustomUiaValidationResult,
	MAX_DOCUMENT_BYTES,
	parseConfiguration,
	serializeConfiguration,
	validateConfiguration,
)


class RegistrationRegistry(Protocol):
	def register(self, configuration: CustomUiaConfiguration) -> tuple[object, ...]: ...


@dataclass(frozen=True, slots=True)
class CustomUiaLoadResult:
	configuration: CustomUiaConfiguration
	issues: tuple[CustomUiaIssue, ...] = ()
	warnings: tuple[CustomUiaIssue, ...] = ()

	@property
	def accepted(self) -> bool:
		return not self.issues


@dataclass(frozen=True, slots=True)
class CustomUiaChangeResult:
	accepted: bool
	configuration: CustomUiaConfiguration | None
	issues: tuple[CustomUiaIssue, ...] = ()
	warnings: tuple[CustomUiaIssue, ...] = ()
	restartRequired: bool = False
	errorCode: str | None = None

	def __post_init__(self) -> None:
		if self.accepted and (self.configuration is None or self.issues or self.errorCode is not None):
			raise ValueError("accepted custom UIA change result is inconsistent")
		if not self.accepted and self.configuration is not None:
			raise ValueError("rejected custom UIA change result cannot carry a configuration")


class CustomUiaService:
	def __init__(
		self,
		userConfigurationRoot: Path,
		*,
		registry: RegistrationRegistry | None = None,
	) -> None:
		super().__init__()
		self._root = Path(userConfigurationRoot)
		self._registry = registry
		self.storagePath = self._root / "keystone" / "custom-uia.json"

	def load(self) -> CustomUiaLoadResult:
		try:
			data = self.storagePath.read_bytes()
		except FileNotFoundError:
			return CustomUiaLoadResult(CustomUiaConfiguration.empty())
		except OSError:
			return CustomUiaLoadResult(
				CustomUiaConfiguration.empty(),
				(CustomUiaIssue("document", "KSERR_CUIA_READ_FAILED"),),
			)
		result = parseConfiguration(data)
		if result.configuration is None:
			return CustomUiaLoadResult(CustomUiaConfiguration.empty(), result.issues, result.warnings)
		return CustomUiaLoadResult(result.configuration, result.issues, result.warnings)

	def _rejected(self, validation: CustomUiaValidationResult) -> CustomUiaChangeResult:
		return CustomUiaChangeResult(False, None, validation.issues, validation.warnings)

	def save(self, configuration: CustomUiaConfiguration) -> CustomUiaChangeResult:
		validation = validateConfiguration(configuration)
		if not validation.isValid or validation.configuration is None:
			return self._rejected(validation)
		canonical = validation.configuration
		try:
			encoded = serializeConfiguration(canonical)
		except ValueError:
			return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_WRITE_FAILED")
		try:
			previous = self.storagePath.read_bytes()
		except FileNotFoundError:
			previous = None
		except OSError:
			return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_READ_FAILED")
		previousConfiguration = None if previous is None else parseConfiguration(previous).configuration
		if previousConfiguration == canonical:
			if previous != encoded:
				try:
					self._writeAtomically(self.storagePath, encoded)
				except OSError:
					return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_WRITE_FAILED")
			return CustomUiaChangeResult(True, canonical, warnings=validation.warnings)
		try:
			self._writeAtomically(self.storagePath, encoded)
		except OSError:
			return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_WRITE_FAILED")
		return CustomUiaChangeResult(
			True,
			canonical,
			warnings=validation.warnings,
			restartRequired=True,
		)

	def importBytes(self, data: bytes) -> CustomUiaChangeResult:
		validation = parseConfiguration(data)
		if not validation.isValid or validation.configuration is None:
			return self._rejected(validation)
		return self.save(validation.configuration)

	def importFrom(self, source: Path) -> CustomUiaChangeResult:
		try:
			with Path(source).open("rb") as stream:
				data = stream.read(MAX_DOCUMENT_BYTES + 1)
		except OSError:
			return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_IMPORT_FAILED")
		return self.importBytes(data)

	def exportTo(self, target: Path) -> CustomUiaChangeResult:
		loaded = self.load()
		if not loaded.accepted:
			return CustomUiaChangeResult(False, None, loaded.issues, loaded.warnings)
		try:
			self._writeAtomically(Path(target), serializeConfiguration(loaded.configuration))
		except OSError:
			return CustomUiaChangeResult(False, None, errorCode="KSERR_CUIA_EXPORT_FAILED")
		return CustomUiaChangeResult(True, loaded.configuration, warnings=loaded.warnings)

	def registerAtStartup(self) -> tuple[object, ...]:
		if self._registry is None:
			return ()
		loaded = self.load()
		if not loaded.accepted:
			return ()
		return self._registry.register(loaded.configuration)

	@staticmethod
	def _writeAtomically(target: Path, data: bytes) -> None:
		target.parent.mkdir(parents=True, exist_ok=True)
		temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
		try:
			with temporary.open("wb") as stream:
				_ = stream.write(data)
				stream.flush()
				os.fsync(stream.fileno())
			os.replace(temporary, target)
		finally:
			try:
				temporary.unlink()
			except FileNotFoundError:
				pass
