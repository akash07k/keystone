from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Literal, Protocol, cast

from ...capability import requireOpaqueId
from ...domain.correlation import CorrelationContext, requireCompleteCorrelation
from ...domain.privacy import UNREDACTED_SCREENSHOT_WARNING
from ...domain.snapshot_bundle import INDEX_FILENAME, validateBundleArtifacts
from .path_ops import applicationDirectoryName, captureDirectoryName


type CaptureKind = Literal["snapshot", "navigatorSnapshot", "diff"]

DOCUMENTS_BY_KIND: dict[CaptureKind, tuple[str, ...]] = {
	"snapshot": ("snapshot.json", "summary.json"),
	"navigatorSnapshot": ("navigatorSnapshot.json", "navigatorSummary.json"),
	"diff": ("diff.json",),
}
_SCREENSHOT_NAME = "screenshot.png"
_METADATA_NAME = "publication-metadata.json"
_REPARSE_POINT_ATTRIBUTE = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_OPEN = 1
_FILE_CREATE = 2
_FILE_OPEN_IF = 3
_FILE_DIRECTORY_FILE = 0x1
_FILE_NON_DIRECTORY_FILE = 0x40
_FILE_SYNCHRONOUS_IO_NONALERT = 0x20
_FILE_OPEN_REPARSE_POINT = 0x200000
_FILE_READ_DATA = 0x1
_FILE_WRITE_DATA = 0x2
_FILE_READ_ATTRIBUTES = 0x80
_DELETE = 0x10000
_SYNCHRONIZE = 0x100000
_FILE_SHARE_ALL = 0x7
_FILE_RENAME_INFORMATION = 10
_FILE_DISPOSITION_INFORMATION = 13
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_MAX_FOLDER_COLLISION_ATTEMPTS = 32


class _FolderCollisionLimitError(Exception):
	"""Raised when every bounded publication-folder candidate already exists."""


class _UnicodeString(ctypes.Structure):
	_fields_ = [
		("Length", wintypes.USHORT),
		("MaximumLength", wintypes.USHORT),
		("Buffer", wintypes.LPWSTR),
	]


class _ObjectAttributes(ctypes.Structure):
	_fields_ = [
		("Length", wintypes.ULONG),
		("RootDirectory", wintypes.HANDLE),
		("ObjectName", ctypes.POINTER(_UnicodeString)),
		("Attributes", wintypes.ULONG),
		("SecurityDescriptor", wintypes.LPVOID),
		("SecurityQualityOfService", wintypes.LPVOID),
	]


class _IoStatusBlock(ctypes.Structure):
	_fields_ = [("Status", wintypes.LONG), ("Information", ctypes.c_size_t)]


class _FileAttributeTagInfo(ctypes.Structure):
	_fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


@dataclass(slots=True)
class DirectoryLease:
	path: Path
	handle: object


def isOrdinaryDirectory(path: Path) -> bool:
	try:
		value = path.lstat()
	except OSError:
		return False
	return stat.S_ISDIR(value.st_mode) and not bool(
		getattr(value, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE,
	)


def isOrdinaryFile(path: Path) -> bool:
	try:
		value = path.lstat()
	except OSError:
		return False
	return stat.S_ISREG(value.st_mode) and not bool(
		getattr(value, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE,
	)


class DirectoryAuthority(Protocol):
	"""Keeps Windows directory authority independent of mutable path names."""

	def openRoot(self, root: Path, *, create: bool) -> DirectoryLease: ...

	def openChild(
		self,
		parent: DirectoryLease,
		name: str,
		*,
		create: bool = False,
		deletable: bool = False,
	) -> DirectoryLease: ...

	def writeFile(self, directory: DirectoryLease, name: str, payload: bytes) -> None: ...

	def readFile(self, directory: DirectoryLease, name: str) -> bytes: ...

	def ordinaryFile(self, directory: DirectoryLease, name: str) -> bool: ...

	def rename(
		self,
		source: DirectoryLease,
		destinationParent: DirectoryLease,
		destinationName: str,
	) -> None: ...

	def deleteFile(self, directory: DirectoryLease, name: str) -> None: ...

	def deleteDirectory(self, directory: DirectoryLease) -> None: ...

	def close(self, directory: DirectoryLease) -> None: ...


class PathDirectoryAuthority:
	"""Portable fallback used by tests; production Windows uses native handles."""

	@staticmethod
	def _child(parent: DirectoryLease, name: str) -> Path:
		if not name or Path(name).name != name:
			raise ValueError("directory entry must be a single component")
		return parent.path / name

	def openRoot(self, root: Path, *, create: bool) -> DirectoryLease:
		if create:
			root.mkdir(mode=0o700, parents=True, exist_ok=True)
		if not isOrdinaryDirectory(root):
			raise OSError("publication root is unsafe")
		return DirectoryLease(root, root)

	def openChild(
		self,
		parent: DirectoryLease,
		name: str,
		*,
		create: bool = False,
		deletable: bool = False,
	) -> DirectoryLease:
		_ = deletable
		path = self._child(parent, name)
		if create:
			path.mkdir(mode=0o700)
		if not isOrdinaryDirectory(path):
			raise OSError("publication directory is unsafe")
		return DirectoryLease(path, path)

	def writeFile(self, directory: DirectoryLease, name: str, payload: bytes) -> None:
		target = self._child(directory, name)
		if target.exists():
			raise FileExistsError(target)
		temporary = self._child(directory, f".{name}.{os.urandom(8).hex()}.tmp")
		with temporary.open("xb") as stream:
			_ = stream.write(payload)
			stream.flush()
			os.fsync(stream.fileno())
		try:
			os.link(temporary, target)
		finally:
			temporary.unlink(missing_ok=True)

	def readFile(self, directory: DirectoryLease, name: str) -> bytes:
		return self._child(directory, name).read_bytes()

	def ordinaryFile(self, directory: DirectoryLease, name: str) -> bool:
		return isOrdinaryFile(self._child(directory, name))

	def rename(
		self,
		source: DirectoryLease,
		destinationParent: DirectoryLease,
		destinationName: str,
	) -> None:
		destination = self._child(destinationParent, destinationName)
		if destination.exists():
			raise FileExistsError(destination)
		os.rename(source.path, destination)
		source.path = destination

	def deleteFile(self, directory: DirectoryLease, name: str) -> None:
		self._child(directory, name).unlink()

	def deleteDirectory(self, directory: DirectoryLease) -> None:
		directory.path.rmdir()

	def close(self, directory: DirectoryLease) -> None:
		_ = directory


class _WindowsDirectoryAuthority:
	"""No-follow NT directory handles and handle-relative mutations."""

	def __init__(self) -> None:
		super().__init__()
		self._kernel32 = cast(Any, ctypes.WinDLL("kernel32", use_last_error=True))
		self._ntdll = cast(Any, ctypes.WinDLL("ntdll"))
		self._kernel32.CreateFileW.argtypes = (
			wintypes.LPCWSTR,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.LPVOID,
			wintypes.DWORD,
			wintypes.DWORD,
			wintypes.HANDLE,
		)
		self._kernel32.CreateFileW.restype = wintypes.HANDLE
		self._kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
		self._kernel32.CloseHandle.restype = wintypes.BOOL
		self._kernel32.GetFileInformationByHandleEx.argtypes = (
			wintypes.HANDLE,
			wintypes.INT,
			wintypes.LPVOID,
			wintypes.DWORD,
		)
		self._kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
		self._kernel32.WriteFile.argtypes = (
			wintypes.HANDLE,
			wintypes.LPCVOID,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPVOID,
		)
		self._kernel32.WriteFile.restype = wintypes.BOOL
		self._kernel32.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
		self._kernel32.FlushFileBuffers.restype = wintypes.BOOL
		self._kernel32.GetFileSizeEx.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong))
		self._kernel32.GetFileSizeEx.restype = wintypes.BOOL
		self._kernel32.ReadFile.argtypes = (
			wintypes.HANDLE,
			wintypes.LPVOID,
			wintypes.DWORD,
			ctypes.POINTER(wintypes.DWORD),
			wintypes.LPVOID,
		)
		self._kernel32.ReadFile.restype = wintypes.BOOL
		self._ntdll.NtCreateFile.argtypes = (
			ctypes.POINTER(wintypes.HANDLE),
			wintypes.DWORD,
			ctypes.POINTER(_ObjectAttributes),
			ctypes.POINTER(_IoStatusBlock),
			wintypes.LPVOID,
			wintypes.ULONG,
			wintypes.ULONG,
			wintypes.ULONG,
			wintypes.ULONG,
			wintypes.LPVOID,
			wintypes.ULONG,
		)
		self._ntdll.NtCreateFile.restype = wintypes.LONG
		self._ntdll.NtSetInformationFile.argtypes = (
			wintypes.HANDLE,
			ctypes.POINTER(_IoStatusBlock),
			wintypes.LPVOID,
			wintypes.ULONG,
			wintypes.ULONG,
		)
		self._ntdll.NtSetInformationFile.restype = wintypes.LONG
		self._ntdll.RtlNtStatusToDosError.argtypes = (wintypes.LONG,)
		self._ntdll.RtlNtStatusToDosError.restype = wintypes.ULONG

	def _raiseStatus(self, status: int) -> None:
		if status < 0:
			error = int(self._ntdll.RtlNtStatusToDosError(status))
			raise OSError(error, os.strerror(error))

	def _isSafeDirectory(self, handle: object) -> None:
		info = _FileAttributeTagInfo()
		if not self._kernel32.GetFileInformationByHandleEx(
			handle,
			9,  # FileAttributeTagInfo
			ctypes.byref(info),
			ctypes.sizeof(info),
		):
			raise ctypes.WinError(ctypes.get_last_error())
		if (
			not info.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY
			or info.FileAttributes & _REPARSE_POINT_ATTRIBUTE
		):
			raise OSError("publication directory is unsafe")

	def _open(
		self,
		parent: object | None,
		name: str,
		*,
		create: bool,
		directory: bool,
		exclusive: bool = False,
		deletable: bool = False,
		readable: bool = False,
	) -> object:
		if not name:
			raise ValueError("directory entry must be nonempty")
		buffer = ctypes.create_unicode_buffer(name)
		unicode = _UnicodeString(
			len(name.encode("utf-16-le")),
			ctypes.sizeof(buffer),
			ctypes.cast(buffer, wintypes.LPWSTR),
		)
		attributes = _ObjectAttributes(
			ctypes.sizeof(_ObjectAttributes),
			parent,
			ctypes.pointer(unicode),
			0x40,  # OBJ_CASE_INSENSITIVE
			None,
			None,
		)
		status = _IoStatusBlock()
		handle = wintypes.HANDLE()
		options = _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT
		options |= _FILE_DIRECTORY_FILE if directory else _FILE_NON_DIRECTORY_FILE
		desired = _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
		if directory:
			desired |= _FILE_READ_DATA
			if create:
				desired |= _FILE_WRITE_DATA | 0x4
		else:
			desired |= _FILE_READ_DATA if readable else _FILE_WRITE_DATA
		if deletable:
			desired |= _DELETE
		result = int(
			self._ntdll.NtCreateFile(
				ctypes.byref(handle),
				desired,
				ctypes.byref(attributes),
				ctypes.byref(status),
				None,
				0,
				_FILE_SHARE_ALL,
				_FILE_CREATE if exclusive else (_FILE_OPEN_IF if create else _FILE_OPEN),
				options,
				None,
				0,
			),
		)
		self._raiseStatus(result)
		return handle

	def openRoot(self, root: Path, *, create: bool) -> DirectoryLease:
		anchor = root.anchor
		if not anchor:
			raise ValueError("publication root must be drive-qualified")
		handle = self._kernel32.CreateFileW(
			anchor,
			# The volume root need not be deletable. Opening it with DELETE is
			# commonly denied even when its descendant TEMP directory is writable.
			_FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
			_FILE_SHARE_ALL,
			None,
			3,
			_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
			None,
		)
		if handle == wintypes.HANDLE(-1).value:
			raise ctypes.WinError(ctypes.get_last_error())
		lease = DirectoryLease(Path(anchor), handle)
		try:
			for component in root.parts[1:]:
				try:
					child = self.openChild(lease, component)
				except OSError as error:
					if not create or error.errno not in (2, 3):
						raise
					child = self.openChild(lease, component, create=True)
				self.close(lease)
				lease = child
			return lease
		except Exception:
			self.close(lease)
			raise

	def openChild(
		self,
		parent: DirectoryLease,
		name: str,
		*,
		create: bool = False,
		deletable: bool = False,
	) -> DirectoryLease:
		if Path(name).name != name:
			raise ValueError("directory entry must be a single component")
		handle = self._open(
			parent.handle,
			name,
			create=create,
			directory=True,
			deletable=deletable,
		)
		try:
			self._isSafeDirectory(handle)
			return DirectoryLease(parent.path / name, handle)
		except Exception:
			_ = self._kernel32.CloseHandle(handle)
			raise

	def writeFile(self, directory: DirectoryLease, name: str, payload: bytes) -> None:
		if Path(name).name != name:
			raise ValueError("artifact name must be a single component")
		temporaryName = f".{name}.{os.urandom(8).hex()}.tmp"
		handle = self._open(
			directory.handle,
			temporaryName,
			create=True,
			directory=False,
			exclusive=True,
			deletable=True,
		)
		published = False
		try:
			written = wintypes.DWORD()
			buffer = ctypes.create_string_buffer(payload)
			if not self._kernel32.WriteFile(
				handle,
				buffer,
				len(payload),
				ctypes.byref(written),
				None,
			) or written.value != len(payload):
				raise ctypes.WinError(ctypes.get_last_error())
			if not self._kernel32.FlushFileBuffers(handle):
				raise ctypes.WinError(ctypes.get_last_error())
			self.rename(
				DirectoryLease(directory.path / temporaryName, handle),
				directory,
				name,
			)
			published = True
		finally:
			if not published:
				try:
					self._delete(handle)
				except OSError:
					pass
			_ = self._kernel32.CloseHandle(handle)

	def readFile(self, directory: DirectoryLease, name: str) -> bytes:
		handle = self._open(directory.handle, name, create=False, directory=False, readable=True)
		try:
			info = _FileAttributeTagInfo()
			if not self._kernel32.GetFileInformationByHandleEx(
				handle, 9, ctypes.byref(info), ctypes.sizeof(info)
			):
				raise ctypes.WinError(ctypes.get_last_error())
			if info.FileAttributes & (_FILE_ATTRIBUTE_DIRECTORY | _REPARSE_POINT_ATTRIBUTE):
				raise OSError("publication artifact is unsafe")
			size = ctypes.c_longlong()
			if not self._kernel32.GetFileSizeEx(handle, ctypes.byref(size)) or size.value < 0:
				raise ctypes.WinError(ctypes.get_last_error())
			buffer = ctypes.create_string_buffer(size.value)
			read = wintypes.DWORD()
			if not self._kernel32.ReadFile(handle, buffer, size.value, ctypes.byref(read), None):
				raise ctypes.WinError(ctypes.get_last_error())
			if read.value != size.value:
				raise OSError("publication artifact was read incompletely")
			return buffer.raw
		finally:
			_ = self._kernel32.CloseHandle(handle)

	def ordinaryFile(self, directory: DirectoryLease, name: str) -> bool:
		try:
			handle = self._open(directory.handle, name, create=False, directory=False, readable=True)
		except OSError:
			return False
		try:
			info = _FileAttributeTagInfo()
			return bool(
				self._kernel32.GetFileInformationByHandleEx(
					handle, 9, ctypes.byref(info), ctypes.sizeof(info)
				)
				and not info.FileAttributes & (_FILE_ATTRIBUTE_DIRECTORY | _REPARSE_POINT_ATTRIBUTE)
			)
		finally:
			_ = self._kernel32.CloseHandle(handle)

	def rename(
		self,
		source: DirectoryLease,
		destinationParent: DirectoryLease,
		destinationName: str,
	) -> None:
		if Path(destinationName).name != destinationName:
			raise ValueError("directory entry must be a single component")
		name = destinationName.encode("utf-16-le")
		value = ctypes.create_string_buffer(24 + len(name))
		_ = ctypes.memset(ctypes.addressof(value), 0, len(value))
		parentHandle = wintypes.HANDLE(cast(Any, destinationParent.handle).value)
		_ = ctypes.memmove(
			ctypes.addressof(value) + 8,
			ctypes.byref(parentHandle),
			ctypes.sizeof(parentHandle),
		)
		_ = ctypes.memmove(ctypes.addressof(value) + 16, ctypes.byref(wintypes.ULONG(len(name))), 4)
		_ = ctypes.memmove(ctypes.addressof(value) + 20, name, len(name))
		status = _IoStatusBlock()
		result = int(
			self._ntdll.NtSetInformationFile(
				source.handle,
				ctypes.byref(status),
				value,
				len(value),
				_FILE_RENAME_INFORMATION,
			),
		)
		self._raiseStatus(result)
		source.path = destinationParent.path / destinationName

	def deleteFile(self, directory: DirectoryLease, name: str) -> None:
		handle = self._open(directory.handle, name, create=False, directory=False, deletable=True)
		try:
			self._delete(handle)
		finally:
			_ = self._kernel32.CloseHandle(handle)

	def deleteDirectory(self, directory: DirectoryLease) -> None:
		self._delete(directory.handle)

	def _delete(self, handle: object) -> None:
		value = ctypes.c_byte(1)
		status = _IoStatusBlock()
		result = int(
			self._ntdll.NtSetInformationFile(
				handle,
				ctypes.byref(status),
				ctypes.byref(value),
				ctypes.sizeof(value),
				_FILE_DISPOSITION_INFORMATION,
			),
		)
		self._raiseStatus(result)

	def close(self, directory: DirectoryLease) -> None:
		_ = self._kernel32.CloseHandle(directory.handle)


@dataclass(frozen=True, slots=True)
class PublicationPackage:
	publicationId: str
	executable: str
	processId: int
	captureKind: CaptureKind
	completedAt: datetime
	artifacts: tuple[tuple[str, bytes], ...]
	screenshotWarning: str | None
	subject: str | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.publicationId, "publicationId")
		if self.captureKind not in DOCUMENTS_BY_KIND:
			raise ValueError("captureKind is not supported")
		if type(self.processId) is not int or self.processId < 0 or self.processId > 0xFFFFFFFF:
			raise ValueError("processId must be a nonnegative 32-bit integer")
		if self.completedAt.tzinfo is not None:
			raise ValueError("completedAt must be a local wall-clock value")
		if self.subject is not None and not self.subject:
			raise ValueError("subject must be a nonempty string when provided")
		if any(not name or type(payload) is not bytes for name, payload in self.artifacts):
			raise ValueError("artifacts require names and byte payloads")


@dataclass(frozen=True, slots=True)
class PublicationPolicy:
	cancelled: bool = False
	secure: bool = False
	schemaValidated: bool = True
	privacyValidated: bool = True
	generationCurrent: bool = True

	@property
	def admitted(self) -> bool:
		return (
			not self.cancelled
			and not self.secure
			and self.schemaValidated
			and self.privacyValidated
			and self.generationCurrent
		)


@dataclass(frozen=True, slots=True)
class PublicationReceipt:
	publicationId: str
	path: Path
	folderName: str
	artifacts: tuple[str, ...]

	def __post_init__(self) -> None:
		requireOpaqueId(self.publicationId, "publicationId")
		if self.path.name != self.folderName:
			raise ValueError("receipt path and folder name must agree")
		if not self.artifacts or len(set(self.artifacts)) != len(self.artifacts):
			raise ValueError("receipt artifacts must be nonempty and unique")


@dataclass(frozen=True, slots=True)
class PublicationResult:
	committed: bool
	receipt: PublicationReceipt | None
	errorCode: str | None
	warningCode: str | None

	def __post_init__(self) -> None:
		if not self.committed and self.receipt is not None:
			raise ValueError("only committed publication can carry a receipt")
		if self.committed and self.errorCode is not None:
			raise ValueError("committed publication cannot carry a failure code")
		if not self.committed and self.errorCode is None:
			raise ValueError("failed publication requires a stable error code")
		if self.committed and self.receipt is None and self.warningCode is None:
			raise ValueError("unverified committed publication requires a warning")


@dataclass(frozen=True, slots=True)
class DiscoverySnapshot:
	recognizedCount: int
	suspiciousCount: int
	revision: int

	def __post_init__(self) -> None:
		if min(self.recognizedCount, self.suspiciousCount, self.revision) < 0:
			raise ValueError("discovery counts and revision must be nonnegative")


@dataclass(frozen=True, slots=True)
class CleanupOutcome:
	deletedCount: int
	skippedCount: int
	failedCount: int
	suspiciousCount: int

	def __post_init__(self) -> None:
		if (
			min(
				self.deletedCount,
				self.skippedCount,
				self.failedCount,
				self.suspiciousCount,
			)
			< 0
		):
			raise ValueError("cleanup counts must be nonnegative")


class PublicationBackend(Protocol):
	def destinationExists(
		self,
		applicationName: str,
		folderName: str,
		context: CorrelationContext,
	) -> bool: ...

	def createStaging(
		self,
		applicationName: str,
		stagingName: str,
		nonce: str,
		context: CorrelationContext,
	) -> str: ...

	def writeAtomic(
		self,
		staging: str,
		artifactName: str,
		payload: bytes,
		context: CorrelationContext,
	) -> None: ...

	def validateStaging(
		self,
		staging: str,
		nonce: str,
		expectedArtifacts: tuple[str, ...],
		context: CorrelationContext,
	) -> None: ...

	def commit(
		self,
		staging: str,
		applicationName: str,
		folderName: str,
		context: CorrelationContext,
	) -> Path: ...

	def validateCommitted(
		self,
		path: Path,
		publicationId: str,
		expectedArtifacts: tuple[str, ...],
		context: CorrelationContext,
	) -> None: ...

	def catalog(self, receipt: PublicationReceipt, context: CorrelationContext) -> None: ...

	def discardStaging(self, staging: str, nonce: str, context: CorrelationContext) -> None: ...

	def discover(self, context: CorrelationContext) -> DiscoverySnapshot: ...

	def clearAll(self, discoveryRevision: int, context: CorrelationContext) -> CleanupOutcome: ...

	def revalidate(self, receipt: PublicationReceipt, context: CorrelationContext) -> bool: ...

	def newest(self, captureKind: CaptureKind, context: CorrelationContext) -> PublicationReceipt | None: ...


def _metadata(
	package: PublicationPackage,
	applicationName: str,
	folderName: str,
	nonce: str,
	expectedArtifacts: tuple[str, ...],
) -> bytes:
	value = {
		"schemaVersion": 1,
		"publicationId": package.publicationId,
		"applicationName": applicationName,
		"folderName": folderName,
		"executable": package.executable,
		"processId": package.processId,
		"captureKind": package.captureKind,
		"completedAt": package.completedAt.isoformat(timespec="milliseconds"),
		"ownershipNonce": nonce,
		"artifacts": list(expectedArtifacts),
		"screenshotWarning": package.screenshotWarning,
	}
	return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _plainObject(value: object, label: str, fields: tuple[str, ...] | None = None) -> dict[str, object]:
	if not isinstance(value, dict):
		raise ValueError(f"{label} must be an object")
	raw = cast(dict[object, object], value)
	if not all(isinstance(key, str) for key in raw):
		raise ValueError(f"{label} must be an object")
	result = cast(dict[str, object], raw)
	if fields is not None and set(result) != set(fields):
		raise ValueError(f"{label} fields do not match the closed schema")
	return result


def _correlationObject(context: CorrelationContext) -> dict[str, object]:
	complete = requireCompleteCorrelation(context)
	assert complete.operationId is not None
	assert complete.jobId is not None
	return {
		"sessionId": complete.sessionId.value,
		"operationId": complete.operationId.value,
		"jobId": complete.jobId.value,
		"generation": complete.generation,
	}


def _screenshotArtifacts(
	package: PublicationPackage,
	artifactMap: dict[str, bytes],
	context: CorrelationContext,
) -> tuple[str, ...]:
	documentNames = DOCUMENTS_BY_KIND[package.captureKind]
	if any(name not in artifactMap for name in documentNames):
		raise ValueError("publication is missing a required document")
	for name in documentNames:
		try:
			value = json.loads(artifactMap[name].decode("utf-8", errors="strict"))
		except (UnicodeDecodeError, json.JSONDecodeError) as error:
			raise ValueError("publication document is not strict UTF-8 JSON") from error
		document = _plainObject(value, "publication document")
		if name != documentNames[0] and "screenshot" in document:
			raise ValueError("only the containing document may carry screenshot evidence")

	try:
		containing = cast(
			dict[str, object],
			json.loads(artifactMap[documentNames[0]].decode("utf-8", errors="strict")),
		)
	except (UnicodeDecodeError, json.JSONDecodeError) as error:
		raise ValueError("containing document is not strict UTF-8 JSON") from error
	if containing.get("documentKind") != package.captureKind:
		raise ValueError("containing document kind does not match the package")
	screenshot = _plainObject(
		containing.get("screenshot"),
		"screenshot result",
		("attempt", "status", "image", "error", "warning"),
	)
	if screenshot["warning"] != UNREDACTED_SCREENSHOT_WARNING:
		raise ValueError("screenshot result warning is not current")
	attempt = _plainObject(
		screenshot["attempt"],
		"screenshot attempt",
		("attemptId", "generation", "target", "correlation"),
	)
	attemptId = attempt["attemptId"]
	if not isinstance(attemptId, str):
		raise ValueError("screenshot attempt ID must be a string")
	requireOpaqueId(attemptId, "screenshot attempt ID")
	if attempt["generation"] != context.generation:
		raise ValueError("screenshot attempt generation is stale")
	if attempt["correlation"] != _correlationObject(context):
		raise ValueError("screenshot attempt correlation does not match publication")
	target = _plainObject(
		attempt["target"],
		"screenshot target",
		("scopeKind", "scopeId", "geometry"),
	)
	if target["scopeKind"] != "containingForeground":
		raise ValueError("screenshot target is not the containing foreground")
	scopeId = target["scopeId"]
	if not isinstance(scopeId, str):
		raise ValueError("screenshot target ID must be a string")
	requireOpaqueId(scopeId, "screenshot target ID")
	geometry = target["geometry"]
	if not isinstance(geometry, list):
		raise ValueError("screenshot target geometry is invalid")
	geometryItems = cast(list[object], geometry)
	if len(geometryItems) != 4 or any(type(component) is not int for component in geometryItems):
		raise ValueError("screenshot target geometry is invalid")
	containingTarget = _plainObject(
		containing.get("containingForeground"),
		"containing foreground",
		("scopeId", "geometry"),
	)
	if containingTarget != {"scopeId": scopeId, "geometry": geometryItems}:
		raise ValueError("screenshot attempt does not match the containing foreground")

	status = screenshot["status"]
	png = artifactMap.get(_SCREENSHOT_NAME)
	if status == "value":
		image = _plainObject(
			screenshot["image"],
			"screenshot image",
			("sha256", "byteLength", "width", "height", "capturedAt"),
		)
		if screenshot["error"] is not None or png is None:
			raise ValueError("successful screenshot requires exactly one PNG and no error")
		width = image["width"]
		height = image["height"]
		if (
			image["sha256"] != hashlib.sha256(png).hexdigest()
			or image["byteLength"] != len(png)
			or type(width) is not int
			or width <= 0
			or type(height) is not int
			or height <= 0
			or not isinstance(image["capturedAt"], str)
		):
			raise ValueError("screenshot image metadata does not match the current PNG")
		return (*documentNames, _SCREENSHOT_NAME)
	if status not in ("failed", "absent") or png is not None or screenshot["image"] is not None:
		raise ValueError("non-value screenshot must have typed null evidence and no PNG")
	error = _plainObject(
		screenshot["error"],
		"screenshot error",
		("code", "diagnosticId"),
	)
	for name in ("code", "diagnosticId"):
		value = error[name]
		if not isinstance(value, str):
			raise ValueError("screenshot error values must be strings")
		requireOpaqueId(value, f"screenshot error {name}")
	return documentNames


class PublicationManager:
	def __init__(
		self,
		backend: PublicationBackend,
		*,
		nonceFactory: Callable[[], str] | None = None,
	) -> None:
		super().__init__()
		self._backend = backend
		self._nonceFactory = nonceFactory if nonceFactory is not None else lambda: os.urandom(16).hex()

	def _folderName(self, package: PublicationPackage, context: CorrelationContext) -> str:
		collisionIndex = 0
		for _ in range(_MAX_FOLDER_COLLISION_ATTEMPTS):
			folderName = captureDirectoryName(
				package.completedAt,
				package.captureKind,
				subject=package.subject,
				collisionIndex=collisionIndex,
			)
			applicationName = applicationDirectoryName(package.executable, package.processId)
			if not self._backend.destinationExists(applicationName, folderName, context):
				return folderName
			collisionIndex = 2 if collisionIndex == 0 else collisionIndex + 1
		raise _FolderCollisionLimitError("publication folder collision limit reached")

	def publish(
		self,
		package: PublicationPackage,
		policyProvider: Callable[[], PublicationPolicy],
		context: CorrelationContext,
	) -> PublicationResult:
		_ = requireCompleteCorrelation(context)
		artifactMap = dict(package.artifacts)
		try:
			if (
				len(artifactMap) != len(package.artifacts)
				or package.screenshotWarning != UNREDACTED_SCREENSHOT_WARNING
			):
				raise ValueError("publication package is not closed")
			if INDEX_FILENAME in artifactMap:
				expectedPayloads = validateBundleArtifacts(artifactMap)
			else:
				expectedPayloads = _screenshotArtifacts(package, artifactMap, context)
			if tuple(artifactMap) != expectedPayloads:
				raise ValueError("publication artifact names or order are not exact")
		except (TypeError, ValueError):
			return PublicationResult(False, None, "KS.OUTPUT.INVALID_PACKAGE", None)
		applicationName = applicationDirectoryName(package.executable, package.processId)
		staging: str | None = None
		nonce: str | None = None
		renamed = False
		receipt: PublicationReceipt | None = None
		try:
			if not policyProvider().admitted:
				return PublicationResult(False, None, "KS.OUTPUT.NOT_ADMITTED", None)
			folderName = self._folderName(package, context)
			nonce = self._nonceFactory()
			requireOpaqueId(nonce, "ownership nonce")
			stagingName = f".{folderName}.{nonce}.pending"
			expectedArtifacts = (*expectedPayloads, _METADATA_NAME)
			staging = self._backend.createStaging(applicationName, stagingName, nonce, context)
			for artifactName in expectedPayloads:
				self._backend.writeAtomic(staging, artifactName, artifactMap[artifactName], context)
			self._backend.writeAtomic(
				staging,
				_METADATA_NAME,
				_metadata(package, applicationName, folderName, nonce, expectedArtifacts),
				context,
			)
			self._backend.validateStaging(staging, nonce, expectedArtifacts, context)
			if not policyProvider().admitted:
				raise PermissionError("publication policy changed before commit")
			path = self._backend.commit(staging, applicationName, folderName, context)
			renamed = True
			if path.name != folderName:
				raise ValueError("committed path does not match the requested folder")
			receipt = PublicationReceipt(
				package.publicationId,
				path,
				folderName,
				expectedArtifacts,
			)
			self._backend.validateCommitted(path, package.publicationId, expectedArtifacts, context)
			self._backend.catalog(receipt, context)
			if not policyProvider().admitted:
				return PublicationResult(True, receipt, None, "KS.OUTPUT.POSTCOMMIT_WARNING")
			return PublicationResult(True, receipt, None, None)
		except _FolderCollisionLimitError:
			return PublicationResult(False, None, "KS.OUTPUT.FOLDER_COLLISION_LIMIT", None)
		except Exception:
			if renamed:
				return PublicationResult(True, receipt, None, "KS.OUTPUT.POSTCOMMIT_WARNING")
			if staging is not None and nonce is not None:
				try:
					self._backend.discardStaging(staging, nonce, context)
				except Exception:
					pass
			return PublicationResult(False, None, "KS.OUTPUT.PUBLICATION_FAILED", None)

	def discover(self, context: CorrelationContext) -> DiscoverySnapshot:
		_ = requireCompleteCorrelation(context)
		return self._backend.discover(context)

	def clearAll(self, discoveryRevision: int, context: CorrelationContext) -> CleanupOutcome:
		_ = requireCompleteCorrelation(context)
		return self._backend.clearAll(discoveryRevision, context)

	def revalidate(self, receipt: PublicationReceipt, context: CorrelationContext) -> bool:
		_ = requireCompleteCorrelation(context)
		return self._backend.revalidate(receipt, context)

	def newest(self, captureKind: CaptureKind, context: CorrelationContext) -> PublicationReceipt | None:
		_ = requireCompleteCorrelation(context)
		return self._backend.newest(captureKind, context)


class LocalPublicationBackend:
	def __init__(
		self,
		root: Path,
		*,
		directoryAuthority: DirectoryAuthority | None = None,
	) -> None:
		super().__init__()
		if not root.is_absolute():
			raise ValueError("publication root must be absolute")
		self._root = root
		self._directories = directoryAuthority or (
			_WindowsDirectoryAuthority() if os.name == "nt" else PathDirectoryAuthority()
		)
		self._rootDirectory: DirectoryLease | None = None
		self._stagingPaths: dict[str, tuple[DirectoryLease, DirectoryLease]] = {}
		self._stagingArtifacts: dict[str, set[str]] = {}
		self._discovered: tuple[PublicationReceipt, ...] = ()
		self._suspiciousCount = 0
		self._discoveryRevision = 0

	def _openRoot(self, *, create: bool) -> DirectoryLease:
		if self._rootDirectory is None:
			self._rootDirectory = self._directories.openRoot(self._root, create=create)
		return self._rootDirectory

	def close(self) -> None:
		root = self._rootDirectory
		self._rootDirectory = None
		if root is not None:
			self._directories.close(root)

	def _openExistingDirectory(self, path: Path) -> DirectoryLease:
		root = self._openRoot(create=False)
		try:
			relative = path.relative_to(self._root)
		except ValueError as error:
			raise OSError("publication directory is outside the output root") from error
		directory = root
		opened: list[DirectoryLease] = []
		try:
			for index, component in enumerate(relative.parts):
				directory = self._directories.openChild(
					directory,
					component,
					deletable=index == len(relative.parts) - 1,
				)
				opened.append(directory)
			for item in reversed(opened[:-1]):
				self._directories.close(item)
			return directory
		except Exception:
			for item in reversed(opened):
				self._directories.close(item)
			raise

	def destinationExists(
		self,
		applicationName: str,
		folderName: str,
		context: CorrelationContext,
	) -> bool:
		_ = requireCompleteCorrelation(context)
		return (self._root / applicationName / folderName).exists()

	def createStaging(
		self,
		applicationName: str,
		stagingName: str,
		nonce: str,
		context: CorrelationContext,
	) -> str:
		_ = requireCompleteCorrelation(context)
		root = self._openRoot(create=True)
		try:
			application = self._directories.openChild(root, applicationName)
		except OSError:
			application = self._directories.openChild(root, applicationName, create=True)
		try:
			staging = self._directories.openChild(
				application,
				stagingName,
				create=True,
				deletable=True,
			)
		except Exception:
			self._directories.close(application)
			raise
		self._stagingPaths[stagingName] = (application, staging)
		self._stagingArtifacts[stagingName] = set()
		return stagingName

	def writeAtomic(
		self,
		staging: str,
		artifactName: str,
		payload: bytes,
		context: CorrelationContext,
	) -> None:
		_ = requireCompleteCorrelation(context)
		if Path(artifactName).name != artifactName:
			raise ValueError("artifact name must be a single component")
		_directoryParent, directory = self._stagingPaths[staging]
		self._directories.writeFile(directory, artifactName, payload)
		self._stagingArtifacts[staging].add(artifactName)

	def _metadataObject(self, directory: Path) -> dict[str, object]:
		try:
			text = (directory / _METADATA_NAME).read_text(encoding="utf-8")
		except UnicodeDecodeError as error:
			raise ValueError("publication metadata must be UTF-8") from error
		value = cast(object, json.loads(text))
		if not isinstance(value, dict):
			raise ValueError("publication metadata must be an object")
		return cast(dict[str, object], value)

	def _metadataObjectIn(self, directory: DirectoryLease) -> dict[str, object]:
		try:
			text = self._directories.readFile(directory, _METADATA_NAME).decode("utf-8", errors="strict")
		except UnicodeDecodeError as error:
			raise ValueError("publication metadata must be UTF-8") from error
		value = cast(object, json.loads(text))
		if not isinstance(value, dict):
			raise ValueError("publication metadata must be an object")
		return cast(dict[str, object], value)

	def validateStaging(
		self,
		staging: str,
		nonce: str,
		expectedArtifacts: tuple[str, ...],
		context: CorrelationContext,
	) -> None:
		_ = requireCompleteCorrelation(context)
		_directoryParent, directory = self._stagingPaths[staging]
		if set(expectedArtifacts) != self._stagingArtifacts[staging]:
			raise ValueError("staging artifact set is not closed")
		if any(not self._directories.ordinaryFile(directory, artifact) for artifact in expectedArtifacts):
			raise ValueError("staging contains a non-ordinary artifact")
		metadata = self._metadataObjectIn(directory)
		if metadata.get("ownershipNonce") != nonce:
			raise ValueError("staging ownership changed")

	def commit(
		self,
		staging: str,
		applicationName: str,
		folderName: str,
		context: CorrelationContext,
	) -> Path:
		_ = requireCompleteCorrelation(context)
		application, source = self._stagingPaths[staging]
		self._directories.rename(source, application, folderName)
		del self._stagingPaths[staging]
		del self._stagingArtifacts[staging]
		path = source.path
		self._directories.close(source)
		self._directories.close(application)
		return path

	def validateCommitted(
		self,
		path: Path,
		publicationId: str,
		expectedArtifacts: tuple[str, ...],
		context: CorrelationContext,
	) -> None:
		_ = requireCompleteCorrelation(context)
		directory = self._openExistingDirectory(path)
		try:
			if any(not self._directories.ordinaryFile(directory, artifact) for artifact in expectedArtifacts):
				raise ValueError("committed publication contains a non-ordinary artifact")
			if self._metadataObjectIn(directory).get("publicationId") != publicationId:
				raise ValueError("committed publication identity changed")
		finally:
			self._directories.close(directory)

	def catalog(self, receipt: PublicationReceipt, context: CorrelationContext) -> None:
		_ = receipt
		_ = requireCompleteCorrelation(context)

	def discardStaging(self, staging: str, nonce: str, context: CorrelationContext) -> None:
		_ = requireCompleteCorrelation(context)
		leases = self._stagingPaths.get(staging)
		if leases is None:
			return
		application, directory = leases
		artifacts = self._stagingArtifacts[staging]
		if self._directories.ordinaryFile(directory, _METADATA_NAME):
			try:
				metadata = self._metadataObjectIn(directory)
			except (OSError, ValueError):
				return
			if metadata.get("ownershipNonce") != nonce:
				return
		if any(not self._directories.ordinaryFile(directory, artifact) for artifact in artifacts):
			return
		for artifact in artifacts:
			self._directories.deleteFile(directory, artifact)
		self._directories.deleteDirectory(directory)
		del self._stagingPaths[staging]
		del self._stagingArtifacts[staging]
		self._directories.close(directory)
		self._directories.close(application)

	def _recognize(self, path: Path) -> PublicationReceipt | None:
		try:
			if not isOrdinaryDirectory(path):
				return None
			metadata = self._metadataObject(path)
			expectedFields = {
				"schemaVersion",
				"publicationId",
				"applicationName",
				"folderName",
				"executable",
				"processId",
				"captureKind",
				"completedAt",
				"ownershipNonce",
				"artifacts",
				"screenshotWarning",
			}
			if set(metadata) != expectedFields or metadata["folderName"] != path.name:
				return None
			artifacts = metadata["artifacts"]
			if not isinstance(artifacts, list):
				return None
			artifactValues = cast(list[object], artifacts)
			if not all(isinstance(item, str) for item in artifactValues):
				return None
			names = tuple(cast(list[str], artifactValues))
			if tuple(sorted(item.name for item in path.iterdir())) != tuple(sorted(names)):
				return None
			if any(not isOrdinaryFile(path / name) for name in names):
				return None
			publicationId = metadata["publicationId"]
			if not isinstance(publicationId, str):
				return None
			return PublicationReceipt(publicationId, path, path.name, names)
		except (OSError, ValueError, json.JSONDecodeError):
			return None

	def discover(self, context: CorrelationContext) -> DiscoverySnapshot:
		_ = requireCompleteCorrelation(context)
		recognized: list[PublicationReceipt] = []
		suspicious = 0
		if self._root.exists():
			for application in tuple(self._root.iterdir()):
				if application.name in ("logs", "runtime"):
					continue
				if not isOrdinaryDirectory(application):
					suspicious += 1
					continue
				for capture in tuple(application.iterdir()):
					if capture.name.startswith(".") and capture.name.endswith(".pending"):
						continue
					receipt = self._recognize(capture)
					if receipt is None:
						suspicious += 1
					else:
						recognized.append(receipt)
		recognized.sort(key=lambda item: item.folderName)
		self._discovered = tuple(recognized[:10_000])
		self._suspiciousCount = suspicious
		self._discoveryRevision += 1
		return DiscoverySnapshot(
			len(self._discovered),
			self._suspiciousCount,
			self._discoveryRevision,
		)

	def clearAll(self, discoveryRevision: int, context: CorrelationContext) -> CleanupOutcome:
		_ = requireCompleteCorrelation(context)
		if discoveryRevision != self._discoveryRevision:
			return CleanupOutcome(0, len(self._discovered), 0, self._suspiciousCount)
		deleted = skipped = failed = 0
		for receipt in self._discovered:
			try:
				directory = self._openExistingDirectory(receipt.path)
			except OSError:
				skipped += 1
				continue
			try:
				try:
					self.validateCommitted(receipt.path, receipt.publicationId, receipt.artifacts, context)
				except (OSError, ValueError):
					skipped += 1
					continue
				for artifact in receipt.artifacts:
					self._directories.deleteFile(directory, artifact)
				self._directories.deleteDirectory(directory)
				deleted += 1
			except OSError:
				failed += 1
			finally:
				self._directories.close(directory)
		return CleanupOutcome(deleted, skipped, failed, self._suspiciousCount)

	def revalidate(self, receipt: PublicationReceipt, context: CorrelationContext) -> bool:
		_ = requireCompleteCorrelation(context)
		try:
			self.validateCommitted(receipt.path, receipt.publicationId, receipt.artifacts, context)
		except (OSError, ValueError):
			return False
		return True

	def newest(self, captureKind: CaptureKind, context: CorrelationContext) -> PublicationReceipt | None:
		_ = requireCompleteCorrelation(context)
		candidates: list[tuple[str, str, PublicationReceipt]] = []
		if not self._root.exists():
			return None
		for application in tuple(self._root.iterdir()):
			if application.name in ("logs", "runtime") or not isOrdinaryDirectory(application):
				continue
			for capture in tuple(application.iterdir()):
				if capture.name.startswith(".") and capture.name.endswith(".pending"):
					continue
				receipt = self._recognize(capture)
				if receipt is None:
					continue
				try:
					metadata = self._metadataObject(capture)
				except (OSError, ValueError, json.JSONDecodeError):
					continue
				completedAt = metadata.get("completedAt")
				if metadata.get("captureKind") != captureKind or not isinstance(completedAt, str):
					continue
				candidates.append((completedAt, receipt.folderName, receipt))
		if not candidates:
			return None
		return max(candidates, key=lambda item: (item[0], item[1]))[2]
