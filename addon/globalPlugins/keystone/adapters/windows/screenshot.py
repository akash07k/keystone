from __future__ import annotations

from collections.abc import Callable
import ctypes
import os
from pathlib import Path
from typing import Protocol, cast

from ...domain.geometry import GeometryState, Rectangle, checkedRectangle, clipRectangle
from ...ports.effects import (
	ScreenshotAttempt,
	ScreenshotResult,
)


class ScreenshotBackend(Protocol):
	def virtualDesktop(self) -> Rectangle: ...

	def paths(self, attempt: ScreenshotAttempt) -> tuple[Path, Path]: ...

	def createScreen(self) -> object: ...

	def createBitmap(self, width: int, height: int) -> object: ...

	def createMemory(self) -> object: ...

	def selectBitmap(self, memory: object, bitmap: object) -> object: ...

	def blit(self, memory: object, screen: object, captured: Rectangle) -> None: ...

	def openImage(self, path: Path) -> object: ...

	def encodePng(self, bitmap: object, image: object) -> None: ...

	def flushImage(self, image: object) -> None: ...

	def closeImage(self, image: object) -> None: ...

	def replace(self, temporary: Path, destination: Path) -> None: ...

	def validate(self, destination: Path) -> bool: ...

	def readImage(self, destination: Path) -> bytes: ...

	def discard(self, path: Path) -> None: ...

	def deselect(self, memory: object, previous: object) -> None: ...

	def release(self, resource: object) -> None: ...


def _diagnosticId(attempt: ScreenshotAttempt) -> str:
	return f"screenshot-{attempt.attemptId}-{attempt.generation}"


def _discardBestEffort(backend: ScreenshotBackend, path: Path) -> None:
	try:
		backend.discard(path)
	except Exception:
		pass


def _screenshotFilename(attempt: ScreenshotAttempt) -> str:
	"""Build a filename only from an attempt ID that cannot introduce a path segment."""
	if "/" in attempt.attemptId or "\\" in attempt.attemptId:
		raise ValueError("screenshot attemptId must not contain path separators")
	return f"screenshot-{attempt.attemptId}-{attempt.generation}.png"


class ScreenshotAdapter:
	def __init__(
		self,
		backend: ScreenshotBackend | None,
		*,
		enabled: bool,
		clock: Callable[[], str],
	) -> None:
		super().__init__()
		if enabled and backend is None:
			raise ValueError("enabled screenshot capture requires a backend")
		self._backend = backend
		self._enabled = enabled
		self._clock = clock

	def _failure(
		self,
		attempt: ScreenshotAttempt,
		code: str,
		*,
		absent: bool = False,
	) -> ScreenshotResult:
		return ScreenshotResult(
			attempt,
			"absent" if absent else "failed",
			None,
			None,
			None,
			code,
			_diagnosticId(attempt),
		)

	def captureScreenshot(self, attempt: ScreenshotAttempt) -> ScreenshotResult:
		geometry = checkedRectangle(*attempt.target.geometry)
		requested = geometry.rectangle
		if not self._enabled:
			return self._failure(
				attempt,
				"KS.SCREENSHOT.UNAVAILABLE",
				absent=True,
			)
		backend = self._backend
		if backend is None:
			return self._failure(
				attempt,
				"KS.SCREENSHOT.UNAVAILABLE",
				absent=True,
			)
		if geometry.state is not GeometryState.VALID or requested is None:
			return self._failure(attempt, "KS.SCREENSHOT.INVALID_GEOMETRY")
		try:
			clipped = clipRectangle(requested, backend.virtualDesktop())
		except Exception:
			return self._failure(attempt, "KS.SCREENSHOT.DESKTOP_UNAVAILABLE")
		if clipped.state is not GeometryState.VALID or clipped.captured is None:
			return self._failure(attempt, "KS.SCREENSHOT.OUTSIDE_DESKTOP")
		captured = clipped.captured

		screen: object | None = None
		bitmap: object | None = None
		memory: object | None = None
		previous: object | None = None
		image: object | None = None
		temporary: Path | None = None
		destination: Path | None = None
		try:
			temporary, destination = backend.paths(attempt)
			if temporary.parent != destination.parent or temporary == destination:
				raise ValueError("screenshot paths must be distinct same-directory entries")
			screen = backend.createScreen()
			bitmap = backend.createBitmap(captured.width, captured.height)
			memory = backend.createMemory()
			previous = backend.selectBitmap(memory, bitmap)
			backend.blit(memory, screen, captured)
			image = backend.openImage(temporary)
			backend.encodePng(bitmap, image)
			backend.flushImage(image)
			try:
				backend.closeImage(image)
			finally:
				image = None
			backend.replace(temporary, destination)
			if not backend.validate(destination):
				raise ValueError("current screenshot validation failed")
			payload = backend.readImage(destination)
			if not payload:
				raise ValueError("current screenshot is empty")
			_discardBestEffort(backend, destination)
			destination = None
			return ScreenshotResult(
				attempt,
				"value",
				payload,
				(captured.left, captured.top, captured.width, captured.height),
				self._clock(),
				None,
				None,
			)
		except Exception:
			if temporary is not None:
				_discardBestEffort(backend, temporary)
			if destination is not None:
				_discardBestEffort(backend, destination)
			return self._failure(
				attempt,
				"KS.SCREENSHOT.CAPTURE_FAILED",
			)
		finally:
			if image is not None:
				try:
					backend.closeImage(image)
				except Exception:
					pass
			if memory is not None and previous is not None:
				try:
					backend.deselect(memory, previous)
				except Exception:
					pass
			for resource in (memory, bitmap, screen):
				if resource is not None:
					try:
						backend.release(resource)
					except Exception:
						pass


class WxModule(Protocol):
	NullBitmap: object
	BITMAP_TYPE_PNG: int

	def ScreenDC(self) -> object: ...

	def Bitmap(self, width: int, height: int) -> object: ...

	def MemoryDC(self) -> object: ...


class WxBitmap(Protocol):
	def SaveFile(self, path: str, bitmapType: int) -> bool: ...


class WxMemory(Protocol):
	def SelectObject(self, bitmap: object) -> None: ...

	def Blit(
		self,
		destinationX: int,
		destinationY: int,
		width: int,
		height: int,
		screen: object,
		sourceX: int,
		sourceY: int,
	) -> bool: ...


def windowsVirtualDesktop() -> Rectangle:
	user32 = ctypes.WinDLL("user32", use_last_error=True)
	getSystemMetrics = user32.GetSystemMetrics
	getSystemMetrics.argtypes = [ctypes.c_int]
	getSystemMetrics.restype = ctypes.c_int
	return Rectangle(
		getSystemMetrics(76),
		getSystemMetrics(77),
		getSystemMetrics(78),
		getSystemMetrics(79),
	)


class WxScreenshotBackend:
	def __init__(
		self,
		wxModule: WxModule,
		destinationDirectory: Path,
		*,
		desktopProvider: Callable[[], Rectangle] = windowsVirtualDesktop,
	) -> None:
		super().__init__()
		if not destinationDirectory.is_absolute():
			raise ValueError("screenshot destination must be absolute")
		self._wx = wxModule
		self._destinationDirectory = destinationDirectory
		self._desktopProvider = desktopProvider

	def virtualDesktop(self) -> Rectangle:
		return self._desktopProvider()

	def paths(self, attempt: ScreenshotAttempt) -> tuple[Path, Path]:
		base = _screenshotFilename(attempt)
		return (
			self._destinationDirectory / f".{base}.tmp",
			self._destinationDirectory / base,
		)

	def createScreen(self) -> object:
		return self._wx.ScreenDC()

	def createBitmap(self, width: int, height: int) -> object:
		return self._wx.Bitmap(width, height)

	def createMemory(self) -> object:
		return self._wx.MemoryDC()

	def selectBitmap(self, memory: object, bitmap: object) -> object:
		cast(WxMemory, memory).SelectObject(bitmap)
		return self._wx.NullBitmap

	def blit(self, memory: object, screen: object, captured: Rectangle) -> None:
		if not cast(WxMemory, memory).Blit(
			0,
			0,
			captured.width,
			captured.height,
			screen,
			captured.left,
			captured.top,
		):
			raise OSError("composited screen blit failed")

	def openImage(self, path: Path) -> object:
		with path.open("xb") as stream:
			stream.flush()
			os.fsync(stream.fileno())
		return path

	def encodePng(self, bitmap: object, image: object) -> None:
		path = cast(Path, image)
		if not cast(WxBitmap, bitmap).SaveFile(str(path), self._wx.BITMAP_TYPE_PNG):
			raise OSError("PNG encoding failed")

	def flushImage(self, image: object) -> None:
		with cast(Path, image).open("r+b") as stream:
			os.fsync(stream.fileno())

	def closeImage(self, image: object) -> None:
		return None

	def replace(self, temporary: Path, destination: Path) -> None:
		os.replace(temporary, destination)

	def validate(self, destination: Path) -> bool:
		return destination.is_file() and not destination.is_symlink() and destination.stat().st_size > 0

	def readImage(self, destination: Path) -> bytes:
		return destination.read_bytes()

	def discard(self, path: Path) -> None:
		try:
			path.unlink()
		except FileNotFoundError:
			pass

	def deselect(self, memory: object, previous: object) -> None:
		cast(WxMemory, memory).SelectObject(previous)

	def release(self, resource: object) -> None:
		return None
