from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from addon.globalPlugins.keystone.adapters.windows.screenshot import (
	ScreenshotAdapter,
	WxScreenshotBackend,
)
from addon.globalPlugins.keystone.domain.geometry import Rectangle
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.domain.privacy import UNREDACTED_SCREENSHOT_WARNING
from addon.globalPlugins.keystone.ports.effects import ScreenshotAttempt, ScreenshotTarget


CONTEXT = CorrelationFactory().admit(generation=7)


class _ScreenshotBackend:
	def __init__(
		self,
		faultAt: str | None = None,
		*,
		faultError: type[BaseException] = OSError,
		discardError: BaseException | None = None,
	) -> None:
		super().__init__()
		self.faultAt = faultAt
		self.faultError = faultError
		self.discardError = discardError
		self.events: list[str] = []
		self.acquired: list[str] = []
		self.released: list[str] = []
		self.captured: Rectangle | None = None

	def _effect(self, name: str) -> None:
		self.events.append(name)
		if self.faultAt == name:
			raise self.faultError(f"injected {name} failure")

	def virtualDesktop(self) -> Rectangle:
		self._effect("virtualDesktop")
		return Rectangle(-100, -50, 1920, 1080)

	def paths(self, attempt: ScreenshotAttempt) -> tuple[Path, Path]:
		self._effect("paths")
		return (
			Path(f"C:/Temp/.{attempt.attemptId}.tmp"),
			Path(f"C:/Temp/{attempt.attemptId}.png"),
		)

	def createScreen(self) -> str:
		self._effect("createScreen")
		self.acquired.append("screen")
		return "screen"

	def createBitmap(self, width: int, height: int) -> str:
		self._effect("createBitmap")
		self.acquired.append("bitmap")
		return "bitmap"

	def createMemory(self) -> str:
		self._effect("createMemory")
		self.acquired.append("memory")
		return "memory"

	def selectBitmap(self, memory: object, bitmap: object) -> object:
		self._effect("selectBitmap")
		return "previous"

	def blit(
		self,
		memory: object,
		screen: object,
		captured: Rectangle,
	) -> None:
		self._effect("blit")
		self.captured = captured

	def openImage(self, path: Path) -> str:
		self._effect("openImage")
		self.acquired.append("image")
		return "image"

	def encodePng(self, bitmap: object, image: object) -> None:
		self._effect("encodePng")

	def flushImage(self, image: object) -> None:
		self._effect("flushImage")

	def closeImage(self, image: object) -> None:
		self._effect("closeImage")
		self.released.append("image")

	def replace(self, temporary: Path, destination: Path) -> None:
		self._effect("replace")

	def validate(self, destination: Path) -> bool:
		self._effect("validate")
		return self.faultAt != "invalid"

	def readImage(self, destination: Path) -> bytes:
		self._effect("readImage")
		return b"current-composited-pixels"

	def discard(self, path: Path) -> None:
		self.events.append("discard")
		if self.discardError is not None:
			raise self.discardError

	def deselect(self, memory: object, previous: object) -> None:
		self._effect("deselect")

	def release(self, resource: object) -> None:
		self.events.append(f"release:{resource}")
		self.released.append(str(resource))


class TestScreenshotAdapter(unittest.TestCase):
	@staticmethod
	def _attempt(
		attemptId: str = "capture-a",
		geometry: tuple[int, int, int, int] = (0, 0, 20, 10),
	) -> ScreenshotAttempt:
		return ScreenshotAttempt(
			attemptId,
			7,
			ScreenshotTarget("containingForeground", "window-42", geometry),
			CONTEXT,
		)

	def test_composited_capture_clips_requested_negative_geometry(self) -> None:
		backend = _ScreenshotBackend()
		adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "2026-07-24T09:11:22.742")
		attempt = self._attempt(geometry=(-200, -100, 400, 300))

		result = adapter.captureScreenshot(attempt)

		self.assertEqual("value", result.status)
		self.assertIs(attempt, result.attempt)
		self.assertEqual((-100, -50, 300, 250), result.capturedGeometry)
		self.assertEqual(Rectangle(-100, -50, 300, 250), backend.captured)
		self.assertEqual(b"current-composited-pixels", result.image)
		self.assertEqual(UNREDACTED_SCREENSHOT_WARNING, result.warning)
		self.assertEqual(["image", "memory", "bitmap", "screen"], backend.released)

	def test_each_fault_returns_fresh_failure_and_releases_owned_resources_in_reverse(self) -> None:
		for fault in (
			"paths",
			"createScreen",
			"createBitmap",
			"createMemory",
			"selectBitmap",
			"blit",
			"openImage",
			"encodePng",
			"flushImage",
			"closeImage",
			"replace",
			"validate",
			"readImage",
			"invalid",
		):
			with self.subTest(fault=fault):
				backend = _ScreenshotBackend(fault)
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "unused")
				result = adapter.captureScreenshot(self._attempt())

				self.assertEqual("failed", result.status)
				self.assertIsNone(result.image)
				self.assertIsNone(result.succeededAt)
				self.assertIsNotNone(result.errorCode)
				self.assertIsNotNone(result.diagnosticId)
				self.assertEqual(
					list(reversed([item for item in backend.acquired if item != "image"])),
					[item for item in backend.released if item != "image"],
				)

	def test_discard_cleanup_failure_does_not_mask_capture_failure(self) -> None:
		for discardError in (OSError("discard failed"), ValueError("discard failed")):
			with self.subTest(discardError=type(discardError).__name__):
				backend = _ScreenshotBackend("blit", discardError=discardError)
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "unused")

				result = adapter.captureScreenshot(self._attempt())

				self.assertEqual("failed", result.status)
				self.assertEqual("KS.SCREENSHOT.CAPTURE_FAILED", result.errorCode)
				self.assertEqual(2, backend.events.count("discard"))

	def test_discard_failure_after_reading_image_preserves_success(self) -> None:
		for discardError in (OSError("discard failed"), RuntimeError("discard failed")):
			with self.subTest(discardError=type(discardError).__name__):
				backend = _ScreenshotBackend(discardError=discardError)
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "2026-07-24T09:11:22.742")

				result = adapter.captureScreenshot(self._attempt())

				self.assertEqual("value", result.status)
				self.assertEqual(b"current-composited-pixels", result.image)
				self.assertEqual(1, backend.events.count("discard"))

	def test_unexpected_backend_exceptions_return_typed_failures(self) -> None:
		for fault, faultError, errorCode in (
			("virtualDesktop", RuntimeError, "KS.SCREENSHOT.DESKTOP_UNAVAILABLE"),
			("createBitmap", MemoryError, "KS.SCREENSHOT.CAPTURE_FAILED"),
		):
			with self.subTest(fault=fault, faultError=faultError.__name__):
				backend = _ScreenshotBackend(fault, faultError=faultError)
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "unused")

				result = adapter.captureScreenshot(self._attempt())

				self.assertEqual("failed", result.status)
				self.assertEqual(errorCode, result.errorCode)
				self.assertIsNone(result.image)

	def test_unexpected_cleanup_exceptions_do_not_hide_success(self) -> None:
		for fault in ("deselect", "release"):
			with self.subTest(fault=fault):
				backend = _ScreenshotBackend(fault, faultError=RuntimeError)
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "2026-07-24T09:11:22.742")

				result = adapter.captureScreenshot(self._attempt())

				self.assertEqual("value", result.status)
				self.assertEqual(b"current-composited-pixels", result.image)

	def test_control_flow_exceptions_propagate(self) -> None:
		adapter = ScreenshotAdapter(
			_ScreenshotBackend("createScreen", faultError=KeyboardInterrupt),
			enabled=True,
			clock=lambda: "unused",
		)
		with self.assertRaises(KeyboardInterrupt):
			_ = adapter.captureScreenshot(self._attempt())

		adapter = ScreenshotAdapter(
			_ScreenshotBackend("createScreen", faultError=SystemExit),
			enabled=True,
			clock=lambda: "unused",
		)
		with self.assertRaises(SystemExit):
			_ = adapter.captureScreenshot(self._attempt())

	def test_new_attempt_cannot_reuse_prior_success(self) -> None:
		backend = _ScreenshotBackend()
		adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "2026-07-24T09:11:22.742")
		first = adapter.captureScreenshot(self._attempt())
		backend.faultAt = "blit"

		second = adapter.captureScreenshot(self._attempt("capture-b"))

		self.assertEqual("value", first.status)
		self.assertEqual("failed", second.status)
		self.assertNotEqual(first.attempt.attemptId, second.attempt.attemptId)
		self.assertIsNone(second.image)
		self.assertIsNone(second.succeededAt)

	def test_off_desktop_empty_and_invalid_geometry_are_typed_failures(self) -> None:
		for geometry in (
			(3000, 3000, 10, 10),
			(0, 0, 0, 10),
			((1 << 63) - 1, 0, 10, 10),
		):
			with self.subTest(geometry=geometry):
				backend = _ScreenshotBackend()
				adapter = ScreenshotAdapter(backend, enabled=True, clock=lambda: "unused")
				result = adapter.captureScreenshot(self._attempt(geometry=geometry))
				self.assertEqual("failed", result.status)
				self.assertEqual(UNREDACTED_SCREENSHOT_WARNING, result.warning)
				self.assertNotIn("createScreen", backend.events)

	def test_held_closed_capture_returns_typed_absence_without_backend_effects(self) -> None:
		backend = _ScreenshotBackend()
		adapter = ScreenshotAdapter(backend, enabled=False, clock=lambda: "unused")

		result = adapter.captureScreenshot(self._attempt())

		self.assertEqual("absent", result.status)
		self.assertIsNone(result.image)
		self.assertEqual(UNREDACTED_SCREENSHOT_WARNING, result.warning)
		self.assertEqual([], backend.events)

	def test_windows_backend_flushes_the_encoded_png_from_a_writable_handle(self) -> None:
		with TemporaryDirectory() as directory:
			path = Path(directory).resolve()
			image = path / "capture.png"
			_ = image.write_bytes(b"encoded-png")
			backend = WxScreenshotBackend(object(), path)  # type: ignore[arg-type]

			backend.flushImage(image)

			self.assertEqual(b"encoded-png", image.read_bytes())

	def test_windows_backend_rejects_path_escape_attempt_id(self) -> None:
		with TemporaryDirectory() as directory:
			destinationDirectory = Path(directory).resolve()
			backend = WxScreenshotBackend(object(), destinationDirectory)  # type: ignore[arg-type]
			for attemptId in ("nested/../../outside", "nested\\..\\..\\outside"):
				with self.subTest(attemptId=attemptId):
					with self.assertRaisesRegex(ValueError, "path separators"):
						_ = backend.paths(self._attempt(attemptId))


if __name__ == "__main__":
	_ = unittest.main()
