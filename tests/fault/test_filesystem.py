from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import override
import unittest

from addon.globalPlugins.keystone.adapters.windows.publication import (
	CleanupOutcome,
	DirectoryLease,
	DiscoverySnapshot,
	PublicationPackage,
	PublicationPolicy,
	PublicationReceipt,
	PublicationResult,
	PublicationManager,
	LocalPublicationBackend,
	PathDirectoryAuthority,
)
from addon.globalPlugins.keystone.application.output_service import OutputService
from addon.globalPlugins.keystone.domain.correlation import (
	CorrelationContext,
	CorrelationFactory,
)
from addon.globalPlugins.keystone.domain.privacy import UNREDACTED_SCREENSHOT_WARNING
from addon.globalPlugins.keystone.ports.effects import (
	CaptureManagementRequest,
	ClipboardRequest,
	EffectResult,
	FeedbackRequest,
	PortOutcome,
	PortStatus,
	ShellRequest,
)


CONTEXT = CorrelationFactory().admit(generation=3)


def _context(generation: int = 3) -> CorrelationContext:
	return CONTEXT if generation == 3 else CorrelationFactory().admit(generation=generation)


class _PublicationBackend:
	def __init__(self, faultAt: str | None = None) -> None:
		super().__init__()
		self.faultAt = faultAt
		self.events: list[str] = []
		self.staging: set[str] = set()
		self.committed: dict[str, PublicationReceipt] = {}
		self.artifacts: dict[str, dict[str, bytes]] = {}

	def _effect(self, name: str) -> None:
		self.events.append(name)
		if self.faultAt == name:
			raise OSError(f"injected {name} failure")

	def destinationExists(self, applicationName: str, folderName: str, context: object) -> bool:
		self._assertContext(context)
		self._effect("destinationExists")
		return folderName in self.committed

	def createStaging(
		self,
		applicationName: str,
		stagingName: str,
		nonce: str,
		context: object,
	) -> str:
		self._assertContext(context)
		self._effect("createStaging")
		self.staging.add(stagingName)
		self.artifacts[stagingName] = {}
		return stagingName

	def writeAtomic(
		self,
		staging: str,
		artifactName: str,
		payload: bytes,
		context: object,
	) -> None:
		self._assertContext(context)
		self._effect(f"write:{artifactName}")
		self.artifacts[staging][artifactName] = payload

	def validateStaging(
		self,
		staging: str,
		nonce: str,
		expectedArtifacts: tuple[str, ...],
		context: object,
	) -> None:
		self._assertContext(context)
		self._effect("validateStaging")
		self.assertEqualSet(expectedArtifacts, tuple(self.artifacts[staging]))

	def commit(
		self,
		staging: str,
		applicationName: str,
		folderName: str,
		context: object,
	) -> Path:
		self._assertContext(context)
		self._effect("commit")
		if folderName in self.committed:
			raise FileExistsError(folderName)
		self.staging.remove(staging)
		return Path("C:/Temp/Keystone") / applicationName / folderName

	def validateCommitted(
		self,
		path: Path,
		publicationId: str,
		expectedArtifacts: tuple[str, ...],
		context: object,
	) -> None:
		self._assertContext(context)
		self._effect("validateCommitted")

	def catalog(self, receipt: PublicationReceipt, context: object) -> None:
		self._assertContext(context)
		self._effect("catalog")
		self.committed[receipt.folderName] = receipt

	def discardStaging(self, staging: str, nonce: str, context: object) -> None:
		self._assertContext(context)
		self._effect("discardStaging")
		self.staging.discard(staging)

	def discover(self, context: object) -> DiscoverySnapshot:
		self._assertContext(context)
		return DiscoverySnapshot(len(self.committed), 0, 1)

	def clearAll(self, discoveryRevision: int, context: object) -> CleanupOutcome:
		self._assertContext(context)
		return CleanupOutcome(0, 0, 0, 0)

	def revalidate(self, receipt: PublicationReceipt, context: object) -> bool:
		self._assertContext(context)
		return receipt.folderName in self.committed

	def newest(self, captureKind: object, context: object) -> PublicationReceipt | None:
		self._assertContext(context)
		return None

	@staticmethod
	def _assertContext(context: object) -> None:
		if context is not CONTEXT:
			raise AssertionError("publication boundary replaced correlation context")

	@staticmethod
	def assertEqualSet(expected: tuple[str, ...], actual: tuple[str, ...]) -> None:
		if set(expected) != set(actual):
			raise AssertionError((expected, actual))


class _CleanupFailureBackend(_PublicationBackend):
	@override
	def writeAtomic(
		self,
		staging: str,
		artifactName: str,
		payload: bytes,
		context: object,
	) -> None:
		raise OSError("injected write failure")

	@override
	def discardStaging(self, staging: str, nonce: str, context: object) -> None:
		raise ValueError("injected cleanup failure")


class _UnexpectedPrecommitFailureBackend(_PublicationBackend):
	@override
	def validateStaging(
		self,
		staging: str,
		nonce: str,
		expectedArtifacts: tuple[str, ...],
		context: object,
	) -> None:
		super().validateStaging(staging, nonce, expectedArtifacts, context)
		raise RuntimeError("injected unexpected validation failure")


class _MismatchedCommitPathBackend(_PublicationBackend):
	@override
	def commit(
		self,
		staging: str,
		applicationName: str,
		folderName: str,
		context: object,
	) -> Path:
		_ = super().commit(staging, applicationName, folderName, context)
		return Path("C:/Temp/Keystone") / applicationName / "unexpected-folder"


class _AlwaysCollidingBackend(_PublicationBackend):
	@override
	def destinationExists(self, applicationName: str, folderName: str, context: object) -> bool:
		_ = super().destinationExists(applicationName, folderName, context)
		return True


class _RedirectingDirectoryAuthority:
	"""Models a pathname redirect after a directory handle was retained."""

	def __init__(self, safeRoot: Path, redirectedRoot: Path) -> None:
		super().__init__()
		self._delegate = PathDirectoryAuthority()
		self.safeRoot = safeRoot
		self.redirectedRoot = redirectedRoot
		self.redirected = False
		self.mutations: list[str] = []
		self._leases: list[DirectoryLease] = []

	def openRoot(self, root: Path, *, create: bool) -> DirectoryLease:
		lease = self._delegate.openRoot(root, create=create)
		return self._lease(lease.path)

	def openChild(
		self,
		parent: DirectoryLease,
		name: str,
		*,
		create: bool = False,
		deletable: bool = False,
	) -> DirectoryLease:
		lease = self._delegate.openChild(
			self._safeLease(parent),
			name,
			create=create,
			deletable=deletable,
		)
		return self._lease(lease.path)

	def writeFile(self, directory: DirectoryLease, name: str, payload: bytes) -> None:
		self._redirect()
		self._record(directory, f"write:{name}")
		self._delegate.writeFile(self._safeLease(directory), name, payload)

	def readFile(self, directory: DirectoryLease, name: str) -> bytes:
		return self._delegate.readFile(self._safeLease(directory), name)

	def ordinaryFile(self, directory: DirectoryLease, name: str) -> bool:
		return self._delegate.ordinaryFile(self._safeLease(directory), name)

	def rename(
		self,
		source: DirectoryLease,
		destinationParent: DirectoryLease,
		destinationName: str,
	) -> None:
		self._record(source, f"rename:{destinationName}")
		safeSource = self._safeLease(source)
		self._delegate.rename(safeSource, self._safeLease(destinationParent), destinationName)
		source.path = safeSource.path
		source.handle = safeSource.path

	def deleteFile(self, directory: DirectoryLease, name: str) -> None:
		self._redirect()
		self._record(directory, f"delete:{name}")
		self._delegate.deleteFile(self._safeLease(directory), name)

	def deleteDirectory(self, directory: DirectoryLease) -> None:
		self._record(directory, "rmdir")
		self._delegate.deleteDirectory(self._safeLease(directory))

	def close(self, directory: DirectoryLease) -> None:
		self._delegate.close(self._safeLease(directory))

	def _record(self, directory: DirectoryLease, operation: str) -> None:
		if not isinstance(directory.handle, Path) or not directory.handle.is_relative_to(self.safeRoot):
			raise AssertionError("mutation did not use the retained directory handle")
		if self.redirected and not directory.path.is_relative_to(self.redirectedRoot):
			raise AssertionError("test did not replace the mutable directory pathname")
		self.mutations.append(operation)

	def _safeLease(self, directory: DirectoryLease) -> DirectoryLease:
		if not isinstance(directory.handle, Path):
			raise AssertionError("test authority requires path handles")
		return DirectoryLease(directory.handle, directory.handle)

	def _visiblePath(self, safePath: Path) -> Path:
		return self.redirectedRoot / safePath.name if self.redirected else safePath

	def _lease(self, safePath: Path) -> DirectoryLease:
		lease = DirectoryLease(self._visiblePath(safePath), safePath)
		self._leases.append(lease)
		return lease

	def _redirect(self) -> None:
		if self.redirected:
			return
		self.redirected = True
		for lease in self._leases:
			if isinstance(lease.handle, Path):
				lease.path = self._visiblePath(lease.handle)


def _package(publicationId: str = "publication-a") -> PublicationPackage:
	assert CONTEXT.operationId is not None
	assert CONTEXT.jobId is not None
	screenshot = {
		"attempt": {
			"attemptId": "attempt-a",
			"generation": CONTEXT.generation,
			"target": {
				"scopeKind": "containingForeground",
				"scopeId": "window-42",
				"geometry": [0, 0, 40, 30],
			},
			"correlation": {
				"sessionId": CONTEXT.sessionId.value,
				"operationId": CONTEXT.operationId.value,
				"jobId": CONTEXT.jobId.value,
				"generation": CONTEXT.generation,
			},
		},
		"status": "failed",
		"image": None,
		"error": {"code": "KS.SCREENSHOT.UNAVAILABLE", "diagnosticId": "screenshot-attempt-a"},
		"warning": UNREDACTED_SCREENSHOT_WARNING,
	}
	return PublicationPackage(
		publicationId=publicationId,
		executable="reader.exe",
		processId=42,
		captureKind="snapshot",
		completedAt=datetime(2026, 7, 24, 9, 8, 7, 654321),
		artifacts=(
			(
				"snapshot.json",
				(
					json.dumps(
						{
							"documentKind": "snapshot",
							"containingForeground": {
								"scopeId": "window-42",
								"geometry": [0, 0, 40, 30],
							},
							"screenshot": screenshot,
						},
					)
					+ "\n"
				).encode(),
			),
			("summary.json", b'{"documentKind":"snapshotSummary"}\n'),
		),
		screenshotWarning=UNREDACTED_SCREENSHOT_WARNING,
	)


class TestPublicationStateMachine(unittest.TestCase):
	def test_close_releases_the_cached_root_handle_once(self) -> None:
		class _TrackingAuthority(PathDirectoryAuthority):
			def __init__(self) -> None:
				super().__init__()
				self.closed: list[DirectoryLease] = []

			@override
			def close(self, directory: DirectoryLease) -> None:
				self.closed.append(directory)
				super().close(directory)

		with TemporaryDirectory() as temporary:
			authority = _TrackingAuthority()
			output = Path(temporary) / "output"
			backend = LocalPublicationBackend(output, directoryAuthority=authority)
			_ = backend.createStaging("reader-42", ".capture.nonce.pending", "nonce", CONTEXT)

			backend.close()
			backend.close()

		self.assertEqual([output], [directory.path for directory in authority.closed])

	def test_package_rejects_unsupported_time_and_process_values(self) -> None:
		for processId, completedAt in (
			(0x1_0000_0000, datetime(2026, 7, 24, 9, 8, 7, 654321)),
			(42, datetime(2026, 7, 24, 9, 8, 7, 654321, tzinfo=timezone.utc)),
		):
			with self.subTest(processId=processId, completedAt=completedAt):
				with self.assertRaises(ValueError):
					_ = replace(_package(), processId=processId, completedAt=completedAt)

	def test_success_uses_one_nonreplacing_commit_after_closed_artifacts(self) -> None:
		backend = _PublicationBackend()
		manager = PublicationManager(backend, nonceFactory=lambda: "nonce-a")

		result = manager.publish(_package(), lambda: PublicationPolicy(), CONTEXT)

		self.assertTrue(result.committed)
		self.assertIsNotNone(result.receipt)
		self.assertEqual(set(), backend.staging)
		self.assertEqual(1, backend.events.count("commit"))
		self.assertLess(
			backend.events.index("validateStaging"),
			backend.events.index("commit"),
		)
		self.assertLess(backend.events.index("commit"), backend.events.index("catalog"))

	def test_local_success_validates_committed_publication_once(self) -> None:
		class _CountingLocalPublicationBackend(LocalPublicationBackend):
			def __init__(self, root: Path) -> None:
				super().__init__(root)
				self.committedValidationCount = 0

			@override
			def validateCommitted(
				self,
				path: Path,
				publicationId: str,
				expectedArtifacts: tuple[str, ...],
				context: CorrelationContext,
			) -> None:
				self.committedValidationCount += 1
				super().validateCommitted(path, publicationId, expectedArtifacts, context)

		with TemporaryDirectory() as directory:
			backend = _CountingLocalPublicationBackend(Path(directory))
			result = PublicationManager(
				backend,
				nonceFactory=lambda: "nonce-a",
			).publish(_package(), lambda: PublicationPolicy(), CONTEXT)

		self.assertTrue(result.committed)
		self.assertEqual(1, backend.committedValidationCount)

	def test_every_precommit_fault_discards_only_owned_staging(self) -> None:
		for fault in (
			"write:snapshot.json",
			"write:summary.json",
			"write:publication-metadata.json",
			"validateStaging",
			"commit",
		):
			with self.subTest(fault=fault):
				backend = _PublicationBackend(fault)
				manager = PublicationManager(backend, nonceFactory=lambda: "nonce-a")
				result = manager.publish(_package(), lambda: PublicationPolicy(), CONTEXT)
				self.assertFalse(result.committed)
				self.assertEqual(set(), backend.staging)
				self.assertEqual({}, backend.committed)
				self.assertIn("discardStaging", backend.events)

	def test_cleanup_failure_does_not_mask_publication_failure(self) -> None:
		result = PublicationManager(
			_CleanupFailureBackend(),
			nonceFactory=lambda: "nonce-a",
		).publish(_package(), lambda: PublicationPolicy(), CONTEXT)

		self.assertFalse(result.committed)
		self.assertEqual("KS.OUTPUT.PUBLICATION_FAILED", result.errorCode)

	def test_unexpected_precommit_backend_failure_discards_owned_staging(self) -> None:
		backend = _UnexpectedPrecommitFailureBackend()

		result = PublicationManager(backend, nonceFactory=lambda: "nonce-a").publish(
			_package(),
			lambda: PublicationPolicy(),
			CONTEXT,
		)

		self.assertFalse(result.committed)
		self.assertEqual("KS.OUTPUT.PUBLICATION_FAILED", result.errorCode)
		self.assertEqual(set(), backend.staging)
		self.assertIn("discardStaging", backend.events)

	def test_malformed_staging_metadata_is_preserved_without_cleanup_failure(self) -> None:
		with TemporaryDirectory() as temporary:
			root = Path(temporary)
			backend = LocalPublicationBackend(root)
			staging = backend.createStaging("reader.exe-42", ".capture.nonce-a.pending", "nonce-a", CONTEXT)
			directory = root / "reader.exe-42" / staging
			_ = (directory / "publication-metadata.json").write_bytes(b"\xff")

			backend.discardStaging(staging, "nonce-a", CONTEXT)

			self.assertTrue(directory.exists())

	def test_cancel_or_secure_transition_before_commit_never_publishes(self) -> None:
		for policy in (
			PublicationPolicy(cancelled=True),
			PublicationPolicy(secure=True),
			PublicationPolicy(schemaValidated=False),
			PublicationPolicy(privacyValidated=False),
			PublicationPolicy(generationCurrent=False),
		):
			with self.subTest(policy=policy):
				backend = _PublicationBackend()
				manager = PublicationManager(backend, nonceFactory=lambda: "nonce-a")
				result = manager.publish(_package(), lambda: policy, CONTEXT)
				self.assertFalse(result.committed)
				self.assertNotIn("commit", backend.events)

	def test_second_precommit_policy_rejection_discards_staging_without_committing(self) -> None:
		backend = _PublicationBackend()
		checks = iter((PublicationPolicy(), PublicationPolicy(cancelled=True)))

		result = PublicationManager(backend, nonceFactory=lambda: "nonce-a").publish(
			_package(),
			lambda: next(checks),
			CONTEXT,
		)

		self.assertFalse(result.committed)
		self.assertEqual("KS.OUTPUT.PUBLICATION_FAILED", result.errorCode)
		self.assertEqual(set(), backend.staging)
		self.assertEqual({}, backend.committed)
		self.assertNotIn("commit", backend.events)
		self.assertIn("discardStaging", backend.events)

	def test_unexpected_second_precommit_policy_failure_discards_staging(self) -> None:
		backend = _PublicationBackend()
		checks = iter((PublicationPolicy(), RuntimeError("injected unexpected policy failure")))

		def policy() -> PublicationPolicy:
			value = next(checks)
			if isinstance(value, RuntimeError):
				raise value
			return value

		result = PublicationManager(backend, nonceFactory=lambda: "nonce-a").publish(
			_package(),
			policy,
			CONTEXT,
		)

		self.assertFalse(result.committed)
		self.assertEqual("KS.OUTPUT.PUBLICATION_FAILED", result.errorCode)
		self.assertEqual(set(), backend.staging)
		self.assertNotIn("commit", backend.events)
		self.assertIn("discardStaging", backend.events)

	def test_commit_remains_successful_when_catalog_or_late_cancellation_fails(self) -> None:
		backend = _PublicationBackend("catalog")
		manager = PublicationManager(backend, nonceFactory=lambda: "nonce-a")
		checks = iter(
			(
				PublicationPolicy(),
				PublicationPolicy(),
				PublicationPolicy(cancelled=True),
			),
		)

		result = manager.publish(_package(), lambda: next(checks), CONTEXT)

		self.assertTrue(result.committed)
		self.assertEqual("KS.OUTPUT.POSTCOMMIT_WARNING", result.warningCode)
		self.assertEqual(1, backend.events.count("commit"))
		self.assertNotIn("discardStaging", backend.events)

	def test_postcommit_path_or_validation_failure_returns_warning_without_discard(self) -> None:
		for backend in (
			_MismatchedCommitPathBackend(),
			_PublicationBackend("validateCommitted"),
		):
			with self.subTest(backend=type(backend).__name__):
				result = PublicationManager(backend, nonceFactory=lambda: "nonce-a").publish(
					_package(),
					lambda: PublicationPolicy(),
					CONTEXT,
				)

				self.assertTrue(result.committed)
				self.assertEqual("KS.OUTPUT.POSTCOMMIT_WARNING", result.warningCode)
				self.assertEqual(set(), backend.staging)
				self.assertNotIn("discardStaging", backend.events)
				if isinstance(backend, _MismatchedCommitPathBackend):
					self.assertIsNone(result.receipt)
				else:
					self.assertIsNotNone(result.receipt)

	def test_folder_collision_limit_is_bounded_and_stable(self) -> None:
		backend = _AlwaysCollidingBackend()

		result = PublicationManager(backend, nonceFactory=lambda: "nonce-a").publish(
			_package(),
			lambda: PublicationPolicy(),
			CONTEXT,
		)

		self.assertFalse(result.committed)
		self.assertEqual("KS.OUTPUT.FOLDER_COLLISION_LIMIT", result.errorCode)
		self.assertEqual(set(), backend.staging)
		self.assertNotIn("createStaging", backend.events)
		self.assertLess(backend.events.count("destinationExists"), 100)

	def test_equal_names_receive_deterministic_suffix_without_overwrite(self) -> None:
		backend = _PublicationBackend()
		manager = PublicationManager(backend, nonceFactory=iter(("nonce-a", "nonce-b")).__next__)

		first = manager.publish(_package("publication-a"), lambda: PublicationPolicy(), CONTEXT)
		second = manager.publish(_package("publication-b"), lambda: PublicationPolicy(), CONTEXT)

		firstReceipt = first.receipt
		secondReceipt = second.receipt
		self.assertIsNotNone(firstReceipt)
		self.assertIsNotNone(secondReceipt)
		assert firstReceipt is not None
		assert secondReceipt is not None
		self.assertEqual("20260724-090807.654-snapshot", firstReceipt.folderName)
		self.assertEqual("20260724-090807.654-snapshot-02", secondReceipt.folderName)

	def test_subject_prefixes_the_capture_folder_and_keeps_collision_handling(self) -> None:
		backend = _PublicationBackend()
		manager = PublicationManager(backend, nonceFactory=iter(("nonce-a", "nonce-b")).__next__)
		package = replace(_package(), subject="Display adapters")

		first = manager.publish(package, lambda: PublicationPolicy(), CONTEXT)
		second = manager.publish(
			replace(package, publicationId="publication-b"), lambda: PublicationPolicy(), CONTEXT
		)

		assert first.receipt is not None
		assert second.receipt is not None
		self.assertEqual("Display adapters-20260724-090807.654-snapshot", first.receipt.folderName)
		self.assertEqual("Display adapters-20260724-090807.654-snapshot-02", second.receipt.folderName)

	def test_invalid_artifact_set_and_missing_visual_warning_fail_before_staging(self) -> None:
		backend = _PublicationBackend()
		manager = PublicationManager(backend, nonceFactory=lambda: "nonce-a")
		for package in (
			replace(_package(), artifacts=_package().artifacts[:-1]),
			replace(_package(), screenshotWarning=None),
		):
			with self.subTest(package=package):
				result = manager.publish(package, lambda: PublicationPolicy(), CONTEXT)
				self.assertFalse(result.committed)
				self.assertEqual([], backend.events)

	def test_publication_creates_a_missing_output_root(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory) / "captures"
			result = PublicationManager(
				LocalPublicationBackend(root),
				nonceFactory=lambda: "nonce-a",
			).publish(_package(), lambda: PublicationPolicy(), CONTEXT)

			self.assertTrue(result.committed)
			self.assertTrue(root.is_dir())

	def test_publication_creates_all_missing_output_root_ancestors(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory) / "missing" / "nested" / "captures"
			result = PublicationManager(
				LocalPublicationBackend(root),
				nonceFactory=lambda: "nonce-a",
			).publish(_package(), lambda: PublicationPolicy(), CONTEXT)

			self.assertTrue(result.committed)
			self.assertTrue(root.is_dir())

	def test_retained_directory_authority_keeps_publication_outside_redirected_path(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory) / "captures"
			redirected = Path(directory) / "outside"
			redirected.mkdir()
			authority = _RedirectingDirectoryAuthority(root, redirected)
			result = PublicationManager(
				LocalPublicationBackend(root, directoryAuthority=authority),
				nonceFactory=lambda: "nonce-a",
			).publish(_package(), lambda: PublicationPolicy(), CONTEXT)

			self.assertTrue(result.committed)
			self.assertTrue(authority.redirected)
			self.assertIn("write:snapshot.json", authority.mutations)
			self.assertTrue(any(item.startswith("rename:") for item in authority.mutations))
			self.assertEqual((), tuple(redirected.iterdir()))

	def test_retained_directory_authority_keeps_cleanup_outside_redirected_path(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory) / "captures"
			redirected = Path(directory) / "outside"
			redirected.mkdir()
			authority = _RedirectingDirectoryAuthority(root, redirected)
			manager = PublicationManager(
				LocalPublicationBackend(root, directoryAuthority=authority),
				nonceFactory=lambda: "nonce-a",
			)
			self.assertTrue(manager.publish(_package(), lambda: PublicationPolicy(), CONTEXT).committed)

			discovery = manager.discover(CONTEXT)
			cleanup = manager.clearAll(discovery.revision, CONTEXT)

			self.assertEqual(1, cleanup.deletedCount)
			self.assertTrue(authority.redirected)
			self.assertIn("delete:snapshot.json", authority.mutations)
			self.assertIn("rmdir", authority.mutations)
			self.assertEqual((), tuple(redirected.iterdir()))

	def test_local_discovery_and_clear_leave_unrecognized_and_reserved_entries_untouched(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory)
			(root / "logs").mkdir()
			(root / "runtime").mkdir()
			suspicious = root / "unrecognized.txt"
			_ = suspicious.write_text("leave me", encoding="utf-8")
			manager = PublicationManager(
				LocalPublicationBackend(root),
				nonceFactory=lambda: "nonce-a",
			)
			published = manager.publish(_package(), lambda: PublicationPolicy(), CONTEXT)
			self.assertTrue(published.committed)

			discovery = manager.discover(CONTEXT)
			self.assertEqual((1, 1), (discovery.recognizedCount, discovery.suspiciousCount))
			cleanup = manager.clearAll(discovery.revision, CONTEXT)

			self.assertEqual(
				(1, 0, 0, 1),
				(
					cleanup.deletedCount,
					cleanup.skippedCount,
					cleanup.failedCount,
					cleanup.suspiciousCount,
				),
			)
			self.assertTrue(suspicious.exists())
			self.assertTrue((root / "logs").exists())
			self.assertTrue((root / "runtime").exists())

	def test_changed_artifact_identity_becomes_suspicious_and_is_never_deleted(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory)
			manager = PublicationManager(
				LocalPublicationBackend(root),
				nonceFactory=lambda: "nonce-a",
			)
			published = manager.publish(_package(), lambda: PublicationPolicy(), CONTEXT)
			receipt = published.receipt
			self.assertIsNotNone(receipt)
			assert receipt is not None
			artifact = receipt.path / "snapshot.json"
			artifact.unlink()
			artifact.mkdir()

			discovery = manager.discover(CONTEXT)
			self.assertEqual((0, 1), (discovery.recognizedCount, discovery.suspiciousCount))
			cleanup = manager.clearAll(discovery.revision, CONTEXT)

			self.assertEqual((0, 1), (cleanup.deletedCount, cleanup.suspiciousCount))
			self.assertTrue(artifact.is_dir())

	def test_newest_selects_the_greatest_valid_matching_receipt(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory)
			backend = LocalPublicationBackend(root)
			manager = PublicationManager(
				backend,
				nonceFactory=iter(("nonce-a", "nonce-b", "nonce-c")).__next__,
			)
			early = datetime(2026, 7, 24, 9, 8, 7, 654321)
			first = manager.publish(
				replace(_package("publication-a"), completedAt=early),
				lambda: PublicationPolicy(),
				CONTEXT,
			)
			second = manager.publish(
				replace(_package("publication-b"), completedAt=early),
				lambda: PublicationPolicy(),
				CONTEXT,
			)
			assert first.receipt is not None
			assert second.receipt is not None
			self.assertEqual(second.receipt, backend.newest("snapshot", CONTEXT))

			(root / "logs" / "newer").mkdir(parents=True)
			(root / "runtime" / "newer").mkdir(parents=True)
			(second.receipt.path.parent / ".newer.pending").mkdir()
			later = manager.publish(
				replace(
					_package("publication-c"),
					completedAt=datetime(2026, 7, 24, 9, 8, 8),
				),
				lambda: PublicationPolicy(),
				CONTEXT,
			)

			self.assertIsNotNone(later.receipt)
			assert later.receipt is not None
			self.assertEqual(later.receipt, backend.newest("snapshot", CONTEXT))
			self.assertIsNone(backend.newest("navigatorSnapshot", CONTEXT))


class _Repository:
	def __init__(self, result: PublicationResult) -> None:
		super().__init__()
		self.result = result
		self.discovery = DiscoverySnapshot(2, 1, 7)
		self.cleanup = CleanupOutcome(1, 1, 0, 1)
		self.calls: list[str] = []
		self.contexts: list[object] = []
		self.newestKinds: list[object] = []
		self.newestReceipt: PublicationReceipt | None = None
		self.valid = True
		self.acceptedContexts: tuple[object, ...] = (CONTEXT,)

	def publish(
		self,
		package: PublicationPackage,
		policyProvider: Callable[[], PublicationPolicy],
		context: object,
	) -> PublicationResult:
		self._context(context)
		self.calls.append("publish")
		return self.result

	def discover(self, context: object) -> DiscoverySnapshot:
		self._context(context)
		self.calls.append("discover")
		return self.discovery

	def clearAll(self, discoveryRevision: int, context: object) -> CleanupOutcome:
		self._context(context)
		self.calls.append(f"clear:{discoveryRevision}")
		if self.cleanup.deletedCount:
			self.valid = False
		return self.cleanup

	def revalidate(self, receipt: PublicationReceipt, context: object) -> bool:
		self._context(context)
		self.calls.append("revalidate")
		return self.valid

	def newest(self, captureKind: object, context: object) -> PublicationReceipt | None:
		self._context(context)
		self.calls.append("newest")
		self.newestKinds.append(captureKind)
		return self.newestReceipt

	def _context(self, context: object) -> None:
		if not any(context is expected for expected in self.acceptedContexts):
			raise AssertionError("output repository received replacement correlation")
		self.contexts.append(context)


class _Feedback:
	def __init__(self) -> None:
		super().__init__()
		self.requests: list[FeedbackRequest] = []

	def announce(self, request: FeedbackRequest) -> EffectResult:
		self.requests.append(request)
		return EffectResult(PortStatus("ready", 1), PortOutcome("announced"))


class _Clipboard:
	def __init__(self) -> None:
		super().__init__()
		self.requests: list[ClipboardRequest] = []

	def copyText(self, request: ClipboardRequest) -> EffectResult:
		self.requests.append(request)
		return EffectResult(PortStatus("ready", 1), PortOutcome("copied"))


class _Shell:
	def __init__(self) -> None:
		super().__init__()
		self.opened: list[ShellRequest] = []
		self.revealed: list[ShellRequest] = []

	def openFolder(self, request: ShellRequest) -> EffectResult:
		self.opened.append(request)
		return EffectResult(PortStatus("ready", 1), PortOutcome("opened"))

	def revealFile(self, request: ShellRequest) -> EffectResult:
		self.revealed.append(request)
		return EffectResult(PortStatus("ready", 1), PortOutcome("revealed"))


def _receipt() -> PublicationReceipt:
	return PublicationReceipt(
		"publication-a",
		Path(r"C:\Temp\Keystone\reader.exe-42\20260724-090807.654-snapshot"),
		"20260724-090807.654-snapshot",
		("publication-metadata.json", "snapshot.json"),
	)


class TestOutputService(unittest.TestCase):
	def _service(
		self,
		result: PublicationResult | None = None,
	) -> tuple[OutputService, _Repository, _Feedback, _Clipboard, _Shell]:
		repository = _Repository(result or PublicationResult(True, _receipt(), None, None))
		feedback = _Feedback()
		clipboard = _Clipboard()
		shell = _Shell()
		service = OutputService(
			repository,
			feedback,
			clipboard,
			shell,
			actionIdFactory=lambda: "action-a",
			lifecycleGeneration=3,
		)
		return service, repository, feedback, clipboard, shell

	def test_filesystem_publication_uses_the_repository_validation_path(self) -> None:
		service, repository, _feedback, _clipboard, _shell = self._service()

		presentation = service.publish(_package(), lifecycleGeneration=3, context=_context())

		self.assertEqual("committed", presentation.outcome.value)
		self.assertEqual(["publish"], repository.calls)

	def test_automatic_completion_uses_short_name_without_path_effects(self) -> None:
		service, _repository, feedback, clipboard, shell = self._service()

		presentation = service.publish(_package(), lifecycleGeneration=3, context=_context())

		self.assertEqual("output.committed", feedback.requests[0].messageId)
		self.assertEqual(("20260724-090807.654-snapshot",), feedback.requests[0].arguments)
		self.assertNotIn(r"C:\Temp", repr(feedback.requests))
		self.assertEqual((), tuple(clipboard.requests))
		self.assertEqual((), tuple(shell.opened))
		self.assertEqual(3, len(presentation.actions))

	def test_publication_failure_reports_its_stable_error_code(self) -> None:
		service, _repository, feedback, _clipboard, _shell = self._service(
			PublicationResult(False, None, "KS.OUTPUT.INVALID_PACKAGE", None),
		)

		presentation = service.publish(_package(), lifecycleGeneration=3, context=_context())

		self.assertEqual("failed", presentation.outcome.value)
		self.assertEqual("output.failed", feedback.requests[0].messageId)
		self.assertEqual(("KS.OUTPUT.INVALID_PACKAGE",), feedback.requests[0].arguments)
		self.assertEqual((), presentation.actions)

	def test_postcommit_warning_preserves_receipt_actions_and_reports_its_code(self) -> None:
		service, _repository, feedback, clipboard, _shell = self._service(
			PublicationResult(True, _receipt(), None, "KS.OUTPUT.POSTCOMMIT_WARNING"),
		)

		presentation = service.publish(_package(), lifecycleGeneration=3, context=_context())
		result = service.manageCaptures(
			CaptureManagementRequest("copyCommittedPath", _context(), 3, actionId="action-a"),
		)

		self.assertEqual("committedWithWarning", presentation.outcome.value)
		self.assertEqual("output.committedWithWarning", feedback.requests[0].messageId)
		self.assertEqual(
			("20260724-090807.654-snapshot", "KS.OUTPUT.POSTCOMMIT_WARNING"),
			feedback.requests[0].arguments,
		)
		self.assertEqual(3, len(presentation.actions))
		self.assertEqual("ready", result.status.token)
		self.assertEqual(str(_receipt().path), clipboard.requests[0].text)

	def test_unverified_committed_warning_has_no_receipt_actions(self) -> None:
		service, _repository, feedback, _clipboard, _shell = self._service(
			PublicationResult(True, None, None, "KS.OUTPUT.POSTCOMMIT_WARNING"),
		)

		presentation = service.publish(_package(), lifecycleGeneration=3, context=_context())

		self.assertEqual("committedWithWarning", presentation.outcome.value)
		self.assertEqual(("KS.OUTPUT.POSTCOMMIT_WARNING",), feedback.requests[0].arguments)
		self.assertEqual((), presentation.actions)

	def test_act_on_newest_copies_and_reveals_a_revalidated_receipt(self) -> None:
		service, repository, _feedback, clipboard, shell = self._service()
		repository.newestReceipt = _receipt()

		self.assertTrue(
			service.actOnNewest(
				"snapshot",
				"copy",
				lifecycleGeneration=3,
				context=CONTEXT,
			),
		)
		self.assertTrue(
			service.actOnNewest(
				"snapshot",
				"reveal",
				lifecycleGeneration=3,
				context=CONTEXT,
			),
		)

		path = str(_receipt().path)
		self.assertEqual([path], [request.text for request in clipboard.requests])
		self.assertEqual([path], [request.targetId for request in shell.revealed])
		self.assertEqual(["snapshot", "snapshot"], repository.newestKinds)

	def test_act_on_newest_rejects_stale_receipts_and_lifecycle_mismatch(self) -> None:
		service, repository, _feedback, clipboard, shell = self._service()
		repository.newestReceipt = _receipt()
		repository.valid = False

		self.assertFalse(
			service.actOnNewest(
				"snapshot",
				"copy",
				lifecycleGeneration=3,
				context=CONTEXT,
			),
		)
		self.assertFalse(
			service.actOnNewest(
				"snapshot",
				"reveal",
				lifecycleGeneration=2,
				context=CONTEXT,
			),
		)
		self.assertFalse(
			service.actOnNewest(
				"snapshot",
				"reveal",
				lifecycleGeneration=3,
				context=_context(4),
			),
		)

		self.assertEqual([], clipboard.requests)
		self.assertEqual([], shell.revealed)
		self.assertEqual(["snapshot"], repository.newestKinds)

	def test_act_on_newest_rejects_incomplete_correlation_before_effects(self) -> None:
		service, repository, _feedback, clipboard, shell = self._service()
		repository.newestReceipt = _receipt()
		incomplete = CorrelationContext(CONTEXT.sessionId, generation=3)

		self.assertFalse(
			service.actOnNewest(
				"snapshot",
				"copy",
				lifecycleGeneration=3,
				context=incomplete,
			),
		)

		self.assertEqual([], repository.calls)
		self.assertEqual([], repository.contexts)
		self.assertEqual([], repository.newestKinds)
		self.assertEqual([], clipboard.requests)
		self.assertEqual([], shell.revealed)

	def test_explicit_current_actions_receive_exact_committed_path(self) -> None:
		service, _repository, _feedback, clipboard, shell = self._service()
		_ = service.publish(_package(), lifecycleGeneration=3, context=_context())
		for operation in ("copyCommittedPath", "openCommittedFolder", "revealCommittedFolder"):
			result = service.manageCaptures(
				CaptureManagementRequest(operation, _context(), 3, actionId="action-a"),
			)
			self.assertEqual("ready", result.status.token)

		path = str(_receipt().path)
		self.assertEqual(path, clipboard.requests[0].text)
		self.assertEqual(path, shell.opened[0].targetId)
		self.assertEqual(path, shell.revealed[0].targetId)

	def test_failed_or_stale_output_cannot_reuse_path_actions(self) -> None:
		service, repository, _feedback, clipboard, shell = self._service()
		_ = service.publish(_package(), lifecycleGeneration=3, context=_context())
		repository.valid = False

		result = service.manageCaptures(
			CaptureManagementRequest("copyCommittedPath", _context(), 3, actionId="action-a"),
		)

		self.assertEqual("stale", result.status.token)
		self.assertEqual([], clipboard.requests)
		self.assertEqual([], shell.opened)

	def test_refresh_removes_actions_when_the_published_capture_is_gone(self) -> None:
		service, repository, _feedback, _clipboard, _shell = self._service()
		_ = service.publish(_package(), lifecycleGeneration=3, context=_context())
		repository.valid = False

		result = service.manageCaptures(CaptureManagementRequest("refresh", _context(), 3))

		self.assertEqual(
			(None, None, None),
			(result.copyActionId, result.openActionId, result.revealActionId),
		)

	def test_clear_requires_a_completed_refresh(self) -> None:
		service, repository, _feedback, _clipboard, _shell = self._service()
		_ = service.publish(_package(), lifecycleGeneration=3, context=_context())

		result = service.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				_context(),
				3,
				confirmationRevision=0,
			),
		)

		self.assertEqual("stale", result.status.token)
		self.assertFalse(any(call.startswith("clear:") for call in repository.calls))

	def test_refresh_is_path_free_and_clear_requires_matching_revision(self) -> None:
		service, repository, _feedback, _clipboard, _shell = self._service()
		_ = service.publish(_package(), lifecycleGeneration=3, context=_context())

		refresh = service.manageCaptures(CaptureManagementRequest("refresh", _context(), 3))
		self.assertEqual((2, 1), (refresh.recognizedCount, refresh.suspiciousCount))
		self.assertNotIn("Temp", repr(refresh))

		stale = service.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				_context(),
				3,
				confirmationRevision=refresh.confirmationRevision - 1,
			),
		)
		self.assertEqual("stale", stale.status.token)
		self.assertNotIn("clear:", repository.calls)

		cleared = service.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				_context(),
				3,
				confirmationRevision=refresh.confirmationRevision,
			),
		)
		self.assertEqual(
			(1, 1, 0, 1),
			(
				cleared.deletedCount,
				cleared.skippedCount,
				cleared.failedCount,
				cleared.suspiciousCount,
			),
		)
		self.assertEqual(
			(None, None, None),
			(cleared.copyActionId, cleared.openActionId, cleared.revealActionId),
		)

	def test_lifecycle_advance_requires_refresh_before_clear(self) -> None:
		service, repository, _feedback, _clipboard, _shell = self._service()
		refresh = service.manageCaptures(CaptureManagementRequest("refresh", _context(), 3))
		context = _context(4)
		repository.acceptedContexts = (CONTEXT, context)

		_ = service.publish(_package(), lifecycleGeneration=4, context=context)
		stale = service.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				context,
				4,
				confirmationRevision=refresh.confirmationRevision,
			),
		)
		self.assertEqual("stale", stale.status.token)
		self.assertEqual(["discover", "publish", "revalidate"], repository.calls)
		refreshed = service.manageCaptures(CaptureManagementRequest("refresh", context, 4))
		cleared = service.manageCaptures(
			CaptureManagementRequest(
				"clearAll",
				context,
				4,
				confirmationRevision=refreshed.confirmationRevision,
			),
		)

		self.assertEqual("ready", cleared.status.token)


if __name__ == "__main__":
	_ = unittest.main()
