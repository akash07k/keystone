from __future__ import annotations

from dataclasses import FrozenInstanceError
import inspect
import threading
from typing import cast, get_type_hints
import unittest

from addon.globalPlugins.keystone.capability import CapabilityRequest, CapabilityResult
from addon.globalPlugins.keystone.domain.correlation import CorrelationFactory
from addon.globalPlugins.keystone.ports import effects, providers
from addon.globalPlugins.keystone.ports.effects import (
	CaptureManagementOperation,
	CaptureManagementRequest,
	CaptureManagementResult,
	ClipboardRequest,
	EffectResult,
	FeedbackRequest,
	PortError,
	PortOutcome,
	PortStatus,
	ScreenshotAttempt,
	ScreenshotResult,
	ScreenshotTarget,
	SettingsWriteRequest,
	ShellRequest,
)
from addon.globalPlugins.keystone.ports.providers import (
	IdentityComparisonResult,
	ProviderChildBatch,
	ProviderReadResult,
	ReadBudget,
	ReleaseResult,
)

from .fakes import BoundaryResult, ExecutionContext, ExpectedCall, ResourceLedger, StrictCallFake


CONTEXT_1 = CorrelationFactory().admit(generation=1)
CONTEXT_3 = CorrelationFactory().admit(generation=3)


BOUNDARY_MATRICES = (
	"nvdaSelected",
	"uia",
	"ia2Msaa",
	"javaAccessBridge",
	"wx",
	"win32",
	"filesystem",
	"screenshot",
)
PROHIBITED_FIELD_TYPES = ("Callable", "IO", "Path", "Writer", "FileSystem", "Handle")
PROHIBITED_PARAMETER_NAMES = {
	"callback",
	"delete",
	"dispatch",
	"filePath",
	"filesystem",
	"handle",
	"invoke",
	"path",
	"truncate",
	"writer",
}


def readyStatus(revision: int = 1) -> PortStatus:
	return PortStatus(token="ready", revision=revision)


def failedStatus(revision: int = 1) -> PortStatus:
	return PortStatus(token="failed", revision=revision)


def captureResult(
	operation: CaptureManagementOperation = "refresh",
	*,
	status: PortStatus | None = None,
	error: PortError | None = None,
) -> CaptureManagementResult:
	return CaptureManagementResult(
		operation=operation,
		lifecycleGeneration=3,
		status=status or readyStatus(),
		outcome=PortOutcome("captureStatus", ("capture-set",)),
		error=error,
		recognizedCount=4,
		suspiciousCount=1,
		deletedCount=0,
		skippedCount=1,
		failedCount=0,
		confirmationRevision=7,
		copyActionId="copy-current",
		openActionId="open-current",
		revealActionId="reveal-current",
	)


class StrictFakeTests(unittest.TestCase):
	def test_named_boundary_matrices_reject_unknown_access(self) -> None:
		for matrix in BOUNDARY_MATRICES:
			with self.subTest(matrix=matrix):
				fake = StrictCallFake(matrix, ())
				with self.assertRaisesRegex(AssertionError, rf"{matrix}\.unknown.*call 0"):
					_ = fake.member("unknown")

	def test_expected_order_arguments_and_context_are_exact(self) -> None:
		threadId = threading.get_ident()
		context = ExecutionContext(threadId=threadId, apartment="main", generation=4)
		fake = StrictCallFake(
			"uia",
			(
				ExpectedCall(
					member="readField",
					args=("node-1", "name"),
					kwargs=(("budget", 5),),
					result="value",
					threadId=threadId,
					apartment="main",
					generation=4,
				),
			),
			contextProvider=lambda: context,
		)
		with self.assertRaisesRegex(AssertionError, "expected 'readField'.*call 0"):
			_ = fake.member("readChildren")
		with self.assertRaisesRegex(AssertionError, "argument mismatch.*call 0"):
			_ = fake.member("readField")("wrong", "name", budget=5)
		with self.assertRaisesRegex(AssertionError, "keyword mismatch.*call 0"):
			_ = fake.member("readField")("node-1", "name", budget=6)
		self.assertEqual("value", fake.member("readField")("node-1", "name", budget=5))
		fake.assertComplete()

	def test_thread_apartment_and_generation_drift_fail_closed(self) -> None:
		cases = (
			("thread", ExpectedCall("read", (), None, threadId=9), ExecutionContext(8, "main", 1)),
			("apartment", ExpectedCall("read", (), None, apartment="worker"), ExecutionContext(8, "main", 1)),
			("generation", ExpectedCall("read", (), None, generation=2), ExecutionContext(8, "main", 1)),
		)
		for label, expected, context in cases:
			with self.subTest(label=label):
				fake = StrictCallFake("provider", (expected,), contextProvider=lambda: context)
				with self.assertRaisesRegex(AssertionError, rf"{label} mismatch.*call 0"):
					_ = fake.member("read")()

	def test_release_ledger_rejects_double_unknown_and_missing_release(self) -> None:
		ledger = ResourceLedger("provider")
		ledger.acquire("resource-1")
		fake = StrictCallFake(
			"provider",
			(
				ExpectedCall(
					"releaseResource",
					("resource-1", 2),
					ReleaseResult("released"),
					releaseTokenArgument=0,
				),
			),
			ledger=ledger,
		)
		_ = fake.member("releaseResource")("resource-1", 2)
		fake.assertComplete()
		with self.assertRaisesRegex(AssertionError, "double release"):
			ledger.release("resource-1", 1)
		with self.assertRaisesRegex(AssertionError, "unknown token"):
			ResourceLedger("provider").release("missing", 0)

		missing = ResourceLedger("provider")
		missing.acquire("resource-2")
		with self.assertRaisesRegex(AssertionError, "missing release"):
			missing.assertEmpty()

	def test_cancel_path_emits_no_adapter_call(self) -> None:
		fake = StrictCallFake("filesystem", ())
		self.assertEqual("cancelled", BoundaryResult("cancelled").status)
		fake.assertComplete()

	def test_named_boundaries_preserve_typed_behavior_outcomes(self) -> None:
		outcomes = (
			BoundaryResult("success"),
			BoundaryResult("blocked"),
			BoundaryResult("slow"),
			BoundaryResult("failed", "boundaryFailure"),
		)
		for matrix in BOUNDARY_MATRICES:
			with self.subTest(matrix=matrix):
				fake = StrictCallFake(
					matrix,
					tuple(ExpectedCall("observe", (index,), result) for index, result in enumerate(outcomes)),
				)
				actual = tuple(fake.member("observe")(index) for index in range(len(outcomes)))
				self.assertEqual(outcomes, actual)
				fake.assertComplete()


class ProviderValueTests(unittest.TestCase):
	def test_provider_results_preserve_distinct_outcomes(self) -> None:
		budget = ReadBudget(10, 512, 50)
		self.assertEqual(10, budget.maximumItems)
		self.assertEqual("value", ProviderReadResult("value", "name").status)
		self.assertEqual("empty", ProviderReadResult("empty").status)
		self.assertEqual("unsupported", ProviderReadResult("unsupported").status)
		self.assertEqual("blockedRead", ProviderReadResult("unavailable", errorCode="blockedRead").errorCode)
		self.assertEqual("staleNode", ProviderReadResult("stale", errorCode="staleNode").errorCode)
		self.assertEqual("readFailed", ProviderReadResult("failed", errorCode="readFailed").errorCode)

	def test_provider_collections_and_identity_evidence_are_immutable(self) -> None:
		batch = ProviderChildBatch("value", ("node-a", "node-b"), 2, False)
		failure = ProviderChildBatch("failed", (), 0, False, "readFailed")
		comparison = IdentityComparisonResult("value", "same", ("provider-key", 7))
		self.assertEqual(("node-a", "node-b"), batch.nodeRefs)
		self.assertEqual(
			("failed", (), 0, False, "readFailed"),
			(failure.status, failure.nodeRefs, failure.observedCount, failure.truncated, failure.errorCode),
		)
		self.assertEqual(("provider-key", 7), comparison.evidence)
		with self.assertRaises(FrozenInstanceError):
			batch.status = "empty"  # type: ignore[misc]
		with self.assertRaises(TypeError):
			IdentityComparisonResult("value", "same", (["mutable"],))  # type: ignore[list-item]

	def test_malformed_provider_failures_are_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = ReadBudget(0, 1, 1)
		with self.assertRaises(ValueError):
			_ = ReadBudget(True, 1, 1)
		with self.assertRaises(ValueError):
			_ = ReadBudget(1, 1.5, 1)  # pyright: ignore[reportArgumentType]
		with self.assertRaises(ValueError):
			_ = ReadBudget(1, 1, False)
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("value")
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("failed")
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("failed", "private-value", "readFailed")
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("empty", errorCode="readFailed")
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("unsupported", truncated=True)
		with self.assertRaises(ValueError):
			_ = ProviderReadResult("value", "name", "readFailed")
		with self.assertRaises(ValueError):
			_ = ProviderChildBatch("value", ("node-a",), 0, False)
		with self.assertRaises(ValueError):
			_ = IdentityComparisonResult("stale", "ambiguous", ())
		with self.assertRaises(ValueError):
			_ = ProviderChildBatch("empty", ("node-a",), 1, False)
		with self.assertRaises(ValueError):
			_ = ProviderChildBatch("failed", ("node-a",), 1, True, "readFailed")
		with self.assertRaises(ValueError):
			_ = ProviderChildBatch("value", ("node-a",), 1, False, "readFailed")
		with self.assertRaises(ValueError):
			_ = IdentityComparisonResult("value", "same", (), "compareFailed")
		with self.assertRaises(ValueError):
			_ = IdentityComparisonResult("stale", "failed", ("provider-key",), "staleNode")
		with self.assertRaises(ValueError):
			_ = ReleaseResult("failed")


class EffectValueTests(unittest.TestCase):
	def test_effect_requests_accept_only_immutable_boundary_values(self) -> None:
		requests = (
			ScreenshotAttempt(
				"shot",
				1,
				ScreenshotTarget("containingForeground", "window-1", (0, 0, 20, 20)),
				CONTEXT_1,
			),
			ClipboardRequest("safe text", "copy", CONTEXT_1),
			ShellRequest("approved-target", 2, CONTEXT_1),
			FeedbackRequest("captureComplete", ("folder",), CONTEXT_1),
			SettingsWriteRequest(2, (("enabled", True),), CONTEXT_1),
		)
		self.assertEqual(5, len(requests))
		result = ScreenshotResult(
			requests[0],
			"failed",
			None,
			None,
			None,
			"KS.SCREENSHOT.CAPTURE_FAILED",
			"screenshot-shot",
		)
		self.assertIs(requests[0], result.attempt)
		with self.assertRaises(TypeError):
			SettingsWriteRequest(1, (("value", {"mutable": True}),), CONTEXT_1)  # type: ignore[dict-item]
		with self.assertRaises(TypeError):
			_ = PortOutcome(
				"invalid",
				(lambda: None,),  # pyright: ignore[reportArgumentType]
			)

	def test_effect_results_require_failure_details(self) -> None:
		self.assertIsNone(EffectResult(readyStatus(), PortOutcome("accepted")).error)
		error = PortError("writeFailed", ("safe-detail",))
		self.assertEqual(error, EffectResult(failedStatus(), error=error).error)
		with self.assertRaises(ValueError):
			_ = EffectResult(failedStatus())
		with self.assertRaises(ValueError):
			_ = EffectResult(readyStatus(), error=error)


class ManagementValueTests(unittest.TestCase):
	def test_capture_operations_have_exact_argument_shapes(self) -> None:
		valid = (
			CaptureManagementRequest("refresh", CONTEXT_3, 3),
			CaptureManagementRequest("clearAll", CONTEXT_3, 3, confirmationRevision=7),
			CaptureManagementRequest("copyCommittedPath", CONTEXT_3, 3, actionId="copy-current"),
			CaptureManagementRequest("openCommittedFolder", CONTEXT_3, 3, actionId="open-current"),
			CaptureManagementRequest("revealCommittedFolder", CONTEXT_3, 3, actionId="reveal-current"),
		)
		self.assertEqual(
			(
				"refresh",
				"clearAll",
				"copyCommittedPath",
				"openCommittedFolder",
				"revealCommittedFolder",
			),
			tuple(request.operation for request in valid),
		)
		for invalid in (
			lambda: CaptureManagementRequest("refresh", CONTEXT_1, 1, actionId="unexpected"),
			lambda: CaptureManagementRequest("clearAll", CONTEXT_1, 1),
			lambda: CaptureManagementRequest(
				"clearAll",
				CONTEXT_1,
				1,
				actionId="unexpected",
				confirmationRevision=1,
			),
			lambda: CaptureManagementRequest("copyCommittedPath", CONTEXT_1, 1),
			lambda: CaptureManagementRequest("unknown", CONTEXT_1, 1),  # type: ignore[arg-type]
		):
			with self.assertRaises(ValueError):
				_ = invalid()

	def test_management_results_are_frozen_bounded_and_explicit(self) -> None:
		capture = captureResult()
		self.assertEqual(
			(4, 1, 0, 1, 0),
			(
				capture.recognizedCount,
				capture.suspiciousCount,
				capture.deletedCount,
				capture.skippedCount,
				capture.failedCount,
			),
		)
		self.assertEqual(("capture-set",), capture.outcome.arguments if capture.outcome else ())
		with self.assertRaises(ValueError):
			_ = captureResult(status=failedStatus())
		with self.assertRaises(ValueError):
			_ = CaptureManagementResult(
				operation="refresh",
				lifecycleGeneration=3,
				status=readyStatus(),
				outcome=PortOutcome("captureStatus"),
				error=None,
				recognizedCount=-1,
				suspiciousCount=0,
				deletedCount=0,
				skippedCount=0,
				failedCount=0,
				confirmationRevision=0,
				copyActionId=None,
				openActionId=None,
				revealActionId=None,
			)


class StaticBoundaryTests(unittest.TestCase):
	def test_provider_ports_expose_only_read_identity_and_release_families(self) -> None:
		self.assertEqual(
			{
				"readField",
				"readChildren",
				"readLogicalFirstChild",
				"readRelation",
				"readText",
				"readMetadata",
			},
			{
				name
				for name, value in providers.ReadOnlyNodePort.__dict__.items()
				if callable(value) and not name.startswith("_")
			},
		)
		for protocol in (
			providers.ReadOnlyNodePort,
			providers.IdentityComparisonPort,
			providers.ProviderSessionPort,
		):
			for name in protocol.__dict__:
				self.assertNotRegex(name.lower(), r"(action|click|focus|input|invoke|scroll|setvalue|toggle)")

	def test_management_values_and_protocols_have_no_authority_bearing_types(self) -> None:
		values = (
			effects.CaptureManagementRequest,
			effects.CaptureManagementResult,
		)
		for valueType in values:
			with self.subTest(valueType=valueType.__name__):
				for annotation in get_type_hints(valueType).values():
					rendered = str(annotation)
					for prohibited in PROHIBITED_FIELD_TYPES:
						self.assertNotIn(prohibited, rendered)

		for protocol in (effects.CaptureManagementPort,):
			for memberName, member in protocol.__dict__.items():
				if memberName.startswith("_") or not callable(member):
					continue
				signature = inspect.signature(member)
				for parameter in signature.parameters.values():
					self.assertNotIn(parameter.name, PROHIBITED_PARAMETER_NAMES)
				renderedReturn = str(get_type_hints(member).get("return"))
				for prohibited in PROHIBITED_FIELD_TYPES:
					self.assertNotIn(prohibited, renderedReturn)

	def test_capability_values_reject_mutable_and_cancelled_results_stay_explicit(self) -> None:
		with self.assertRaises(TypeError):
			CapabilityRequest("capture", "request", 1, (("options", []),))  # type: ignore[list-item]
		with self.assertRaises(ValueError):
			_ = CapabilityRequest(cast(str, None), "request", 1)
		with self.assertRaises(ValueError):
			_ = CapabilityRequest("capture", "request", 1, ((cast(str, None), True),))
		result = CapabilityResult("capture", "operation", 1, "cancelled", (("requested", True),))
		self.assertEqual("cancelled", result.status)


if __name__ == "__main__":
	_ = unittest.main()
