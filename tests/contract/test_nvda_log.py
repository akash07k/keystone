from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from importlib import import_module
from types import ModuleType
import sys
from typing import Any, override
import unittest

from addon.globalPlugins.keystone.domain.privacy import (
	FieldGroup,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
)


class HostLogger:
	def __init__(self) -> None:
		super().__init__()
		self.calls: list[tuple[str, str, tuple[object, ...], dict[str, object]]] = []

	def _record(self, level: str, message: str, *args: object, **kwargs: object) -> None:
		self.calls.append((level, message, args, kwargs))

	def debug(self, message: str, *args: object, **kwargs: object) -> None:
		self._record("debug", message, *args, **kwargs)

	def info(self, message: str, *args: object, **kwargs: object) -> None:
		self._record("info", message, *args, **kwargs)

	def warning(self, message: str, *args: object, **kwargs: object) -> None:
		self._record("warning", message, *args, **kwargs)

	def error(self, message: str, *args: object, **kwargs: object) -> None:
		self._record("error", message, *args, **kwargs)

	def critical(self, message: str, *args: object, **kwargs: object) -> None:
		self._record("critical", message, *args, **kwargs)


HOST_LOGGER = HostLogger()
hostModule = ModuleType("logHandler")
setattr(hostModule, "log", HOST_LOGGER)
previousHostModule = sys.modules.get("logHandler")
try:
	sys.modules["logHandler"] = hostModule
	logFormats = import_module("addon.globalPlugins.keystone.encoding.log_formats")
	loggingService = import_module("addon.globalPlugins.keystone.application.logging_service")
	nvdaLog = import_module("addon.globalPlugins.keystone.adapters.nvda.nvda_log")
finally:
	if previousHostModule is None:
		del sys.modules["logHandler"]
	else:
		sys.modules["logHandler"] = previousHostModule

SESSION_ID = "11111111-2222-4333-8444-555555555555"
OPERATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def context() -> Any:
	return loggingService.LogContext(
		sessionCorrelationId=SESSION_ID,
		operationId=OPERATION_ID,
		jobId=None,
		windowGeneration=2,
		inspectorGeneration=None,
		monitorGeneration=None,
		nvdaPid=2468,
		threadIdentity="main",
	)


def field(name: str, value: object, *, privacyClass: PrivacyClass = PrivacyClass.PUBLIC) -> Any:
	return loggingService.LogFieldCandidate(
		name=name,
		value=value,
		fieldGroup=FieldGroup.LOG,
		privacyClass=privacyClass,
		protection=ProtectionEvidence.allClear(),
		sourceId=f"{name}-source",
	)


def candidate(*extra: Any) -> Any:
	return loggingService.LogCandidate(
		timestamp=datetime(2026, 7, 18, 13, 45, 32, 123000, timezone.utc),
		code="KS.COMMAND.REQUEST_REJECTED",
		context=context(),
		fields=(field("commandId", "inspect"), field("reasonCode", "busy"), *extra),
	)


class NvdaSink:
	def __init__(self, *, fail: bool = False) -> None:
		super().__init__()
		self.records: list[Any] = []
		self.fail = fail

	def emit(self, record: Any) -> None:
		self.records.append(record)
		if self.fail:
			raise RuntimeError("host logger failed")


def service(nvda: NvdaSink, policy: PrivacyPolicy | None = None) -> Any:
	return loggingService.LoggingService(
		nvdaSink=nvda,
		sequenceAllocator=logFormats.SequenceAllocator(),
		privacyPolicy=policy or PrivacyPolicy(1, 1, True),
	)


class NvdaAdapterTests(unittest.TestCase):
	@override
	def setUp(self) -> None:
		HOST_LOGGER.calls.clear()

	def test_each_severity_maps_to_one_bounded_host_call(self) -> None:
		cases = (
			("KS.CAPTURE.PROGRESS", (("captureKind", "full"), ("processedNodes", 2)), "debug"),
			("KS.COMMAND.HELP_OPENED", (("helpSurface", "commands"),), "info"),
			("KS.COMMAND.REQUEST_REJECTED", (("commandId", "inspect"), ("reasonCode", "busy")), "warning"),
			("KS.SCREENSHOT.FAILED", (("phase", "capture"), ("reasonCode", "blocked")), "error"),
			(
				"KS.PACKAGE.MANIFEST_INVALID",
				(("manifestField", "name"), ("reasonCode", "missing")),
				"critical",
			),
		)
		adapter = nvdaLog.NvdaLogAdapter(HOST_LOGGER)
		for sequence, (code, fields, expectedLevel) in enumerate(cases, 1):
			with self.subTest(code=code):
				record = logFormats.createRecord(
					sequence=sequence,
					timestamp=datetime.now(timezone.utc),
					code=code,
					sessionCorrelationId=SESSION_ID,
					nvdaPid=1,
					threadIdentity="main",
					fields=fields,
				)
				adapter.emit(record)
				level, message, args, kwargs = HOST_LOGGER.calls[-1]
				self.assertEqual(expectedLevel, level)
				self.assertEqual(logFormats.renderNvdaMessage(record), message)
				self.assertEqual((), args)
				self.assertEqual({}, kwargs)


class NativeLoggingServiceTests(unittest.TestCase):
	def test_privacy_admission_precedes_native_emission_and_sequence(self) -> None:
		nvda = NvdaSink()
		log = service(nvda)
		rejected = loggingService.LogCandidate(
			timestamp=datetime.now(timezone.utc),
			code="KS.COMMAND.REQUEST_REJECTED",
			context=context(),
			fields=(
				field("commandId", "secret", privacyClass=PrivacyClass.PROTECTED),
				field("reasonCode", "busy"),
			),
		)
		result = log.emit(rejected)
		self.assertEqual("admissionRejected", result.status)
		self.assertEqual([], nvda.records)
		admitted = log.emit(
			candidate(field("activeOperationKind", "protected", privacyClass=PrivacyClass.PROTECTED)),
		)
		assert admitted.record is not None
		self.assertEqual(1, admitted.record.sequence)
		self.assertNotIn("activeOperationKind", dict(admitted.record.fields))

	def test_rejected_context_and_field_validation_do_not_consume_sequences(self) -> None:
		nvda = NvdaSink()
		allocator = logFormats.SequenceAllocator()
		log = loggingService.LoggingService(
			nvdaSink=nvda,
			sequenceAllocator=allocator,
			privacyPolicy=PrivacyPolicy(1, 1, True),
		)
		invalidContext = loggingService.LogCandidate(
			timestamp=datetime.now(timezone.utc),
			code="KS.COMMAND.REQUEST_REJECTED",
			context=replace(context(), sessionCorrelationId="invalid"),
			fields=(field("commandId", "inspect"), field("reasonCode", "busy")),
		)
		invalidField = loggingService.LogCandidate(
			timestamp=datetime.now(timezone.utc),
			code="KS.COMMAND.REQUEST_REJECTED",
			context=context(),
			fields=(field("commandId", 2), field("reasonCode", "busy")),
		)
		for rejected in (invalidContext, invalidField):
			with self.subTest(candidate=rejected):
				result = log.emit(rejected)
				self.assertEqual("admissionRejected", result.status)
				self.assertEqual([], nvda.records)
		result = log.emit(candidate())
		assert result.record is not None
		self.assertEqual(1, result.record.sequence)

	def test_native_sink_failure_is_explicit(self) -> None:
		result = service(NvdaSink(fail=True)).emit(candidate())
		self.assertEqual("emitted", result.status)
		self.assertEqual("failed", result.nvdaStatus)
		self.assertEqual("nvdaLogFailed", result.errorCode)

	def test_native_logging_keeps_protected_evidence_when_redaction_is_off(self) -> None:
		nvda = NvdaSink()
		result = service(nvda, PrivacyPolicy(1, 1, False)).emit(
			candidate(field("activeOperationKind", "protected", privacyClass=PrivacyClass.PROTECTED)),
		)
		assert result.record is not None
		self.assertEqual("protected", dict(result.record.fields)["activeOperationKind"])
		self.assertEqual(1, len(nvda.records))


if __name__ == "__main__":
	_ = unittest.main()
