from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from importlib import import_module
import unittest


logFormats = import_module("addon.globalPlugins.keystone.encoding.log_formats")
SESSION_ID = "11111111-2222-4333-8444-555555555555"
OPERATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
FIXED_OFFSET = timezone(timedelta(hours=5, minutes=30))


def fixtureRecord():
	return logFormats.createRecord(
		sequence=42,
		timestamp=datetime(2026, 7, 18, 13, 45, 32, 123000, FIXED_OFFSET),
		code="KS.CAPTURE.COMPLETED_PARTIAL_SCREENSHOT",
		sessionCorrelationId=SESSION_ID,
		operationId=OPERATION_ID,
		nvdaPid=2468,
		threadIdentity="main",
		fields=(("nodeCount", 37), ("screenshotCode", "captureFailed")),
	)


class NativeRecordTests(unittest.TestCase):
	def test_native_message_is_bounded_and_uses_validated_record_fields(self) -> None:
		record = fixtureRecord()
		message = logFormats.renderNvdaMessage(record)
		self.assertIn(record.code, message)
		self.assertIn('nodeCount="37"', message)
		self.assertLessEqual(len(message.encode("utf-8")), logFormats.NVDA_MESSAGE_MAXIMUM)

	def test_session_header_has_no_file_writer_fields(self) -> None:
		fields = (
			("addonVersion", "1.0.0"),
			("boundaryReason", "open"),
			("configurationScope", "global"),
			("nvdaVersion", "2026.1"),
			("policyRevision", 3),
			("processArchitecture", "x64"),
			("redactionEnabled", True),
			("schemaMajor", 1),
			("sessionStartTime", "2026-07-18T13:45:32.123+05:30"),
			("settingsRevision", 7),
			("windowsBuild", "26100"),
		)
		record = logFormats.createRecord(
			sequence=1,
			timestamp=datetime.now(FIXED_OFFSET),
			code="KS.LIFECYCLE.SESSION_STARTED",
			sessionCorrelationId=SESSION_ID,
			nvdaPid=1,
			threadIdentity="main",
			fields=fields,
		)
		self.assertEqual("open", dict(record.fields)["boundaryReason"])
		with self.assertRaises(ValueError):
			_ = logFormats.createRecord(
				sequence=2,
				timestamp=record.timestamp,
				code=record.code,
				sessionCorrelationId=record.sessionCorrelationId,
				nvdaPid=record.nvdaPid,
				threadIdentity=record.threadIdentity,
				fields=(*fields, ("logFormat", "jsonl")),
			)

	def test_sequence_allocator_and_identity_validation_remain_strict(self) -> None:
		allocator = logFormats.SequenceAllocator(start=2, maximum=2)
		self.assertEqual(2, allocator.next())
		with self.assertRaises(OverflowError):
			_ = allocator.next()
		with self.assertRaises(ValueError):
			_ = replace(fixtureRecord(), threadIdentity="thread name")
		with self.assertRaises(FrozenInstanceError):
			fixtureRecord().code = "KS.COMMAND.HELP_OPENED"

	def test_safe_exceptions_are_static_diagnostics(self) -> None:
		exception = logFormats.SafeException(
			type="OperationFailure",
			message="The operation could not be completed.",
			code="operationFailed",
			stack="",
		)
		self.assertEqual("operationFailed", exception.code)
		with self.assertRaises(ValueError):
			_ = logFormats.SafeException(
				type="OperationFailure",
				message="user supplied secret",
				code="operationFailed",
				stack="",
			)

	def test_partial_screenshot_fields_have_one_registry_definition(self) -> None:
		definition = next(
			item
			for item in logFormats.EVENT_REGISTRY
			if item.code == "KS.CAPTURE.COMPLETED_PARTIAL_SCREENSHOT"
		)
		self.assertEqual(("nodeCount", "screenshotCode"), definition.requiredFields)
		self.assertEqual(("captureKind", "elapsedMs"), definition.optionalFields)

	def test_field_validation_and_native_truncation_remain_strict(self) -> None:
		with self.assertRaises(ValueError):
			_ = logFormats.createRecord(
				sequence=1,
				timestamp=datetime.now(timezone.utc),
				code="KS.COMMAND.HELP_OPENED",
				sessionCorrelationId=SESSION_ID,
				nvdaPid=1,
				threadIdentity="main",
				fields=(("helpSurface", "commands"), ("capturedValue", "secret")),
			)
		record = logFormats.createRecord(
			sequence=4,
			timestamp=datetime.now(timezone.utc),
			code="KS.CAPTURE.FAILED",
			sessionCorrelationId=SESSION_ID,
			operationId=OPERATION_ID,
			nvdaPid=1,
			threadIdentity="main",
			fields=(
				("captureKind", "capture"),
				("phase", "y" * 2048),
				("reasonCode", "z" * 2048),
				("processedNodes", 40),
				("elapsedMs", 45_000),
			),
		)
		self.assertIn('fieldsTruncated="true"', logFormats.renderNvdaMessage(record))


if __name__ == "__main__":
	_ = unittest.main()
