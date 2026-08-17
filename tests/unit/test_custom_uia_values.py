from __future__ import annotations

import math
from typing import Literal, override
import unittest

from addon.globalPlugins.keystone.domain.custom_uia_values import (
	CustomValueEvidence,
	CustomValueLimits,
	ElementReference,
	nonvalueCustomEvidence,
	normalizeCustomValue,
)
from addon.globalPlugins.keystone.domain.privacy import (
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
)


_LIMITS = CustomValueLimits(4, 5, 3)
_RETAIN_POLICY = PrivacyPolicy(1, 1, False)
_REDACT_POLICY = PrivacyPolicy(1, 1, True)
_CLEAR = ProtectionEvidence.allClear()


def _normalize(
	declaredType: str,
	value: object,
	*,
	privacy: str = "unknown",
	protection: ProtectionEvidence = _CLEAR,
	policy: PrivacyPolicy = _RETAIN_POLICY,
):
	return normalizeCustomValue(
		declaredType,  # type: ignore[arg-type]
		value,
		configuredPrivacy=privacy,
		protection=protection,
		policy=policy,
		limits=_LIMITS,
		sourceId="custom-value-test",
	)


class CustomUiaValueNormalizationTests(unittest.TestCase):
	def test_bool_precedes_int_and_false_zero_and_empty_string_remain_values(self) -> None:
		falseValue = _normalize("bool", False)
		zeroValue = _normalize("int", 0)
		emptyText = _normalize("string", "")

		self.assertEqual(
			("value", False, "bool"),
			(falseValue.status, falseValue.value, falseValue.observedShape),
		)
		self.assertEqual(("value", 0, "int"), (zeroValue.status, zeroValue.value, zeroValue.observedShape))
		self.assertEqual(
			("value", "", "string"),
			(emptyText.status, emptyText.value, emptyText.observedShape),
		)
		self.assertEqual("mismatch", _normalize("int", False).status)

	def test_signed_integers_doubles_nonfinite_tags_and_points_are_deterministic(self) -> None:
		self.assertEqual(-42, _normalize("int", -42).value)
		self.assertEqual(9, _normalize("enum", 9).value)
		self.assertEqual("mismatch", _normalize("enum", False).status)
		self.assertEqual(2.0, _normalize("double", 2).value)
		self.assertEqual(("nonFinite", "nan"), _normalize("double", math.nan).value)
		self.assertEqual(("nonFinite", "positiveInfinity"), _normalize("double", math.inf).value)
		self.assertEqual(("nonFinite", "negativeInfinity"), _normalize("double", -math.inf).value)
		self.assertEqual((-2.0, 3.5), _normalize("point", (-2, 3.5)).value)
		self.assertEqual("unknownVariant", _normalize("point", (math.inf, 2)).status)

	def test_strings_are_nfc_and_bounded_by_scalars_and_utf8_bytes(self) -> None:
		value = _normalize("string", "e\u0301🙂ab")

		self.assertEqual("truncated", value.status)
		self.assertEqual("é", value.value)
		self.assertEqual(4, value.scalarCount)
		self.assertEqual(8, value.byteCount)

	def test_element_references_are_capture_local_or_bounded_scoped_metadata(self) -> None:
		local = _normalize("element", ElementReference("node-2", "element-2"))
		external = _normalize(
			"element",
			ElementReference(None, "element-3", (9, 8, 7, 6), 42),
		)

		self.assertEqual(("captureLocal", "node-2", "element-2"), local.value)
		self.assertEqual(
			(
				"external",
				"element-3",
				("providerProcessId", 42),
				("runtimeIdMetadata", (9, 8, 7)),
				("runtimeIdMetadataTruncated", True),
			),
			external.value,
		)

	def test_capture_local_element_references_cannot_include_external_metadata(self) -> None:
		for runtimeIds, processId in (((9,), None), ((), 42), ((9,), 42)):
			with (
				self.subTest(runtimeIds=runtimeIds, processId=processId),
				self.assertRaisesRegex(ValueError, "capture-local.*external"),
			):
				_ = ElementReference("node-2", "element-2", runtimeIds, processId)

	def test_declared_shape_mismatch_unknown_variant_and_empty_are_distinct(self) -> None:
		class NoRepresentation:
			@override
			def __repr__(self) -> str:
				raise AssertionError("unknown custom values must never be represented")

			@override
			def __getattribute__(self, name: str) -> object:
				if name in {"__class__", "__repr__"}:
					return object.__getattribute__(self, name)
				raise AssertionError("unknown custom values must never be inspected")

		self.assertEqual("mismatch", _normalize("bool", 1).status)
		self.assertEqual(
			("unknown", "string", "value"),
			(
				_normalize("unknown", "ok").declaredType,
				_normalize("unknown", "ok").observedShape,
				_normalize("unknown", "ok").status,
			),
		)
		self.assertEqual("unknownVariant", _normalize("string", b"private").status)
		self.assertEqual("unknownVariant", _normalize("string", NoRepresentation()).status)
		self.assertEqual("empty", _normalize("string", None).status)
		self.assertEqual(
			"unsupported",
			nonvalueCustomEvidence("string", "unsupported", "unknown", _CLEAR).status,
		)
		self.assertEqual(
			"unavailable",
			nonvalueCustomEvidence(
				"string",
				"unavailable",
				"unknown",
				_CLEAR,
				"KS.CUSTOM_UIA.UNAVAILABLE",
			).status,
		)
		self.assertEqual(
			"failed",
			nonvalueCustomEvidence(
				"string",
				"failed",
				"unknown",
				_CLEAR,
				"KS.CUSTOM_UIA.FAILED",
			).status,
		)
		cases: tuple[
			tuple[Literal["empty", "unsupported", "unavailable", "failed"], str | None, str | None],
			...,
		] = (
			("empty", "KS.CUSTOM_UIA.IGNORED", None),
			("unsupported", "KS.CUSTOM_UIA.IGNORED", None),
			("unavailable", None, "KS.CUSTOM_UIA.UNAVAILABLE"),
			("failed", None, "KS.CUSTOM_UIA.FAILED"),
			("failed", "KS.CUSTOM_UIA.PROVIDER_FAILED", "KS.CUSTOM_UIA.PROVIDER_FAILED"),
		)
		for status, suppliedCode, expectedCode in cases:
			with self.subTest(status=status):
				evidence = nonvalueCustomEvidence("string", status, "unknown", _CLEAR, suppliedCode)

				self.assertEqual(expectedCode, evidence.errorCode)
				self.assertEqual("null" if status == "empty" else status, evidence.observedShape)

	def test_privacy_defaults_unknown_can_only_rise_and_protected_context_wins(self) -> None:
		unknown = _normalize("string", "value")
		sensitive = _normalize("string", "value", privacy="sensitive")
		protected = _normalize(
			"string",
			"value",
			privacy="unknown",
			protection=ProtectionEvidence(True),
		)
		redacted = _normalize("string", "value", policy=_REDACT_POLICY)

		self.assertEqual(PrivacyClass.UNKNOWN, unknown.effectivePrivacy)
		self.assertEqual(PrivacyClass.SENSITIVE, sensitive.effectivePrivacy)
		self.assertEqual(PrivacyClass.PROTECTED, protected.effectivePrivacy)
		self.assertEqual("redacted", redacted.status)
		self.assertIsNone(redacted.value)

	def test_string_counts_require_retained_text_evidence(self) -> None:
		for status, value in (
			("redacted", None),
			("empty", None),
			("value", 1),
			("truncated", ("text",)),
		):
			with self.subTest(status=status, value=value), self.assertRaises(ValueError):
				_ = CustomValueEvidence(
					status,  # type: ignore[arg-type]
					"string",
					"string",
					PrivacyClass.UNKNOWN,
					value,
					scalarCount=1,
					byteCount=1,
				)


if __name__ == "__main__":
	_ = unittest.main()
