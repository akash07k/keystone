from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import cast
import unittest

from addon.globalPlugins.keystone.capability import PlainValue
from addon.globalPlugins.keystone.domain.privacy import (
	SINKS,
	FieldGroup,
	ObservedValue,
	PolicyProvenance,
	PrivacyClass,
	PrivacyPolicy,
	ProtectionEvidence,
	SinkId,
	TransformAction,
	UNREDACTED_SCREENSHOT_WARNING,
	classify,
	transformValue,
)


SECRET = "distinctive protected payload"


def policy(revision: int, *, redaction: bool) -> PrivacyPolicy:
	return PrivacyPolicy(
		policyRevision=revision,
		settingsRevision=revision + 10,
		redactProtectedText=redaction,
	)


def observed(
	group: FieldGroup,
	value: PlainValue = SECRET,
	privacyClass: PrivacyClass = PrivacyClass.PROTECTED,
) -> ObservedValue:
	return ObservedValue(
		fieldGroup=group,
		value=value,
		privacyClass=privacyClass,
		protection=ProtectionEvidence.allClear(),
		sourceId=f"{group.value}-source",
	)


class PrivacyRegistryTests(unittest.TestCase):
	def test_protection_evidence_is_one_tri_state_signal(self) -> None:
		self.assertEqual(("protected",), ProtectionEvidence.__match_args__)
		self.assertIsNone(getattr(ProtectionEvidence(), "protected"))
		self.assertIs(getattr(ProtectionEvidence(True), "protected"), True)
		self.assertIs(getattr(ProtectionEvidence.allClear(), "protected"), False)

	def test_policy_revisions_and_flags_validate_runtime_types(self) -> None:
		for invalid in (True, 1.5, "1", None):
			with self.subTest(policyRevision=invalid), self.assertRaises(ValueError):
				_ = PrivacyPolicy(cast(int, invalid), 1, True)
			with self.subTest(settingsRevision=invalid), self.assertRaises(ValueError):
				_ = PolicyProvenance(1, cast(int, invalid), False)
		with self.assertRaises(TypeError):
			_ = PolicyProvenance(1, 1, cast(bool, 1))

	def test_classification_uses_closed_precedence_and_conservative_unknowns(self) -> None:
		self.assertEqual(
			PrivacyClass.UNKNOWN,
			classify(PrivacyClass.PUBLIC, ProtectionEvidence()),
		)
		self.assertEqual(
			PrivacyClass.PROTECTED,
			classify(PrivacyClass.PUBLIC, ProtectionEvidence(True)),
		)
		self.assertEqual(
			PrivacyClass.PROTECTED,
			classify(PrivacyClass.SENSITIVE, ProtectionEvidence(True)),
		)
		self.assertEqual(
			PrivacyClass.SENSITIVE,
			classify(PrivacyClass.SENSITIVE, ProtectionEvidence.allClear()),
		)
		self.assertEqual(
			PrivacyClass.UNKNOWN,
			classify(PrivacyClass.PUBLIC, ProtectionEvidence(None)),
		)
		self.assertEqual(
			PrivacyClass.PUBLIC,
			classify(PrivacyClass.PUBLIC, ProtectionEvidence.allClear()),
		)

	def test_normalized_empty_false_and_zero_values_remain_explicit(self) -> None:
		for value in ("", False, 0, "e\u0301"):
			with self.subTest(value=value):
				source = observed(
					FieldGroup.NODE,
					value,
					PrivacyClass.PUBLIC,
				)
				result = transformValue(source, SinkId.NODE, policy(1, redaction=True))
				self.assertEqual(TransformAction.RETAIN, result.action)
				expected = "é" if value == "e\u0301" else value
				self.assertEqual(expected, result.value)


class PrivacyTransformTests(unittest.TestCase):
	def test_enabled_redaction_blocks_every_nonpublic_class_from_content_sinks(self) -> None:
		contentSinks = tuple(
			sink
			for sink in SINKS
			if sink
			not in {
				SinkId.SCREENSHOT,
				SinkId.NVDA_LOG,
			}
		)
		for privacyClass in (PrivacyClass.UNKNOWN, PrivacyClass.SENSITIVE, PrivacyClass.PROTECTED):
			for sink in contentSinks:
				with self.subTest(privacyClass=privacyClass, sink=sink):
					result = transformValue(
						observed(FieldGroup.NODE, privacyClass=privacyClass),
						sink,
						policy(1, redaction=True),
					)
					self.assertEqual(TransformAction.REDACT, result.action)
					self.assertNotIn(SECRET, repr(result))

	def test_logs_follow_the_same_redaction_choice_as_every_other_sink(self) -> None:
		logSinks = (SinkId.NVDA_LOG,)
		for sink in logSinks:
			for group, privacyClass, value in (
				(FieldGroup.NODE, PrivacyClass.PROTECTED, SECRET),
				(FieldGroup.CUSTOM, PrivacyClass.PUBLIC, SECRET),
				(FieldGroup.TEXT, PrivacyClass.PUBLIC, SECRET),
				(FieldGroup.EVENT, PrivacyClass.UNKNOWN, ""),
				(FieldGroup.DIAGNOSTIC, PrivacyClass.SENSITIVE, SECRET),
			):
				with self.subTest(sink=sink, group=group, redaction=True):
					redacted = transformValue(
						observed(group, value, privacyClass),
						sink,
						policy(2, redaction=True),
					)
					expected = (
						TransformAction.RETAIN
						if redacted.effectiveClass is PrivacyClass.PUBLIC
						else TransformAction.REDACT
					)
					self.assertEqual(expected, redacted.action)
					if expected is TransformAction.REDACT:
						self.assertIsNone(redacted.value)
						self.assertNotIn(SECRET, repr(redacted))

				with self.subTest(sink=sink, group=group, redaction=False):
					retained = transformValue(
						observed(group, value, privacyClass),
						sink,
						policy(2, redaction=False),
					)
					self.assertEqual(TransformAction.RETAIN, retained.action)
					self.assertEqual(value, retained.value)

	def test_public_safe_log_metadata_is_retained(self) -> None:
		source = observed(FieldGroup.LOG, ("count", 0), PrivacyClass.PUBLIC)
		for sink in (SinkId.NVDA_LOG,):
			with self.subTest(sink=sink):
				result = transformValue(source, sink, policy(1, redaction=False))
				self.assertEqual(TransformAction.RETAIN, result.action)
				self.assertEqual(("count", 0), result.value)

	def test_screenshot_is_always_marked_unredacted_even_without_image(self) -> None:
		for value in (b"pixels", None):
			with self.subTest(value=value):
				result = transformValue(
					observed(FieldGroup.SCREENSHOT, value, PrivacyClass.PROTECTED),
					SinkId.SCREENSHOT,
					policy(4, redaction=True),
				)
				self.assertEqual(TransformAction.RETAIN_UNREDACTED, result.action)
				self.assertEqual(value, result.value)
				self.assertEqual(UNREDACTED_SCREENSHOT_WARNING, result.warning)

	def test_screenshot_evidence_is_omitted_from_other_sinks_and_vice_versa(self) -> None:
		for source, sink in (
			(observed(FieldGroup.SCREENSHOT, b"pixels"), SinkId.NODE),
			(observed(FieldGroup.NODE), SinkId.SCREENSHOT),
		):
			with self.subTest(source=source.fieldGroup, sink=sink):
				result = transformValue(source, sink, policy(4, redaction=False))
				self.assertEqual(TransformAction.OMIT, result.action)
				self.assertIsNone(result.value)
				self.assertIsNone(result.warning)

	def test_disabled_redaction_retains_new_content_with_exact_provenance(self) -> None:
		current = policy(7, redaction=False)
		result = transformValue(
			observed(FieldGroup.EVENT, privacyClass=PrivacyClass.PROTECTED),
			SinkId.EVENT_EXPORT,
			current,
		)
		self.assertEqual(TransformAction.RETAIN, result.action)
		self.assertEqual(SECRET, result.value)
		self.assertEqual(
			PolicyProvenance(7, 17, False),
			result.provenance,
		)

	def test_transforms_do_not_mutate_source_or_prior_views(self) -> None:
		source = observed(FieldGroup.NODE)
		first = transformValue(source, SinkId.GUI, policy(1, redaction=False))
		second = transformValue(source, SinkId.GUI, policy(2, redaction=True))
		self.assertEqual(SECRET, source.value)
		self.assertEqual(SECRET, first.value)
		self.assertIsNone(second.value)
		with self.assertRaises(FrozenInstanceError):
			second.value = SECRET  # type: ignore[misc]


if __name__ == "__main__":
	_ = unittest.main()
