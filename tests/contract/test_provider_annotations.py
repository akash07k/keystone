from __future__ import annotations

import unittest
from collections.abc import Iterator

from addon.globalPlugins.keystone.adapters.providers.common import (
	NvdaObjectGetter,
	collectAnnotations,
	normalizeProviderValue,
)
from addon.globalPlugins.keystone.domain.inspector import AnnotationStatus
from addon.globalPlugins.keystone.ports.providers import ReadBudget


class ProviderAnnotationCollectionTests(unittest.TestCase):
	def test_annotation_collection_stops_at_elapsed_time_budget_with_partial_records(self) -> None:
		class _Clock:
			def __init__(self) -> None:
				super().__init__()
				self.milliseconds = 0

			def __call__(self) -> int:
				return self.milliseconds

		class _Target:
			name = "first"
			role = "button"

		class _AnnotationTarget:
			role = "comment"
			summary = "summary"

			def __init__(self, target: object, clock: _Clock | None = None) -> None:
				super().__init__()
				self._target = target
				self._clock = clock

			@property
			def targetObject(self) -> object:
				if self._clock is not None:
					self._clock.milliseconds = 10
				return self._target

		class _Origin:
			def __init__(self, clock: _Clock) -> None:
				super().__init__()
				self.targets = (_AnnotationTarget(_Target()), _AnnotationTarget(_Target(), clock))
				self.roles = ("details", "details")

			def __bool__(self) -> bool:
				return True

		class _Source:
			def __init__(self, clock: _Clock) -> None:
				super().__init__()
				self.annotations = _Origin(clock)

		clock = _Clock()
		records = collectAnnotations(
			_Source(clock),
			ReadBudget(maximumItems=8, maximumTextLength=80, maximumMilliseconds=5),
			privacyTransform=str,
			clockMilliseconds=clock,
		)

		self.assertEqual(
			(AnnotationStatus.VALUE, AnnotationStatus.FAILED),
			tuple(record.status for record in records),
		)
		self.assertEqual("first", records[0].targetName)

	def test_broken_annotation_target_preserves_other_target_records(self) -> None:
		class _BrokenAnnotationTarget:
			role = "comment"

			@property
			def targetObject(self) -> object:
				raise RuntimeError("stale target")

		class _AnnotationTarget:
			role = "comment"
			summary = "summary"

			def __init__(self, name: str) -> None:
				super().__init__()
				self.targetObject = type("_Target", (), {"name": name, "role": "button"})()

		class _Origin:
			targets = (_AnnotationTarget("first"), _BrokenAnnotationTarget(), _AnnotationTarget("last"))
			roles = ("details", "details", "details")

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()

		records = collectAnnotations(
			_Source(),
			ReadBudget(maximumItems=8, maximumTextLength=80, maximumMilliseconds=50),
			privacyTransform=str,
		)

		self.assertEqual(3, len(records))
		self.assertEqual(("first", None, "last"), tuple(record.targetName for record in records))
		self.assertEqual(
			(AnnotationStatus.VALUE, AnnotationStatus.FAILED, AnnotationStatus.VALUE),
			tuple(record.status for record in records),
		)

	def test_primary_annotation_properties_do_not_read_stale_fallbacks(self) -> None:
		class _Target:
			name = "target"
			role = "button"
			author = "author"
			dateTime = "date"

			@property
			def currentName(self) -> object:
				raise AssertionError("currentName must not be read")

			@property
			def currentControlType(self) -> object:
				raise AssertionError("currentControlType must not be read")

			@property
			def annotationAuthor(self) -> object:
				raise AssertionError("annotationAuthor must not be read")

			@property
			def annotationDateTime(self) -> object:
				raise AssertionError("annotationDateTime must not be read")

		class _AnnotationTarget:
			role = "comment"
			summary = "summary"
			targetObject = _Target()

		class _Origin:
			targets = (_AnnotationTarget(),)
			roles = ("details",)

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()

		(record,) = collectAnnotations(
			_Source(),
			ReadBudget(maximumItems=8, maximumTextLength=80, maximumMilliseconds=50),
			privacyTransform=str,
		)

		self.assertIs(AnnotationStatus.VALUE, record.status)
		self.assertEqual(
			("target", "button", "author", "date"),
			(record.targetName, record.targetRole, record.author, record.dateTime),
		)

	def test_iterable_normalization_stops_at_elapsed_time_budget(self) -> None:
		class _Clock:
			def __init__(self) -> None:
				super().__init__()
				self.milliseconds = 0

			def __call__(self) -> int:
				return self.milliseconds

		class _SlowValues:
			def __init__(self, clock: _Clock) -> None:
				super().__init__()
				self._clock = clock

			def __iter__(self) -> Iterator[str]:
				yield "first"
				self._clock.milliseconds = 10
				yield "second"

		clock = _Clock()
		value, truncated = normalizeProviderValue(
			_SlowValues(clock),
			maximumItems=8,
			maximumTextLength=80,
			maximumMilliseconds=5,
			clockMilliseconds=clock,
		)

		self.assertEqual(("first",), value)
		self.assertTrue(truncated)

	def test_child_iteration_stops_at_elapsed_time_budget_with_retained_objects(self) -> None:
		class _Clock:
			def __init__(self) -> None:
				super().__init__()
				self.milliseconds = 0

			def __call__(self) -> int:
				return self.milliseconds

		first = object()
		second = object()
		clock = _Clock()

		def children() -> Iterator[object]:
			yield first
			clock.milliseconds = 10
			yield second

		target = type("_Target", (), {"children": children()})()
		result = NvdaObjectGetter.readChildren(
			target,
			ReadBudget(maximumItems=8, maximumTextLength=80, maximumMilliseconds=5),
			clockMilliseconds=clock,
		)

		self.assertEqual(("value", 2, True), (result.status, result.observedCount, result.truncated))
		self.assertEqual(1, len(result.values))
		self.assertIs(first, result.values[0])

	def test_combined_sources_report_annotation_truncation(self) -> None:
		class _Target:
			role = "button"

			def __init__(self, name: str) -> None:
				super().__init__()
				self.name = name

		class _AnnotationTarget:
			role = "comment"

			def __init__(self, name: str) -> None:
				super().__init__()
				self.targetObject = _Target(name)

		class _Origin:
			targets = (_AnnotationTarget("first"), _AnnotationTarget("second"))
			roles = ("details", "details")

			def __bool__(self) -> bool:
				return True

		class _Source:
			annotations = _Origin()
			UIAAnnotationObjects = ((1, _AnnotationTarget("third")),)

		budget = ReadBudget(maximumItems=2, maximumTextLength=80, maximumMilliseconds=50)
		records = collectAnnotations(_Source(), budget, privacyTransform=str)
		result = NvdaObjectGetter.readAttribute(_Source(), "annotations", budget)

		self.assertEqual(
			(AnnotationStatus.VALUE, AnnotationStatus.TRUNCATED),
			tuple(record.status for record in records),
		)
		self.assertEqual("value", result.status)
		self.assertTrue(result.truncated)

	def test_nested_annotation_truncation_marks_the_provider_result(self) -> None:
		class _Target:
			role = "button"

			def __init__(self, name: str) -> None:
				super().__init__()
				self.name = name

		class _AnnotationTarget:
			role = "comment"

			def __init__(self, target: object) -> None:
				super().__init__()
				self.targetObject = target

		class _Origin:
			def __init__(self, targets: tuple[object, ...]) -> None:
				super().__init__()
				self.targets = targets
				self.roles = ("details",) * len(targets)

			def __bool__(self) -> bool:
				return True

		class _NestedTarget(_Target):
			def __init__(self) -> None:
				super().__init__("nested")
				self.annotations = _Origin(
					(_AnnotationTarget(_Target("first")), _AnnotationTarget(_Target("second"))),
				)
				self.UIAAnnotationObjects = ((1, _AnnotationTarget(_Target("third"))),)

		class _Source:
			annotations = _Origin((_AnnotationTarget(_NestedTarget()),))

		budget = ReadBudget(maximumItems=2, maximumTextLength=80, maximumMilliseconds=50)
		(records,) = collectAnnotations(_Source(), budget, privacyTransform=str)
		result = NvdaObjectGetter.readAttribute(_Source(), "annotations", budget)

		self.assertIs(AnnotationStatus.VALUE, records.status)
		self.assertEqual(AnnotationStatus.TRUNCATED, records.related[-1].status)
		self.assertTrue(result.truncated)
