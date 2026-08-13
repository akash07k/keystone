"""Synthetic compact-bundle shapes for local snapshot opening contracts."""

from __future__ import annotations

from pathlib import Path

from addon.globalPlugins.keystone.domain.document_records import JsonArray, JsonObject
from addon.globalPlugins.keystone.domain.evidence import ErrorReference
from addon.globalPlugins.keystone.domain.inspector import AnnotationRecord, AnnotationStatus
from addon.globalPlugins.keystone.domain.snapshot_bundle import (
	COMPLETE_HARD_BYTES,
	LOCAL_SELECTED_BUNDLE_LIMITS,
	BundleSource,
	BundleTopicRecords,
	prepareBundle,
)


def _syntheticSnapshotSource(payloadLength: int, *, name: str) -> BundleSource:
	"""Return one valid non-sensitive snapshot with a controlled decoded size."""

	node = JsonObject(
		(
			("id", "n0"),
			("parent", None),
			("depth", 0),
			("childCount", 0),
			("role", "window"),
			("name", name),
			("children", JsonArray(())),
			(
				"flags",
				JsonObject(
					(
						("cycleDetected", False),
						("truncated", False),
						("childFetchFailed", False),
					),
				),
			),
			("fields", JsonObject(())),
			("payload", "x" * payloadLength),
		),
	)
	return BundleSource(
		snapshotKind="snapshot",
		generatedAt="2026-07-24T09:08:07Z",
		redactionEnabled=True,
		policyRevision=1,
		settingsRevision=1,
		executable="reader.exe",
		processId=42,
		rootIds=("n0",),
		topics=(BundleTopicRecords("nodes", (node,)),),
	)


def oversizedSnapshotSource() -> BundleSource:
	"""Return one valid offline snapshot that needs the explicit local-size retry."""

	return _syntheticSnapshotSource(COMPLETE_HARD_BYTES, name="Large snapshot")


def overLocalRetrySnapshotSource() -> BundleSource:
	"""Return one valid snapshot that remains over the 64 MiB local retry ceiling."""

	return _syntheticSnapshotSource(
		LOCAL_SELECTED_BUNDLE_LIMITS.maximumBytes,
		name="Too large snapshot",
	)


def writeLocalRetryLimitFixture(directory: Path, *, overLocalRetryLimit: bool = False) -> None:
	"""Write a temporary generated retry-boundary bundle without storing capture bytes in the repo."""

	source = overLocalRetrySnapshotSource() if overLocalRetryLimit else oversizedSnapshotSource()
	for name, payload in prepareBundle(source).artifacts():
		_ = (directory / name).write_bytes(payload)


def powerPointCyclicRibbonAnnotation() -> AnnotationRecord:
	"""Return the approved failed Ribbon shape without serializing an exception payload."""
	return AnnotationRecord(
		key="powerpoint-cyclic-ribbon",
		status=AnnotationStatus.FAILED,
		typeName="Ribbon annotation",
		source="NVDA annotations",
		errorRef=ErrorReference(
			"KS.ANNOTATION.CONVERSION_FAILED",
			"annotation-conversion-powerpoint-cyclic-ribbon",
		),
	)


def firefoxRelationshipAnnotations() -> tuple[AnnotationRecord, ...]:
	"""Return the Firefox relationship shape with preserved nested relationship meaning."""
	target = AnnotationRecord(
		key="firefox-relationship-target",
		status=AnnotationStatus.VALUE,
		typeName="Relationship target",
		source="IA2 relation",
		targetName="Relationship target",
		targetRole="staticText",
		relationship="labelledBy",
	)
	return (
		AnnotationRecord(
			key="firefox-relationship",
			status=AnnotationStatus.VALUE,
			typeName="Relationship",
			source="IA2 relation",
			summary="Firefox relationship evidence",
			relationship="labelledBy",
			related=(target,),
		),
	)
