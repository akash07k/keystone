"""Application service that ties one bundle from capture through open and selective export.

``BundleService`` prepares a deterministic bundle from a privacy-transformed capture, bridges it
into the strict publication package, opens a committed directory index-first, and joins a single
selected node from recorded offsets. Every open advances a monotonic source generation so a stale
export cannot read offsets from a superseded capture, and projections are cached per generation so
the same node is joined once. The service re-exports the pure bundle operations so callers depend on
one application entry point.
"""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
from shutil import rmtree
from typing import cast
from uuid import uuid4

from ..adapters.windows.publication import CaptureKind, PublicationPackage
from ..domain.privacy import UNREDACTED_SCREENSHOT_WARNING
from ..domain.snapshot_bundle import (
	DEFAULT_BUNDLE_LIMITS,
	BundleAdmission,
	BundleAdmissionLimits,
	BundlePackage,
	BundleSource,
	SelectedNodeProjection,
	SelectedSubtreeProjection,
	admitBundle,
	estimateTokenCount,
	prepareBundle,
	projectSelectedNode,
	projectSelectedSubtree,
	validateBundleArtifacts,
)

__all__ = (
	"BundleService",
	"admitBundle",
	"estimateTokenCount",
	"prepareBundle",
	"portableSubtreeDestination",
	"projectSelectedNode",
	"projectSelectedSubtree",
	"toPublicationPackage",
	"writePortableBundle",
)

_WINDOWS_INVALID_COMPONENT = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED_COMPONENTS = frozenset(
	{
		"con",
		"prn",
		"aux",
		"nul",
		*(f"com{index}" for index in range(1, 10)),
		*(f"lpt{index}" for index in range(1, 10)),
	},
)


def _safePathComponent(value: str | None, fallback: str) -> str:
	"""Return one nonempty Windows-safe directory component."""

	component = "" if value is None else _WINDOWS_INVALID_COMPONENT.sub("_", value).strip()[:120].rstrip(". ")
	if not component or component.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_COMPONENTS:
		return fallback
	return component


def portableSubtreeDestination(
	baseDirectory: Path,
	*,
	applicationName: str | None,
	elementName: str | None,
	automationId: str | None,
	role: str | None,
	now: datetime,
) -> Path:
	"""Build the collision-resistant portable subtree export directory below a user-selected base."""

	rawApplication = (applicationName or "").replace("\\", "/").rsplit("/", 1)[-1]
	if rawApplication.casefold().endswith(".exe"):
		rawApplication = rawApplication[:-4]
	application = _safePathComponent(rawApplication, "application")
	element = _safePathComponent(elementName, "")
	if not element:
		element = _safePathComponent(automationId, "")
	if not element:
		element = _safePathComponent(role, "object")
	timestamp = now.strftime("%Y%m%d-%H%M%S.%f")
	return Path(baseDirectory) / application / element / timestamp


def toPublicationPackage(
	package: BundlePackage,
	*,
	publicationId: str,
	completedAt: datetime,
	subject: str | None = None,
) -> PublicationPackage:
	"""Bridge a prepared bundle into a strict publication package."""

	return PublicationPackage(
		publicationId=publicationId,
		executable=package.index.executable,
		processId=package.index.processId,
		captureKind=cast("CaptureKind", package.index.snapshotKind),
		completedAt=completedAt,
		artifacts=package.artifacts(),
		screenshotWarning=UNREDACTED_SCREENSHOT_WARNING,
		subject=subject,
	)


def writePortableBundle(package: BundlePackage, destination: Path) -> Path:
	"""Atomically create and reopen-validate a standalone Inspector snapshot directory."""

	destination = Path(destination)
	if destination.exists():
		raise FileExistsError("the snapshot export directory already exists")
	if not destination.parent.is_dir():
		raise ValueError("the snapshot export parent directory does not exist")
	artifacts = dict(package.artifacts())
	_ = validateBundleArtifacts(artifacts)
	staging = destination.parent / f".{destination.name}.keystone-staging-{uuid4().hex}"
	try:
		staging.mkdir()
		for name, payload in package.artifacts():
			with (staging / name).open("xb") as stream:
				_ = stream.write(payload)
		_ = admitBundle(staging, sourceGeneration=0)
		os.replace(staging, destination)
		try:
			_ = admitBundle(destination, sourceGeneration=0)
		except (OSError, ValueError):
			rmtree(destination)
			raise
	finally:
		if staging.exists():
			rmtree(staging)
	return destination


class BundleService:
	"""Prepare, publish-bridge, open, and selectively export one capture bundle."""

	__slots__ = ("_current", "_directory", "_generation", "_limits", "_projections", "_subtrees")

	def __init__(self, *, limits: BundleAdmissionLimits = DEFAULT_BUNDLE_LIMITS) -> None:
		super().__init__()
		self._limits = limits
		self._generation = 0
		self._current: BundleAdmission | None = None
		self._directory: Path | None = None
		self._projections: dict[tuple[int, str], SelectedNodeProjection] = {}
		self._subtrees: dict[tuple[int, str], SelectedSubtreeProjection] = {}

	@property
	def currentGeneration(self) -> int:
		return self._generation

	@property
	def admission(self) -> BundleAdmission | None:
		return self._current

	@property
	def defaultLimits(self) -> BundleAdmissionLimits:
		"""Return the persistent admission limits without exposing mutable service state."""

		return self._limits

	def prepare(self, source: BundleSource) -> BundlePackage:
		return prepareBundle(source)

	def toPublicationPackage(
		self,
		package: BundlePackage,
		*,
		publicationId: str,
		completedAt: datetime,
		subject: str | None = None,
	) -> PublicationPackage:
		return toPublicationPackage(
			package,
			publicationId=publicationId,
			completedAt=completedAt,
			subject=subject,
		)

	def openDirectory(
		self,
		directory: Path,
		*,
		limits: BundleAdmissionLimits | None = None,
	) -> BundleAdmission:
		"""Open one bundle atomically, optionally with a one-operation admission ceiling."""

		nextGeneration = self._generation + 1
		admission = admitBundle(
			directory,
			sourceGeneration=nextGeneration,
			limits=self._limits if limits is None else limits,
		)
		self._generation = nextGeneration
		self._current = admission
		self._directory = directory
		self._projections.clear()
		self._subtrees.clear()
		return admission

	def selectNode(self, nodeId: str) -> SelectedNodeProjection:
		admission = self._current
		directory = self._directory
		if admission is None or directory is None:
			raise RuntimeError("no bundle is open")
		key = (admission.sourceGeneration, nodeId)
		cached = self._projections.get(key)
		if cached is not None:
			return cached
		projection = projectSelectedNode(admission, directory, nodeId)
		self._projections[key] = projection
		return projection

	def selectSubtree(self, nodeId: str) -> SelectedSubtreeProjection:
		"""Project the selected recorded subtree into a portable bundle."""

		admission = self._current
		directory = self._directory
		if admission is None or directory is None:
			raise RuntimeError("no bundle is open")
		key = (admission.sourceGeneration, nodeId)
		cached = self._subtrees.get(key)
		if cached is not None:
			return cached
		projection = projectSelectedSubtree(admission, directory, nodeId)
		self._subtrees[key] = projection
		return projection
