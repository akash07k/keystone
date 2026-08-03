# pyright: reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

from collections.abc import Callable
import hashlib
from importlib import import_module
import json
import os
from pathlib import Path
from typing import cast

from ...domain.commands import COMMAND_DEFINITIONS
from ...domain.correlation import CorrelationFactory
from ...domain.projection import ProjectionBudget, ProjectionRequest
from ..providers.custom_uia import NvdaCustomUiaGetter
from ..providers.raw_uia import RawUiaAdapter
from ..windows.screenshot import ScreenshotAdapter, WxModule, WxScreenshotBackend
from ...ports.effects import ScreenshotAttempt, ScreenshotTarget
from ...ports.providers import (
	ProviderChildrenRequest,
	ProviderMetadataRequest,
	ProviderSessionCloseRequest,
	ReadBudget,
)
from .selected_objects import NvdaSelectedObjectSource, SelectedObjectSession
from .inspector_source import providerSectionDatums


def _safeValue(target: object, name: str) -> tuple[bool, str]:
	try:
		value = target.__getattribute__(name)
	except Exception:
		return False, ""
	encoded = repr(value).encode("utf-8", errors="replace")
	return True, hashlib.sha256(encoded).hexdigest()


def _selectionDigest(target: object) -> tuple[bool, str]:
	try:
		textInfos = import_module("textInfos")
		info = target.makeTextInfo(textInfos.POSITION_SELECTION)
		value = str(info.text)
	except Exception:
		return False, ""
	return True, hashlib.sha256(value.encode("utf-8")).hexdigest()


def _targetState() -> dict[str, object]:
	api = import_module("api")
	focus = api.getFocusObject()
	navigator = api.getNavigatorObject()
	valueAvailable, valueDigest = _safeValue(focus, "value")
	selectionAvailable, selectionDigest = _selectionDigest(focus)
	return {
		"focusIdentity": id(focus),
		"navigatorIdentity": id(navigator),
		"valueAvailable": valueAvailable,
		"valueDigest": valueDigest,
		"selectionAvailable": selectionAvailable,
		"selectionDigest": selectionDigest,
	}


def _providerObservation() -> dict[str, object]:
	session = SelectedObjectSession(NvdaSelectedObjectSource(), generation=1)
	context = CorrelationFactory().admit(generation=1)
	try:
		selected = session.acquire("foreground")
		sections = session.readMetadata(
			ProviderMetadataRequest(
				selected.rootRef,
				"providerSections",
				ReadBudget(64, 4_096, 2_000),
				context,
			),
		)
		return {
			"runtime": "available",
			"selectedObject": "value",
			"providerSections": sections.status,
			"overlayPreserved": True,
			"liveObjectsEmitted": False,
		}
	finally:
		_ = session.closeSession(ProviderSessionCloseRequest(context))


def _rawObservation() -> dict[str, object]:
	api = import_module("api")
	handler = import_module("UIAHandler").handler
	before = (
		id(api.getFocusObject()),
		id(api.getNavigatorObject()),
		id(handler.clientObject),
		id(handler.baseTreeWalker),
	)
	session = SelectedObjectSession(NvdaSelectedObjectSource(), generation=1)
	context = CorrelationFactory().admit(generation=1)
	try:
		selected = session.acquire(
			"foreground",
			rawRequest=ProjectionRequest.explicit(
				"packaged-review",
				ProjectionBudget(150, 600, 2_000),
			),
		)
		children = session.readChildren(
			ProviderChildrenRequest(
				selected.rootRef,
				ReadBudget(150, 4_096, 2_000),
				context,
			),
		)
		projection = selected.projection
		assert projection is not None
		after = (
			id(api.getFocusObject()),
			id(api.getNavigatorObject()),
			id(handler.clientObject),
			id(handler.baseTreeWalker),
		)
		return {
			"runtime": "available",
			"requested": projection.requested,
			"applied": projection.applied,
			"status": projection.status.value,
			"reasonCode": projection.reasonCode,
			"selectedFallbackUsed": not projection.applied and selected.rootRef == selected.originalRootRef,
			"childrenStatus": children.status,
			"completenessClaimed": projection.completenessClaimed,
			"focusUnchanged": before[0] == after[0],
			"navigatorUnchanged": before[1] == after[1],
			"clientUnchanged": before[2] == after[2],
			"rawWalkerUnchanged": before[3] == after[3],
		}
	finally:
		_ = session.closeSession(ProviderSessionCloseRequest(context))


def _customObservation() -> dict[str, object]:
	"""Exercise installed polling entry points without emitting values or claiming Office support."""
	source = NvdaSelectedObjectSource()
	target = source.selectedObject("foreground")
	appModule = target.__getattribute__("appModule")
	appName = str(appModule.__getattribute__("appName")).casefold()
	try:
		element = target.__getattribute__("UIAElement")
	except Exception:
		return {
			"runtime": "available",
			"propertyPolling": "unsupported",
			"patternPolling": "unsupported",
			"officeTargetDetected": appName in {"excel", "powerpnt", "winword"},
			"valuesEmitted": False,
			"patternInterfaceObtained": False,
		}
	getter = NvdaCustomUiaGetter()
	properties = getter.pollPotentialProperties(element)
	patterns = getter.pollPotentialPatterns(element)
	return {
		"runtime": "available",
		"propertyPolling": properties.status,
		"patternPolling": patterns.status,
		"officeTargetDetected": appName in {"excel", "powerpnt", "winword"},
		"valuesEmitted": False,
		"patternInterfaceObtained": False,
	}


def _runtimeScreenshot(outputDirectory: Path) -> tuple[str, int]:
	wx = import_module("wx")
	outputDirectory.mkdir(parents=True, exist_ok=True)
	backend = WxScreenshotBackend(cast(WxModule, wx), outputDirectory)
	desktop = backend.virtualDesktop()
	width = min(32, desktop.width)
	height = min(32, desktop.height)
	context = CorrelationFactory().admit(generation=1)
	attempt = ScreenshotAttempt(
		"installed-runtime",
		1,
		ScreenshotTarget(
			"containingForeground",
			"runtime-desktop",
			(desktop.left, desktop.top, width, height),
		),
		context,
	)
	result = ScreenshotAdapter(
		backend,
		enabled=True,
		clock=lambda: "installed-runtime",
	).captureScreenshot(attempt)
	image = bytes(result.image or b"")
	temporary, destination = backend.paths(attempt)
	backend.discard(temporary)
	backend.discard(destination)
	return result.status, len(image)


def _plainPairs(value: object) -> dict[str, object]:
	if not isinstance(value, tuple):
		return {}
	pairs: dict[str, object] = {}
	for item in value:
		if not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str):
			continue
		pairs[item[0]] = item[1]
	return pairs


def _runtimeRawProjection() -> dict[str, object]:
	"""Exercise explicit raw projection and its ordinary UIA evidence without moving selection."""

	session = SelectedObjectSession(NvdaSelectedObjectSource(), generation=1)
	context = CorrelationFactory().admit(generation=1)
	try:
		selected = session.acquire(
			"focus",
			rawRequest=ProjectionRequest.explicit(
				"installed-runtime-raw",
				ProjectionBudget(16, 128, 1_000),
			),
		)
		evidence = selected.projection
		metadata = session.readMetadata(
			ProviderMetadataRequest(
				selected.rootRef,
				"providerSections",
				ReadBudget(128, 4_096, 1_000),
				context,
			),
		)
		rawSection = providerSectionDatums(metadata.value, "rawUia") if metadata.status == "value" else None
		uiaSection = providerSectionDatums(metadata.value, "uia") if metadata.status == "value" else None
		rawDatums = rawSection[1] if rawSection is not None else ()
		projectionResult = next((result for fieldId, result in rawDatums if fieldId == "projection"), None)
		projection = (
			_plainPairs(projectionResult.value)
			if projectionResult is not None and projectionResult.status == "value"
			else {}
		)
		quality = str(projection.get("evidenceQuality", ""))
		requiredProjectionFields = {
			"requested",
			"applied",
			"status",
			"method",
			"reasonCode",
			"evidenceQuality",
		}
		evidencePresent = evidence is not None and requiredProjectionFields.issubset(projection)
		return {
			"rawProjectionRequested": bool(evidence is not None and evidence.requested),
			"rawProjectionApplied": bool(evidence is not None and evidence.applied),
			"rawProjectionStatus": "" if evidence is None else evidence.status.value,
			"rawProjectionMethod": "" if evidence is None else evidence.method.value,
			"rawProjectionReason": "" if evidence is None else evidence.reasonCode,
			"rawProjectionEvidenceQuality": quality,
			"rawProjectionEvidencePresent": evidencePresent,
			"ordinaryUiaSectionPresent": uiaSection is not None,
		}
	finally:
		_ = session.closeSession(ProviderSessionCloseRequest(context))


def _loadedModuleEvidence() -> dict[str, object]:
	"""Report the exact Keystone source files imported by this NVDA process."""

	modules = {
		"reviewHook": Path(__file__).resolve(),
		"rawUia": Path(str(import_module(RawUiaAdapter.__module__).__file__)).resolve(),
		"selectedObjects": Path(str(import_module(SelectedObjectSession.__module__).__file__)).resolve(),
	}
	hashes: dict[str, str] = {}
	identifier = hashlib.sha256()
	for name, path in sorted(modules.items()):
		digest = hashlib.sha256(path.read_bytes()).hexdigest()
		hashes[name] = digest
		identifier.update(name.encode("utf-8"))
		identifier.update(b"\0")
		identifier.update(bytes.fromhex(digest))
	return {
		"hostProcessId": os.getpid(),
		"loadedCodeIdentifier": f"sha256:{identifier.hexdigest()}",
		"reviewHookModulePath": str(modules["reviewHook"]),
		"reviewHookModuleSha256": hashes["reviewHook"],
		"rawUiaModulePath": str(modules["rawUia"]),
		"rawUiaModuleSha256": hashes["rawUia"],
		"selectedObjectsModulePath": str(modules["selectedObjects"]),
		"selectedObjectsModuleSha256": hashes["selectedObjects"],
	}


def runAutomatedRuntimeReview(
	outputPath: Path,
	*,
	enabledCapabilities: frozenset[str],
	inspectorRawRetarget: dict[str, object],
) -> dict[str, object]:
	"""Publish objective runtime capability and screenshot evidence without opening a user interface."""

	screenshotStatus, screenshotBytes = _runtimeScreenshot(outputPath.parent / "runtime-screenshot")
	rawProjection = _runtimeRawProjection()
	moduleEvidence = _loadedModuleEvidence()
	sourceGeneration = inspectorRawRetarget.get("sourceGeneration")
	inspectorRetargetObserved = bool(
		inspectorRawRetarget.get("succeeded") and inspectorRawRetarget.get("requested"),
	)
	ready = (
		screenshotStatus == "value"
		and screenshotBytes > 8
		and bool(rawProjection["rawProjectionEvidencePresent"])
		and bool(rawProjection["ordinaryUiaSectionPresent"])
		and inspectorRetargetObserved
	)
	payload: dict[str, object] = {
		"status": "pass" if ready else "failed",
		"enabledCapabilities": sorted(enabledCapabilities),
		"screenshotStatus": screenshotStatus,
		"screenshotBytes": screenshotBytes,
		"inspectorRawRetargetSucceeded": bool(inspectorRawRetarget.get("succeeded")),
		"inspectorRawRetargetRequested": bool(inspectorRawRetarget.get("requested")),
		"inspectorRawRetargetApplied": bool(inspectorRawRetarget.get("applied")),
		"inspectorRawRetargetSourceGeneration": sourceGeneration if type(sourceGeneration) is int else 0,
		**rawProjection,
		**moduleEvidence,
	}
	outputPath.parent.mkdir(parents=True, exist_ok=True)
	temporary = outputPath.with_suffix(".tmp")
	_ = temporary.write_text(
		json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
		encoding="utf-8",
		newline="\n",
	)
	_ = temporary.replace(outputPath)
	return payload


def runPackagedReview(
	outputPath: Path,
	*,
	openInspector: Callable[[], None],
) -> dict[str, object]:
	before = _targetState()

	def observed(call: Callable[[], dict[str, object]]) -> dict[str, object]:
		try:
			return call()
		except Exception:
			return {"runtime": "available", "status": "failed"}

	provider = observed(_providerObservation)
	custom = observed(_customObservation)
	raw = observed(_rawObservation)
	after = _targetState()
	targetUnchanged = {
		"focus": before["focusIdentity"] == after["focusIdentity"],
		"navigator": before["navigatorIdentity"] == after["navigatorIdentity"],
		"value": (
			before["valueAvailable"] == after["valueAvailable"]
			and before["valueDigest"] == after["valueDigest"]
		),
		"selection": (
			before["selectionAvailable"] == after["selectionAvailable"]
			and before["selectionDigest"] == after["selectionDigest"]
		),
	}
	payload: dict[str, object] = {
		"schema": "keystone.installedReview.v1",
		"pythonExecutable": cast(str, import_module("sys").executable),
		"commands": [
			{
				"key": definition.key,
				"label": definition.label,
			}
			for definition in COMMAND_DEFINITIONS
		],
		"provider": provider,
		"customUia": custom,
		"rawUia": raw,
		"targetUnchanged": targetUnchanged,
	}
	outputPath.parent.mkdir(parents=True, exist_ok=True)
	temporary = outputPath.with_suffix(".tmp")
	_ = temporary.write_text(
		json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
		encoding="utf-8",
		newline="\n",
	)
	_ = temporary.replace(outputPath)
	openInspector()
	return payload
