"""One installed Inspector, event, audio, and settings review runner.

This runner uses the single ``keystone`` archive already installed in the user's current, backed-up
primary NVDA profile and prints one informational build identifier. It checks event monitoring, raw
UIA inspection, screenshot capture, audio feedback, and the settings interface through their direct
runtime prerequisites, without replacing the loaded add-on tree. It then reruns every live host seam
as a blocking automated check: a wx accessibility/destruction round-trip, the bounded focus-match
ladder, the shipped raw-UIA subscription, the asynchronous audio seam, and -- authoritatively -- the
installed production event-source observation driven through ``ProductionComposition`` with the
shipped ``RawUiaEventSource`` and ``NvdaEventSource``. Finally it presents a linear, keyboard- and
screen-reader-first human checklist and only reports a pass once every automated seam is clean and a
human has explicitly approved. The exact tested archive is left installed afterwards.

Nothing here is faked: every metric is measured against fixed safety budgets, and
the installed production observation is delegated to
:func:`tests.live.probe_installed_event_sources.runInstalledEventSourceObservation` so neither a
standalone seam diagnostic nor a strict fake can stand in for the packaged production path. Any
unavailable, skipped, missing, malformed, unsafe, late, over-budget, or unapproved outcome exits
nonzero and blocks phase completion; a safe runtime fallback is never completion evidence.

Exit codes: 0 pass; 2 unavailable/skipped/missing input or observation; 3 malformed/failed/unsafe/
over-budget observation; 4 teardown or late-callback mutation; 5 incomplete or rejected human review.
The module performs no host, COM, wx, or audio work at import time, so the contract tests can import
:func:`evaluate`, :func:`buildReviewScenarios`, and the result type without a host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field, fields
from importlib import import_module
from pathlib import Path
from typing import Any, cast, get_args
from zipfile import ZipFile

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
	sys.path.insert(0, str(_REPO_ROOT))

# Fixed budgets, families, and exit categories are reused unchanged from the standalone seam probes; they
# are constants here as well and are never inferred from the judged run.
from tests.live import probe_installed_event_sources as installedProbe  # noqa: E402
from tests.live import probe_raw_uia_subscription as uiaProbe  # noqa: E402
from tests.live import probe_sound_playback as soundProbe  # noqa: E402

RESULT_PREFIX = "KEYSTONE_INSPECTOR_REVIEW_RESULT="
BUILD_PREFIX = "KEYSTONE_INSPECTOR_REVIEW_BUILD="
SOUND_THEME_SPEC = _REPO_ROOT / "tests" / "fixtures" / "sound_theme.json"

EXIT_PASS = 0
EXIT_UNAVAILABLE = 2
EXIT_FAILED = 3
EXIT_TEARDOWN = 4
EXIT_HUMAN = 5

# Fixed budgets (milliseconds). Constants, never derived from the judged run.
WX_CALLBACK_MAX_MS = 50.0
RAW_CALLBACK_MAX_MS = uiaProbe.CALLBACK_MAX_MS
FORWARDING_MAX_MS = uiaProbe.FORWARDING_MAX_MS
BURST100_MAX_MS = uiaProbe.BURST100_MAX_MS
RECEIPT_TO_PROCESSING_MAX_MS = uiaProbe.RECEIPT_TO_PROCESSING_MAX_MS
RECEIPT_TO_PROPERTY_READ_MAX_MS = uiaProbe.RECEIPT_TO_PROPERTY_READ_MAX_MS
SOUND_DISPATCH_MAX_MS = soundProbe.DISPATCH_MAX_MS
SPEECH_SUBMIT_MAX_MS = soundProbe.SPEECH_SUBMIT_MAX_MS
REPLACEMENT_START_MAX_MS = soundProbe.REPLACEMENT_START_MAX_MS
INTER_ATOM_GAP_MIN_MS = soundProbe.INTER_ATOM_GAP_MIN_MS
INTER_ATOM_GAP_MAX_MS = soundProbe.INTER_ATOM_GAP_MAX_MS
OBSERVATION_WINDOW_MS = uiaProbe.OBSERVATION_WINDOW_MS

# Fixed focus-match budgets from the capture limit registry (150 nodes / depth 40).
FOCUS_MATCH_NODES_MAX = 150
FOCUS_MATCH_DEPTH_MAX = 40

REQUIRED_CAPABILITIES = frozenset(
	("eventMonitoring", "rawUiaInspection", "screenCapture", "audioFeedback", "userInterface"),
)

# The three manual verification gates superseded by current STATE; they must never be presented.
EXCLUDED_MANUAL_GATES = ("high contrast", "display scaling", "display-scaling", "visual reflow")

HUMAN_CHECKLIST_CHOICES = ("pending", "approved", "rejected")


@dataclass(frozen=True, slots=True)
class ReviewScenario:
	"""One linear, keyboard- and screen-reader-first human review prompt."""

	scenarioId: str
	category: str
	title: str
	prompt: str


def buildReviewScenarios() -> tuple[ReviewScenario, ...]:
	"""The fixed linear checklist a human walks with keyboard and NVDA only.

	Every prompt is direct-manipulation, keyboard-first, and screen-reader-first. High Contrast,
	display-scaling, and visual-reflow gates are deliberately omitted per current STATE; the retained
	gates still cover keyboard-only operation, native control semantics, English long strings, system
	theme/font inheritance, and sighted usability.
	"""

	return (
		ReviewScenario(
			"notepad-menu-target",
			"screen-reader",
			"Notepad menu target and hierarchy",
			"Focus a Notepad File-menu item, open Focus Inspector, and confirm the exact menu item is "
			+ "selected with a traversable containing hierarchy and no duplicate speech.",
		),
		ReviewScenario(
			"firefox-target",
			"screen-reader",
			"Firefox exact target",
			"Focus a Firefox control, open Focus Inspector, and confirm the focused control rather "
			+ "than the browser root is selected and announced.",
		),
		ReviewScenario(
			"all-properties-keyboard",
			"screen-reader",
			"Property category and keyboard access",
			"Open each Property category, copy a selected row or UIA subtree, and confirm selection "
			+ "stays put while native Tab and Shift+Tab remain usable.",
		),
		ReviewScenario(
			"loaded-only-search",
			"keyboard",
			"Loaded-only search",
			"Press Ctrl+F from the hierarchy, confirm native Find opens, and use F3 and Shift+F3 "
			+ "without loading hidden branches.",
		),
		ReviewScenario(
			"retarget-follow-focus",
			"keyboard",
			"Retarget and Follow Focus",
			"Use Retarget to Focus and Retarget to Navigator, then enable Follow Focus within one "
			+ "application. Confirm target, category, selection, and keyboard focus remain coherent.",
		),
		ReviewScenario(
			"raw-uia-evidence",
			"screen-reader",
			"Explicit raw UIA evidence",
			"Enable raw UIA retargeting and confirm native, proxy, unavailable, or fallback evidence "
			+ "is stated explicitly while ordinary UIA properties remain available.",
		),
		ReviewScenario(
			"event-start-stop",
			"screen-reader",
			"Event monitoring start, stop, and live rows",
			"Open Event Monitor, confirm Start Monitoring is first, activate it to start and stop, and "
			+ "confirm new events appear without moving the current list selection or focus.",
		),
		ReviewScenario(
			"event-filter-dialog",
			"screen-reader",
			"Event Filter dialog",
			"Open Event Filter, traverse both named checkbox lists, use Defaults, Select All, and Clear, "
			+ "confirm zero selections are rejected, then apply a filter without changing retained rows.",
		),
		ReviewScenario(
			"event-four-scopes",
			"screen-reader",
			"Four event monitoring scopes",
			"Start and stop Selected element, Selected subtree, Application, and warned Broad scope in "
			+ "that order. Confirm each scope is announced and subtree admits a newly created descendant.",
		),
		ReviewScenario(
			"annotations",
			"screen-reader",
			"Annotations and target navigation",
			"Select an annotation row, use Alt+T or its context-menu action, and confirm no-data, stale, "
			+ "and target-navigation states are announced.",
		),
		ReviewScenario(
			"event-export-clear-reopen",
			"screen-reader",
			"Event export, clear, and reopen",
			"Select an event, inspect details, export it, cancel and confirm Clear, then close and reopen "
			+ "Events. Confirm retained rows and selection survive until a confirmed clear.",
		),
		ReviewScenario(
			"feature-discoverability",
			"screen-reader",
			"Feature names and shortcuts",
			"Confirm Event Monitor, Custom UIA Properties, every tree and list, source identity, and the "
			+ "documented Ctrl+I, Ctrl+E, Ctrl+F, F3, copy, and retarget actions are named.",
		),
		ReviewScenario(
			"snapshot-screenshot",
			"screen-reader",
			"Snapshot screenshot capture",
			"Capture a Snapshot of the foreground window and confirm NVDA reports screenshot success, "
			+ "the published bundle contains a current PNG for that window, and no earlier image is "
			+ "reused after a failed attempt.",
		),
		ReviewScenario(
			"secure-teardown",
			"keyboard",
			"Secure teardown and reopen",
			"Trigger a secure-desktop transition, confirm the workspace tears down with no residual "
			+ "speech or sound, then reopen and confirm it is usable again from the keyboard.",
		),
		ReviewScenario(
			"speech-sound-disabled",
			"screen-reader",
			"Complete speech with sound disabled or failed",
			"Disable optional sound and then simulate a sound failure, and confirm every cue is still "
			+ "fully conveyed by speech alone with no missing information.",
		),
		ReviewScenario(
			"build-output",
			"build",
			"Built archive",
			"Confirm the reviewed archive is the single current .nvda-addon under dist and the installed "
			+ "Keystone commands remain available after the required NVDA restart.",
		),
		ReviewScenario(
			"documentation",
			"documentation",
			"Documentation",
			"Confirm the shipped documentation describes the reviewed workflows accurately and is "
			+ "itself reachable and readable with the keyboard and NVDA.",
		),
		ReviewScenario(
			"workspace-usability",
			"usability",
			"End-to-end keyboard usability",
			"Complete one Inspector-to-Events-to-Inspector workflow without a mouse and confirm speech, "
			+ "focus order, status, and recovery remain understandable throughout.",
		),
	)


def _empty_observation() -> dict[str, object]:
	"""Typed default factory for the installed observation payload field."""

	return {}


@dataclass(slots=True)
class InstalledReviewResult:
	"""Everything the installed review measured. Field names match the emitted JSON keys."""

	unavailableObservations: tuple[str, ...] = ()
	skippedObservations: tuple[str, ...] = ()
	missingObservations: tuple[str, ...] = ()
	unsafeObservations: tuple[str, ...] = ()
	failedObservations: tuple[str, ...] = ()
	buildIdentifier: str = ""
	enabledCapabilities: tuple[str, ...] = ()
	archiveRemainsInstalled: bool = False
	wxCallbackMaxMs: float = 0.0
	focusMatchNodesMax: int = 0
	focusMatchDepthMax: int = 0
	rawUiaCallbackMaxMs: float = 0.0
	forwardingMaxMs: float = 0.0
	burst100MaxMs: float = 0.0
	receiptToProcessingMaxMs: float = 0.0
	receiptToPropertyReadMaxMs: float = 0.0
	soundDispatchMaxMs: float = 0.0
	speechSubmitMaxMs: float = 0.0
	replacementStartMaxMs: float = 0.0
	interAtomGapMinMs: float = 0.0
	interAtomGapMaxMs: float = 0.0
	lateCallbacksAccepted: int = 0
	subscriptionsAfterTeardown: int = 0
	callbacksObservedAfterTeardown: int = 0
	providerAccessesAfterTeardown: int = 0
	queuedSoundsAfterTeardown: int = 0
	soundsStartedAfterTeardown: int = 0
	staleAtomsStarted: int = 0
	screenshotStatus: str = ""
	screenshotBytes: int = 0
	eventFilterDialogPresent: bool = False
	annotationsTabPresent: bool = False
	scopeKindsExercised: tuple[str, ...] = ()
	rawEvidenceNativeProxyField: bool = False
	rawProjectionRequested: bool = False
	rawProjectionApplied: bool = False
	rawProjectionStatus: str = ""
	rawProjectionMethod: str = ""
	rawProjectionReason: str = ""
	rawProjectionEvidenceQuality: str = ""
	rawProjectionEvidencePresent: bool = False
	ordinaryUiaSectionPresent: bool = False
	inspectorRawRetargetSucceeded: bool = False
	inspectorRawRetargetRequested: bool = False
	inspectorRawRetargetApplied: bool = False
	inspectorRawRetargetSourceGeneration: int = 0
	hostProcessId: int = 0
	loadedCodeIdentifier: str = ""
	loadedCodeMatchesArchive: bool = False
	buildBatPublishedToDist: bool = False
	configSectionRegistered: bool = False
	installedTreeReady: bool = False
	retainedMutationsAfterTeardown: int = 0
	controlMutationsAfterTeardown: int = 0
	secureMutations: int = 0
	observationWindowMs: int = OBSERVATION_WINDOW_MS
	humanChecklistStatus: str = "pending"
	installedEventSourceObservation: dict[str, object] = field(default_factory=_empty_observation)


@dataclass(frozen=True, slots=True)
class ReviewResult:
	"""Judged verdict: a status string, a process exit code, and the emitted payload."""

	status: str
	exitCode: int
	payload: dict[str, object]


@dataclass(frozen=True, slots=True)
class _DelegatedProbeResult:
	status: str
	exitCode: int
	payload: dict[str, object]


def _runDelegatedProbe(
	script: Path,
	arguments: tuple[str, ...],
	*,
	resultPrefix: str,
) -> _DelegatedProbeResult:
	"""Run one host probe in a fresh interpreter so COM and NVDA globals cannot leak between probes."""

	try:
		completed = subprocess.run(
			[sys.executable, str(script), *arguments],
			cwd=_REPO_ROOT,
			check=False,
			capture_output=True,
			text=True,
			timeout=180,
		)
	except (OSError, subprocess.SubprocessError):
		return _DelegatedProbeResult("unavailable", EXIT_UNAVAILABLE, {})
	line = next(
		(
			candidate
			for candidate in reversed(completed.stdout.splitlines())
			if candidate.startswith(resultPrefix)
		),
		None,
	)
	if line is None:
		return _DelegatedProbeResult("unavailable", EXIT_UNAVAILABLE, {})
	try:
		payload = cast("dict[str, object]", json.loads(line[len(resultPrefix) :]))
	except (TypeError, ValueError):
		return _DelegatedProbeResult("failed", EXIT_FAILED, {})
	status = str(payload.get("status", "failed"))
	return _DelegatedProbeResult(status, completed.returncode, payload)


def _installed_observation_shipped(observation: dict[str, object]) -> bool:
	"""Return True only for a well-formed installed observation with shipped identities and state."""

	if not observation:
		return False
	required = {
		"rawSourceType": installedProbe.EXPECTED_RAW_SOURCE_TYPE,
		"nvdaSourceType": installedProbe.EXPECTED_NVDA_SOURCE_TYPE,
	}
	for key, expected in required.items():
		if str(observation.get(key, "")) != expected:
			return False
	if not str(observation.get("rawSourceModule", "")).endswith(installedProbe.RAW_SOURCE_MODULE_SUFFIX):
		return False
	if not str(observation.get("nvdaSourceModule", "")).endswith(installedProbe.NVDA_SOURCE_MODULE_SUFFIX):
		return False
	return bool(
		observation.get("productionCompositionStarted")
		and observation.get("monitorStarted")
		and observation.get("monitorStopped"),
	)


def _evaluate(
	result: InstalledReviewResult,
	*,
	requireHuman: bool,
) -> ReviewResult:  # noqa: C901 - one linear exit matrix
	"""Judge the review against the fixed budgets, the identity/enablement contract, and the matrix.

	Precedence: an observation we could not establish (exit 2) outranks a teardown or late-callback
	breach (exit 4), which outranks any failed, unsafe, or over-budget reading (exit 3), which
	outranks an incomplete or rejected human review (exit 5). Only a fully clean, fully enabled,
	human-approved run is a pass (exit 0).
	"""

	payload: dict[str, object] = {"status": "pass"}
	for descriptor in fields(InstalledReviewResult):
		value: object = getattr(result, descriptor.name)
		if isinstance(value, tuple):
			payload[descriptor.name] = list(cast("tuple[object, ...]", value))
		elif isinstance(value, float):
			payload[descriptor.name] = round(value, 3)
		else:
			payload[descriptor.name] = value

	installed: dict[str, Any] = cast("dict[str, Any]", result.installedEventSourceObservation)
	installed_status = str(installed.get("status", "")) if installed else ""

	# Level 2: anything we could not establish, at either the review or installed-observation level.
	if (
		result.unavailableObservations
		or result.skippedObservations
		or result.missingObservations
		or installed_status in ("unavailable", "")
		or list(installed.get("unavailableObservations", []))
		or list(installed.get("skippedObservations", []))
		or list(installed.get("missingObservations", []))
	):
		payload["status"] = "unavailable"
		return ReviewResult("unavailable", EXIT_UNAVAILABLE, payload)

	teardown_breach = (
		result.lateCallbacksAccepted != 0
		or result.subscriptionsAfterTeardown != 0
		or result.callbacksObservedAfterTeardown != 0
		or result.providerAccessesAfterTeardown != 0
		or result.queuedSoundsAfterTeardown != 0
		or result.soundsStartedAfterTeardown != 0
		or result.staleAtomsStarted != 0
		or result.retainedMutationsAfterTeardown != 0
		or result.controlMutationsAfterTeardown != 0
		or result.secureMutations != 0
		or int(installed.get("callbacksObservedAfterTeardown", 0)) != 0
		or int(installed.get("providerAccessesAfterTeardown", 0)) != 0
		or int(installed.get("subscriptionsAfterTeardown", 0)) != 0
		or int(installed.get("retainedMutationsAfterTeardown", 0)) != 0
		or int(installed.get("lateCallbacksAccepted", 0)) != 0
		or int(installed.get("secureMutations", 0)) != 0
	)
	if teardown_breach:
		payload["status"] = "unsafe"
		return ReviewResult("unsafe", EXIT_TEARDOWN, payload)

	over_budget = (
		result.wxCallbackMaxMs > WX_CALLBACK_MAX_MS
		or result.rawUiaCallbackMaxMs > RAW_CALLBACK_MAX_MS
		or result.forwardingMaxMs > FORWARDING_MAX_MS
		or result.burst100MaxMs > BURST100_MAX_MS
		or result.receiptToProcessingMaxMs > RECEIPT_TO_PROCESSING_MAX_MS
		or result.receiptToPropertyReadMaxMs > RECEIPT_TO_PROPERTY_READ_MAX_MS
		or result.soundDispatchMaxMs > SOUND_DISPATCH_MAX_MS
		or result.speechSubmitMaxMs > SPEECH_SUBMIT_MAX_MS
		or result.replacementStartMaxMs > REPLACEMENT_START_MAX_MS
		or result.interAtomGapMinMs < INTER_ATOM_GAP_MIN_MS
		or result.interAtomGapMaxMs > INTER_ATOM_GAP_MAX_MS
		or result.focusMatchNodesMax > FOCUS_MATCH_NODES_MAX
		or result.focusMatchDepthMax > FOCUS_MATCH_DEPTH_MAX
		or result.screenshotStatus != "value"
		or result.screenshotBytes <= 8
	)
	enablement_ok = (
		REQUIRED_CAPABILITIES.issubset(set(result.enabledCapabilities))
		and result.archiveRemainsInstalled
		and result.configSectionRegistered
		and result.installedTreeReady
	)
	rawProjectionOk = (
		result.rawProjectionRequested
		and result.rawProjectionEvidencePresent
		and result.ordinaryUiaSectionPresent
		and result.rawProjectionStatus in {"applied", "degraded", "rejected"}
		and bool(result.rawProjectionMethod)
		and bool(result.rawProjectionReason)
		and result.rawProjectionEvidenceQuality in {"native", "synthesizedProxy", "incomplete"}
		and (
			(
				result.rawProjectionApplied
				and result.rawProjectionStatus == "applied"
				and result.rawProjectionEvidenceQuality == "native"
			)
			or (not result.rawProjectionApplied and result.rawProjectionStatus in {"degraded", "rejected"})
		)
	)
	loadedCodeOk = (
		result.hostProcessId > 0
		and result.loadedCodeIdentifier.startswith("sha256:")
		and len(result.loadedCodeIdentifier) == 71
		and result.loadedCodeMatchesArchive
	)
	inspectorRawRetargetOk = (
		result.inspectorRawRetargetSucceeded
		and result.inspectorRawRetargetRequested
		and result.inspectorRawRetargetSourceGeneration > 0
	)
	unsafe = (
		bool(result.unsafeObservations)
		or bool(result.failedObservations)
		or installed_status not in ("observed", "pass")
		or not _installed_observation_shipped(installed)
		or result.observationWindowMs != OBSERVATION_WINDOW_MS
		or not result.eventFilterDialogPresent
		or not result.annotationsTabPresent
		or set(result.scopeKindsExercised) != {"element", "subtree", "application", "broad"}
		or not result.rawEvidenceNativeProxyField
		or not rawProjectionOk
		or not loadedCodeOk
		or not inspectorRawRetargetOk
		or not result.buildBatPublishedToDist
		or not enablement_ok
	)
	if over_budget or unsafe:
		payload["status"] = "failed"
		return ReviewResult("failed", EXIT_FAILED, payload)

	if requireHuman and result.humanChecklistStatus != "approved":
		payload["status"] = "incomplete-human-review"
		return ReviewResult("incomplete-human-review", EXIT_HUMAN, payload)

	status = "pass" if requireHuman else "ready-for-human"
	payload["status"] = status
	return ReviewResult(status, EXIT_PASS, payload)


def evaluate(result: InstalledReviewResult) -> ReviewResult:
	return _evaluate(result, requireHuman=True)


def evaluateAutomated(result: InstalledReviewResult) -> ReviewResult:
	"""Judge every objective observation while leaving human checklist status untouched."""

	return _evaluate(result, requireHuman=False)


def resolveBuiltArchive(path: Path) -> Path:
	"""Resolve either an explicit archive or a directory containing exactly one archive."""

	candidate = path.resolve()
	if candidate.is_file():
		return candidate
	if not candidate.is_dir():
		raise ValueError(f"build output does not exist: {candidate}")
	archives = tuple(sorted(candidate.glob("*.nvda-addon")))
	if len(archives) != 1:
		raise ValueError("build output must contain exactly one .nvda-addon archive")
	return archives[0]


def _buildIdentifier(archive: Path) -> str:
	digest = hashlib.sha256()
	with archive.open("rb") as stream:
		while chunk := stream.read(1024 * 1024):
			digest.update(chunk)
	return f"sha256:{digest.hexdigest()}"


_LOADED_MODULE_MEMBERS = {
	"reviewHook": "globalPlugins/keystone/adapters/nvda/review_hook.py",
	"rawUia": "globalPlugins/keystone/adapters/providers/raw_uia.py",
	"selectedObjects": "globalPlugins/keystone/adapters/nvda/selected_objects.py",
}


def _loadedCodeMatchesArchive(runtime: dict[str, Any], archive: Path, installedRoot: Path) -> bool:
	try:
		with ZipFile(archive) as bundle:
			for name, member in _LOADED_MODULE_MEMBERS.items():
				modulePath = Path(str(runtime[f"{name}ModulePath"])).resolve()
				if installedRoot.resolve() not in modulePath.parents:
					return False
				if not modulePath.as_posix().casefold().endswith(member.casefold()):
					return False
				loadedHash = str(runtime[f"{name}ModuleSha256"])
				archiveHash = hashlib.sha256(bundle.read(member)).hexdigest()
				if loadedHash != archiveHash:
					return False
	except (KeyError, OSError, ValueError):
		return False
	return True


def _wxApplication(wx: Any) -> Any:
	existing = wx.GetApp()
	return existing if existing is not None else wx.App()


def _typeAliasValues(alias: object) -> set[object]:
	return set(get_args(getattr(alias, "__value__", alias)))


def _collectProductContracts() -> dict[str, Any]:
	"""Inspect the installed package's event-filter, annotation, and raw-evidence contracts."""

	try:
		frameModule = cast("Any", import_module("keystone.adapters.wx.inspector_frame"))
		eventMonitor = cast("Any", import_module("keystone.domain.event_monitor"))
		rawUia = cast("Any", import_module("keystone.adapters.providers.raw_uia"))
	except Exception as error:  # noqa: BLE001 - required installed modules must all import
		return {
			"unavailable": (f"installed workspace contracts unavailable: {type(error).__name__}: {error}",),
		}

	try:
		eventChoices = tuple(eventMonitor.eventFilterChoices())
		eventFilterPresent = callable(getattr(frameModule, "EventFilterDialog", None)) and len(
			eventChoices,
		) == len(tuple(eventMonitor.NVDA_EVENT_TYPES)) + len(tuple(eventMonitor.RAW_UIA_FAMILIES))
		definition = frameModule.InspectorWorkspaceDefinition()
		annotationsPresent = (
			frameModule.pgettext(
				"inspector property category",
				"Annotations",
			)
			in definition.tabNames
		)
		qualityValues = _typeAliasValues(rawUia.RawEvidenceQuality)
		outcomeFields = {field.name for field in fields(rawUia.RawProjectionOutcome)}
		rawEvidenceField = {"native", "synthesizedProxy"}.issubset(qualityValues) and (
			"evidenceQuality" in outcomeFields
		)
	except Exception as error:  # noqa: BLE001 - malformed installed contracts fail explicitly
		return {"failed": (f"installed workspace contracts malformed: {type(error).__name__}: {error}",)}
	return {
		"eventFilterDialogPresent": eventFilterPresent,
		"annotationsTabPresent": annotationsPresent,
		"rawEvidenceNativeProxyField": rawEvidenceField,
	}


def _reviewCapabilities(
	installed: dict[str, Any],
	*,
	runtime: dict[str, Any] | None = None,
	soundReady: bool,
	screenshotReady: bool,
	userInterfaceReady: bool,
) -> tuple[str, ...]:
	"""Combine each independently observed runtime prerequisite into one capability list."""

	enabled = {str(value) for value in installed.get("enabledCapabilities", ())}
	if runtime is not None:
		enabled.update(str(value) for value in runtime.get("enabledCapabilities", ()))
	if soundReady:
		enabled.add("audioFeedback")
	if screenshotReady:
		enabled.add("screenCapture")
	if userInterfaceReady:
		enabled.add("userInterface")
	return tuple(sorted(enabled))


def _loadRuntimeResult(path: Path) -> dict[str, Any]:
	try:
		payload = json.loads(path.read_text(encoding="utf-8"))
	except (OSError, ValueError):
		return {}
	if not isinstance(payload, dict):
		return {}
	result = cast("dict[str, Any]", payload)
	required = {
		"status",
		"enabledCapabilities",
		"screenshotStatus",
		"screenshotBytes",
		"rawProjectionRequested",
		"rawProjectionApplied",
		"rawProjectionStatus",
		"rawProjectionMethod",
		"rawProjectionReason",
		"rawProjectionEvidenceQuality",
		"rawProjectionEvidencePresent",
		"ordinaryUiaSectionPresent",
		"inspectorRawRetargetSucceeded",
		"inspectorRawRetargetRequested",
		"inspectorRawRetargetApplied",
		"inspectorRawRetargetSourceGeneration",
		"hostProcessId",
		"loadedCodeIdentifier",
		"reviewHookModulePath",
		"reviewHookModuleSha256",
		"rawUiaModulePath",
		"rawUiaModuleSha256",
		"selectedObjectsModulePath",
		"selectedObjectsModuleSha256",
	}
	return result if required.issubset(result) else {}


def _collect_wx() -> dict[str, Any]:
	"""Measure one live wx accessibility/destruction callback round-trip and a clean teardown.

	Uses the installed NVDA wx build. A real button command event is posted and its handler latency
	recorded; the frame is then destroyed and any control interaction after destruction is counted as
	a teardown mutation. If wx cannot initialise, the observation is reported unavailable, never a
	silent pass.
	"""

	try:
		wx = cast("Any", import_module("wx"))
	except Exception as error:  # noqa: BLE001 - a missing display/toolkit is unavailable, not a pass
		return {"unavailable": (f"wx toolkit unavailable: {type(error).__name__}: {error}",)}

	app = _wxApplication(wx)
	frame = wx.Frame(None, title="Keystone review probe")
	callback_times: list[float] = []
	post_time = 0.0

	def _handler(_event: Any) -> None:
		callback_times.append((time.perf_counter() - post_time) * 1000.0)

	button = wx.Button(frame, label="ok")
	button.Bind(wx.EVT_BUTTON, _handler)
	frame.Show(False)
	post_time = time.perf_counter()
	post_event = wx.CommandEvent(wx.wxEVT_COMMAND_BUTTON_CLICKED, button.GetId())
	post_event.SetEventObject(button)
	wx.PostEvent(button.GetEventHandler(), post_event)
	app.Yield()
	wx_callback_max = max(callback_times, default=0.0)
	frame.Destroy()
	app.Yield()

	control_mutations = 0
	try:
		# The control is destroyed; any successful mutation of it is a teardown breach.
		button.SetLabel("post-teardown")
		control_mutations += 1
	except Exception:  # noqa: BLE001 - the expected, safe outcome is that the control is gone
		control_mutations = 0
	return {
		"wxCallbackMaxMs": float(wx_callback_max),
		"controlMutationsAfterTeardown": control_mutations,
		"destroyedCleanly": control_mutations == 0,
	}


def _collect_focus() -> dict[str, Any]:
	"""Run the shipped focus matcher over a bounded ladder and report its budget usage.

	Drives the production ``matchInspectorTarget`` under the fixed 150-node / depth-40 limits with a
	single positively-identified target so the retarget/Follow Focus path resolves exactly one match
	while staying inside budget. Any failure to reach the shipped matcher is reported unavailable.
	"""

	try:
		inspector = cast("Any", import_module("keystone.domain.inspector"))
	except Exception as error:  # noqa: BLE001 - the shipped matcher must be importable, else unavailable
		return {"unavailable": (f"shipped focus matcher unavailable: {type(error).__name__}: {error}",)}

	limits = inspector.focusMatchLimits()
	target_depth = 12
	candidates = (
		inspector.FocusMatchCandidate(
			"target",
			target_depth,
			inspector.FocusMatchEvidence(pythonIdentity=True),
		),
	)
	result = inspector.matchInspectorTarget(candidates, limits=limits)
	if str(result.decision) != "matched" or str(result.candidateId) != "target":
		return {"failed": (f"focus match did not resolve the identified target: {result.reasonCode}",)}
	return {
		"focusMatchNodesMax": int(result.visitedNodes),
		"focusMatchDepthMax": target_depth,
	}


def _collect_screenshot(workspace: Path) -> dict[str, Any]:
	"""Capture and discard one current 32-by-32 composited desktop PNG through the shipped backend."""

	try:
		wx = cast("Any", import_module("wx"))
		screenshot = cast("Any", import_module("keystone.adapters.windows.screenshot"))
		effects = cast("Any", import_module("keystone.ports.effects"))
		correlation = cast("Any", import_module("keystone.domain.correlation"))
	except Exception as error:  # noqa: BLE001 - an unavailable host capture seam cannot enable the gate
		return {"unavailable": (f"screenshot runtime unavailable: {type(error).__name__}: {error}",)}

	try:
		_ = _wxApplication(wx)
		destination = (workspace / "screenshot-runtime").resolve()
		destination.mkdir(parents=True, exist_ok=True)
		backend = screenshot.WxScreenshotBackend(wx, destination)
		desktop = backend.virtualDesktop()
		width = min(32, int(desktop.width))
		height = min(32, int(desktop.height))
		context = correlation.CorrelationFactory().admit(generation=1)
		attempt = effects.ScreenshotAttempt(
			"installed-review",
			1,
			effects.ScreenshotTarget(
				"containingForeground",
				"review-desktop",
				(int(desktop.left), int(desktop.top), width, height),
			),
			context,
		)
		result = screenshot.ScreenshotAdapter(
			backend,
			enabled=True,
			clock=lambda: "installed-review",
		).captureScreenshot(attempt)
	except Exception as error:  # noqa: BLE001 - a host capture failure is explicit review failure
		return {"failed": (f"screenshot capture failed: {type(error).__name__}: {error}",)}
	image = bytes(result.image or b"")
	if result.status != "value" or not image.startswith(b"\x89PNG\r\n\x1a\n"):
		return {
			"failed": (f"screenshot capture returned {result.status}: {result.errorCode}",),
			"screenshotStatus": str(result.status),
			"screenshotBytes": len(image),
		}
	return {
		"screenshotStatus": "value",
		"screenshotBytes": len(image),
	}


def runInstalledReview(  # noqa: C901 - one linear installed review with guarded legs
	archive: Path,
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
	*,
	humanChecklistResponse: str = "pending",
	runtimeResult: Path | None = None,
) -> InstalledReviewResult:
	"""Use the installed archive, rerun every objective seam, and gather the checklist state.

	Installation and restart happen once before this function. This function only verifies and uses the
	already-installed tree, so no running add-on directory is replaced during a probe. The installed
	production event-source observation is delegated to
	:func:`tests.live.probe_installed_event_sources.runInstalledEventSourceObservation`. Any acquisition
	failure is reported as an unavailable observation (exit 2); it is never converted into a pass.
	"""

	workspace.mkdir(parents=True, exist_ok=True)
	unavailable: list[str] = []
	if not archive.is_file():
		unavailable.append("built archive not found")
	if not nvda_executable.is_file():
		unavailable.append("NVDA executable not found")
	if not source_profile.is_dir():
		unavailable.append("primary NVDA profile not found")
	if unavailable:
		return InstalledReviewResult(
			unavailableObservations=tuple(unavailable),
			humanChecklistStatus=humanChecklistResponse,
		)

	# The installed, versioned NVDA runtime is made importable by the probe's own runtime
	# preparation (it declares the frozen layout so NVDA resolves its versioned libraries).
	installedProbe._prepare_runtime(nvda_executable)  # pyright: ignore[reportPrivateUsage]
	import gettext

	gettext.NullTranslations().install(names=["gettext", "ngettext", "pgettext", "npgettext"])

	unavailable_obs: list[str] = []
	skipped_obs: list[str] = []
	missing_obs: list[str] = []
	unsafe_obs: list[str] = []
	failed_obs: list[str] = []

	build_identifier = _buildIdentifier(archive)
	enabled_caps: tuple[str, ...] = ()
	archive_remains = False
	screenshot_obs: dict[str, Any] = {}
	runtime_obs: dict[str, Any] = {}
	installedRoot = source_profile / "addons" / "keystone"
	try:
		installedRoot = installedProbe._requireInstalledTree(  # pyright: ignore[reportPrivateUsage]
			source_profile,
		)
		installedProbe._initialize_nvda_config(  # pyright: ignore[reportPrivateUsage]
			source_profile,
			nvda_executable.resolve().parent,
		)
		_ = installedProbe._import_installed_keystone(  # pyright: ignore[reportPrivateUsage]
			installedRoot,
		)
		runtime_obs = _loadRuntimeResult(runtimeResult) if runtimeResult is not None else {}
		if runtimeResult is not None:
			if not runtime_obs:
				unavailable_obs.append("in-process runtime observation unavailable")
			else:
				screenshot_obs = {
					"screenshotStatus": str(runtime_obs.get("screenshotStatus", "")),
					"screenshotBytes": int(runtime_obs.get("screenshotBytes", 0)),
				}
				if runtime_obs.get("status") != "pass":
					failed_obs.append("in-process runtime observation failed")
		else:
			screenshot_obs = _collect_screenshot(workspace)
		unavailable_obs.extend(str(item) for item in screenshot_obs.get("unavailable", ()))
		failed_obs.extend(str(item) for item in screenshot_obs.get("failed", ()))
		archive_remains = (source_profile / "addons" / "keystone").is_dir()
	except BaseException as error:  # noqa: BLE001 - an unusable installed tree cannot pass
		unavailable_obs.append(f"installed add-on unavailable: {error}")

	# Live seam observations. Each guarded leg is authoritative or reported unavailable/failed.
	wx_obs = _collect_wx()
	unavailable_obs.extend(str(item) for item in wx_obs.get("unavailable", ()))
	failed_obs.extend(str(item) for item in wx_obs.get("failed", ()))

	focus_obs = _collect_focus()
	unavailable_obs.extend(str(item) for item in focus_obs.get("unavailable", ()))
	failed_obs.extend(str(item) for item in focus_obs.get("failed", ()))

	product_obs = _collectProductContracts()
	unavailable_obs.extend(str(item) for item in product_obs.get("unavailable", ()))
	failed_obs.extend(str(item) for item in product_obs.get("failed", ()))

	raw_result = _runDelegatedProbe(
		_REPO_ROOT / "tests" / "live" / "probe_raw_uia_subscription.py",
		(
			"--nvda-executable",
			str(nvda_executable),
			"--source-profile",
			str(source_profile),
			"--workspace",
			str(workspace / "raw-uia"),
		),
		resultPrefix=uiaProbe.RESULT_PREFIX,
	)
	raw_payload: dict[str, Any] = cast("dict[str, Any]", raw_result.payload)
	if raw_result.status != "pass":
		_route_probe_status(raw_result.status, "raw-uia", unavailable_obs, unsafe_obs, failed_obs)

	sound_result = _runDelegatedProbe(
		_REPO_ROOT / "tests" / "live" / "probe_sound_playback.py",
		(
			"--nvda-executable",
			str(nvda_executable),
			"--source-profile",
			str(source_profile),
			"--workspace",
			str(workspace / "audio"),
			"--theme-spec",
			str(SOUND_THEME_SPEC),
		),
		resultPrefix=soundProbe.RESULT_PREFIX,
	)
	sound_payload: dict[str, Any] = cast("dict[str, Any]", sound_result.payload)
	if sound_result.status != "pass":
		_route_probe_status(sound_result.status, "audio", unavailable_obs, unsafe_obs, failed_obs)

	installed_result = _runDelegatedProbe(
		_REPO_ROOT / "tests" / "live" / "probe_installed_event_sources.py",
		(
			"--archive",
			str(archive.resolve()),
			"--nvda-executable",
			str(nvda_executable),
			"--source-profile",
			str(source_profile),
			"--workspace",
			str(workspace / "installed-event-sources"),
		),
		resultPrefix=installedProbe.RESULT_PREFIX,
	)
	installed_payload: dict[str, Any] = cast("dict[str, Any]", installed_result.payload)
	enabled_caps = _reviewCapabilities(
		installed_payload,
		runtime=runtime_obs,
		soundReady=sound_result.status == "pass",
		screenshotReady=screenshot_obs.get("screenshotStatus") == "value",
		userInterfaceReady=not wx_obs.get("unavailable") and not wx_obs.get("failed"),
	)
	if not REQUIRED_CAPABILITIES.issubset(enabled_caps):
		missing_obs.append(
			"Runtime prerequisites do not enable event monitoring, raw UIA inspection, "
			+ "screen capture, audio feedback, and the settings interface.",
		)
	if installed_result.status != "pass":
		_route_probe_status(
			installed_result.status,
			"installed-event-source",
			unavailable_obs,
			unsafe_obs,
			failed_obs,
		)
	build_output_ready = (
		archive.parent.name.casefold() == "dist"
		and len(
			tuple(archive.parent.glob("*.nvda-addon")),
		)
		== 1
	)
	scope_kinds = tuple(str(value) for value in installed_payload.get("scopeKindsExercised", ()))
	config_registered = bool(installed_payload.get("configSectionRegistered"))
	installed_tree_ready = bool(installed_payload.get("installedTreeReady"))
	return InstalledReviewResult(
		unavailableObservations=tuple(unavailable_obs),
		skippedObservations=tuple(skipped_obs),
		missingObservations=tuple(missing_obs),
		unsafeObservations=tuple(unsafe_obs),
		failedObservations=tuple(failed_obs),
		buildIdentifier=build_identifier,
		enabledCapabilities=enabled_caps,
		archiveRemainsInstalled=archive_remains,
		wxCallbackMaxMs=float(wx_obs.get("wxCallbackMaxMs", 0.0)),
		focusMatchNodesMax=int(focus_obs.get("focusMatchNodesMax", 0)),
		focusMatchDepthMax=int(focus_obs.get("focusMatchDepthMax", 0)),
		rawUiaCallbackMaxMs=max(
			float(raw_payload.get("callbackMaxMs", 0.0)),
			float(installed_payload.get("callbackMaxMs", 0.0)),
		),
		forwardingMaxMs=max(
			float(raw_payload.get("forwardingMaxMs", 0.0)),
			float(installed_payload.get("forwardingMaxMs", 0.0)),
		),
		burst100MaxMs=max(
			float(raw_payload.get("burst100MaxMs", 0.0)),
			float(installed_payload.get("burst100MaxMs", 0.0)),
		),
		receiptToProcessingMaxMs=max(
			float(raw_payload.get("receiptToProcessingMaxMs", 0.0)),
			float(installed_payload.get("receiptToProcessingMaxMs", 0.0)),
		),
		receiptToPropertyReadMaxMs=max(
			float(raw_payload.get("receiptToPropertyReadMaxMs", 0.0)),
			float(installed_payload.get("receiptToPropertyReadMaxMs", 0.0)),
		),
		soundDispatchMaxMs=float(sound_payload.get("dispatchMaxMs", 0.0)),
		speechSubmitMaxMs=float(sound_payload.get("speechSubmitMaxMs", 0.0)),
		replacementStartMaxMs=float(sound_payload.get("replacementStartMaxMs", 0.0)),
		interAtomGapMinMs=float(sound_payload.get("interAtomGapMinMs", 0.0)),
		interAtomGapMaxMs=float(sound_payload.get("interAtomGapMaxMs", 0.0)),
		lateCallbacksAccepted=max(
			int(raw_payload.get("lateCallbacksAccepted", 0)),
			int(sound_payload.get("lateCallbacksAccepted", 0)),
			int(installed_payload.get("lateCallbacksAccepted", 0)),
		),
		subscriptionsAfterTeardown=max(
			int(raw_payload.get("subscriptionsAfterTeardown", 0)),
			int(installed_payload.get("subscriptionsAfterTeardown", 0)),
		),
		callbacksObservedAfterTeardown=int(installed_payload.get("callbacksObservedAfterTeardown", 0)),
		providerAccessesAfterTeardown=int(installed_payload.get("providerAccessesAfterTeardown", 0)),
		queuedSoundsAfterTeardown=int(sound_payload.get("queuedSoundsAfterTeardown", 0)),
		soundsStartedAfterTeardown=int(sound_payload.get("soundsStartedAfterTeardown", 0)),
		staleAtomsStarted=int(sound_payload.get("staleAtomsStarted", 0)),
		screenshotStatus=str(screenshot_obs.get("screenshotStatus", "")),
		screenshotBytes=int(screenshot_obs.get("screenshotBytes", 0)),
		eventFilterDialogPresent=bool(product_obs.get("eventFilterDialogPresent")),
		annotationsTabPresent=bool(product_obs.get("annotationsTabPresent")),
		scopeKindsExercised=scope_kinds,
		rawEvidenceNativeProxyField=bool(product_obs.get("rawEvidenceNativeProxyField")),
		rawProjectionRequested=bool(runtime_obs.get("rawProjectionRequested")),
		rawProjectionApplied=bool(runtime_obs.get("rawProjectionApplied")),
		rawProjectionStatus=str(runtime_obs.get("rawProjectionStatus", "")),
		rawProjectionMethod=str(runtime_obs.get("rawProjectionMethod", "")),
		rawProjectionReason=str(runtime_obs.get("rawProjectionReason", "")),
		rawProjectionEvidenceQuality=str(runtime_obs.get("rawProjectionEvidenceQuality", "")),
		rawProjectionEvidencePresent=bool(runtime_obs.get("rawProjectionEvidencePresent")),
		ordinaryUiaSectionPresent=bool(runtime_obs.get("ordinaryUiaSectionPresent")),
		inspectorRawRetargetSucceeded=bool(runtime_obs.get("inspectorRawRetargetSucceeded")),
		inspectorRawRetargetRequested=bool(runtime_obs.get("inspectorRawRetargetRequested")),
		inspectorRawRetargetApplied=bool(runtime_obs.get("inspectorRawRetargetApplied")),
		inspectorRawRetargetSourceGeneration=int(runtime_obs.get("inspectorRawRetargetSourceGeneration", 0)),
		hostProcessId=int(runtime_obs.get("hostProcessId", 0)),
		loadedCodeIdentifier=str(runtime_obs.get("loadedCodeIdentifier", "")),
		loadedCodeMatchesArchive=(
			_loadedCodeMatchesArchive(runtime_obs, archive, installedRoot) if runtime_obs else False
		),
		buildBatPublishedToDist=build_output_ready,
		configSectionRegistered=config_registered,
		installedTreeReady=installed_tree_ready,
		retainedMutationsAfterTeardown=max(
			int(raw_payload.get("retainedMutationsAfterTeardown", 0)),
			int(installed_payload.get("retainedMutationsAfterTeardown", 0)),
		),
		controlMutationsAfterTeardown=int(wx_obs.get("controlMutationsAfterTeardown", 0)),
		secureMutations=max(
			int(raw_payload.get("secureMutations", 0)),
			int(installed_payload.get("secureMutations", 0)),
		),
		observationWindowMs=OBSERVATION_WINDOW_MS,
		humanChecklistStatus=humanChecklistResponse,
		installedEventSourceObservation=installed_payload,
	)


def _route_probe_status(
	status: str,
	label: str,
	unavailable_obs: list[str],
	unsafe_obs: list[str],
	failed_obs: list[str],
) -> None:
	"""Map a delegated probe status to the correct review-level fail-closed bucket."""

	if status == "unavailable":
		unavailable_obs.append(f"{label} observation unavailable")
	elif status == "unsafe":
		unsafe_obs.append(f"{label} observation reported a teardown or late-callback breach")
	else:
		failed_obs.append(f"{label} observation failed or exceeded budget")


def _print_checklist(scenarios: tuple[ReviewScenario, ...], buildIdentifier: str) -> None:
	lines = [
		"",
		"Keystone installed Inspector review - linear keyboard and NVDA checklist.",
		f"Build identifier: {buildIdentifier}",
		"Walk each item in order; approve only if every one matches the expected behavior.",
		"",
	]
	for index, scenario in enumerate(scenarios, start=1):
		lines.append(f"{index}. [{scenario.category}] {scenario.title}")
		lines.append(f"   {scenario.prompt}")
	lines.append("")
	lines.append(
		"Excluded from this walkthrough: High Contrast, display-scaling, and visual-reflow "
		+ "review are outside this walkthrough.",
	)
	lines.append("")
	_ = sys.stdout.write("\n".join(lines) + "\n")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Installed Inspector/event/audio/UI review runner.")
	_ = parser.add_argument("--archive", required=True, type=Path)
	_ = parser.add_argument("--nvda-executable", required=True, type=Path)
	_ = parser.add_argument("--source-profile", required=True, type=Path)
	_ = parser.add_argument("--workspace", required=True, type=Path)
	_ = parser.add_argument(
		"--runtime-result",
		type=Path,
		help="objective in-process runtime result produced by the installed add-on",
	)
	_ = parser.add_argument(
		"--human-checklist",
		choices=HUMAN_CHECKLIST_CHOICES,
		default="pending",
		help="the human review outcome; defaults to pending until a human has walked the checklist",
	)
	_ = parser.add_argument(
		"--automated-only",
		action="store_true",
		help="run objective installed checks and stop before printing the human checklist",
	)
	return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
	args = _parse_args(argv)
	try:
		archive = resolveBuiltArchive(Path(str(args.archive)))
	except ValueError as error:
		_ = sys.stderr.write(f"{error}\n")
		return EXIT_UNAVAILABLE
	nvda_executable = Path(str(args.nvda_executable))
	source_profile = Path(str(args.source_profile))
	workspace = Path(str(args.workspace))
	result = runInstalledReview(
		archive,
		nvda_executable,
		source_profile,
		workspace,
		humanChecklistResponse=str(args.human_checklist),
		runtimeResult=None if args.runtime_result is None else Path(str(args.runtime_result)),
	)
	automatedOnly = bool(args.automated_only)
	verdict = evaluateAutomated(result) if automatedOnly else evaluate(result)
	_ = sys.stdout.write(BUILD_PREFIX + result.buildIdentifier + "\n")
	if not automatedOnly:
		_print_checklist(buildReviewScenarios(), result.buildIdentifier)
	line = RESULT_PREFIX + json.dumps(verdict.payload, sort_keys=True)
	try:
		_ = (workspace / "inspector_review_result.json").write_text(
			json.dumps(verdict.payload, indent="\t"),
			encoding="utf-8",
		)
	except OSError:
		pass
	_ = sys.stdout.write(line + "\n")
	return verdict.exitCode


if __name__ == "__main__":
	raise SystemExit(main())
