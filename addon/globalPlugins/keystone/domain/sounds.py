from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

from .status import requireNonnegativeInteger, requireToken


__all__ = (
	"CuePriority",
	"CueAtomId",
	"SOUND_ASSETS",
	"CueEventId",
	"SoundOwnerKind",
	"SoundOwner",
	"CueComposition",
	"SoundRequest",
	"DispatchDecision",
	"SoundDispatch",
	"SoundSchedulerState",
	"SoundScheduler",
	"CUE_GRAMMAR",
	"soundRequestFor",
	"INTER_ATOM_GAP_MILLISECONDS",
	"FIRST_PROGRESS_DELAY_MILLISECONDS",
	"MINIMUM_PROGRESS_INTERVAL_MILLISECONDS",
)


INTER_ATOM_GAP_MILLISECONDS = 30
_MINIMUM_INTER_ATOM_GAP_MILLISECONDS = 20
_MAXIMUM_INTER_ATOM_GAP_MILLISECONDS = 40
FIRST_PROGRESS_DELAY_MILLISECONDS = 2_000
MINIMUM_PROGRESS_INTERVAL_MILLISECONDS = 2_000


class CuePriority(IntEnum):
	CRITICAL = 0
	URGENT = 1
	STANDARD = 2
	AMBIENT = 3


class CueAtomId(StrEnum):
	LAYER_ENTERED = "layerEntered"
	LAYER_INVALID_KEY = "layerInvalidKey"
	LAYER_TIMEOUT = "layerTimeout"
	LAYER_EXPLICIT_EXIT = "layerExplicitExit"
	BOUNDED_FULL_FAMILY = "boundedFullFamily"
	UNLIMITED_FULL_FAMILY = "unlimitedFullFamily"
	DIFF_FAMILY = "diffFamily"
	BOUNDED_NAVIGATOR_FAMILY = "boundedNavigatorFamily"
	UNLIMITED_NAVIGATOR_FAMILY = "unlimitedNavigatorFamily"
	START_STATE = "startState"
	PROGRESS_STATE = "progressState"
	CANCELLATION_REQUESTED = "cancellationRequested"
	CANCELLED_OUTCOME = "cancelledOutcome"
	SUCCESS_OUTCOME = "successOutcome"
	TRUNCATED_SUCCESS_OUTCOME = "truncatedSuccessOutcome"
	PARTIAL_SCREENSHOT_OUTCOME = "partialScreenshotOutcome"
	NO_CHANGE_OUTCOME = "noChangeOutcome"
	BASELINE_CREATED_OUTCOME = "baselineCreatedOutcome"
	FAILURE_OUTCOME = "failureOutcome"
	FOCUS_INSPECTOR_FAMILY = "focusInspectorFamily"
	NAVIGATOR_INSPECTOR_FAMILY = "navigatorInspectorFamily"
	INSPECTOR_REFRESH = "inspectorRefresh"
	INSPECTOR_READY = "inspectorReady"
	INSPECTOR_CLOSE = "inspectorClose"
	EVENT_MONITOR_START = "eventMonitorStart"
	EVENT_MONITOR_STOP = "eventMonitorStop"
	PENDING_QUEUE_DROP = "pendingQueueDrop"
	RETAINED_ROW_DROP = "retainedRowDrop"
	EVENT_EXPORT_FAMILY = "eventExportFamily"
	OUTPUT_PATH_COPIED = "outputPathCopied"
	EXPLORER_REVEAL = "explorerReveal"
	COMMAND_HELP_OPENED = "commandHelpOpened"
	QUICK_PROPERTY_BROWSABLE_MESSAGE = "quickPropertyBrowsableMessage"
	QUICK_PROPERTY_COPY = "quickPropertyCopy"
	SHARED_WARNING = "sharedWarning"


# The closed production sound manifest: every cue atom maps one-to-one to a fixed
# bundled WAV filename under the runtime theme directory (sounds/rich). The paths are
# frozen here in the product language and are never read from a test fixture or a
# planning document at runtime. Per D-29 a maintainer may replace any file at the same
# path before a build and the asset/archive checks validate the replacement; per D-30
# nothing is synthesized at runtime and there is no downloaded, remote, or end-user
# drop-in theme directory. No canonical byte digest is pinned: the current bytes are
# judged on their own by the build-time checks. Filenames are bare (no directory
# component) so the playback adapter joins them onto its injected theme root and
# rejects any entry that would escape it.
SOUND_ASSETS: tuple[tuple[CueAtomId, str], ...] = (
	(CueAtomId.LAYER_ENTERED, "layer-enter.wav"),
	(CueAtomId.LAYER_INVALID_KEY, "layer-invalid.wav"),
	(CueAtomId.LAYER_TIMEOUT, "layer-timeout.wav"),
	(CueAtomId.LAYER_EXPLICIT_EXIT, "layer-exit.wav"),
	(CueAtomId.BOUNDED_FULL_FAMILY, "family-full-bounded.wav"),
	(CueAtomId.UNLIMITED_FULL_FAMILY, "family-full-unlimited.wav"),
	(CueAtomId.DIFF_FAMILY, "family-diff.wav"),
	(CueAtomId.BOUNDED_NAVIGATOR_FAMILY, "family-navigator-bounded.wav"),
	(CueAtomId.UNLIMITED_NAVIGATOR_FAMILY, "family-navigator-unlimited.wav"),
	(CueAtomId.START_STATE, "state-start.wav"),
	(CueAtomId.PROGRESS_STATE, "state-progress.wav"),
	(CueAtomId.CANCELLATION_REQUESTED, "state-cancel-requested.wav"),
	(CueAtomId.CANCELLED_OUTCOME, "outcome-cancelled.wav"),
	(CueAtomId.SUCCESS_OUTCOME, "outcome-success.wav"),
	(CueAtomId.TRUNCATED_SUCCESS_OUTCOME, "outcome-truncated.wav"),
	(CueAtomId.PARTIAL_SCREENSHOT_OUTCOME, "outcome-partial-screenshot.wav"),
	(CueAtomId.NO_CHANGE_OUTCOME, "outcome-no-change.wav"),
	(CueAtomId.BASELINE_CREATED_OUTCOME, "outcome-baseline-created.wav"),
	(CueAtomId.FAILURE_OUTCOME, "outcome-failure.wav"),
	(CueAtomId.FOCUS_INSPECTOR_FAMILY, "family-inspector-focus.wav"),
	(CueAtomId.NAVIGATOR_INSPECTOR_FAMILY, "family-inspector-navigator.wav"),
	(CueAtomId.INSPECTOR_REFRESH, "inspector-refresh.wav"),
	(CueAtomId.INSPECTOR_READY, "inspector-ready.wav"),
	(CueAtomId.INSPECTOR_CLOSE, "inspector-close.wav"),
	(CueAtomId.EVENT_MONITOR_START, "event-monitor-start.wav"),
	(CueAtomId.EVENT_MONITOR_STOP, "event-monitor-stop.wav"),
	(CueAtomId.PENDING_QUEUE_DROP, "event-drop-pending.wav"),
	(CueAtomId.RETAINED_ROW_DROP, "event-drop-retained.wav"),
	(CueAtomId.EVENT_EXPORT_FAMILY, "family-event-export.wav"),
	(CueAtomId.OUTPUT_PATH_COPIED, "confirm-output-copy.wav"),
	(CueAtomId.EXPLORER_REVEAL, "confirm-explorer-reveal.wav"),
	(CueAtomId.COMMAND_HELP_OPENED, "confirm-help-open.wav"),
	(CueAtomId.QUICK_PROPERTY_BROWSABLE_MESSAGE, "confirm-quick-browse.wav"),
	(CueAtomId.QUICK_PROPERTY_COPY, "confirm-quick-copy.wav"),
	(CueAtomId.SHARED_WARNING, "warning-shared.wav"),
)


if tuple(atom for atom, _ in SOUND_ASSETS) != tuple(CueAtomId):
	raise RuntimeError("sound assets must map every cue atom exactly once in declaration order")


if len({path for _, path in SOUND_ASSETS}) != len(SOUND_ASSETS):
	raise RuntimeError("sound asset paths must be unique")


class CueEventId(StrEnum):
	LAYER_ENTERED = "layerEntered"
	LAYER_INVALID_KEY = "layerInvalidKey"
	LAYER_TIMEOUT = "layerTimeout"
	LAYER_EXIT = "layerExit"
	START_BOUNDED_FULL = "startBoundedFull"
	START_UNLIMITED_FULL = "startUnlimitedFull"
	START_DIFF = "startDiff"
	START_BOUNDED_NAVIGATOR = "startBoundedNavigator"
	START_UNLIMITED_NAVIGATOR = "startUnlimitedNavigator"
	CAPTURE_PROGRESS = "captureProgress"
	CAPTURE_CANCELLATION_REQUESTED = "captureCancellationRequested"
	CAPTURE_CANCELLED = "captureCancelled"
	CAPTURE_SUCCESS = "captureSuccess"
	CAPTURE_TRUNCATED_SUCCESS = "captureTruncatedSuccess"
	CAPTURE_PARTIAL_SCREENSHOT = "capturePartialScreenshot"
	CAPTURE_FAILURE = "captureFailure"
	DIFF_NO_CHANGE = "diffNoChange"
	DIFF_BASELINE_CREATED = "diffBaselineCreated"
	OPEN_FOCUS_INSPECTOR = "openFocusInspector"
	OPEN_NAVIGATOR_INSPECTOR = "openNavigatorInspector"
	REFRESH_INSPECTOR = "refreshInspector"
	INSPECTOR_READY = "inspectorReady"
	INSPECTOR_CLOSE = "inspectorClose"
	INSPECTOR_FAILURE = "inspectorFailure"
	EVENT_MONITOR_START = "eventMonitorStart"
	EVENT_MONITOR_STOP = "eventMonitorStop"
	PENDING_QUEUE_DROP = "pendingQueueDrop"
	RETAINED_ROW_DROP = "retainedRowDrop"
	EVENT_MONITOR_FAILURE = "eventMonitorFailure"
	EVENT_EXPORT_SUCCESS = "eventExportSuccess"
	EVENT_EXPORT_FAILURE = "eventExportFailure"
	OUTPUT_PATH_COPY = "outputPathCopy"
	EXPLORER_REVEAL = "explorerReveal"
	COMMAND_HELP_OPENED = "commandHelpOpened"
	QUICK_PROPERTY_BROWSABLE = "quickPropertyBrowsable"
	QUICK_PROPERTY_COPY = "quickPropertyCopy"
	RAW_UIA_FALLBACK = "rawUiaFallback"
	SECURE_DESKTOP_DENIAL = "secureDesktopDenial"
	BROAD_EVENT_SCOPE = "broadEventScope"
	REDACTION_DISABLED = "redactionDisabled"


class SoundOwnerKind(StrEnum):
	LAYER = "layer"
	CAPTURE = "capture"
	INSPECTOR = "inspector"
	MONITOR = "monitor"
	EXPORT = "export"
	COMMAND = "command"
	SETTINGS = "settings"
	SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class SoundOwner:
	kind: SoundOwnerKind
	generation: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.generation, "sound owner generation")


@dataclass(frozen=True, slots=True)
class CueComposition:
	priority: CuePriority
	primaryAtom: CueAtomId
	familyAtom: CueAtomId | None = None
	activeFamily: bool = False
	coalesces: bool = False
	startsProgress: bool = False

	def __post_init__(self) -> None:
		if self.activeFamily and self.familyAtom is not None:
			raise ValueError("active-family cues supply the family atom at request time")
		if self.familyAtom is not None and self.familyAtom == self.primaryAtom:
			raise ValueError("family and primary atoms must differ")
		if self.startsProgress and self.familyAtom is None:
			raise ValueError("a progress-bearing cue requires a fixed family atom")


@dataclass(frozen=True, slots=True)
class SoundRequest:
	event: CueEventId
	owner: SoundOwner
	priority: CuePriority
	primaryAtom: CueAtomId
	familyAtom: CueAtomId | None = None
	coalescingKey: str | None = None
	startsProgress: bool = False
	progressIntervalMilliseconds: int = MINIMUM_PROGRESS_INTERVAL_MILLISECONDS

	def __post_init__(self) -> None:
		if self.familyAtom is not None and self.familyAtom == self.primaryAtom:
			raise ValueError("family and primary atoms must differ")
		if self.coalescingKey is not None:
			_ = requireToken(self.coalescingKey, "coalescing key")
		_ = requireNonnegativeInteger(self.progressIntervalMilliseconds, "progress interval")
		if self.startsProgress and self.familyAtom is None:
			raise ValueError("a progress-bearing start requires a family atom")

	@property
	def atoms(self) -> tuple[CueAtomId, ...]:
		if self.familyAtom is not None:
			return (self.familyAtom, self.primaryAtom)
		return (self.primaryAtom,)


class DispatchDecision(StrEnum):
	PLAY = "play"
	REPLACE = "replace"
	DEFER = "defer"
	COALESCE = "coalesce"
	SKIP = "skip"
	IDLE = "idle"


@dataclass(frozen=True, slots=True)
class SoundDispatch:
	decision: DispatchDecision
	atom: CueAtomId | None = None
	owner: SoundOwner | None = None
	token: int = 0
	hasFollowOn: bool = False
	gapMilliseconds: int = 0

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.token, "dispatch token")
		_ = requireNonnegativeInteger(self.gapMilliseconds, "dispatch gap")
		if self.plays:
			if self.atom is None or self.owner is None:
				raise ValueError("playing dispatches require an atom and owner")
			if self.token == 0:
				raise ValueError("playing dispatches require a positive token")
		else:
			if self.atom is not None:
				raise ValueError("nonplaying dispatches cannot carry an atom")
			if self.hasFollowOn:
				raise ValueError("nonplaying dispatches cannot promise a follow-on atom")
		if self.hasFollowOn and self.gapMilliseconds <= 0:
			raise ValueError("a follow-on atom requires a positive gap")
		if not self.hasFollowOn and self.gapMilliseconds != 0:
			raise ValueError("a final atom cannot carry a gap")

	@property
	def plays(self) -> bool:
		return self.decision in (DispatchDecision.PLAY, DispatchDecision.REPLACE)


@dataclass(frozen=True, slots=True)
class SoundSchedulerState:
	occupied: bool
	activeOwner: SoundOwner | None
	activePriority: CuePriority | None
	activeToken: int
	pendingAtoms: int
	progressOwners: tuple[SoundOwner, ...]
	coalescedKeys: tuple[str, ...]


@dataclass(slots=True)
class _ActiveSequence:
	token: int
	owner: SoundOwner
	priority: CuePriority
	atoms: tuple[CueAtomId, ...]
	index: int


@dataclass(slots=True)
class _ProgressTrack:
	owner: SoundOwner
	familyAtom: CueAtomId
	intervalMilliseconds: int
	startedAtMilliseconds: int
	lastPulseMilliseconds: int | None


CUE_GRAMMAR: dict[CueEventId, CueComposition] = {
	CueEventId.LAYER_ENTERED: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.LAYER_ENTERED,
	),
	CueEventId.LAYER_INVALID_KEY: CueComposition(
		CuePriority.URGENT,
		CueAtomId.LAYER_INVALID_KEY,
		coalesces=True,
	),
	CueEventId.LAYER_TIMEOUT: CueComposition(
		CuePriority.URGENT,
		CueAtomId.LAYER_TIMEOUT,
	),
	CueEventId.LAYER_EXIT: CueComposition(
		CuePriority.URGENT,
		CueAtomId.LAYER_EXPLICIT_EXIT,
	),
	CueEventId.START_BOUNDED_FULL: CueComposition(
		CuePriority.URGENT,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.BOUNDED_FULL_FAMILY,
		startsProgress=True,
	),
	CueEventId.START_UNLIMITED_FULL: CueComposition(
		CuePriority.URGENT,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.UNLIMITED_FULL_FAMILY,
		startsProgress=True,
	),
	CueEventId.START_DIFF: CueComposition(
		CuePriority.URGENT,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.DIFF_FAMILY,
		startsProgress=True,
	),
	CueEventId.START_BOUNDED_NAVIGATOR: CueComposition(
		CuePriority.URGENT,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.BOUNDED_NAVIGATOR_FAMILY,
		startsProgress=True,
	),
	CueEventId.START_UNLIMITED_NAVIGATOR: CueComposition(
		CuePriority.URGENT,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.UNLIMITED_NAVIGATOR_FAMILY,
		startsProgress=True,
	),
	CueEventId.CAPTURE_PROGRESS: CueComposition(
		CuePriority.AMBIENT,
		CueAtomId.PROGRESS_STATE,
		activeFamily=True,
	),
	CueEventId.CAPTURE_CANCELLATION_REQUESTED: CueComposition(
		CuePriority.URGENT,
		CueAtomId.CANCELLATION_REQUESTED,
		activeFamily=True,
	),
	CueEventId.CAPTURE_CANCELLED: CueComposition(
		CuePriority.URGENT,
		CueAtomId.CANCELLED_OUTCOME,
		activeFamily=True,
	),
	CueEventId.CAPTURE_SUCCESS: CueComposition(
		CuePriority.URGENT,
		CueAtomId.SUCCESS_OUTCOME,
		activeFamily=True,
	),
	CueEventId.CAPTURE_TRUNCATED_SUCCESS: CueComposition(
		CuePriority.URGENT,
		CueAtomId.TRUNCATED_SUCCESS_OUTCOME,
		activeFamily=True,
	),
	CueEventId.CAPTURE_PARTIAL_SCREENSHOT: CueComposition(
		CuePriority.URGENT,
		CueAtomId.PARTIAL_SCREENSHOT_OUTCOME,
		activeFamily=True,
	),
	CueEventId.CAPTURE_FAILURE: CueComposition(
		CuePriority.CRITICAL,
		CueAtomId.FAILURE_OUTCOME,
		activeFamily=True,
	),
	CueEventId.DIFF_NO_CHANGE: CueComposition(
		CuePriority.URGENT,
		CueAtomId.NO_CHANGE_OUTCOME,
		familyAtom=CueAtomId.DIFF_FAMILY,
	),
	CueEventId.DIFF_BASELINE_CREATED: CueComposition(
		CuePriority.URGENT,
		CueAtomId.BASELINE_CREATED_OUTCOME,
		familyAtom=CueAtomId.DIFF_FAMILY,
	),
	CueEventId.OPEN_FOCUS_INSPECTOR: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.FOCUS_INSPECTOR_FAMILY,
	),
	CueEventId.OPEN_NAVIGATOR_INSPECTOR: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.NAVIGATOR_INSPECTOR_FAMILY,
	),
	CueEventId.REFRESH_INSPECTOR: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.START_STATE,
		familyAtom=CueAtomId.INSPECTOR_REFRESH,
		coalesces=True,
	),
	CueEventId.INSPECTOR_READY: CueComposition(
		CuePriority.URGENT,
		CueAtomId.INSPECTOR_READY,
	),
	CueEventId.INSPECTOR_CLOSE: CueComposition(
		CuePriority.URGENT,
		CueAtomId.INSPECTOR_CLOSE,
	),
	CueEventId.INSPECTOR_FAILURE: CueComposition(
		CuePriority.CRITICAL,
		CueAtomId.FAILURE_OUTCOME,
		activeFamily=True,
	),
	CueEventId.EVENT_MONITOR_START: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.EVENT_MONITOR_START,
	),
	CueEventId.EVENT_MONITOR_STOP: CueComposition(
		CuePriority.URGENT,
		CueAtomId.EVENT_MONITOR_STOP,
	),
	CueEventId.PENDING_QUEUE_DROP: CueComposition(
		CuePriority.URGENT,
		CueAtomId.PENDING_QUEUE_DROP,
		coalesces=True,
	),
	CueEventId.RETAINED_ROW_DROP: CueComposition(
		CuePriority.URGENT,
		CueAtomId.RETAINED_ROW_DROP,
		coalesces=True,
	),
	CueEventId.EVENT_MONITOR_FAILURE: CueComposition(
		CuePriority.CRITICAL,
		CueAtomId.FAILURE_OUTCOME,
		familyAtom=CueAtomId.EVENT_MONITOR_START,
	),
	CueEventId.EVENT_EXPORT_SUCCESS: CueComposition(
		CuePriority.URGENT,
		CueAtomId.SUCCESS_OUTCOME,
		familyAtom=CueAtomId.EVENT_EXPORT_FAMILY,
	),
	CueEventId.EVENT_EXPORT_FAILURE: CueComposition(
		CuePriority.CRITICAL,
		CueAtomId.FAILURE_OUTCOME,
		familyAtom=CueAtomId.EVENT_EXPORT_FAMILY,
	),
	CueEventId.OUTPUT_PATH_COPY: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.OUTPUT_PATH_COPIED,
		coalesces=True,
	),
	CueEventId.EXPLORER_REVEAL: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.EXPLORER_REVEAL,
	),
	CueEventId.COMMAND_HELP_OPENED: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.COMMAND_HELP_OPENED,
	),
	CueEventId.QUICK_PROPERTY_BROWSABLE: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.QUICK_PROPERTY_BROWSABLE_MESSAGE,
	),
	CueEventId.QUICK_PROPERTY_COPY: CueComposition(
		CuePriority.STANDARD,
		CueAtomId.QUICK_PROPERTY_COPY,
	),
	CueEventId.RAW_UIA_FALLBACK: CueComposition(
		CuePriority.URGENT,
		CueAtomId.SHARED_WARNING,
		coalesces=True,
	),
	CueEventId.SECURE_DESKTOP_DENIAL: CueComposition(
		CuePriority.CRITICAL,
		CueAtomId.SHARED_WARNING,
	),
	CueEventId.BROAD_EVENT_SCOPE: CueComposition(
		CuePriority.URGENT,
		CueAtomId.SHARED_WARNING,
		coalesces=True,
	),
	CueEventId.REDACTION_DISABLED: CueComposition(
		CuePriority.URGENT,
		CueAtomId.SHARED_WARNING,
		coalesces=True,
	),
}


if set(CUE_GRAMMAR) != set(CueEventId):
	raise RuntimeError("cue grammar must define every cue event")


def soundRequestFor(
	event: CueEventId,
	owner: SoundOwner,
	*,
	activeFamilyAtom: CueAtomId | None = None,
	coalescingKey: str | None = None,
	progressIntervalMilliseconds: int = MINIMUM_PROGRESS_INTERVAL_MILLISECONDS,
) -> SoundRequest:
	composition = CUE_GRAMMAR[event]
	if composition.activeFamily:
		if activeFamilyAtom is None:
			raise ValueError(f"{event.value} requires an active family atom")
		familyAtom = activeFamilyAtom
	else:
		if activeFamilyAtom is not None:
			raise ValueError(f"{event.value} does not accept an active family atom")
		familyAtom = composition.familyAtom
	if composition.coalesces:
		if coalescingKey is not None:
			key = f"{event.value}:{requireToken(coalescingKey, 'coalescing key')}"
		else:
			key = event.value
	elif coalescingKey is not None:
		raise ValueError(f"{event.value} does not coalesce")
	else:
		key = None
	return SoundRequest(
		event=event,
		owner=owner,
		priority=composition.priority,
		primaryAtom=composition.primaryAtom,
		familyAtom=familyAtom,
		coalescingKey=key,
		startsProgress=composition.startsProgress,
		progressIntervalMilliseconds=progressIntervalMilliseconds,
	)


class SoundScheduler:
	def __init__(
		self,
		*,
		interAtomGapMilliseconds: int = INTER_ATOM_GAP_MILLISECONDS,
		firstProgressDelayMilliseconds: int = FIRST_PROGRESS_DELAY_MILLISECONDS,
	) -> None:
		super().__init__()
		gap = requireNonnegativeInteger(interAtomGapMilliseconds, "inter-atom gap")
		if not _MINIMUM_INTER_ATOM_GAP_MILLISECONDS <= gap <= _MAXIMUM_INTER_ATOM_GAP_MILLISECONDS:
			raise ValueError("inter-atom gap must fall within the validated 20-40 ms range")
		self._gap = gap
		self._firstProgressDelay = requireNonnegativeInteger(
			firstProgressDelayMilliseconds,
			"first progress delay",
		)
		self._nextToken = 1
		self._active: _ActiveSequence | None = None
		self._progress: dict[SoundOwnerKind, _ProgressTrack] = {}
		self._coalesced: dict[str, SoundOwner] = {}
		# The one capture-start request (if any) waiting for the transient LAYER_ENTERED cue
		# it arrived behind to finish naturally; see _defersForTransientLayerCue. Nothing else
		# ever populates this - every other REPLACE/SKIP path is unchanged.
		self._deferred: SoundRequest | None = None

	@property
	def state(self) -> SoundSchedulerState:
		active = self._active
		return SoundSchedulerState(
			occupied=active is not None,
			activeOwner=active.owner if active is not None else None,
			activePriority=active.priority if active is not None else None,
			activeToken=active.token if active is not None else 0,
			pendingAtoms=(len(active.atoms) - active.index - 1) if active is not None else 0,
			progressOwners=tuple(track.owner for track in self._progress.values()),
			coalescedKeys=tuple(sorted(self._coalesced)),
		)

	def dispatch(self, request: SoundRequest, *, nowMilliseconds: int) -> SoundDispatch:
		_ = requireNonnegativeInteger(nowMilliseconds, "sound clock")
		if request.coalescingKey is not None and self._coalesced.get(request.coalescingKey) == request.owner:
			return SoundDispatch(DispatchDecision.COALESCE, owner=request.owner)
		if request.priority <= CuePriority.URGENT:
			self._clearProgress(request.owner)
		decision = self._arbitrate(request)
		if decision is DispatchDecision.SKIP:
			return SoundDispatch(DispatchDecision.SKIP, owner=request.owner)
		if decision is DispatchDecision.DEFER:
			# The active LAYER_ENTERED cue keeps playing untouched; completeAtom() promotes
			# this request the instant that short cue's own completion is discovered.
			self._deferred = request
			return SoundDispatch(DispatchDecision.DEFER, owner=request.owner)
		return self._begin(request, decision, nowMilliseconds)

	def _begin(
		self,
		request: SoundRequest,
		decision: DispatchDecision,
		nowMilliseconds: int,
	) -> SoundDispatch:
		if request.startsProgress and request.familyAtom is not None:
			self._progress[request.owner.kind] = _ProgressTrack(
				owner=request.owner,
				familyAtom=request.familyAtom,
				intervalMilliseconds=max(
					MINIMUM_PROGRESS_INTERVAL_MILLISECONDS,
					request.progressIntervalMilliseconds,
				),
				startedAtMilliseconds=nowMilliseconds,
				lastPulseMilliseconds=None,
			)
		if request.coalescingKey is not None:
			self._coalesced[request.coalescingKey] = request.owner
		atoms = request.atoms
		token = self._occupy(request.owner, request.priority, atoms)
		return SoundDispatch(
			decision,
			atom=atoms[0],
			owner=request.owner,
			token=token,
			hasFollowOn=len(atoms) > 1,
			gapMilliseconds=self._gap if len(atoms) > 1 else 0,
		)

	def completeAtom(self, token: int, *, nowMilliseconds: int) -> SoundDispatch:
		_ = requireNonnegativeInteger(nowMilliseconds, "sound clock")
		_ = requireNonnegativeInteger(token, "sound token")
		active = self._active
		if active is None or active.token != token:
			return SoundDispatch(DispatchDecision.IDLE)
		active.index += 1
		if active.index >= len(active.atoms):
			owner = active.owner
			self._active = None
			deferred = self._deferred
			if deferred is not None:
				self._deferred = None
				return self._begin(deferred, DispatchDecision.PLAY, nowMilliseconds)
			return SoundDispatch(DispatchDecision.IDLE, owner=owner)
		pending = len(active.atoms) - active.index - 1
		return SoundDispatch(
			DispatchDecision.PLAY,
			atom=active.atoms[active.index],
			owner=active.owner,
			token=token,
			hasFollowOn=pending > 0,
			gapMilliseconds=self._gap if pending > 0 else 0,
		)

	def tick(self, nowMilliseconds: int) -> SoundDispatch:
		_ = requireNonnegativeInteger(nowMilliseconds, "sound clock")
		if self._active is not None:
			return SoundDispatch(DispatchDecision.IDLE)
		for track in self._progress.values():
			threshold = (
				track.startedAtMilliseconds + self._firstProgressDelay
				if track.lastPulseMilliseconds is None
				else track.lastPulseMilliseconds + track.intervalMilliseconds
			)
			if nowMilliseconds >= threshold:
				track.lastPulseMilliseconds = nowMilliseconds
				atoms = (track.familyAtom, CueAtomId.PROGRESS_STATE)
				token = self._occupy(track.owner, CuePriority.AMBIENT, atoms)
				return SoundDispatch(
					DispatchDecision.PLAY,
					atom=atoms[0],
					owner=track.owner,
					token=token,
					hasFollowOn=True,
					gapMilliseconds=self._gap,
				)
		return SoundDispatch(DispatchDecision.IDLE)

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		if owner is None:
			self._active = None
			self._progress.clear()
			self._coalesced.clear()
			self._deferred = None
			return
		if self._active is not None and self._active.owner == owner:
			self._active = None
		if self._deferred is not None and self._deferred.owner == owner:
			self._deferred = None
		track = self._progress.get(owner.kind)
		if track is not None and track.owner == owner:
			_ = self._progress.pop(owner.kind, None)
		self._coalesced = {key: keyOwner for key, keyOwner in self._coalesced.items() if keyOwner != owner}

	def _arbitrate(self, request: SoundRequest) -> DispatchDecision:
		active = self._active
		if active is None:
			return DispatchDecision.PLAY
		if self._defersForTransientLayerCue(request, active):
			return DispatchDecision.DEFER
		if request.priority < active.priority:
			return DispatchDecision.REPLACE
		if (
			request.priority == active.priority
			and request.owner.kind == active.owner.kind
			and request.owner.generation > active.owner.generation
		):
			return DispatchDecision.REPLACE
		return DispatchDecision.SKIP

	@staticmethod
	def _defersForTransientLayerCue(request: SoundRequest, active: _ActiveSequence) -> bool:
		# Product policy: a capture-start cue arriving while the short (225ms) transient
		# layer-enter cue is still playing lets that cue finish rather than cutting it off
		# mid-play; capture-start begins the instant it naturally completes (see
		# completeAtom's promotion of self._deferred). Scoped narrowly on both sides so no
		# other preemption is weakened:
		#  - the active cue must be exactly the transient LAYER_ENTERED single atom (never
		#    layerTimeout/layerInvalidKey/layerExplicitExit, which are already URGENT and are
		#    not reached by this branch at all);
		#  - the incoming request must be one of the five capture-start events, identified by
		#    startsProgress (the only cues that set it) rather than by naming a fixed event
		#    list, so CRITICAL cues, warnings, and every other URGENT cue still REPLACE the
		#    layer-enter cue immediately, exactly as before.
		return (
			active.owner.kind is SoundOwnerKind.LAYER
			and active.atoms == (CueAtomId.LAYER_ENTERED,)
			and request.owner.kind is SoundOwnerKind.CAPTURE
			and request.startsProgress
		)

	def _clearProgress(self, owner: SoundOwner) -> None:
		track = self._progress.get(owner.kind)
		if track is not None and owner.generation >= track.owner.generation:
			_ = self._progress.pop(owner.kind, None)

	def _occupy(self, owner: SoundOwner, priority: CuePriority, atoms: tuple[CueAtomId, ...]) -> int:
		token = self._nextToken
		self._nextToken += 1
		self._active = _ActiveSequence(token, owner, priority, atoms, 0)
		return token
