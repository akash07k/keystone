"""Installed event-source production observation probe (research + acceptance gate for EVT-04/EVT-05).

This runner uses the freshly built ``keystone`` archive already installed in the user's current,
backed-up primary NVDA profile, checks the runtime prerequisites for event monitoring and raw UIA
inspection directly, and then drives the *packaged*
``buildProductionComposition`` through ``ProductionComposition.runInstalledEventSourceObservation`` with
the shipped ``RawUiaEventSource`` and ``NvdaEventSource``, forces ten controlled 100-receipt raw storms
plus one exact-once forwarded NVDA event, stops monitoring through production composition, and observes a
fixed 250 ms no-effect window after teardown. The loaded add-on tree is never replaced during the observation.

The raw UIA client and one real focus subscription are genuine liveness. Controlled storm load is driven
through the very same shipped routing path a live callback uses, so the safety arithmetic is
deterministic. Every fixed field and threshold is reused unchanged from the standalone raw UIA probe and is
never inferred from this run. The module performs no COM or host work at import time, so the contract
tests can import :func:`evaluate` and :class:`InstalledEventSourceObservations` without a host.

Exit codes: 0 pass; 2 unavailable/skipped/missing; 3 failed/unsafe/over-budget; 4 teardown or
late-callback violation. A nonzero result blocks the plan; a safe runtime fallback is never completion
evidence.
"""

from __future__ import annotations

import argparse
import certifi
import importlib.util
from importlib import import_module
import json
from pathlib import Path
import shutil
import sys
import threading
import time
from types import ModuleType
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, cast
from zipfile import ZipFile

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
	sys.path.insert(0, str(_REPO_ROOT))

# Fixed budgets, families, exit categories, and result type come from the standalone raw probe; they are
# constants here as well and are never derived from the judged run.
from tests.live.probe_raw_uia_subscription import (  # noqa: E402
	BURST100_MAX_MS,
	BURST_COUNT,
	BURST_SIZE,
	CALLBACK_MAX_MS,
	EXIT_FAILED,
	EXIT_PASS,
	EXIT_TEARDOWN,
	EXIT_UNAVAILABLE,
	EXPECTED_EVENT_FAMILIES,
	FORWARDING_MAX_MS,
	OBSERVATION_WINDOW_MS,
	RECEIPT_TO_PROCESSING_MAX_MS,
	RECEIPT_TO_PROPERTY_READ_MAX_MS,
	ProbeResult,
)

RESULT_PREFIX = "KEYSTONE_INSTALLED_EVENT_SOURCE_RESULT="
INSTALL_PREFIX = "KEYSTONE_INSTALL_PREPARATION_RESULT="

SESSION_TIMEOUT_S = 90.0
MISMATCH_PROBE_RECEIPTS = 25

# Shipped identities the installed observation must name exactly.
EXPECTED_RAW_SOURCE_TYPE = "RawUiaEventSource"
EXPECTED_NVDA_SOURCE_TYPE = "NvdaEventSource"
RAW_SOURCE_MODULE_SUFFIX = "adapters.windows.raw_uia_events"
NVDA_SOURCE_MODULE_SUFFIX = "adapters.nvda.event_sources"

REQUIRED_CAPABILITIES = frozenset({"eventMonitoring", "rawUiaInspection"})

STORM_EXECUTABLE = "explorer.exe"


@dataclass(frozen=True, slots=True)
class InstalledEventSourceObservations:
	"""Everything the installed observation measured. Field names match the emitted JSON keys."""

	# Shared standalone raw-probe fields.
	unavailableObservations: tuple[str, ...] = ()
	skippedObservations: tuple[str, ...] = ()
	missingObservations: tuple[str, ...] = ()
	callbackMaxMs: float = 0.0
	forwardingMaxMs: float = 0.0
	burst100MaxMs: float = 0.0
	receiptToProcessingMaxMs: float = 0.0
	receiptToPropertyReadMaxMs: float = 0.0
	eventFamiliesObserved: tuple[str, ...] = ()
	pidMismatchAccepted: int = 0
	forwardingCount: int = 0
	receiptCount: int = 0
	retainedRowDrops: int = 0
	ownershipViolations: int = 0
	lateCallbacksAccepted: int = 0
	subscriptionsAfterTeardown: int = 0
	retainedMutationsAfterTeardown: int = 0
	secureMutations: int = 0
	observationWindowMs: int = OBSERVATION_WINDOW_MS
	# Installed-observation fields.
	enabledCapabilities: tuple[str, ...] = ()
	configSectionRegistered: bool = False
	installedTreeReady: bool = False
	scopeKindsExercised: tuple[str, ...] = ()
	productionNvdaForwarded: int = 0
	outOfSubtreeAccepted: int = 0
	rawSourceModule: str = ""
	rawSourceType: str = ""
	nvdaSourceModule: str = ""
	nvdaSourceType: str = ""
	productionCompositionStarted: bool = False
	monitorStarted: bool = False
	monitorStopped: bool = False
	callbacksObservedAfterTeardown: int = 0
	providerAccessesAfterTeardown: int = 0


def evaluate(obs: InstalledEventSourceObservations) -> ProbeResult:
	"""Judge observations against the fixed budgets, the installed-identity contract, and the exit matrix.

	Precedence: an observation we could not establish (exit 2) outranks a teardown or late-callback
	breach (exit 4), which outranks any other failure, identity gap, missing enablement, or over-budget
	reading (exit 3). Only a fully clean, fully enabled run is a pass (exit 0).
	"""

	families = tuple(obs.eventFamiliesObserved)
	payload: dict[str, object] = {
		"status": "pass",
		"unavailableObservations": list(obs.unavailableObservations),
		"skippedObservations": list(obs.skippedObservations),
		"missingObservations": list(obs.missingObservations),
		"callbackMaxMs": round(obs.callbackMaxMs, 3),
		"forwardingMaxMs": round(obs.forwardingMaxMs, 3),
		"burst100MaxMs": round(obs.burst100MaxMs, 3),
		"receiptToProcessingMaxMs": round(obs.receiptToProcessingMaxMs, 3),
		"receiptToPropertyReadMaxMs": round(obs.receiptToPropertyReadMaxMs, 3),
		"eventFamiliesObserved": list(families),
		"pidMismatchAccepted": obs.pidMismatchAccepted,
		"forwardingCount": obs.forwardingCount,
		"receiptCount": obs.receiptCount,
		"retainedRowDrops": obs.retainedRowDrops,
		"ownershipViolations": obs.ownershipViolations,
		"lateCallbacksAccepted": obs.lateCallbacksAccepted,
		"subscriptionsAfterTeardown": obs.subscriptionsAfterTeardown,
		"retainedMutationsAfterTeardown": obs.retainedMutationsAfterTeardown,
		"secureMutations": obs.secureMutations,
		"observationWindowMs": obs.observationWindowMs,
		"enabledCapabilities": list(obs.enabledCapabilities),
		"configSectionRegistered": obs.configSectionRegistered,
		"installedTreeReady": obs.installedTreeReady,
		"scopeKindsExercised": list(obs.scopeKindsExercised),
		"productionNvdaForwarded": obs.productionNvdaForwarded,
		"outOfSubtreeAccepted": obs.outOfSubtreeAccepted,
		"rawSourceModule": obs.rawSourceModule,
		"rawSourceType": obs.rawSourceType,
		"nvdaSourceModule": obs.nvdaSourceModule,
		"nvdaSourceType": obs.nvdaSourceType,
		"productionCompositionStarted": obs.productionCompositionStarted,
		"monitorStarted": obs.monitorStarted,
		"monitorStopped": obs.monitorStopped,
		"callbacksObservedAfterTeardown": obs.callbacksObservedAfterTeardown,
		"providerAccessesAfterTeardown": obs.providerAccessesAfterTeardown,
	}

	if obs.unavailableObservations or obs.skippedObservations or obs.missingObservations:
		payload["status"] = "unavailable"
		return ProbeResult("unavailable", EXIT_UNAVAILABLE, payload)

	teardown_breach = (
		obs.lateCallbacksAccepted != 0
		or obs.subscriptionsAfterTeardown != 0
		or obs.retainedMutationsAfterTeardown != 0
		or obs.secureMutations != 0
		or obs.callbacksObservedAfterTeardown != 0
		or obs.providerAccessesAfterTeardown != 0
	)

	over_budget = (
		obs.callbackMaxMs > CALLBACK_MAX_MS
		or obs.forwardingMaxMs > FORWARDING_MAX_MS
		or obs.burst100MaxMs > BURST100_MAX_MS
		or obs.receiptToProcessingMaxMs > RECEIPT_TO_PROCESSING_MAX_MS
		or obs.receiptToPropertyReadMaxMs > RECEIPT_TO_PROPERTY_READ_MAX_MS
	)

	identity_ok = (
		obs.rawSourceType == EXPECTED_RAW_SOURCE_TYPE
		and obs.rawSourceModule.endswith(RAW_SOURCE_MODULE_SUFFIX)
		and obs.nvdaSourceType == EXPECTED_NVDA_SOURCE_TYPE
		and obs.nvdaSourceModule.endswith(NVDA_SOURCE_MODULE_SUFFIX)
	)
	enablement_ok = (
		obs.productionCompositionStarted
		and obs.monitorStarted
		and obs.monitorStopped
		and REQUIRED_CAPABILITIES.issubset(set(obs.enabledCapabilities))
		and obs.configSectionRegistered
		and obs.installedTreeReady
	)
	unsafe = (
		set(families) != set(EXPECTED_EVENT_FAMILIES)
		or len(families) != len(EXPECTED_EVENT_FAMILIES)
		or obs.forwardingCount != obs.receiptCount + obs.retainedRowDrops
		or obs.forwardingCount <= 0
		or obs.pidMismatchAccepted != 0
		or obs.ownershipViolations != 0
		or obs.observationWindowMs != OBSERVATION_WINDOW_MS
		or set(obs.scopeKindsExercised) != {"element", "subtree", "application", "broad"}
		or obs.productionNvdaForwarded != 1
		or obs.outOfSubtreeAccepted != 0
		or not identity_ok
		or not enablement_ok
	)

	if teardown_breach:
		payload["status"] = "unsafe"
		return ProbeResult("unsafe", EXIT_TEARDOWN, payload)
	if over_budget or unsafe:
		payload["status"] = "failed"
		return ProbeResult("failed", EXIT_FAILED, payload)
	return ProbeResult("pass", EXIT_PASS, payload)


def _prepare_runtime(nvda_executable: Path) -> None:
	# Declare the installed frozen layout so NVDA resolves its versioned runtime libraries
	# (lib/<version>/x64) exactly as its own launcher does, rather than the source-tree dev path.
	# Importing certifi before the frozen library enters sys.path keeps its packaged certificate
	# resource available when NVDA's UIA import chain reaches requests.
	_ = certifi.where()
	setattr(sys, "frozen", "windows_exe")  # noqa: B010 - NVDA resolves installed versioned libs
	install = nvda_executable.resolve().parent
	library = install / "library.zip"
	for entry in (str(library), str(install)):
		if entry not in sys.path:
			sys.path.insert(0, entry)


def _install_archive(archive: Path, source_profile: Path) -> Path:
	"""Install the exact built archive into the primary profile's add-on directory in place (XD-02)."""

	installed_root = source_profile / "addons" / "keystone"
	if installed_root.exists():
		shutil.rmtree(installed_root)
	installed_root.mkdir(parents=True, exist_ok=True)
	with ZipFile(archive) as source:
		source.extractall(installed_root)
	return installed_root


def _verify_archive(archive: Path) -> None:
	from tests.archive.check_addon_archive import verify_build

	_ = verify_build(_REPO_ROOT, archive)


def _run_install_task(installed_root: Path) -> None:
	taskPath = installed_root / "installTasks.py"
	if not taskPath.is_file():
		raise FileNotFoundError("installed add-on has no installTasks.py")
	packageName = "_keystoneInstalledAddon"
	moduleName = f"{packageName}.installTasks"
	package = ModuleType(packageName)
	setattr(package, "__path__", [str(installed_root)])
	sys.modules[packageName] = package
	try:
		spec = importlib.util.spec_from_file_location(moduleName, taskPath)
		if spec is None or spec.loader is None:
			raise RuntimeError("installed add-on task loader is unavailable")
		module = importlib.util.module_from_spec(spec)
		sys.modules[moduleName] = module
		spec.loader.exec_module(module)
		onInstall = getattr(module, "onInstall", None)
		if not callable(onInstall):
			raise RuntimeError("installed add-on has no callable onInstall task")
		_ = onInstall()
	finally:
		for loadedName in tuple(sys.modules):
			if loadedName == packageName or loadedName.startswith(f"{packageName}."):
				_ = sys.modules.pop(loadedName, None)


def prepareInstalledArchive(
	archive: Path,
	nvda_executable: Path,
	source_profile: Path,
) -> Path:
	"""Verify and install one archive, including its supported configuration registration task."""

	_prepare_runtime(nvda_executable)
	_initialize_nvda_config(source_profile, nvda_executable.resolve().parent)
	_verify_archive(archive)
	installedRoot = _install_archive(archive, source_profile)
	_run_install_task(installedRoot)
	return installedRoot


def _requireInstalledTree(source_profile: Path) -> Path:
	installedRoot = source_profile / "addons" / "keystone"
	required = (
		installedRoot / "manifest.ini",
		installedRoot / "globalPlugins" / "keystone" / "__init__.py",
	)
	if not all(path.is_file() for path in required):
		raise FileNotFoundError("the installed Keystone add-on tree is incomplete")
	return installedRoot


def _configSectionRegistered() -> bool:
	try:
		config: Any = __import__("config")
		_ = config.conf["keystone"]
	except (AttributeError, KeyError, TypeError):
		return False
	return True


def _import_installed_keystone(installed_root: Path) -> Any:
	"""Import the packaged keystone from the installed location so build digests align."""

	packages = installed_root / "globalPlugins"
	if str(packages) not in sys.path:
		sys.path.insert(0, str(packages))
	from types import SimpleNamespace

	raw_events: Any = __import__("keystone.adapters.windows.raw_uia_events", fromlist=["*"])
	nvda_events: Any = __import__("keystone.adapters.nvda.event_sources", fromlist=["*"])
	composition: Any = __import__("keystone.adapters.nvda.composition", fromlist=["*"])
	event_monitor: Any = __import__("keystone.domain.event_monitor", fromlist=["*"])
	return SimpleNamespace(
		raw_events=raw_events,
		nvda_events=nvda_events,
		composition=composition,
		event_monitor=event_monitor,
	)


def _initialize_nvda_config(source_profile: Path, nvda_install_dir: Path) -> None:
	"""Bootstrap just enough of the installed NVDA runtime to read config without saving it.

	Mirrors what NVDA's own startup establishes before add-ons load: ``globalVars.appDir`` (needed
	because ``config`` builds ``nvda_slave.exe`` paths from it at import), the primary profile path,
	and the gettext i18n builtins (``_``, ``ngettext``, ``pgettext``, ``npgettext``) that NVDA modules
	reference at import time. Nothing here writes to or mutates the user's profile.
	"""

	globalVars: Any = __import__("globalVars")
	globalVars.appArgs.configPath = str(source_profile)
	globalVars.appDir = str(nvda_install_dir)
	try:
		logHandler: Any = __import__("logHandler")
		if getattr(logHandler, "log", None) is None:
			logHandler.initialize()
	except Exception:  # noqa: BLE001 - logging is best effort; config init is what matters
		pass
	config: Any = __import__("config")
	if getattr(config, "conf", None) is None:
		config.initialize()
	import gettext

	gettext.NullTranslations().install(names=["gettext", "ngettext", "pgettext", "npgettext"])


def _identity_field(identities: Any, index: int, key: str) -> str:
	"""Read one string field from a source-identity mapping without leaking unknown types."""

	if len(identities) <= index:
		return ""
	entry: Any = identities[index]
	value: Any = entry.get(key, "")
	return str(value)


def _make_nvda_object(pid: int) -> Any:
	from types import SimpleNamespace

	return SimpleNamespace(
		name="Address bar",
		role=SimpleNamespace(name="editableText"),
		processID=pid,
		appModule=SimpleNamespace(appName="explorer"),
		value="https://example.test",
		isProtected=False,
	)


def _applyNvdaMonkeyPatches() -> None:
	"""Mirror NVDA's entry point before importing any comtypes-backed handler."""

	monkeyPatches = import_module("monkeyPatches")
	apply = getattr(monkeyPatches, "applyMonkeyPatches", None)
	if not callable(apply):
		raise RuntimeError("NVDA monkey-patch initialization is unavailable")
	_ = apply()


def _initializeNvdaUia() -> Callable[[], None]:
	"""Initialize the real NVDA UIA handler and return its matching release action."""

	uiaHandler = import_module("UIAHandler")
	owned = getattr(uiaHandler, "handler", None) is None
	if owned:
		initialize = getattr(uiaHandler, "initialize", None)
		if not callable(initialize):
			raise RuntimeError("NVDA UIA initialization is unavailable")
		_ = initialize()
	if getattr(uiaHandler, "handler", None) is None:
		raise RuntimeError("NVDA UIA handler did not initialize")

	def release() -> None:
		if not owned:
			return
		terminate = getattr(uiaHandler, "terminate", None)
		if callable(terminate):
			_ = terminate()

	return release


def _run_session(
	archive: Path,
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
	holder: dict[str, Any],
) -> None:
	_prepare_runtime(nvda_executable)
	setattr(sys, "coinit_flags", 0)  # noqa: B010 - request an MTA before comtypes imports
	_applyNvdaMonkeyPatches()
	_initialize_nvda_config(source_profile, nvda_executable.resolve().parent)
	releaseUia = _initializeNvdaUia()
	try:
		_run_initialized_session(archive, source_profile, workspace, holder)
	finally:
		releaseUia()


def _run_initialized_session(  # noqa: C901 - one linear observation with guarded legs
	archive: Path,
	source_profile: Path,
	workspace: Path,
	holder: dict[str, Any],
) -> None:
	session_thread = threading.get_ident()
	ownership_violations = 0

	installed_root = _requireInstalledTree(source_profile)
	config_section_registered = _configSectionRegistered()
	keystone = _import_installed_keystone(installed_root)

	# Genuine client read for the pinned process id and the real property-read latency.
	import comtypes.client  # pyright: ignore[reportMissingImports, reportUnusedImport]

	comtypesModule: Any = comtypes
	comtypesClient: Any = comtypesModule.client
	uia: Any = comtypesClient.GetModule("UIAutomationCore.dll")
	client: Any = comtypesClient.CreateObject(uia.CUIAutomation, interface=uia.IUIAutomation)
	root: Any = client.GetRootElement()
	requested_pid = int(root.CurrentProcessId)
	property_read_start = time.perf_counter()
	_ = root.CurrentName
	receipt_to_property_read_ms = (time.perf_counter() - property_read_start) * 1000.0

	monitorModule: Any = keystone.event_monitor
	rawSource: Any = keystone.raw_events.RawUiaEventSource()
	nvdaSource: Any = keystone.nvda_events.NvdaEventSource()
	rawDescriptor = keystone.raw_events.RawUiaObjectDescriptor
	rawFamilies: Any = monitorModule.RAW_UIA_FAMILIES
	nvdaFocus: Any = monitorModule.NvdaEventType.FOCUS
	scope: Any = monitorModule.MonitorScope.pinned("Windows Explorer", requested_pid)
	fullFilter: Any = monitorModule.EventFilter(
		nvdaTypes=frozenset(monitorModule.NVDA_EVENT_TYPES),
		rawFamilies=frozenset(rawFamilies),
	)
	window_handle = int(getattr(root, "CurrentNativeWindowHandle", 0)) or 1
	root_identity: Any = monitorModule.TargetIdentity(
		requested_pid,
		window_handle,
		(("providerIdentifier", "installed-scope-root"),),
	)
	child_identity: Any = monitorModule.TargetIdentity(
		requested_pid,
		window_handle,
		(("providerIdentifier", "installed-scope-child"),),
	)
	foreign_identity: Any = monitorModule.TargetIdentity(
		requested_pid,
		window_handle,
		(("providerIdentifier", "installed-scope-foreign"),),
	)

	metrics: dict[str, Any] = {}

	def _descriptor(pid: int) -> Any:
		return rawDescriptor(processId=pid, executable=STORM_EXECUTABLE, name="Item", role="dataItem")

	def stimulus(service: Any) -> dict[str, object]:
		burst_max_ms = 0.0
		processing_max_ms = 0.0
		generation = rawSource.generation
		families_forwarded: set[str] = set()
		# Ten families, each routed once for the pinned process.
		for family in rawFamilies:
			if rawSource.observe(family, _descriptor(requested_pid), issuedGeneration=generation):
				families_forwarded.add(str(family.value))
		_ = service.drain()
		# Mismatched-process receipts must be dropped, never retained.
		mismatch_accepted = 0
		for _ in range(MISMATCH_PROBE_RECEIPTS):
			if rawSource.observe(
				rawFamilies[0],
				_descriptor(requested_pid + 7919),
				issuedGeneration=generation,
			):
				mismatch_accepted += 1
		_ = service.drain()
		# Ten controlled 100-receipt bursts; each burst stays within budget and is drained immediately.
		for burst_index in range(BURST_COUNT):
			family = rawFamilies[burst_index % len(rawFamilies)]
			burst_start = time.perf_counter()
			for _ in range(BURST_SIZE):
				if rawSource.observe(family, _descriptor(requested_pid), issuedGeneration=generation):
					families_forwarded.add(str(family.value))
			burst_max_ms = max(burst_max_ms, (time.perf_counter() - burst_start) * 1000.0)
			drain_start = time.perf_counter()
			_ = service.drain()
			processing_max_ms = max(processing_max_ms, (time.perf_counter() - drain_start) * 1000.0)
		# One production NVDA event through exact-once forwarding.
		nvda_forwarded = 1 if nvdaSource.forward(nvdaFocus, _make_nvda_object(requested_pid)) else 0
		_ = service.drain()
		# Secure transition modeled as a generation flip: pre-transition callbacks must be refused.
		forwarding_before_secure = rawSource.forwardCount
		rawSource.invalidate()
		secure_deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
		while time.perf_counter() < secure_deadline:
			_ = rawSource.observe(rawFamilies[1], _descriptor(requested_pid), issuedGeneration=generation)
			time.sleep(0.01)
		_ = service.drain()
		secure_mutations = rawSource.forwardCount - forwarding_before_secure

		snapshot: Any = service.historySnapshot()
		rows: Any = snapshot.rows
		families_seen = sorted(families_forwarded)
		pid_mismatch = sum(1 for row in rows if int(row.processId) != requested_pid)
		forwarding_count = int(rawSource.forwardCount) - raw_forwarding_baseline + nvda_forwarded
		receipt_count = len(rows)

		metrics["providerAccessesBaseline"] = int(rawSource.providerAccesses)
		metrics["retainedBaseline"] = receipt_count
		return {
			"callbackMaxMs": float(rawSource.callbackMaxMs),
			"forwardingMaxMs": float(rawSource.forwardingMaxMs),
			"burst100MaxMs": burst_max_ms,
			"receiptToProcessingMaxMs": processing_max_ms,
			"receiptToPropertyReadMaxMs": receipt_to_property_read_ms,
			"eventFamiliesObserved": tuple(families_seen),
			"pidMismatchAccepted": pid_mismatch + mismatch_accepted,
			"forwardingCount": forwarding_count,
			"receiptCount": receipt_count,
			"retainedRowDrops": int(snapshot.drops.retainedRowDrops),
			"productionNvdaForwarded": nvda_forwarded,
			"ownershipViolations": int(rawSource.ownershipViolations),
			"secureMutations": secure_mutations,
			"lateCallbacksAccepted": int(rawSource.lateCallbacksAccepted),
		}

	composition: Any = keystone.composition.buildProductionComposition()
	composition.start()
	production_started = True
	scope_kinds: list[str] = []
	out_of_subtree_accepted = 0

	def exercise_scope(
		kind: Any,
		scope_under_test: Any,
		descriptor: Any,
		*,
		rejected_descriptor: Any | None = None,
	) -> None:
		nonlocal out_of_subtree_accepted

		def scope_stimulus(service: Any) -> dict[str, object]:
			generation = rawSource.generation
			accepted = int(
				rawSource.observe(
					rawFamilies[0],
					descriptor,
					issuedGeneration=generation,
				),
			)
			rejected = 0
			if rejected_descriptor is not None:
				rejected = int(
					rawSource.observe(
						rawFamilies[0],
						rejected_descriptor,
						issuedGeneration=generation,
					),
				)
			_ = service.drain()
			return {"scopeAccepted": accepted, "outOfSubtreeAccepted": rejected}

		result: dict[str, object] = composition.runInstalledEventSourceObservation(
			scope=scope_under_test,
			sources=(rawSource, nvdaSource),
			stimulus=scope_stimulus,
			activeFilter=fullFilter,
		)
		out_of_subtree_accepted += int(cast(Any, result.get("outOfSubtreeAccepted", 0)))
		if (
			result.get("status") == "observed"
			and int(cast(Any, result.get("scopeAccepted", 0))) == 1
			and bool(result.get("monitorStarted"))
			and bool(result.get("monitorStopped"))
		):
			scope_kinds.append(str(kind.value))

	exercise_scope(
		monitorModule.MonitorScopeKind.ELEMENT,
		monitorModule.MonitorScope.element("Windows Explorer", requested_pid, root_identity),
		rawDescriptor(
			processId=requested_pid,
			executable=STORM_EXECUTABLE,
			name="Element",
			role="button",
			identity=root_identity,
		),
	)
	exercise_scope(
		monitorModule.MonitorScopeKind.SUBTREE,
		monitorModule.MonitorScope.subtree("Windows Explorer", requested_pid, root_identity),
		rawDescriptor(
			processId=requested_pid,
			executable=STORM_EXECUTABLE,
			name="Created descendant",
			role="button",
			identity=child_identity,
			ancestorIdentities=(root_identity,),
		),
		rejected_descriptor=rawDescriptor(
			processId=requested_pid,
			executable=STORM_EXECUTABLE,
			name="Outside subtree",
			role="button",
			identity=foreign_identity,
		),
	)
	exercise_scope(
		monitorModule.MonitorScopeKind.APPLICATION,
		monitorModule.MonitorScope.pinned("Windows Explorer", requested_pid),
		_descriptor(requested_pid),
	)
	exercise_scope(
		monitorModule.MonitorScopeKind.BROAD,
		monitorModule.MonitorScope.broadScope(),
		_descriptor(requested_pid + 1),
	)

	raw_forwarding_baseline = int(rawSource.forwardCount)
	observation: dict[str, Any] = composition.runInstalledEventSourceObservation(
		scope=scope,
		sources=(rawSource, nvdaSource),
		stimulus=stimulus,
		activeFilter=fullFilter,
	)

	# Post-teardown no-effect window: the shipped source is unsubscribed; nothing may forward or read.
	provider_before = int(rawSource.providerAccesses)
	forwards_before = int(rawSource.forwardCount)
	late_before = int(rawSource.lateCallbacksAccepted)
	generation_after = int(rawSource.generation)
	callbacks_observed_after = 0
	teardown_deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
	while time.perf_counter() < teardown_deadline:
		if rawSource.observe(rawFamilies[0], _descriptor(requested_pid), issuedGeneration=generation_after):
			callbacks_observed_after += 1
		time.sleep(0.01)
	provider_after = int(rawSource.providerAccesses) - provider_before
	subscriptions_after = int(rawSource.subscriptionCount)
	late_after = int(rawSource.lateCallbacksAccepted) - late_before
	retained_mutations_after = int(rawSource.forwardCount) - forwards_before

	identities: Any = observation.get("sourceIdentities", ())
	enabled_capabilities = tuple(sorted(str(name) for name in observation.get("enabledCapabilities", ())))

	if threading.get_ident() != session_thread:
		ownership_violations += 1

	holder["observations"] = InstalledEventSourceObservations(
		callbackMaxMs=float(observation.get("callbackMaxMs", 0.0)),
		forwardingMaxMs=float(observation.get("forwardingMaxMs", 0.0)),
		burst100MaxMs=float(observation.get("burst100MaxMs", 0.0)),
		receiptToProcessingMaxMs=float(observation.get("receiptToProcessingMaxMs", 0.0)),
		receiptToPropertyReadMaxMs=float(observation.get("receiptToPropertyReadMaxMs", 0.0)),
		eventFamiliesObserved=tuple(str(name) for name in observation.get("eventFamiliesObserved", ())),
		pidMismatchAccepted=int(observation.get("pidMismatchAccepted", 0)),
		forwardingCount=int(observation.get("forwardingCount", 0)),
		receiptCount=int(observation.get("receiptCount", 0)),
		retainedRowDrops=int(observation.get("retainedRowDrops", 0)),
		ownershipViolations=int(observation.get("ownershipViolations", 0)) + ownership_violations,
		lateCallbacksAccepted=int(observation.get("lateCallbacksAccepted", 0)) + late_after,
		subscriptionsAfterTeardown=subscriptions_after,
		retainedMutationsAfterTeardown=retained_mutations_after,
		secureMutations=int(observation.get("secureMutations", 0)),
		observationWindowMs=OBSERVATION_WINDOW_MS,
		enabledCapabilities=enabled_capabilities,
		configSectionRegistered=config_section_registered,
		installedTreeReady=installed_root.is_dir(),
		scopeKindsExercised=tuple(scope_kinds),
		productionNvdaForwarded=int(observation.get("productionNvdaForwarded", 0)),
		outOfSubtreeAccepted=out_of_subtree_accepted,
		rawSourceModule=_identity_field(identities, 0, "module"),
		rawSourceType=_identity_field(identities, 0, "type"),
		nvdaSourceModule=_identity_field(identities, 1, "module"),
		nvdaSourceType=_identity_field(identities, 1, "type"),
		productionCompositionStarted=bool(
			observation.get("productionCompositionStarted", production_started),
		),
		monitorStarted=bool(observation.get("monitorStarted", False)),
		monitorStopped=bool(observation.get("monitorStopped", False)),
		callbacksObservedAfterTeardown=callbacks_observed_after,
		providerAccessesAfterTeardown=provider_after,
	)


def collect(
	archive: Path,
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
) -> InstalledEventSourceObservations:
	"""Run the installed observation on a dedicated MTA thread and return real measurements.

	Any acquisition or composition failure is reported as an unavailable observation (exit 2); it is
	never silently converted into a pass.
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
		return InstalledEventSourceObservations(unavailableObservations=tuple(unavailable))

	holder: dict[str, Any] = {}
	errors: list[str] = []

	def worker() -> None:
		try:
			_run_session(archive, nvda_executable, source_profile, workspace, holder)
		except BaseException as err:  # noqa: BLE001 - report any acquisition failure as unavailable
			errors.append(type(err).__name__)

	thread = threading.Thread(target=worker, name="keystone-installed-event-sources", daemon=True)
	thread.start()
	thread.join(SESSION_TIMEOUT_S)

	if thread.is_alive():
		return InstalledEventSourceObservations(
			unavailableObservations=("installed event-source session exceeded its time budget",),
		)
	if errors:
		return InstalledEventSourceObservations(
			unavailableObservations=(f"installed event-source observation failed: {errors[0]}",),
		)
	observations = holder.get("observations")
	if not isinstance(observations, InstalledEventSourceObservations):
		return InstalledEventSourceObservations(
			unavailableObservations=("installed event-source session produced no observations",),
		)
	return observations


def runInstalledEventSourceObservation(
	archive: Path,
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
) -> ProbeResult:
	"""Collect and judge the installed production event-source observation in one call.

	This is the entry point used by the installed Inspector runner. It uses the already-installed
	archive and drives ``ProductionComposition.runInstalledEventSourceObservation``
	through the shipped ``RawUiaEventSource`` and ``NvdaEventSource``, and returns the judged
	:class:`ProbeResult` whose payload is the exact ``KEYSTONE_INSTALLED_EVENT_SOURCE_RESULT``
	object. Any acquisition or composition failure is judged unavailable (exit 2) and never a pass.
	"""

	return evaluate(collect(archive, nvda_executable, source_profile, workspace))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Installed event-source production observation probe.")
	_ = parser.add_argument("--archive", required=True, type=Path)
	_ = parser.add_argument("--nvda-executable", required=True, type=Path)
	_ = parser.add_argument("--source-profile", required=True, type=Path)
	_ = parser.add_argument("--workspace", required=True, type=Path)
	_ = parser.add_argument(
		"--prepare-install",
		action="store_true",
		help="verify and install the archive once, including its install task, then exit before restart",
	)
	return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
	args = _parse_args(argv)
	archive = Path(str(args.archive)).resolve()
	nvda_executable = Path(str(args.nvda_executable))
	source_profile = Path(str(args.source_profile))
	workspace = Path(str(args.workspace))
	if bool(args.prepare_install):
		try:
			installedRoot = prepareInstalledArchive(archive, nvda_executable, source_profile)
		except BaseException as error:  # noqa: BLE001 - installation preparation must fail closed
			payload = {
				"status": "failed",
				"archiveVerified": False,
				"installTaskCompleted": False,
				"installedTreeReady": False,
				"error": type(error).__name__,
			}
			_ = sys.stdout.write(INSTALL_PREFIX + json.dumps(payload, sort_keys=True) + "\n")
			return EXIT_FAILED
		payload = {
			"status": "prepared",
			"archiveVerified": True,
			"installTaskCompleted": True,
			"installedTreeReady": installedRoot.is_dir(),
		}
		_ = sys.stdout.write(INSTALL_PREFIX + json.dumps(payload, sort_keys=True) + "\n")
		return EXIT_PASS
	observations = collect(archive, nvda_executable, source_profile, workspace)
	result = evaluate(observations)
	line = RESULT_PREFIX + json.dumps(result.payload, sort_keys=True)
	try:
		_ = (workspace / "installed_event_source_result.json").write_text(
			json.dumps(result.payload, indent="\t"),
			encoding="utf-8",
		)
	except OSError:
		pass
	_ = sys.stdout.write(line + "\n")
	return result.exitCode


if __name__ == "__main__":
	raise SystemExit(main())
