"""Installed live Inspector capture probe (integration gate for INSP-07/12/15).

Runs against the installed NVDA runtime archive derived from ``--nvda-executable``. It proves,
on the live host, that the production command runtime reads the *currently focused* object through
the real read-only capture seam, projects it as a *live* Inspector source, and hands a browsable
hierarchy to the shared :class:`InspectorService` -- the same source the native workspace renders.

The capture is genuine: it resolves the real selection through ``NvdaSelectedObjectSource``, runs
``captureForInspection`` (foreground+navigator admissible, nothing published, no baseline replaced),
and projects the in-memory snapshot through the validated offline projection while presenting a live
identity so Follow Focus stays available. Building the production composition is withheld unless the
caller passes ``--allow-composition`` on a disposable host, because assembling it touches the
installed NVDA configuration surface; the default run records that obstruction rather than mutating a
real profile. The module performs no host work at import time, so the contract tests can import
:func:`evaluate` and :class:`LiveInspectorObservations` without a host.

Exit codes: 0 pass; 2 unavailable/skipped/missing; 3 failed/unsafe/over-budget. A nonzero result
blocks dependent plans; a safe runtime fallback is never completion evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from importlib import import_module
import json
from pathlib import Path
import sys
import threading
import time
from typing import Any

# The whole read -- selection, capture, projection -- must complete well inside this bound. It is a
# constant, never derived from the judged run.
BUILD_MAX_MS = 2000.0
SESSION_TIMEOUT_S = 40.0

RESULT_PREFIX = "KEYSTONE_LIVE_INSPECTOR_PROBE_RESULT="

EXIT_PASS = 0
EXIT_UNAVAILABLE = 2
EXIT_FAILED = 3


@dataclass(frozen=True, slots=True)
class LiveInspectorObservations:
	"""Everything the judged run measured. Field names match the emitted JSON keys."""

	unavailableObservations: tuple[str, ...] = ()
	skippedObservations: tuple[str, ...] = ()
	missingObservations: tuple[str, ...] = ()
	sourceBuilt: bool = False
	identityKind: str = ""
	executable: str = ""
	processId: int = -1
	rawReason: str = ""
	followFocusAvailable: bool = False
	rootCount: int = 0
	serviceIdentityLive: bool = False
	closedCleanly: bool = False
	buildMaxMs: float = 0.0
	focusExecutable: str = ""
	focusProcessId: int = -1
	foregroundExecutable: str = ""
	foregroundProcessId: int = -1
	buildBudgetMs: float = BUILD_MAX_MS


@dataclass(frozen=True, slots=True)
class ProbeResult:
	"""Judged verdict: a status string, a process exit code, and the emitted payload."""

	status: str
	exitCode: int
	payload: dict[str, object]


def evaluate(obs: LiveInspectorObservations) -> ProbeResult:
	"""Judge observations against the fixed budget and the exit-code matrix.

	Precedence: an observation we could not establish (exit 2) outranks any failure or
	over-budget reading (exit 3). Only a fully clean run -- a live source built from the focused
	target, a non-empty hierarchy handed to the service, a clean release, and no leaked raw
	reason -- is a pass (exit 0).
	"""

	payload: dict[str, object] = {
		"status": "pass",
		"unavailableObservations": list(obs.unavailableObservations),
		"skippedObservations": list(obs.skippedObservations),
		"missingObservations": list(obs.missingObservations),
		"sourceBuilt": obs.sourceBuilt,
		"identityKind": obs.identityKind,
		"executable": obs.executable,
		"processId": obs.processId,
		"rawReason": obs.rawReason,
		"followFocusAvailable": obs.followFocusAvailable,
		"rootCount": obs.rootCount,
		"serviceIdentityLive": obs.serviceIdentityLive,
		"closedCleanly": obs.closedCleanly,
		"buildMaxMs": round(obs.buildMaxMs, 3),
		"focusExecutable": obs.focusExecutable,
		"focusProcessId": obs.focusProcessId,
		"foregroundExecutable": obs.foregroundExecutable,
		"foregroundProcessId": obs.foregroundProcessId,
		"buildBudgetMs": obs.buildBudgetMs,
	}

	if obs.unavailableObservations or obs.skippedObservations or obs.missingObservations:
		payload["status"] = "unavailable"
		return ProbeResult("unavailable", EXIT_UNAVAILABLE, payload)

	over_budget = obs.buildMaxMs > BUILD_MAX_MS
	unsafe = (
		not obs.sourceBuilt
		or obs.identityKind != "live"
		or not obs.followFocusAvailable
		or obs.rawReason != ""
		or obs.rootCount <= 0
		or not obs.serviceIdentityLive
		or not obs.closedCleanly
		or not obs.executable
		or obs.processId < 0
		or obs.processId != obs.focusProcessId
	)

	if over_budget or unsafe:
		payload["status"] = "failed"
		return ProbeResult("failed", EXIT_FAILED, payload)
	return ProbeResult("pass", EXIT_PASS, payload)


def _prepare_runtime(nvda_executable: Path) -> None:
	install = nvda_executable.resolve().parent
	library = install / "library.zip"
	# The add-on package lives at the repository root; put it on the path so the deferred
	# ``addon...`` imports resolve when the probe is launched as a standalone script.
	repo_root = Path(__file__).resolve().parents[2]
	for entry in (str(repo_root), str(library), str(install)):
		if entry not in sys.path:
			sys.path.insert(0, entry)


def _executable_of(obj: Any) -> str:
	appModule = getattr(obj, "appModule", None)
	appName = getattr(appModule, "appName", "") if appModule is not None else ""
	name = str(appName or "").strip()
	if not name:
		return ""
	return name if name.endswith(".exe") else f"{name}.exe"


def _run_capture(holder: dict[str, Any]) -> None:
	"""Drive the real production runtime on the host and store observations.

	Nothing here is faked: the runtime resolves the live selection, captures it in memory without
	publishing, projects a live source, and the shared service renders it. Any failure to reach a
	genuine live source is recorded as an unavailable observation, never converted into a pass.
	"""

	# Deferred imports: the add-on package and the NVDA runtime are only importable once the host
	# archive is on sys.path, so importing at module scope would break off-host contract tests.
	from addon.globalPlugins.keystone.adapters.nvda.commands import ProductionCommandRuntime
	from addon.globalPlugins.keystone.adapters.nvda.composition import buildProductionComposition

	api = import_module("api")
	foreground = api.getForegroundObject()
	focus = api.getFocusObject()
	if foreground is None or focus is None:
		holder["observations"] = LiveInspectorObservations(
			unavailableObservations=("no live foreground or focus object (NVDA core not running)",),
		)
		return

	focusExecutable = _executable_of(focus)
	focusProcessId = int(getattr(focus, "processID", -1))
	foregroundExecutable = _executable_of(foreground)
	foregroundProcessId = int(getattr(foreground, "processID", -1))

	composition = buildProductionComposition()
	composition.start()
	try:
		runtime = getattr(composition, "_commandRuntime", None)
		if not isinstance(runtime, ProductionCommandRuntime):
			holder["observations"] = LiveInspectorObservations(
				unavailableObservations=("production command runtime was not configured",),
				focusExecutable=focusExecutable,
				focusProcessId=focusProcessId,
				foregroundExecutable=foregroundExecutable,
				foregroundProcessId=foregroundProcessId,
			)
			return

		start = time.perf_counter()
		source = runtime._buildLiveInspectorSource("focus")  # pyright: ignore[reportPrivateUsage]
		buildMs = (time.perf_counter() - start) * 1000.0
		if source is None:
			holder["observations"] = LiveInspectorObservations(
				unavailableObservations=("live capture did not commit for the focus target",),
				focusExecutable=focusExecutable,
				focusProcessId=focusProcessId,
				foregroundExecutable=foregroundExecutable,
				foregroundProcessId=foregroundProcessId,
				buildMaxMs=buildMs,
			)
			return

		identity = source.identity()
		roots = source.roots()
		service = import_module(
			"addon.globalPlugins.keystone.application.inspector_service",
		).InspectorService()
		service.openSource(source)
		serviceIdentity = service.sourceIdentity()
		serviceLive = serviceIdentity is not None and str(serviceIdentity.kind.value) == "live"

		closedCleanly = True
		try:
			service.close()
			source.close()
		except Exception:  # noqa: BLE001 - a release failure is a lifecycle fault, not a pass
			closedCleanly = False

		holder["observations"] = LiveInspectorObservations(
			sourceBuilt=True,
			identityKind=str(identity.kind.value),
			executable=str(identity.executable),
			processId=int(identity.processId),
			rawReason="" if identity.rawReason is None else str(identity.rawReason),
			followFocusAvailable=bool(identity.followFocusAvailable),
			rootCount=len(roots),
			serviceIdentityLive=serviceLive,
			closedCleanly=closedCleanly,
			buildMaxMs=buildMs,
			focusExecutable=focusExecutable,
			focusProcessId=focusProcessId,
			foregroundExecutable=foregroundExecutable,
			foregroundProcessId=foregroundProcessId,
		)
	finally:
		composition.close()


def collect(
	nvda_executable: Path,
	source_profile: Path,
	workspace: Path,
	*,
	allowComposition: bool = False,
) -> LiveInspectorObservations:
	"""Acquire the live runtime on a dedicated thread and return real observations.

	Any acquisition failure is reported as an unavailable observation (exit 2); it is never
	silently converted into a pass. Building the production composition is withheld unless
	``allowComposition`` is set, so a default run never mutates an installed NVDA profile.
	"""

	workspace.mkdir(parents=True, exist_ok=True)
	unavailable: list[str] = []
	if not nvda_executable.is_file():
		unavailable.append(f"NVDA executable not found: {nvda_executable}")
	if not source_profile.is_dir():
		unavailable.append(f"primary NVDA profile not found: {source_profile}")
	if unavailable:
		return LiveInspectorObservations(unavailableObservations=tuple(unavailable))

	if not allowComposition:
		return LiveInspectorObservations(
			skippedObservations=(
				"live Inspector capture requires --allow-composition on a disposable NVDA host; "
				+ "assembling the production composition touches the installed configuration surface "
				+ "and is withheld by default so a real profile is never mutated",
			),
		)

	_prepare_runtime(nvda_executable)

	holder: dict[str, Any] = {}
	errors: list[str] = []

	def worker() -> None:
		try:
			_run_capture(holder)
		except BaseException as err:  # noqa: BLE001 - report any acquisition failure as unavailable
			errors.append(f"{type(err).__name__}: {err}")

	thread = threading.Thread(target=worker, name="keystone-live-inspector", daemon=True)
	thread.start()
	thread.join(SESSION_TIMEOUT_S)

	if thread.is_alive():
		return LiveInspectorObservations(
			unavailableObservations=("live Inspector capture exceeded its time budget",),
		)
	if errors:
		return LiveInspectorObservations(
			unavailableObservations=(f"live Inspector capture failed: {errors[0]}",),
		)
	observations = holder.get("observations")
	if not isinstance(observations, LiveInspectorObservations):
		return LiveInspectorObservations(
			unavailableObservations=("live Inspector capture produced no observations",),
		)
	return observations


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Installed live Inspector capture probe.")
	_ = parser.add_argument("--nvda-executable", required=True, type=Path)
	_ = parser.add_argument("--source-profile", required=True, type=Path)
	_ = parser.add_argument("--workspace", required=True, type=Path)
	_ = parser.add_argument(
		"--allow-composition",
		action="store_true",
		help="permit building the production composition on a disposable NVDA host",
	)
	return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	args = _parse_args(argv)
	nvda_executable = Path(str(args.nvda_executable))
	source_profile = Path(str(args.source_profile))
	workspace = Path(str(args.workspace))
	observations = collect(
		nvda_executable,
		source_profile,
		workspace,
		allowComposition=bool(args.allow_composition),
	)
	result = evaluate(observations)
	line = RESULT_PREFIX + json.dumps(result.payload, sort_keys=True)
	try:
		_ = (workspace / "live_inspector_result.json").write_text(
			json.dumps(result.payload, indent="\t"),
			encoding="utf-8",
		)
	except OSError:
		pass
	_ = sys.stdout.write(line + "\n")
	return result.exitCode


if __name__ == "__main__":
	raise SystemExit(main())
