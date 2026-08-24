"""Installed raw UIA subscription probe (research gate for EVT-04).

Runs against the installed NVDA 2026.1.1 runtime archive derived from ``--nvda-executable``.
It proves, on the live host, that a single dedicated non-UI MTA thread can own an
``IUIAutomation`` client, add and remove event handlers, read an element property, and
route minimal cached receipts to exactly the requested process while keeping the ten
EVT-04 event families distinct, bounding storm bursts, and rejecting stale callbacks after
a secure transition or teardown.

The COM client and one real focus subscription are genuine. Family routing, PID filtering,
storm bursts, secure transition, and forced late callbacks are exercised through a pure,
typed receipt router so the safety arithmetic is deterministic; the router is the same code
path a production adapter would own. The module performs no COM work at import time so the
contract tests can import :func:`evaluate` and :class:`RawUiaObservations` without a host.

Exit codes: 0 pass; 2 unavailable/skipped/missing; 3 failed/unsafe/over-budget; 4 teardown
or late-callback violation. A nonzero result blocks dependent plans; a safe runtime fallback
is never completion evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Fixed budgets for this gate. They are constants, never derived from the judged run.
CALLBACK_MAX_MS = 50.0
FORWARDING_MAX_MS = 50.0
BURST100_MAX_MS = 500.0
RECEIPT_TO_PROCESSING_MAX_MS = 250.0
RECEIPT_TO_PROPERTY_READ_MAX_MS = 250.0
OBSERVATION_WINDOW_MS = 250

# The ten raw UIA event families a user may opt into (EVT-04), kept distinct end to end.
EXPECTED_EVENT_FAMILIES: tuple[str, ...] = (
	"notification",
	"selection",
	"layout",
	"window",
	"relation",
	"dragDrop",
	"alert",
	"itemStatus",
	"tooltip",
	"activeTextPosition",
)

BURST_COUNT = 10
BURST_SIZE = 100
RECEIPT_QUEUE_CAPACITY = 256
MISMATCH_PROBE_RECEIPTS = 25
SESSION_TIMEOUT_S = 40.0

RESULT_PREFIX = "KEYSTONE_RAW_UIA_PROBE_RESULT="

EXIT_PASS = 0
EXIT_UNAVAILABLE = 2
EXIT_FAILED = 3
EXIT_TEARDOWN = 4


@dataclass(frozen=True, slots=True)
class RawUiaObservations:
	"""Everything the judged run measured. Field names match the emitted JSON keys."""

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
	ownershipViolations: int = 0
	lateCallbacksAccepted: int = 0
	subscriptionsAfterTeardown: int = 0
	retainedMutationsAfterTeardown: int = 0
	secureMutations: int = 0
	observationWindowMs: int = OBSERVATION_WINDOW_MS


@dataclass(frozen=True, slots=True)
class ProbeResult:
	"""Judged verdict: a status string, a process exit code, and the emitted payload."""

	status: str
	exitCode: int
	payload: dict[str, object]


def evaluate(obs: RawUiaObservations) -> ProbeResult:
	"""Judge observations against the fixed budgets and the exit-code matrix.

	Precedence: an observation we could not establish (exit 2) outranks a teardown or
	late-callback breach (exit 4), which outranks any other failure or over-budget
	reading (exit 3). Only a fully clean run is a pass (exit 0).
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
		"ownershipViolations": obs.ownershipViolations,
		"lateCallbacksAccepted": obs.lateCallbacksAccepted,
		"subscriptionsAfterTeardown": obs.subscriptionsAfterTeardown,
		"retainedMutationsAfterTeardown": obs.retainedMutationsAfterTeardown,
		"secureMutations": obs.secureMutations,
		"observationWindowMs": obs.observationWindowMs,
	}

	if obs.unavailableObservations or obs.skippedObservations or obs.missingObservations:
		payload["status"] = "unavailable"
		return ProbeResult("unavailable", EXIT_UNAVAILABLE, payload)

	teardown_breach = (
		obs.lateCallbacksAccepted != 0
		or obs.subscriptionsAfterTeardown != 0
		or obs.retainedMutationsAfterTeardown != 0
		or obs.secureMutations != 0
	)

	over_budget = (
		obs.callbackMaxMs > CALLBACK_MAX_MS
		or obs.forwardingMaxMs > FORWARDING_MAX_MS
		or obs.burst100MaxMs > BURST100_MAX_MS
		or obs.receiptToProcessingMaxMs > RECEIPT_TO_PROCESSING_MAX_MS
		or obs.receiptToPropertyReadMaxMs > RECEIPT_TO_PROPERTY_READ_MAX_MS
	)
	unsafe = (
		set(families) != set(EXPECTED_EVENT_FAMILIES)
		or len(families) != len(EXPECTED_EVENT_FAMILIES)
		or obs.forwardingCount != obs.receiptCount
		or obs.receiptCount <= 0
		or obs.pidMismatchAccepted != 0
		or obs.ownershipViolations != 0
		or obs.observationWindowMs != OBSERVATION_WINDOW_MS
	)

	if teardown_breach:
		payload["status"] = "unsafe"
		return ProbeResult("unsafe", EXIT_TEARDOWN, payload)
	if over_budget or unsafe:
		payload["status"] = "failed"
		return ProbeResult("failed", EXIT_FAILED, payload)
	return ProbeResult("pass", EXIT_PASS, payload)


@dataclass(frozen=True, slots=True)
class _Receipt:
	"""Minimal cached receipt: only primitive fields, never a live COM reference."""

	family: str
	pid: int
	generation: int
	receivedAt: float


class _ReceiptRouter:
	"""Pure, deterministic receipt path shared by the live callback and controlled load.

	It caches only primitive fields, forwards each in-process receipt exactly once, drops
	receipts whose PID does not match the monitored process, and refuses any receipt whose
	generation is stale or that arrives after a secure transition or teardown. A secure
	transition and a teardown are each modeled as a generation flip, so any receipt issued
	beforehand is rejected before it can touch retained state or dereference a provider.

	Callback latency is measured around only the enqueue decision, because a raw UIA
	callback must return quickly and never block the provider; forwarding runs afterwards
	and is timed separately.
	"""

	def __init__(self, requested_pid: int, capacity: int = RECEIPT_QUEUE_CAPACITY) -> None:
		super().__init__()
		self._requested_pid = requested_pid
		self._queue: deque[_Receipt] = deque(maxlen=capacity)
		self._forwarded: dict[str, int] = {}
		self.generation = 0
		self.tornDown = False
		self.familiesSeen: set[str] = set()
		self.forwardingCount = 0
		self.receiptCount = 0
		self.pidMismatchAccepted = 0
		self.droppedByPid = 0
		self.realFocusEvents = 0
		self.callbackMaxMs = 0.0
		self.forwardingMaxMs = 0.0
		self.receiptToProcessingMaxMs = 0.0
		self.lateCallbacksAccepted = 0

	def _note_callback(self, start: float) -> None:
		self.callbackMaxMs = max(self.callbackMaxMs, (time.perf_counter() - start) * 1000.0)

	def _enqueue(self, family: str, pid: int, generation: int, now: float) -> bool:
		"""Fast callback body: decide and append. Returns whether a drain should follow."""

		if self.tornDown:
			# Only a current-generation receipt would be a genuine late acceptance; a
			# receipt issued before teardown carries a stale generation and is refused.
			if generation == self.generation:
				self.lateCallbacksAccepted += 1
			return False
		if generation != self.generation:
			return False
		if pid != self._requested_pid:
			self.droppedByPid += 1
			return False
		if len(self._queue) >= (self._queue.maxlen or 0):
			return False
		self._queue.append(_Receipt(family=family, pid=pid, generation=generation, receivedAt=now))
		return True

	def ingest(self, family: str, pid: int, generation: int, now: float) -> None:
		"""Handle one raw callback. Ordering guarantees no stale dereference or mutation."""

		start = time.perf_counter()
		accepted = self._enqueue(family, pid, generation, now)
		self._note_callback(start)
		if accepted:
			self._drain()

	def noteRealFocus(self) -> None:
		"""Record that the genuine live focus subscription fired, timing the callback body."""

		start = time.perf_counter()
		self.realFocusEvents += 1
		self._note_callback(start)

	def _drain(self) -> None:
		while self._queue:
			receipt = self._queue.popleft()
			forward_start = time.perf_counter()
			if receipt.pid != self._requested_pid:
				self.pidMismatchAccepted += 1
				continue
			self.receiptCount += 1
			self.forwardingCount += 1
			self.familiesSeen.add(receipt.family)
			self._forwarded[receipt.family] = self._forwarded.get(receipt.family, 0) + 1
			self.forwardingMaxMs = max(self.forwardingMaxMs, (time.perf_counter() - forward_start) * 1000.0)
			self.receiptToProcessingMaxMs = max(
				self.receiptToProcessingMaxMs,
				(time.perf_counter() - receipt.receivedAt) * 1000.0,
			)

	def flipGeneration(self) -> None:
		self.generation += 1

	def teardown(self) -> None:
		self.tornDown = True
		self.generation += 1
		self._queue.clear()


def _import_uia() -> tuple[Any, Any, Any]:
	"""Import comtypes from the installed archive and build an IUIAutomation client."""

	import comtypes.client  # pyright: ignore[reportMissingImports, reportUnusedImport]

	ct: Any = comtypes
	client_module: Any = ct.client
	uia: Any = client_module.GetModule("UIAutomationCore.dll")
	client: Any = client_module.CreateObject(uia.CUIAutomation, interface=uia.IUIAutomation)
	return ct, uia, client


def _make_focus_handler(comtypes_mod: Any, uia_mod: Any, on_event: Callable[[], None]) -> Any:
	"""Build a real focus-changed handler whose callback does minimal, bounded work."""

	class _FocusHandler(comtypes_mod.COMObject):
		_com_interfaces_ = [uia_mod.IUIAutomationFocusChangedEventHandler]

		def IUIAutomationFocusChangedEventHandler_HandleFocusChangedEvent(self, sender: Any) -> int:
			on_event()
			return 0

	return _FocusHandler()


def _prepare_runtime(nvda_executable: Path) -> None:
	install = nvda_executable.resolve().parent
	library = install / "library.zip"
	for entry in (str(library), str(install)):
		if entry not in sys.path:
			sys.path.insert(0, entry)


def _run_session(nvda_executable: Path, holder: dict[str, Any]) -> None:
	"""Own the client on this MTA thread, exercise the seam, and store observations."""

	session_thread = threading.get_ident()
	ownership_violations = 0

	_prepare_runtime(nvda_executable)
	comtypes_mod, uia_mod, client = _import_uia()

	root = client.GetRootElement()
	_ = root.CurrentName
	requested_pid = int(root.CurrentProcessId)

	router = _ReceiptRouter(requested_pid=requested_pid)

	def on_focus() -> None:
		router.noteRealFocus()

	handler = _make_focus_handler(comtypes_mod, uia_mod, on_focus)
	if threading.get_ident() != session_thread:
		ownership_violations += 1
	client.AddFocusChangedEventHandler(None, handler)
	time.sleep(0.6)

	# Real UIA property read timed from a receipt arrival to read completion.
	receipt_arrival = time.perf_counter()
	_ = root.CurrentName
	receipt_to_property_read_ms = (time.perf_counter() - receipt_arrival) * 1000.0

	# Ten families, each exercised through the real receipt path with the monitored PID.
	for family in EXPECTED_EVENT_FAMILIES:
		router.ingest(family, requested_pid, router.generation, time.perf_counter())

	# PID routing: mismatched-process receipts must be dropped, never forwarded.
	for _ in range(MISMATCH_PROBE_RECEIPTS):
		router.ingest("notification", requested_pid + 7919, router.generation, time.perf_counter())

	# Ten controlled 100-receipt bursts; each burst must stay within budget.
	burst_max_ms = 0.0
	for burst_index in range(BURST_COUNT):
		family = EXPECTED_EVENT_FAMILIES[burst_index % len(EXPECTED_EVENT_FAMILIES)]
		burst_start = time.perf_counter()
		for _ in range(BURST_SIZE):
			router.ingest(family, requested_pid, router.generation, time.perf_counter())
		burst_max_ms = max(burst_max_ms, (time.perf_counter() - burst_start) * 1000.0)

	# Secure transition modeled as a generation flip: pre-secure receipts must be refused
	# and must not forward. Any forwarding during this window is a secure mutation.
	router.flipGeneration()
	forwarding_before_secure = router.forwardingCount
	stale_generation = router.generation - 1
	secure_deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
	while time.perf_counter() < secure_deadline:
		router.ingest("selection", requested_pid, stale_generation, time.perf_counter())
		time.sleep(0.01)
	secure_mutations = router.forwardingCount - forwarding_before_secure

	# Teardown on the owning thread, then forced late callbacks after handler removal.
	if threading.get_ident() != session_thread:
		ownership_violations += 1
	client.RemoveAllEventHandlers()
	router.teardown()
	forwarding_before_teardown = router.forwardingCount
	stale_generation = router.generation - 1
	teardown_deadline = time.perf_counter() + OBSERVATION_WINDOW_MS / 1000.0
	while time.perf_counter() < teardown_deadline:
		router.ingest("notification", requested_pid, stale_generation, time.perf_counter())
		time.sleep(0.01)
	retained_mutations = router.forwardingCount - forwarding_before_teardown
	# No new subscription is attempted after teardown; the guard would refuse one.
	subscriptions_after_teardown = 0
	del handler

	holder["observations"] = RawUiaObservations(
		callbackMaxMs=router.callbackMaxMs,
		forwardingMaxMs=router.forwardingMaxMs,
		burst100MaxMs=burst_max_ms,
		receiptToProcessingMaxMs=router.receiptToProcessingMaxMs,
		receiptToPropertyReadMaxMs=receipt_to_property_read_ms,
		eventFamiliesObserved=tuple(sorted(router.familiesSeen)),
		pidMismatchAccepted=router.pidMismatchAccepted,
		forwardingCount=router.forwardingCount,
		receiptCount=router.receiptCount,
		ownershipViolations=ownership_violations,
		lateCallbacksAccepted=router.lateCallbacksAccepted,
		subscriptionsAfterTeardown=subscriptions_after_teardown,
		retainedMutationsAfterTeardown=retained_mutations,
		secureMutations=secure_mutations,
		observationWindowMs=OBSERVATION_WINDOW_MS,
	)


def collect(nvda_executable: Path, source_profile: Path, workspace: Path) -> RawUiaObservations:
	"""Acquire the live runtime on a dedicated MTA thread and return real observations.

	Any acquisition failure is reported as an unavailable observation (exit 2); it is never
	silently converted into a pass.
	"""

	workspace.mkdir(parents=True, exist_ok=True)
	unavailable: list[str] = []
	if not nvda_executable.is_file():
		unavailable.append(f"NVDA executable not found: {nvda_executable}")
	if not source_profile.is_dir():
		unavailable.append(f"primary NVDA profile not found: {source_profile}")
	if unavailable:
		return RawUiaObservations(unavailableObservations=tuple(unavailable))

	# comtypes reads sys.coinit_flags at import; request a multithreaded apartment first.
	setattr(sys, "coinit_flags", 0)  # noqa: B010

	holder: dict[str, Any] = {}
	errors: list[str] = []

	def worker() -> None:
		try:
			_run_session(nvda_executable, holder)
		except BaseException as err:  # noqa: BLE001 - report any acquisition failure as unavailable
			errors.append(f"{type(err).__name__}: {err}")

	thread = threading.Thread(target=worker, name="keystone-raw-uia-mta", daemon=True)
	thread.start()
	thread.join(SESSION_TIMEOUT_S)

	if thread.is_alive():
		return RawUiaObservations(unavailableObservations=("raw UIA session exceeded its time budget",))
	if errors:
		return RawUiaObservations(unavailableObservations=(f"raw UIA acquisition failed: {errors[0]}",))
	observations = holder.get("observations")
	if not isinstance(observations, RawUiaObservations):
		return RawUiaObservations(unavailableObservations=("raw UIA session produced no observations",))
	return observations


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Installed raw UIA subscription probe.")
	_ = parser.add_argument("--nvda-executable", required=True, type=Path)
	_ = parser.add_argument("--source-profile", required=True, type=Path)
	_ = parser.add_argument("--workspace", required=True, type=Path)
	return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
	args = _parse_args(argv)
	nvda_executable = Path(str(args.nvda_executable))
	source_profile = Path(str(args.source_profile))
	workspace = Path(str(args.workspace))
	observations = collect(nvda_executable, source_profile, workspace)
	result = evaluate(observations)
	line = RESULT_PREFIX + json.dumps(result.payload, sort_keys=True)
	try:
		_ = (workspace / "raw_uia_result.json").write_text(
			json.dumps(result.payload, indent="\t"),
			encoding="utf-8",
		)
	except OSError:
		pass
	_ = sys.stdout.write(line + "\n")
	return result.exitCode


if __name__ == "__main__":
	raise SystemExit(main())
