# pyright: reportPrivateUsage=false
"""Contract tests for the installed Inspector review runner and installed event-source observation.

``InstalledEventSourceObservationTests`` freezes the installed production event-source observation
schema and every fail-closed category: a clean shipped observation passes, while a missing/malformed
result, a non-shipped source identity, false production start/stop state, family/PID/arithmetic drift,
any post-stop callback/provider/history effect, and any unavailable/skipped/unsafe/late/over-budget
outcome each map to their exact documented exit code. ``ReviewRunner*Tests`` freeze the review runner
evaluator: its emitted schema, the linear keyboard/NVDA-first scenario set (with the three
STATE-superseded visual gates excluded), the runner-argument surface, its privacy discipline, and that
every blocking outcome exits nonzero while only a clean, fully enabled, human-approved run passes.

Importing the runner and the probe does no host, COM, wx, or audio work, so these contracts run
anywhere.
"""

from __future__ import annotations

import dataclasses
import inspect
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from typing import cast
from unittest.mock import patch
from zipfile import ZipFile

from tests.live import probe_installed_event_sources as installedProbe
from tests.live import review_inspector_workspace as review
from addon.globalPlugins.keystone.adapters.providers import raw_uia as rawUiaModule

STATUS_BY_EXIT = {
	installedProbe.EXIT_PASS: "pass",
	installedProbe.EXIT_UNAVAILABLE: "unavailable",
	installedProbe.EXIT_FAILED: "failed",
	installedProbe.EXIT_TEARDOWN: "unsafe",
}

REVIEW_STATUS_BY_EXIT = {
	review.EXIT_PASS: "pass",
	review.EXIT_UNAVAILABLE: "unavailable",
	review.EXIT_FAILED: "failed",
	review.EXIT_TEARDOWN: "unsafe",
	review.EXIT_HUMAN: "incomplete-human-review",
}

_BUILD_ID = "sha256:" + "a" * 64


def _clean_installed() -> installedProbe.InstalledEventSourceObservations:
	"""A fully valid installed production observation that must judge as a clean pass."""

	return installedProbe.InstalledEventSourceObservations(
		callbackMaxMs=1.0,
		forwardingMaxMs=1.0,
		burst100MaxMs=10.0,
		receiptToProcessingMaxMs=5.0,
		receiptToPropertyReadMaxMs=5.0,
		eventFamiliesObserved=installedProbe.EXPECTED_EVENT_FAMILIES,
		forwardingCount=1011,
		receiptCount=1011,
		retainedRowDrops=0,
		observationWindowMs=installedProbe.OBSERVATION_WINDOW_MS,
		enabledCapabilities=("eventMonitoring", "rawUiaInspection"),
		configSectionRegistered=True,
		installedTreeReady=True,
		scopeKindsExercised=("element", "subtree", "application", "broad"),
		productionNvdaForwarded=1,
		outOfSubtreeAccepted=0,
		rawSourceModule="keystone.adapters.windows.raw_uia_events",
		rawSourceType="RawUiaEventSource",
		nvdaSourceModule="keystone.adapters.nvda.event_sources",
		nvdaSourceType="NvdaEventSource",
		productionCompositionStarted=True,
		monitorStarted=True,
		monitorStopped=True,
	)


def _clean_installed_payload() -> dict[str, object]:
	return dict(installedProbe.evaluate(_clean_installed()).payload)


def _clean_review() -> review.InstalledReviewResult:
	"""A fully valid, human-approved installed review that must judge as a clean pass."""

	return review.InstalledReviewResult(
		buildIdentifier=_BUILD_ID,
		enabledCapabilities=(
			"audioFeedback",
			"eventMonitoring",
			"rawUiaInspection",
			"screenCapture",
			"userInterface",
		),
		archiveRemainsInstalled=True,
		wxCallbackMaxMs=1.0,
		focusMatchNodesMax=1,
		focusMatchDepthMax=12,
		rawUiaCallbackMaxMs=1.0,
		forwardingMaxMs=1.0,
		burst100MaxMs=10.0,
		receiptToProcessingMaxMs=5.0,
		receiptToPropertyReadMaxMs=5.0,
		soundDispatchMaxMs=1.0,
		speechSubmitMaxMs=1.0,
		replacementStartMaxMs=1.0,
		interAtomGapMinMs=30.0,
		interAtomGapMaxMs=30.0,
		screenshotStatus="value",
		screenshotBytes=128,
		eventFilterDialogPresent=True,
		annotationsTabPresent=True,
		scopeKindsExercised=("element", "subtree", "application", "broad"),
		rawEvidenceNativeProxyField=True,
		rawProjectionRequested=True,
		rawProjectionApplied=True,
		rawProjectionStatus="applied",
		rawProjectionMethod="pythonIdentity",
		rawProjectionReason="KS.RAW_UIA.PYTHON_IDENTITY",
		rawProjectionEvidenceQuality="native",
		rawProjectionEvidencePresent=True,
		ordinaryUiaSectionPresent=True,
		inspectorRawRetargetSucceeded=True,
		inspectorRawRetargetRequested=True,
		inspectorRawRetargetApplied=True,
		inspectorRawRetargetSourceGeneration=2,
		hostProcessId=7368,
		loadedCodeIdentifier=f"sha256:{'a' * 64}",
		loadedCodeMatchesArchive=True,
		buildBatPublishedToDist=True,
		configSectionRegistered=True,
		installedTreeReady=True,
		observationWindowMs=review.OBSERVATION_WINDOW_MS,
		humanChecklistStatus="approved",
		installedEventSourceObservation=_clean_installed_payload(),
	)


class InstalledEventSourceObservationTests(unittest.TestCase):
	"""The installed production event-source observation must honor its schema and exit matrix."""

	def test_shipped_sources_start_storm_stop_and_no_effect_window(self) -> None:
		base = _clean_installed()
		clean = installedProbe.evaluate(base)
		self.assertEqual(clean.status, "pass")
		self.assertEqual(clean.exitCode, installedProbe.EXIT_PASS)

		# Schema: the payload carries status plus exactly every observation field.
		schema = {field.name for field in dataclasses.fields(installedProbe.InstalledEventSourceObservations)}
		self.assertEqual(set(clean.payload.keys()), {"status"} | schema)
		self.assertEqual(installedProbe.RESULT_PREFIX, "KEYSTONE_INSTALLED_EVENT_SOURCE_RESULT=")

		replace = dataclasses.replace
		unavail = installedProbe.EXIT_UNAVAILABLE
		failed = installedProbe.EXIT_FAILED
		teardown = installedProbe.EXIT_TEARDOWN
		families = installedProbe.EXPECTED_EVENT_FAMILIES
		cases: list[tuple[str, installedProbe.InstalledEventSourceObservations, int]] = [
			# Missing / unestablished installed result.
			("unavailable", replace(base, unavailableObservations=("session",)), unavail),
			("skipped", replace(base, skippedObservations=("composition",)), unavail),
			("missing_result", replace(base, missingObservations=("digest",)), unavail),
			# Non-shipped source identity.
			("non_shipped_raw_type", replace(base, rawSourceType="FakeSource"), failed),
			("non_shipped_raw_module", replace(base, rawSourceModule="tests.fakes"), failed),
			("non_shipped_nvda_type", replace(base, nvdaSourceType="FakeSource"), failed),
			("non_shipped_nvda_module", replace(base, nvdaSourceModule="tests.fakes"), failed),
			# False production start/stop state.
			("not_started", replace(base, productionCompositionStarted=False), failed),
			("monitor_not_started", replace(base, monitorStarted=False), failed),
			("monitor_not_stopped", replace(base, monitorStopped=False), failed),
			# Family / PID / arithmetic drift.
			("family_drift", replace(base, eventFamiliesObserved=families[:-1]), failed),
			("pid_mismatch", replace(base, pidMismatchAccepted=1), failed),
			("count_drift", replace(base, forwardingCount=base.receiptCount - 1), failed),
			("no_receipts", replace(base, forwardingCount=0, receiptCount=0), failed),
			("ownership", replace(base, ownershipViolations=1), failed),
			("window_drift", replace(base, observationWindowMs=200), failed),
			# Enablement / capability binding gaps.
			("missing_caps", replace(base, enabledCapabilities=("eventMonitoring",)), failed),
			# Over budget.
			("callback_over", replace(base, callbackMaxMs=installedProbe.CALLBACK_MAX_MS + 0.1), failed),
			("burst_over", replace(base, burst100MaxMs=installedProbe.BURST100_MAX_MS + 0.1), failed),
			# Post-stop callback / provider / history effect (teardown breach).
			("late_callback", replace(base, lateCallbacksAccepted=1), teardown),
			("subs_after", replace(base, subscriptionsAfterTeardown=1), teardown),
			("callbacks_after", replace(base, callbacksObservedAfterTeardown=1), teardown),
			("provider_after", replace(base, providerAccessesAfterTeardown=1), teardown),
			("retained_after", replace(base, retainedMutationsAfterTeardown=1), teardown),
			("secure_mutation", replace(base, secureMutations=1), teardown),
			# Precedence.
			(
				"unavailable_outranks_teardown",
				replace(base, missingObservations=("x",), lateCallbacksAccepted=1),
				unavail,
			),
			(
				"teardown_outranks_failed",
				replace(base, lateCallbacksAccepted=1, ownershipViolations=1),
				teardown,
			),
		]
		for label, obs, expected_exit in cases:
			with self.subTest(case=label):
				result = installedProbe.evaluate(obs)
				self.assertNotEqual(result.exitCode, installedProbe.EXIT_PASS)
				self.assertEqual(result.exitCode, expected_exit)
				self.assertEqual(result.status, STATUS_BY_EXIT[expected_exit])


class ReviewRunnerSchemaTests(unittest.TestCase):
	"""The review evaluator must honor its schema, budgets, and pass conditions."""

	def test_clean_approved_baseline_passes(self) -> None:
		result = review.evaluate(_clean_review())
		self.assertEqual(result.status, "pass")
		self.assertEqual(result.exitCode, review.EXIT_PASS)

	def test_payload_emits_status_and_every_result_field(self) -> None:
		result = review.evaluate(_clean_review())
		schema = {field.name for field in dataclasses.fields(review.InstalledReviewResult)}
		self.assertEqual(set(result.payload.keys()), {"status"} | schema)
		self.assertTrue(
			{
				"buildIdentifier",
				"enabledCapabilities",
				"archiveRemainsInstalled",
				"installedEventSourceObservation",
				"eventFilterDialogPresent",
				"annotationsTabPresent",
				"scopeKindsExercised",
				"rawEvidenceNativeProxyField",
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
				"loadedCodeMatchesArchive",
				"buildBatPublishedToDist",
				"screenshotStatus",
				"screenshotBytes",
				"configSectionRegistered",
				"installedTreeReady",
				"humanChecklistStatus",
			}.issubset(schema),
		)

	def test_result_prefix_is_stable(self) -> None:
		self.assertEqual(review.RESULT_PREFIX, "KEYSTONE_INSPECTOR_REVIEW_RESULT=")

	def test_runner_uses_runtime_capabilities_without_decision_records(self) -> None:
		self.assertFalse(hasattr(review, "_reviewDecisions"))
		self.assertNotIn(
			"archiveSha256",
			{field.name for field in dataclasses.fields(review.InstalledReviewResult)},
		)
		self.assertNotIn(
			"archiveSha256",
			{field.name for field in dataclasses.fields(installedProbe.InstalledEventSourceObservations)},
		)

	def test_embedded_installed_observation_is_the_exact_object(self) -> None:
		payload = review.evaluate(_clean_review()).payload
		embedded = payload["installedEventSourceObservation"]
		self.assertIsInstance(embedded, dict)
		installed_schema = {
			field.name for field in dataclasses.fields(installedProbe.InstalledEventSourceObservations)
		}
		assert isinstance(embedded, dict)
		embedded_keys = set(cast("dict[str, object]", embedded).keys())
		self.assertEqual(embedded_keys, {"status"} | installed_schema)

	def test_build_identifier_is_informational_and_never_controls_the_verdict(self) -> None:
		self.assertEqual(
			review.evaluate(dataclasses.replace(_clean_review(), buildIdentifier="")).status,
			"pass",
		)

	def test_capabilities_are_combined_from_their_dedicated_runtime_checks(self) -> None:
		installed = {"enabledCapabilities": ["eventMonitoring", "rawUiaInspection"]}

		enabled = review._reviewCapabilities(
			installed,
			soundReady=True,
			screenshotReady=True,
			userInterfaceReady=True,
		)

		self.assertTrue(review.REQUIRED_CAPABILITIES.issubset(enabled))

	def test_in_process_runtime_result_supplies_screenshot_and_capability_evidence(self) -> None:
		with TemporaryDirectory() as directory:
			path = Path(directory) / "runtime.json"
			payload = {
				"status": "pass",
				"enabledCapabilities": ["screenCapture", "userInterface"],
				"screenshotStatus": "value",
				"screenshotBytes": 128,
				"rawProjectionRequested": True,
				"rawProjectionApplied": False,
				"rawProjectionStatus": "rejected",
				"rawProjectionMethod": "none",
				"rawProjectionReason": "KS.RAW_UIA.NO_CANDIDATE",
				"rawProjectionEvidenceQuality": "incomplete",
				"rawProjectionEvidencePresent": True,
				"ordinaryUiaSectionPresent": True,
				"inspectorRawRetargetSucceeded": True,
				"inspectorRawRetargetRequested": True,
				"inspectorRawRetargetApplied": False,
				"inspectorRawRetargetSourceGeneration": 2,
				"hostProcessId": 7368,
				"loadedCodeIdentifier": f"sha256:{'a' * 64}",
				"reviewHookModulePath": r"C:\profile\addons\keystone\globalPlugins\keystone\adapters\nvda\review_hook.py",
				"reviewHookModuleSha256": "a" * 64,
				"rawUiaModulePath": r"C:\profile\addons\keystone\globalPlugins\keystone\adapters\providers\raw_uia.py",
				"rawUiaModuleSha256": "b" * 64,
				"selectedObjectsModulePath": r"C:\profile\addons\keystone\globalPlugins\keystone\adapters\nvda\selected_objects.py",
				"selectedObjectsModuleSha256": "c" * 64,
			}
			_ = path.write_text(__import__("json").dumps(payload), encoding="utf-8")

			self.assertEqual(payload, review._loadRuntimeResult(path))
			del payload["rawProjectionEvidencePresent"]
			_ = path.write_text(__import__("json").dumps(payload), encoding="utf-8")
			self.assertEqual({}, review._loadRuntimeResult(path))

	def test_loaded_module_paths_and_hashes_must_match_the_review_archive(self) -> None:
		with TemporaryDirectory() as directory:
			root = Path(directory) / "profile" / "addons" / "keystone"
			archive = Path(directory) / "keystone.nvda-addon"
			runtime: dict[str, object] = {}
			with ZipFile(archive, "w") as bundle:
				for index, (name, member) in enumerate(review._LOADED_MODULE_MEMBERS.items(), start=1):
					data = f"module-{index}".encode()
					bundle.writestr(member, data)
					modulePath = root / member
					modulePath.parent.mkdir(parents=True, exist_ok=True)
					_ = modulePath.write_bytes(data)
					runtime[f"{name}ModulePath"] = str(modulePath)
					runtime[f"{name}ModuleSha256"] = __import__("hashlib").sha256(data).hexdigest()

			self.assertTrue(review._loadedCodeMatchesArchive(runtime, archive, root))
			runtime["rawUiaModuleSha256"] = "0" * 64
			self.assertFalse(review._loadedCodeMatchesArchive(runtime, archive, root))

	def test_raw_projection_runtime_evidence_is_a_verdict_gate(self) -> None:
		missing = dataclasses.replace(_clean_review(), rawProjectionEvidencePresent=False)
		inconsistent = dataclasses.replace(
			_clean_review(),
			rawProjectionApplied=True,
			rawProjectionStatus="rejected",
		)
		staleCode = dataclasses.replace(_clean_review(), loadedCodeMatchesArchive=False)
		missingInspectorPath = dataclasses.replace(_clean_review(), inspectorRawRetargetRequested=False)

		self.assertEqual("failed", review.evaluate(missing).status)
		self.assertEqual("failed", review.evaluate(inconsistent).status)
		self.assertEqual("failed", review.evaluate(staleCode).status)
		self.assertEqual("failed", review.evaluate(missingInspectorPath).status)

	def test_raw_evidence_alias_exposes_native_and_proxy_values_at_runtime(self) -> None:
		self.assertTrue(
			{"native", "synthesizedProxy"}.issubset(
				review._typeAliasValues(rawUiaModule.RawEvidenceQuality),
			),
		)

	def test_delegated_host_probe_runs_in_a_fresh_interpreter_and_parses_its_result(self) -> None:
		payload = {"status": "pass", "value": 1}
		completed = SimpleNamespace(
			stdout="diagnostic\nPREFIX=" + __import__("json").dumps(payload) + "\n",
			returncode=0,
		)

		with patch.object(review.subprocess, "run", return_value=completed) as run:
			result = review._runDelegatedProbe(
				Path("probe.py"),
				("--flag", "value"),
				resultPrefix="PREFIX=",
			)

		self.assertEqual("pass", result.status)
		self.assertEqual(payload, result.payload)
		command = run.call_args.args[0]
		self.assertEqual(review.sys.executable, command[0])
		self.assertEqual(["probe.py", "--flag", "value"], command[1:])

	def test_automated_evaluation_stops_at_ready_for_human(self) -> None:
		pending = dataclasses.replace(_clean_review(), humanChecklistStatus="pending")

		result = review.evaluateAutomated(pending)

		self.assertEqual("ready-for-human", result.status)
		self.assertEqual(review.EXIT_PASS, result.exitCode)
		self.assertEqual("pending", result.payload["humanChecklistStatus"])

	def test_wx_collection_reuses_the_existing_application(self) -> None:
		existing = object()
		wx = SimpleNamespace(
			GetApp=lambda: existing,
			App=lambda: (_ for _ in ()).throw(AssertionError("must not create a second wx.App")),
		)

		self.assertIs(existing, review._wxApplication(wx))

	def test_archive_resolution_requires_exactly_one_dist_output(self) -> None:
		with TemporaryDirectory() as directory:
			dist = Path(directory)
			archive = dist / "keystone-current.nvda-addon"
			_ = archive.write_bytes(b"archive")
			self.assertEqual(archive, review.resolveBuiltArchive(dist))
			_ = (dist / "keystone-stale.nvda-addon").write_bytes(b"stale")
			with self.assertRaisesRegex(ValueError, "exactly one"):
				_ = review.resolveBuiltArchive(dist)

	def test_probes_use_the_existing_installed_tree_without_reinstalling(self) -> None:
		self.assertNotIn("_install_archive(", inspect.getsource(installedProbe._run_session))
		source = inspect.getsource(review.runInstalledReview)
		self.assertNotIn("_install_archive(", source)
		self.assertLess(source.index("_requireInstalledTree"), source.index("_initialize_nvda_config"))
		self.assertLess(source.index("_initialize_nvda_config"), source.index("_import_installed_keystone"))
		self.assertLess(source.index("_import_installed_keystone"), source.index("_collect_screenshot"))

	def test_install_preparation_runs_install_tasks_after_archive_verification(self) -> None:
		order: list[str] = []
		installed = Path("profile/addons/keystone")

		def noteRuntime(_path: Path) -> None:
			order.append("runtime")

		def noteConfig(_profile: Path, _install: Path) -> None:
			order.append("config")

		def noteVerify(_archive: Path) -> None:
			order.append("verify")

		def noteInstall(_archive: Path, _profile: Path) -> Path:
			order.append("install")
			return installed

		def noteInstallTask(_root: Path) -> None:
			order.append("install-task")

		with (
			patch.object(installedProbe, "_prepare_runtime", side_effect=noteRuntime),
			patch.object(
				installedProbe,
				"_initialize_nvda_config",
				side_effect=noteConfig,
			),
			patch.object(installedProbe, "_verify_archive", side_effect=noteVerify),
			patch.object(
				installedProbe,
				"_install_archive",
				side_effect=noteInstall,
			),
			patch.object(
				installedProbe,
				"_run_install_task",
				side_effect=noteInstallTask,
			),
		):
			self.assertEqual(
				installed,
				installedProbe.prepareInstalledArchive(
					Path("dist/keystone.nvda-addon"),
					Path("nvda.exe"),
					Path("profile"),
				),
			)

		self.assertEqual(["runtime", "config", "verify", "install", "install-task"], order)

	def test_external_probe_initializes_and_releases_nvdas_real_uia_handler(self) -> None:
		order: list[str] = []
		uia = SimpleNamespace(handler=None)

		def applyMonkeyPatches() -> None:
			order.append("monkey-patches")

		def initializeUia() -> None:
			order.append("uia-initialize")
			uia.handler = object()

		def terminateUia() -> None:
			order.append("uia-terminate")
			uia.handler = None

		monkeyPatches = SimpleNamespace(applyMonkeyPatches=applyMonkeyPatches)
		uia.initialize = initializeUia
		uia.terminate = terminateUia

		def loadModule(name: str) -> object:
			return {
				"monkeyPatches": monkeyPatches,
				"UIAHandler": uia,
			}[name]

		with patch.object(installedProbe, "import_module", side_effect=loadModule):
			installedProbe._applyNvdaMonkeyPatches()
			release = installedProbe._initializeNvdaUia()
			self.assertIsNotNone(uia.handler)
			release()

		self.assertEqual(["monkey-patches", "uia-initialize", "uia-terminate"], order)
		self.assertIsNone(uia.handler)


class ReviewScenarioTests(unittest.TestCase):
	"""The linear human checklist must be complete and exclude the superseded visual gates."""

	def test_required_categories_present(self) -> None:
		scenarios = review.buildReviewScenarios()
		categories = {scenario.category for scenario in scenarios}
		self.assertTrue(
			{"keyboard", "screen-reader", "build", "documentation", "usability"}.issubset(categories),
		)
		ids = {scenario.scenarioId for scenario in scenarios}
		for required in (
			"notepad-menu-target",
			"all-properties-keyboard",
			"loaded-only-search",
			"retarget-follow-focus",
			"snapshot-screenshot",
			"event-start-stop",
			"event-filter-dialog",
			"event-four-scopes",
			"annotations",
			"event-export-clear-reopen",
			"firefox-target",
			"feature-discoverability",
			"build-output",
			"secure-teardown",
			"speech-sound-disabled",
			"documentation",
		):
			self.assertIn(required, ids)

	def test_scenario_ids_are_unique(self) -> None:
		scenarios = review.buildReviewScenarios()
		ids = [scenario.scenarioId for scenario in scenarios]
		self.assertEqual(len(ids), len(set(ids)))

	def test_superseded_visual_gates_are_excluded(self) -> None:
		for scenario in review.buildReviewScenarios():
			haystack = f"{scenario.title}\n{scenario.prompt}".lower()
			for excluded in review.EXCLUDED_MANUAL_GATES:
				self.assertNotIn(excluded, haystack)


class ReviewRunnerArgumentTests(unittest.TestCase):
	"""The runner CLI must expose exactly the four required arguments plus the human checklist."""

	def test_required_arguments_parse(self) -> None:
		args = review._parse_args(
			[
				"--archive",
				"keystone-0.0.0.nvda-addon",
				"--nvda-executable",
				r"C:\Program Files\NVDA\nvda.exe",
				"--source-profile",
				r"C:\profile",
				"--workspace",
				r"C:\work",
			],
		)
		self.assertEqual(str(args.archive), "keystone-0.0.0.nvda-addon")
		self.assertEqual(args.human_checklist, "pending")
		self.assertFalse(args.automated_only)

	def test_human_checklist_choices(self) -> None:
		for choice in ("pending", "approved", "rejected"):
			args = review._parse_args(
				[
					"--archive",
					"a",
					"--nvda-executable",
					"b",
					"--source-profile",
					"c",
					"--workspace",
					"d",
					"--human-checklist",
					choice,
				],
			)
			self.assertEqual(args.human_checklist, choice)

	def test_missing_required_argument_is_rejected(self) -> None:
		with self.assertRaises(SystemExit):
			_ = review._parse_args(["--archive", "a"])

	def test_invalid_human_checklist_is_rejected(self) -> None:
		with self.assertRaises(SystemExit):
			_ = review._parse_args(
				[
					"--archive",
					"a",
					"--nvda-executable",
					"b",
					"--source-profile",
					"c",
					"--workspace",
					"d",
					"--human-checklist",
					"approved-please",
				],
			)


class ReviewPrivacyTests(unittest.TestCase):
	"""The emitted result must carry only counts, timings, hashes, and state — never inspected content."""

	def test_payload_keys_are_metrics_only(self) -> None:
		payload = review.evaluate(_clean_review()).payload
		forbidden = ("path", "content", "text", "value", "clipboard", "name", "title", "label")
		for key in payload:
			lowered = key.lower()
			for token in forbidden:
				self.assertNotIn(token, lowered)

	def test_scenarios_do_not_carry_inspected_content(self) -> None:
		# Scenario prompts are fixed review instructions; none may embed captured application content.
		for scenario in review.buildReviewScenarios():
			self.assertNotIn("http://", scenario.prompt.lower())
			self.assertNotIn("c:\\", scenario.prompt.lower())


class ReviewExitMatrixTests(unittest.TestCase):
	"""Every blocking outcome must map to its documented nonzero exit; only a clean approval passes."""

	def test_every_violation_maps_to_its_exit_code(self) -> None:
		base = _clean_review()
		replace = dataclasses.replace
		unavail = review.EXIT_UNAVAILABLE
		failed = review.EXIT_FAILED
		teardown = review.EXIT_TEARDOWN
		human = review.EXIT_HUMAN
		installed_unavailable = dict(base.installedEventSourceObservation, status="unavailable")
		installed_not_stopped = dict(base.installedEventSourceObservation, monitorStopped=False)
		installed_bad_identity = dict(base.installedEventSourceObservation, rawSourceType="FakeSource")
		installed_late = dict(base.installedEventSourceObservation, callbacksObservedAfterTeardown=1)

		cases: list[tuple[str, review.InstalledReviewResult, int]] = [
			("review_unavailable", replace(base, unavailableObservations=("wx",)), unavail),
			("review_skipped", replace(base, skippedObservations=("audio",)), unavail),
			("review_missing", replace(base, missingObservations=("capability",)), unavail),
			(
				"installed_unavailable",
				replace(base, installedEventSourceObservation=installed_unavailable),
				unavail,
			),
			("late_callback", replace(base, lateCallbacksAccepted=1), teardown),
			("control_mutation", replace(base, controlMutationsAfterTeardown=1), teardown),
			("secure_mutation", replace(base, secureMutations=1), teardown),
			("stale_atom", replace(base, staleAtomsStarted=1), teardown),
			(
				"installed_late_callback",
				replace(base, installedEventSourceObservation=installed_late),
				teardown,
			),
			("wx_over_budget", replace(base, wxCallbackMaxMs=review.WX_CALLBACK_MAX_MS + 0.1), failed),
			("focus_nodes_over", replace(base, focusMatchNodesMax=review.FOCUS_MATCH_NODES_MAX + 1), failed),
			("focus_depth_over", replace(base, focusMatchDepthMax=review.FOCUS_MATCH_DEPTH_MAX + 1), failed),
			("screenshot_absent", replace(base, screenshotStatus="absent"), failed),
			("screenshot_empty", replace(base, screenshotBytes=0), failed),
			("event_filter_absent", replace(base, eventFilterDialogPresent=False), failed),
			("annotations_absent", replace(base, annotationsTabPresent=False), failed),
			("scope_missing", replace(base, scopeKindsExercised=("application",)), failed),
			("raw_evidence_missing", replace(base, rawEvidenceNativeProxyField=False), failed),
			("build_output_missing", replace(base, buildBatPublishedToDist=False), failed),
			("config_missing", replace(base, configSectionRegistered=False), failed),
			("installed_tree_missing", replace(base, installedTreeReady=False), failed),
			("gap_too_small", replace(base, interAtomGapMinMs=review.INTER_ATOM_GAP_MIN_MS - 1), failed),
			("gap_too_large", replace(base, interAtomGapMaxMs=review.INTER_ATOM_GAP_MAX_MS + 1), failed),
			(
				"missing_capability",
				replace(base, enabledCapabilities=("eventMonitoring", "rawUiaInspection")),
				failed,
			),
			("archive_removed", replace(base, archiveRemainsInstalled=False), failed),
			("failed_observation", replace(base, failedObservations=("focus match",)), failed),
			("unsafe_observation", replace(base, unsafeObservations=("audio teardown",)), failed),
			(
				"installed_not_stopped",
				replace(base, installedEventSourceObservation=installed_not_stopped),
				failed,
			),
			(
				"installed_bad_identity",
				replace(base, installedEventSourceObservation=installed_bad_identity),
				failed,
			),
			("window_drift", replace(base, observationWindowMs=200), failed),
			("human_pending", replace(base, humanChecklistStatus="pending"), human),
			("human_rejected", replace(base, humanChecklistStatus="rejected"), human),
			# Precedence: unestablished input outranks a missing human approval.
			(
				"unavailable_outranks_human",
				replace(base, unavailableObservations=("wx",), humanChecklistStatus="pending"),
				unavail,
			),
			# Precedence: a teardown breach outranks an over-budget failure.
			(
				"teardown_outranks_failed",
				replace(base, lateCallbacksAccepted=1, wxCallbackMaxMs=review.WX_CALLBACK_MAX_MS + 5),
				teardown,
			),
		]
		for label, result, expected_exit in cases:
			with self.subTest(case=label):
				verdict = review.evaluate(result)
				self.assertNotEqual(verdict.exitCode, review.EXIT_PASS)
				self.assertEqual(verdict.exitCode, expected_exit)
				self.assertEqual(verdict.status, REVIEW_STATUS_BY_EXIT[expected_exit])


if __name__ == "__main__":
	_ = unittest.main()
