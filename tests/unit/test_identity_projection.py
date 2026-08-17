from __future__ import annotations

import unittest

from addon.globalPlugins.keystone.domain.projection import (
	IdentityProbe,
	ProjectionBudget,
	ProjectionCandidate,
	ProjectionMethod,
	ProjectionRequest,
	ProjectionStatus,
	SelectedIdentity,
	decideProjection,
)


def _selected(**changes: object) -> SelectedIdentity:
	values: dict[str, object] = {
		"providerProcessId": 41,
		"providerScope": "uia",
		"role": "button",
		"stableKeys": (("runtime", (1, 2, 3)),),
		"windowHandle": 101,
		"wholeWindow": False,
	}
	values.update(changes)
	return SelectedIdentity(**values)  # type: ignore[arg-type]


def _candidate(**changes: object) -> ProjectionCandidate:
	values: dict[str, object] = {
		"candidateId": "candidate-1",
		"providerProcessId": 41,
		"providerScope": "uia",
		"role": "button",
		"stableKeys": (("runtime", (1, 2, 3)),),
		"windowHandle": 101,
		"wholeWindow": False,
		"probe": IdentityProbe(),
	}
	values.update(changes)
	return ProjectionCandidate(**values)  # type: ignore[arg-type]


class IdentityProjectionTests(unittest.TestCase):
	request = ProjectionRequest.explicit("raw-operation", ProjectionBudget(3, 12, 250))

	def test_projection_budgets_require_positive_integers(self) -> None:
		for candidate in (
			(True, 1, 1),
			(1, 1.5, 1),
			(1, 1, False),
		):
			with self.subTest(candidate=candidate), self.assertRaises(ValueError):
				_ = ProjectionBudget(*candidate)  # pyright: ignore[reportArgumentType]

	def test_exact_python_nvda_and_provider_comparisons_are_layered(self) -> None:
		for probe, method in (
			(IdentityProbe(pythonIdentity=True), ProjectionMethod.PYTHON_IDENTITY),
			(IdentityProbe(nvdaEquality=True), ProjectionMethod.NVDA_EQUALITY),
			(IdentityProbe(providerComparison="same"), ProjectionMethod.PROVIDER_NATIVE),
			(
				IdentityProbe(trustedAcquisition=True),
				ProjectionMethod.PROCESS_SCOPED_ACQUISITION,
			),
		):
			with self.subTest(method=method):
				result = decideProjection(self.request, _selected(), (_candidate(probe=probe),))
				self.assertEqual(ProjectionStatus.APPLIED, result.evidence.status)
				self.assertEqual(method, result.evidence.method)
				self.assertEqual("candidate-1", result.selectedCandidateId)

	def test_overlay_wrappers_accept_only_positive_comparison_not_class_shape(self) -> None:
		wrapper = _candidate(
			role="document",
			stableKeys=(("runtime", (9,)),),
			probe=IdentityProbe(providerComparison="same"),
		)
		result = decideProjection(self.request, _selected(role="pane"), (wrapper,))
		self.assertEqual(ProjectionStatus.APPLIED, result.evidence.status)
		self.assertEqual(ProjectionMethod.PROVIDER_NATIVE, result.evidence.method)

	def test_trusted_acquisition_still_requires_process_and_provider_scope(self) -> None:
		probe = IdentityProbe(trustedAcquisition=True)
		for candidate in (
			_candidate(providerProcessId=99, probe=probe),
			_candidate(providerScope="ia2Msaa", probe=probe),
		):
			with self.subTest(candidate=candidate):
				result = decideProjection(self.request, _selected(), (candidate,))
				self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)

	def test_geometry_guidance_never_proves_cross_backend_identity(self) -> None:
		selected = _selected(stableKeys=(), windowHandle=None)
		candidate = _candidate(
			stableKeys=(),
			windowHandle=None,
			probe=IdentityProbe(geometryGuidance=True),
		)

		result = decideProjection(self.request, selected, (candidate,))

		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.GEOMETRY_ONLY", result.evidence.reasonCode)

	def test_ia2_msaa_jab_and_hosted_process_scope_must_match(self) -> None:
		for scope in ("ia2Msaa", "msaa", "jab"):
			with self.subTest(scope=scope):
				selected = _selected(providerScope=scope, stableKeys=((scope, 7),))
				candidate = _candidate(providerScope=scope, stableKeys=((scope, 7),))
				self.assertEqual(
					ProjectionStatus.APPLIED,
					decideProjection(self.request, selected, (candidate,)).evidence.status,
				)
		hosted = _candidate(providerProcessId=99, probe=IdentityProbe(providerComparison="same"))
		result = decideProjection(self.request, _selected(), (hosted,))
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.CROSS_PROCESS", result.evidence.reasonCode)

	def test_stable_id_role_conflict_and_geometry_only_are_rejected(self) -> None:
		conflict = _candidate(role="checkbox")
		result = decideProjection(self.request, _selected(), (conflict,))
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.STABLE_ROLE_CONFLICT", result.evidence.reasonCode)

		geometry = _candidate(
			stableKeys=(),
			windowHandle=None,
			probe=IdentityProbe(geometryGuidance=True),
		)
		result = decideProjection(self.request, _selected(stableKeys=(), windowHandle=None), (geometry,))
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.GEOMETRY_ONLY", result.evidence.reasonCode)

	def test_unhashable_stable_keys_match_or_reject_by_equality(self) -> None:
		selected = _selected(stableKeys=(("runtime", {"parts": [1, 2, 3]}),))
		matched = decideProjection(
			self.request,
			selected,
			(_candidate(stableKeys=(("runtime", {"parts": [1, 2, 3]}),)),),
		)
		self.assertEqual(ProjectionStatus.APPLIED, matched.evidence.status)
		self.assertEqual(ProjectionMethod.STABLE_PROVIDER_KEY, matched.evidence.method)

		unmatched = decideProjection(
			self.request,
			selected,
			(_candidate(stableKeys=(("runtime", {"parts": [4, 5, 6]}),)),),
		)
		self.assertEqual(ProjectionStatus.REJECTED, unmatched.evidence.status)
		self.assertEqual("KS.RAW_UIA.IDENTITY_UNPROVEN", unmatched.evidence.reasonCode)

	def test_whole_window_identity_is_conservative(self) -> None:
		candidate = _candidate(
			role="window",
			stableKeys=(),
			wholeWindow=True,
			probe=IdentityProbe(),
		)
		result = decideProjection(
			self.request,
			_selected(role="window", stableKeys=(), wholeWindow=True),
			(candidate,),
		)
		self.assertEqual(ProjectionStatus.APPLIED, result.evidence.status)
		self.assertEqual(ProjectionMethod.WHOLE_WINDOW, result.evidence.method)

	def test_strict_request_rejects_a_window_only_substitution(self) -> None:
		candidate = _candidate(probe=IdentityProbe(windowScopedAcquisition=True))
		request = ProjectionRequest.explicit(
			"strict-focus",
			ProjectionBudget(3, 12, 250),
			allowWindowScoped=False,
		)

		result = decideProjection(request, _selected(), (candidate,))

		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.WINDOW_ONLY_TARGET", result.evidence.reasonCode)
		self.assertIsNone(result.selectedCandidateId)

	def test_position_and_name_match_allows_a_position_resolved_raw_element(self) -> None:
		candidate = _candidate(
			probe=IdentityProbe(geometryGuidance=True, positionAndNameMatch=True),
		)

		result = decideProjection(self.request, _selected(), (candidate,))

		self.assertEqual(ProjectionStatus.APPLIED, result.evidence.status)
		self.assertEqual(ProjectionMethod.POSITION_AND_NAME, result.evidence.method)
		self.assertEqual("KS.RAW_UIA.POSITION_AND_NAME", result.evidence.reasonCode)

	def test_ambiguity_and_fetch_budget_fail_closed(self) -> None:
		candidates = (
			_candidate(candidateId="one"),
			_candidate(candidateId="two"),
		)
		result = decideProjection(self.request, _selected(), candidates)
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.AMBIGUOUS", result.evidence.reasonCode)

		budgeted = ProjectionRequest.explicit("budgeted", ProjectionBudget(1, 2, 250))
		result = decideProjection(budgeted, _selected(), candidates)
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.CANDIDATE_BUDGET", result.evidence.reasonCode)
		self.assertLessEqual(result.evidence.propertyReads, 2)

		propertyBudgeted = ProjectionRequest.explicit("property-budgeted", ProjectionBudget(3, 4, 250))
		result = decideProjection(propertyBudgeted, _selected(), (_candidate(),))
		self.assertEqual(ProjectionStatus.REJECTED, result.evidence.status)
		self.assertEqual("KS.RAW_UIA.PROPERTY_BUDGET", result.evidence.reasonCode)
		self.assertLessEqual(result.evidence.propertyReads, 4)

	def test_disabled_request_never_projects(self) -> None:
		result = decideProjection(ProjectionRequest.disabled("normal"), _selected(), (_candidate(),))
		self.assertEqual(ProjectionStatus.NOT_REQUESTED, result.evidence.status)
		self.assertFalse(result.evidence.requested)
		self.assertIsNone(result.selectedCandidateId)


if __name__ == "__main__":
	_ = unittest.main()
