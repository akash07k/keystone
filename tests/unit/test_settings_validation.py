from __future__ import annotations

from dataclasses import replace
import unittest

from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot, validateCandidate


class SettingsValidationTests(unittest.TestCase):
	def test_non_integer_starting_revision_returns_validation_issue(self) -> None:
		candidate = SettingsSnapshot.defaults(settingsRevision=1).asCandidate()
		for revision in ("1", None, True):
			with self.subTest(revision=revision):
				invalid = replace(candidate, startingRevision=revision)
				result = validateCandidate(invalid)
				self.assertEqual("settingsRevision", result.firstInvalidSettingId)
				self.assertEqual("positiveRevisionRequired", result.issues[0].reasonCode)


if __name__ == "__main__":
	_ = unittest.main()
