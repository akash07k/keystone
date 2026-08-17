from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from site_scons.build_version import nextLocalBuildVersion


class LocalBuildVersionTests(unittest.TestCase):
	def test_starts_after_the_configured_patch_and_persists_each_increment(self) -> None:
		with TemporaryDirectory() as directory:
			counter = Path(directory) / ".keystone-build-number"

			self.assertEqual("0.0.1", nextLocalBuildVersion("0.0.0", counter))
			self.assertEqual("0.0.2", nextLocalBuildVersion("0.0.0", counter))
			self.assertEqual("1.4.3", nextLocalBuildVersion("1.4.2", counter))
			self.assertEqual("3\n", counter.read_text(encoding="utf-8"))

	def test_rejects_malformed_counter_without_replacing_it(self) -> None:
		with TemporaryDirectory() as directory:
			counter = Path(directory) / ".keystone-build-number"
			_ = counter.write_text("invalid\n", encoding="utf-8")

			with self.assertRaises(ValueError):
				_ = nextLocalBuildVersion("0.0.0", counter)

			self.assertEqual("invalid\n", counter.read_text(encoding="utf-8"))
