from __future__ import annotations

import builtins
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from addon.globalPlugins.keystone.adapters.wx import inspector_frame
from addon.globalPlugins.keystone.domain.commands import COMMAND_DEFINITIONS
from addon.globalPlugins.keystone.presentation.commands import (
	commandGestureText,
	commandLabelText,
	keyboardReferenceMarkdown,
)
from addon.globalPlugins.keystone.presentation import commands as command_presentation

_REPO_ROOT = Path(__file__).resolve().parents[2]
_KEYBOARD_REFERENCE = _REPO_ROOT / "docs" / "keyboard-reference.md"
_PUBLIC_README = _REPO_ROOT / "README.md"
_LOCALIZED_SOURCES = (
	_REPO_ROOT / "addon" / "globalPlugins" / "keystone" / "presentation" / "commands.py",
	_REPO_ROOT / "addon" / "globalPlugins" / "keystone" / "adapters" / "wx" / "inspector_frame.py",
)


def _extractCatalog() -> str:
	"""Run xgettext over the localized sources exactly as the build does, into a throwaway catalog.

	The message catalog itself is a build artifact, so the contract is verified by re-running the
	real extractor with the same custom ``pgettext`` keyword rather than reading a committed file.
	"""

	with tempfile.TemporaryDirectory() as workdir:
		target = Path(workdir) / "probe.pot"
		command = [
			"xgettext",
			"--keyword=pgettext:1c,2",
			"-o",
			str(target),
			*[str(path) for path in _LOCALIZED_SOURCES],
		]
		_ = subprocess.run(command, check=True, capture_output=True, text=True)
		return target.read_text(encoding="utf-8")


class _StubTranslators:
	"""Install fake NVDA gettext builtins for the duration of a test, then restore the originals."""

	def __init__(self) -> None:
		super().__init__()
		self.plainCalls: list[str] = []
		self.contextCalls: list[tuple[str, str]] = []
		self.pluralCalls: list[tuple[str, str, int]] = []
		self._saved: dict[str, object] = {}

	def __enter__(self) -> "_StubTranslators":
		for name in ("_", "pgettext", "ngettext"):
			if hasattr(builtins, name):
				self._saved[name] = getattr(builtins, name)

		def plain(message: str) -> str:
			self.plainCalls.append(message)
			return f"[t]{message}"

		def context(ctx: str, message: str) -> str:
			self.contextCalls.append((ctx, message))
			return f"[t:{ctx}]{message}"

		def plural(singular: str, pluralForm: str, count: int) -> str:
			self.pluralCalls.append((singular, pluralForm, count))
			return singular if count == 1 else pluralForm

		builtins._ = plain  # type: ignore[attr-defined]
		builtins.pgettext = context  # type: ignore[attr-defined]
		builtins.ngettext = plural  # type: ignore[attr-defined]
		return self

	def __exit__(self, *_exc: object) -> None:
		for name in ("_", "pgettext", "ngettext"):
			if name in self._saved:
				setattr(builtins, name, self._saved[name])
			elif hasattr(builtins, name):
				delattr(builtins, name)


class CommandCatalogAgreementTests(unittest.TestCase):
	def test_command_labels_mirror_the_single_registry_source(self) -> None:
		for definition in COMMAND_DEFINITIONS:
			self.assertEqual(definition.label, commandLabelText(definition.commandId))
			self.assertEqual(definition.gestureLabel, commandGestureText(definition.commandId))

	def test_command_labels_route_through_the_context_catalog(self) -> None:
		with _StubTranslators() as stub:
			for definition in COMMAND_DEFINITIONS:
				self.assertEqual(
					f"[t:keystone command]{definition.label}",
					commandLabelText(definition.commandId),
				)
				self.assertEqual(
					f"[t:keystone gesture]{definition.gestureLabel}",
					commandGestureText(definition.commandId),
				)
		requestedLabels = {message for _ctx, message in stub.contextCalls}
		for definition in COMMAND_DEFINITIONS:
			self.assertIn(definition.label, requestedLabels)
			self.assertIn(definition.gestureLabel, requestedLabels)


class KeyboardReferenceAgreementTests(unittest.TestCase):
	def test_generated_reference_lists_every_command_in_registry_order(self) -> None:
		markdown = keyboardReferenceMarkdown()
		bullets = [line for line in markdown.splitlines() if line.startswith("- ")]
		self.assertEqual(len(COMMAND_DEFINITIONS), len(bullets))
		for definition, bullet in zip(COMMAND_DEFINITIONS, bullets, strict=True):
			gesture = commandGestureText(definition.commandId)
			label = commandLabelText(definition.commandId)
			self.assertEqual(f"- {gesture}: {label}.", bullet)

	def test_committed_reference_document_matches_the_generator(self) -> None:
		self.assertTrue(_KEYBOARD_REFERENCE.is_file(), "docs/keyboard-reference.md must exist")
		onDisk = _KEYBOARD_REFERENCE.read_text(encoding="utf-8")
		self.assertEqual(keyboardReferenceMarkdown().strip(), onDisk.strip())


class DocumentationDiscoverabilityTests(unittest.TestCase):
	def test_public_guide_names_accessible_feature_entry_points(self) -> None:
		required = (
			"# Keystone for NVDA",
			"NVDA+slash, then E",
			"NVDA+Shift+slash",
			"NVDA+slash, then C",
			"Open Event Monitor",
			"Start Monitoring",
			"Event Filter",
			"Manage Custom UIA Properties",
			"NVDA Preferences, Input Gestures, Keystone",
			"NVDA Preferences, Settings, Keystone",
		)
		text = _PUBLIC_README.read_text(encoding="utf-8")
		self.assertNotIn("NVDA Add-on Scons Template", text)
		for entryPoint in required:
			self.assertIn(entryPoint, text)


class GettextRoutingTests(unittest.TestCase):
	def test_shared_catalog_routes_all_nvda_gettext_builtins_with_english_fallback(self) -> None:
		catalogClass = getattr(command_presentation, "NvdaTranslationCatalog")
		catalog = catalogClass()

		with _StubTranslators():
			self.assertEqual("[t]message", catalog.gettext("message"))
			self.assertEqual("[t:context]message", catalog.pgettext("context", "message"))
			self.assertEqual("messages", catalog.ngettext("message", "messages", 2))

		self.assertEqual("message", catalog.gettext("message"))
		self.assertEqual("message", catalog.pgettext("context", "message"))
		self.assertEqual("message", catalog.ngettext("message", "messages", 1))
		self.assertEqual("messages", catalog.ngettext("message", "messages", 0))

	def test_plain_and_context_helpers_prefer_the_installed_catalog(self) -> None:
		with _StubTranslators() as stub:
			self.assertEqual("[t]Inspector closed.", inspector_frame.gettext("Inspector closed."))
			self.assertEqual(
				"[t:inspector region]Monitored events",
				inspector_frame.pgettext("inspector region", "Monitored events"),
			)
		self.assertIn("Inspector closed.", stub.plainCalls)
		self.assertIn(("inspector region", "Monitored events"), stub.contextCalls)

	def test_helpers_fall_back_to_english_without_a_catalog(self) -> None:
		for name in ("_", "pgettext", "ngettext"):
			self.assertFalse(
				hasattr(builtins, name),
				f"tests run off-host and must not see an installed {name} catalog",
			)
		self.assertEqual("Inspector closed.", inspector_frame.gettext("Inspector closed."))
		self.assertEqual(
			"Monitored events",
			inspector_frame.pgettext("inspector region", "Monitored events"),
		)

	def test_plural_helper_selects_singular_and_plural_by_count(self) -> None:
		singular = "Captured event: {count}"
		plural = "Captured events: {count}"
		self.assertEqual(singular, inspector_frame.ngettext(singular, plural, 1))
		self.assertEqual(plural, inspector_frame.ngettext(singular, plural, 0))
		self.assertEqual(plural, inspector_frame.ngettext(singular, plural, 5))

	def test_command_presentation_exposes_a_context_catalog_helper(self) -> None:
		with _StubTranslators():
			self.assertEqual(
				"[t:probe]message",
				command_presentation.pgettext("probe", "message"),
			)


class MessageCatalogExtractionTests(unittest.TestCase):
	def _catalog(self) -> str:
		if shutil.which("xgettext") is None:
			self.skipTest("xgettext is required to verify message extraction")
		return _extractCatalog()

	def test_pot_carries_command_inspector_and_events_messages(self) -> None:
		catalog = self._catalog()
		for msgid in (
			'msgid "Capture foreground with configured limits"',
			'msgid "Monitored events"',
			'msgid "Retarget to &Focus"',
			'msgid "Open Inspector for focus"',
			'msgid "Core"',
			'msgid "UIA"',
			'msgid "Annotations"',
			'msgid "Advanced"',
		):
			self.assertIn(msgid, catalog, f"expected {msgid} in the message catalog")

	def test_pot_disambiguates_with_contexts_and_declares_a_plural(self) -> None:
		catalog = self._catalog()
		for context in (
			'msgctxt "keystone command"',
			'msgctxt "inspector region"',
			'msgctxt "inspector property category"',
			'msgctxt "events control"',
		):
			self.assertIn(context, catalog, f"expected {context} context in the message catalog")
		self.assertIn("msgid_plural", catalog, "the catalog must declare at least one plural form")

	def test_pot_uses_named_placeholders_not_positional_ones(self) -> None:
		catalog = self._catalog()
		self.assertIn('msgid "Inspector now follows {application}."', catalog)
		self.assertIn("{count}", catalog)


if __name__ == "__main__":
	_ = unittest.main()
