# Build customizations
# Change this file instead of sconstruct or manifest files, whenever possible.

from site_scons.site_tools.NVDATool.typings import (
	AddonInfo,
	BrailleTables,
	SymbolDictionaries,
	SpeechDictionaries,
)

# Since some strings in `addon_info` are translatable,
# we need to include them in the .po files.
# Gettext recognizes only strings given as parameters to the `_` function.
# To avoid initializing translations in this module we simply import a "fake" `_` function
# which returns whatever is given to it as an argument.
from site_scons.site_tools.NVDATool.utils import _

# Add-on information variables
addon_info = AddonInfo(
	addon_name="keystone",
	# Translators: Add-on name shown by NVDA.
	addon_summary=_("Keystone"),
	# Translators: Add-on description shown by NVDA.
	addon_description=_(
		"Capture explainable accessibility evidence without changing the inspected application.",
	),
	# This is a development identity, not a release or compatibility claim.
	addon_version="0.0.0",
	# Translators: Development build notice shown by NVDA.
	addon_changelog=_("Development build for validation."),
	addon_author="Akash Kakkar",
	addon_url="https://github.com/akash07k/keystone",
	addon_sourceURL="https://github.com/akash07k/keystone",
	addon_docFileName="README.html",
	addon_minimumNVDAVersion="2026.1",
	addon_lastTestedNVDAVersion="2026.2",
	addon_updateChannel="dev",
	addon_license="GNU General Public License v2 or later",
	addon_licenseURL="https://github.com/akash07k/keystone/blob/main/COPYING.txt",
)

# Runtime sources are declared explicitly.
pythonSources: list[str] = [
	"addon/installTasks.py",
	"addon/appModules/keystone_uia_override.py",
	"addon/globalPlugins/keystone/**/*.py",
]

# Bundled runtime resource files shipped alongside the Python sources.
# The rich sound theme ships one WAV per product cue under a single directory; the
# archive checker resolves this inventory against the closed cue-to-file manifest and
# the built package members so the shipped resources stay complete and undivergent.
resourceSources: list[str] = [
	"addon/globalPlugins/keystone/sounds/rich/*.wav",
]

# Files that contain strings for translation. Usually your python sources
i18nSources: list[str] = pythonSources + ["buildVars.py"]

# Paths are relative to addon/.
excludedFiles: list[str] = [
	"**/__pycache__/**",
	"**/*.pyc",
	"**/*.pyo",
	"**/.env",
	"**/.env.*",
	"**/*.key",
	"**/*.pem",
	"**/*credential*",
	"**/*secret*",
]

# Base language for the NVDA add-on
# If your add-on is written in a language other than english, modify this variable.
# For example, set baseLanguage to "es" if your add-on is primarily written in spanish.
# You must also edit .gitignore file to specify base language files to be ignored.
baseLanguage: str = "en"

# Markdown extensions for add-on documentation
# Most add-ons do not require additional Markdown extensions.
# If you need to add support for markup such as tables, fill out the below list.
# Extensions string must be of the form "markdown.extensions.extensionName"
# e.g. "markdown.extensions.tables" to add tables.
markdownExtensions: list[str] = ["markdown.extensions.toc"]

# Product guides installed as end-user Help. Contributor documentation remains in docs/ but is not
# installed with the add-on.
productGuides: list[str] = [
	"advanced-uia.md",
	"evidence-schema.md",
	"inspector.md",
	"keyboard-reference.md",
	"settings-and-privacy.md",
	"troubleshooting.md",
	"user-guide.md",
]

# Custom braille translation tables
# If your add-on includes custom braille tables (most will not), fill out this dictionary.
# Each key is a dictionary named according to braille table file name,
# with keys inside recording the following attributes:
# displayName (name of the table shown to users and translatable),
# contracted (contracted (True) or uncontracted (False) braille code),
# output (shown in output table list),
# input (shown in input table list).
brailleTables: BrailleTables = {}

# Custom speech symbol dictionaries
# Symbol dictionary files reside in the locale folder, e.g. `locale\en`, and are named `symbols-<name>.dic`.
# If your add-on includes custom speech symbol dictionaries (most will not), fill out this dictionary.
# Each key is the name of the dictionary,
# with keys inside recording the following attributes:
# displayName (name of the speech dictionary shown to users and translatable),
# mandatory (True when always enabled, False when not).
symbolDictionaries: SymbolDictionaries = {}

# Custom speech dictionaries (distinct from symbol dictionaries above)
# Speech dictionary files reside in the speechDicts folder and are named `name.dic`.
# If your add-on includes custom speech (pronunciation) dictionaries (most will not), fill out this dictionary.
# Each key is the name of the dictionary,
# with keys inside recording the following attributes:
# displayName (name of the speech dictionary shown to users and translatable),
# mandatory (True when always enabled, False when not).
speechDictionaries: SpeechDictionaries = {}
