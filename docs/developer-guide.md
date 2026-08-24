# Keystone developer guide

Keystone is an NVDA add-on that captures explainable accessibility evidence without changing the
inspected application. This guide describes the current source layout, local validation, and
package workflow.

## Source ownership

The add-on is organized around three ownership boundaries:

- `addon/globalPlugins/keystone/domain/` contains typed evidence, settings, status, privacy, and
  business rules. It does not depend on NVDA presentation controls.
- `addon/globalPlugins/keystone/application/` coordinates capture, inspection, logging, export,
  and monitoring use cases.
- `addon/globalPlugins/keystone/adapters/` connects those use cases to NVDA, accessibility
  providers, files, and wx controls. `presentation/` contains view-facing presenters and messages.

Provider adapters may read accessibility information, but the provider boundary is read-only:
Keystone must not invoke actions, modify values, move focus or selection, scroll targets, send
input, or expose a generic provider-method escape hatch. Preserve typed unavailable, unsupported,
rejected, redacted, truncated, stale, and failed states rather than substituting ordinary empty
values. See [evidence schema](evidence-schema.md) for the reader-facing conventions.

Raw UIA remains a diagnostic path. Keep the established four-column Event Monitor report—Event,
Source, Changed value, and Time—and keep row details and actions outside those columns. Custom UIA
continues to use its existing scoped, typed definition model; it is not a generalized representation
or a durable identity model for arbitrary provider data.

## Prepare the toolchain

Use Python 3.13 and install the repository's locked toolchain before running checks:

```powershell
uv sync --locked
```

`pyproject.toml` declares the project tooling and `uv.lock` pins its resolved versions. The build
and localization paths use the checked-in SCons setup; do not replace them with an unreviewed
release command.

## Run focused checks

Run the smallest relevant check while editing:

```powershell
uv run prek run --files docs/troubleshooting.md docs/developer-guide.md changelog.md
uv run python -m unittest tests.archive.test_build_contracts
```

Before a broader change, use the same checks as continuous integration:

```powershell
uv run python -m unittest discover -s tests -v
uv run ruff check buildVars.py addon tests
uv run ruff format --check buildVars.py addon tests
uv run python -m pyright
uv run prek run --all-files
```

The archive test builds an add-on from the working tree and checks declared modules and rich sound
assets against the archive. Keep it focused when changing build inputs, archive inventory, or
packaged resources.

## Build and inspect a package

From the repository root, run:

```powershell
.\build.bat
```

The wrapper runs the checked-in SCons build, removes stale archives before a normal build, and
requires exactly one `.nvda-addon` file under `dist\`. To extract translatable messages, run:

```powershell
.\build.bat pot
```

Inspect the package before distributing it:

```powershell
Get-ChildItem dist\*.nvda-addon
Expand-Archive -LiteralPath (Get-ChildItem dist\*.nvda-addon).FullName -DestinationPath tmp\package-check -Force
Get-ChildItem tmp\package-check -Recurse
```

Confirm that the archive has the expected manifest, runtime modules, and bundled rich sound files.
The archive contract test is the automated inventory check; manual inspection is useful for
reviewing the actual package layout.

## Documentation and change guidance

Keep public documentation linear, keyboard-first, and specific about spoken states. Put focused
guides in `docs/` and keep `README.md` as the concise entry point. Update the keyboard reference
through its command-registry source rather than editing generated shortcuts by hand.

Document current behavior only. Explain diagnostic limits and privacy boundaries plainly, avoid
claims about untested environments, and do not imply that a diagnostic UIA option is a generally
preferred provider path. Add concise user-facing entries to `changelog.md` when behavior changes.
