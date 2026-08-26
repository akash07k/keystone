# Keystone evidence schema and conventions

This reference explains the evidence Keystone writes and shows in its read-only workflows. Read it
with the [user guide](user-guide.md) for commands and with the
[settings and privacy guide](settings-and-privacy.md) before sharing evidence.

## Read status before value

Every evidence item has a status. A missing value is not automatically an error and a displayed
value is not automatically complete. Use the status to decide what the item means:

- **Value** means Keystone obtained a value.
- **Empty** means the provider reported an empty value.
- **Unsupported** means the provider does not implement that property or capability.
- **Not applicable** means the property does not apply to this target or operation.
- **Unavailable** means the property could not be obtained now.
- **Stale** means the previously identified live object is no longer current.
- **Rejected** means Keystone refused the value or operation for a stated safety rule.
- **Redacted** means the value was withheld by the active privacy policy.
- **Truncated** means Keystone retained a value but stopped at a limit. Its truncation details name
  the limit, configured limit, actual count, omitted count, reason, and whether continuation is
  available.
- **Cancelled** means the work was cancelled at a safe boundary.
- **Failed** means retrieval failed. Rejected and failed evidence include an error code and
  diagnostic ID; unavailable, stale, and cancelled evidence can include them.
- **Mixed** means an aggregate contains a mixture of outcomes. Its value is useful, but do not
  treat it as complete.

The Inspector uses the same meaning in its property rows. It speaks clear state words instead of
making an unavailable value look blank. For the visible Inspector and Event Monitor workflow,
including the four-column event report, read the [Inspector guide](inspector.md).

## Evidence envelope

Evidence is represented as a typed envelope. Its required fields are `status`, `source`,
`projection`, `confidence`, and `privacy`. When applicable, it also carries `value`,
`truncation`, `errorRef`, `observedAt`, and `scope`.

- `source` identifies the backend, component, and symbol that supplied the evidence. It can also
  name information a wrapper lost.
- `projection` identifies `normalNvda`, `rawUia`, `offline`, or `derived` evidence. A fallback
  is explicit and includes its reason code. Raw UIA is a diagnostic projection, not a replacement
  for normal NVDA-selected inspection; see [advanced UIA](advanced-uia.md).
- `confidence` is `direct`, `derived`, `flattenedByWrapper`, or `indeterminate`.
- `privacy` records the field group, privacy classification, applied transform, and policy
  revision. Classifications are public, sensitive, protected, or unknown.
- `observedAt` is an RFC 3339 timestamp with an offset and always appears with its `scope`.

Normal values are immutable scalars or arrays of immutable scalars. A value is present for Value,
Truncated, and Mixed evidence only. Do not replace a non-value status with an invented empty
string, zero, or false value.

## Documents and schema versions

Keystone's capture documents use schema version 2.0. Their root starts with `schemaVersion`
(`major` 2 and `minor` 0), `documentKind`, `documentId`, and `metadata`, followed by the fields
for that kind. The document ID is a lowercase canonical UUID.

The supported document kinds are:

- `snapshot` and `navigatorSnapshot` for full and navigator capture trees;
- `snapshotSummary` and `navigatorSummary` for their summaries;
- `diff` for baseline comparison;
- `eventExport` for Event Monitor export and drop accounting;
- `diagnosticBundle` for retained diagnostics;
- `settingsSnapshot` for the global Keystone settings;
- `customUiaConfiguration` for Custom UIA definitions;
- `screenshotResult` for an attempted screenshot result; and
- `publicationReceipt` for a completed output publication.

Kinds have closed fields. A reader should use the document kind and its status-bearing fields,
rather than assuming that a field from a different kind exists. Diagnostic bundles retain at most
300 records and state whether more existed. A screenshot result is separate evidence; screenshot
pixels remain unredacted visual content and require the warning in the privacy guide.

## Capture conventions

The capture conventions name the schema as `keystone.capture` at version `2.0`. Required fields are
never omitted, status is independent from value, geometry uses signed half-open virtual-screen
pixels, nodes follow capture traversal order, and children follow provider child order.

Keystone uses deterministic JSON conventions for its structured documents: input text is normalized
to NFC, object keys use ordinal order, UTF-8 has no byte-order mark, and each compact JSON value is
terminated by one line feed. Treat the stated schema major and document kind as the compatibility
boundary; do not infer a different schema from a file name or a provider's display text.

## Provenance and diagnostics

Evidence provenance tells you how an observation was obtained, not whether it is desirable. Preserve
the source, projection, confidence, privacy, observation time, and scope when you copy or report an
item. A normal capture, event export, or property value is evidence. A diagnostic bundle, error
reference, warning, or fallback reason explains an outcome; it is not a substitute value for the
property that was unavailable, rejected, stale, or failed.

When investigating a problem, report the exact status word and any safe error or diagnostic ID. Keystone emits curated diagnostics through NVDA's native log.
