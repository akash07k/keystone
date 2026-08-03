"""Privacy-safe Inspector copy renderers over already-transformed evidence.

The Inspector never re-derives privacy here. Every property row arrives already classified by its
source, so a row carries a value only when its status is value-bearing; a redacted, failed, empty,
unsupported, or otherwise non-value-bearing row has no value at all. Each renderer refuses to emit
content for such a row, printing the explicit status token in parentheses instead. Copying can
therefore never leak text the pane itself does not already show, and the JSON, plain-text,
Markdown, and path renderings all share this one gate.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domain.inspector import (
	InspectorSourceIdentity,
	NodeFacet,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	StructuredPropertyNode,
)

_VALUE_BEARING = frozenset((PropertyStatus.VALUE, PropertyStatus.TRUNCATED))

_CATEGORY_LABELS: dict[PropertyCategory, str] = {
	PropertyCategory.QUICK: "Quick Properties",
	PropertyCategory.CORE: "Core",
	PropertyCategory.SUPPORTED_UIA_PATTERNS: "Supported UIA Patterns",
	PropertyCategory.UIA: "UIA",
	PropertyCategory.IA2_MSAA: "IAccessible2 / MSAA",
	PropertyCategory.JAB: "Java Access Bridge",
	PropertyCategory.OTHER_API: "Other API",
	PropertyCategory.DEVELOPER_INFO: "Developer Info",
	PropertyCategory.ALL_PROPERTIES: "All Properties",
	PropertyCategory.ANNOTATIONS: "Annotations",
	PropertyCategory.DIAGNOSTICS: "Diagnostics",
}


@dataclass(frozen=True, slots=True)
class CopyCategory:
	"""One loaded property tab captured for copying: its flat rows and structured tree."""

	category: PropertyCategory
	rows: tuple[PropertyRow, ...]
	structured: tuple[StructuredPropertyNode, ...]


@dataclass(frozen=True, slots=True)
class CopyNode:
	"""Everything a copy needs about one selected node, already privacy-safe.

	``path`` runs from the root ancestor down to the copied node, so the last element is the node
	itself. Only categories already loaded for the node appear; copy never triggers a source read.
	"""

	identity: InspectorSourceIdentity
	path: tuple[NodeFacet, ...]
	categories: tuple[CopyCategory, ...]

	def __post_init__(self) -> None:
		if not self.path:
			raise ValueError("a copy node must include at least the node itself")

	@property
	def node(self) -> NodeFacet:
		return self.path[-1]


def categoryLabel(category: PropertyCategory) -> str:
	return _CATEGORY_LABELS[category]


def _facetLabel(facet: NodeFacet) -> str:
	return facet.name if facet.hasName else f"[{facet.role}]"


def _safeValue(status: PropertyStatus, value: str | None) -> str | None:
	"""The row's value when its status is value-bearing, else ``None`` regardless of ``value``."""

	return value if status in _VALUE_BEARING else None


def _displayValue(status: PropertyStatus, value: str | None) -> str:
	safe = _safeValue(status, value)
	return safe if safe is not None else f"({status.value})"


def renderPropertyText(row: PropertyRow) -> str:
	"""One property as ``Name: value`` or ``Name: (status)`` for a redacted or missing field."""

	return f"{row.name}: {_displayValue(row.status, row.value)}"


def _rowJson(row: PropertyRow) -> dict[str, object]:
	data: dict[str, object] = {"field": row.fieldKey, "name": row.name, "status": row.status.value}
	safe = _safeValue(row.status, row.value)
	if safe is not None:
		data["value"] = safe
	return data


def _structuredJson(node: StructuredPropertyNode) -> dict[str, object]:
	data: dict[str, object] = {"key": node.key, "label": node.label, "status": node.status.value}
	if node.children:
		data["children"] = [_structuredJson(child) for child in node.children]
		return data
	safe = _safeValue(node.status, node.value)
	if safe is not None:
		data["value"] = safe
	return data


def _identityJson(identity: InspectorSourceIdentity) -> dict[str, object]:
	return {
		"kind": identity.kind.value,
		"label": identity.label,
		"executable": identity.executable,
		"processId": identity.processId,
		"backend": identity.backend,
	}


def _categoryJson(category: CopyCategory) -> dict[str, object]:
	return {
		"category": category.category.value,
		"rows": [_rowJson(row) for row in category.rows],
		"structured": [_structuredJson(node) for node in category.structured],
	}


def renderNodeJson(node: CopyNode) -> str:
	"""A deterministic JSON export of the node, its ancestor path, and every loaded tab."""

	nodePayload: dict[str, object] = {
		"role": node.node.role,
		"hasName": node.node.hasName,
	}
	if node.node.hasName:
		nodePayload["name"] = node.node.name
	payload: dict[str, object] = {
		"source": _identityJson(node.identity),
		"path": [_facetLabel(facet) for facet in node.path],
		"node": nodePayload,
		"categories": [_categoryJson(category) for category in node.categories],
	}
	return json.dumps(payload, ensure_ascii=False, indent="\t")


def renderNodePath(node: CopyNode) -> str:
	"""The ancestor path as ``root > child > node`` using names, or roles for unnamed nodes."""

	return " > ".join(_facetLabel(facet) for facet in node.path)


def renderNodeText(node: CopyNode) -> str:
	"""A readable indented dump: heading, path, then each loaded tab's rows."""

	lines: list[str] = [
		f"{_facetLabel(node.node)} ({node.node.role})",
		f"Path: {renderNodePath(node)}",
	]
	for category in node.categories:
		lines.append("")
		lines.append(f"{categoryLabel(category.category)}:")
		if not category.rows and not category.structured:
			lines.append("\t(no properties)")
			continue
		for row in category.rows:
			lines.append(f"\t{renderPropertyText(row)}")
		for structured in category.structured:
			_appendStructuredText(lines, structured, depth=1)
	return "\n".join(lines)


def _appendStructuredText(lines: list[str], node: StructuredPropertyNode, *, depth: int) -> None:
	indent = "\t" * depth
	if node.children:
		lines.append(f"{indent}{node.label}:")
		for child in node.children:
			_appendStructuredText(lines, child, depth=depth + 1)
		return
	lines.append(f"{indent}{node.label}: {_displayValue(node.status, node.value)}")


def renderNodeMarkdown(node: CopyNode) -> str:
	"""A Markdown export: heading, source and path metadata, then every loaded tab."""

	lines: list[str] = [
		f"# {_facetLabel(node.node)} ({node.node.role})",
		"",
		f"- **Source:** {node.identity.label} ({node.identity.kind.value})",
		f"- **Path:** {renderNodePath(node)}",
	]
	for category in node.categories:
		lines.append("")
		lines.append(f"## {categoryLabel(category.category)}")
		if not category.rows and not category.structured:
			lines.append("")
			lines.append("_No properties._")
			continue
		if category.rows:
			lines.append("")
			lines.append("| Property | Status | Value |")
			lines.append("| --- | --- | --- |")
			for row in category.rows:
				safe = _safeValue(row.status, row.value)
				value = _markdownCell(safe) if safe is not None else ""
				lines.append(f"| {_markdownCell(row.name)} | {row.status.value} | {value} |")
		if category.structured:
			lines.append("")
			lines.append("### Structured Properties")
			for structured in category.structured:
				_appendStructuredMarkdown(lines, structured, depth=0)
	return "\n".join(lines)


def _appendStructuredMarkdown(lines: list[str], node: StructuredPropertyNode, *, depth: int) -> None:
	indent = "  " * depth
	label = _markdownCell(node.label)
	if node.children:
		lines.append(f"{indent}- **{label}**")
		for child in node.children:
			_appendStructuredMarkdown(lines, child, depth=depth + 1)
		return
	safe = _safeValue(node.status, node.value)
	value = _markdownCell(safe) if safe is not None else f"({node.status.value})"
	lines.append(f"{indent}- **{label}:** {value}")


def _markdownCell(text: str) -> str:
	return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")
