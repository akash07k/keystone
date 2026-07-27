"""Shared typed Inspector source protocol for both live and offline backends.

The application service depends only on this protocol, never on wx, NVDA, provider, or file
objects. Every result record crossing this seam is already privacy-safe: values are complete
rendered strings or explicit status markers, and node references are opaque tokens rather than host
or COM handles. One protocol serves the live navigator/focus source and the offline capture-bundle
source so the workspace, search, copy, and speech layers never learn which backend answered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..domain.inspector import (
	ChildState,
	InspectorSourceIdentity,
	NodeFacet,
	PropertyCategory,
	PropertyRow,
	StructuredPropertyNode,
)

__all__ = [
	"ChildFetch",
	"InspectorSource",
	"PropertyFetch",
]


@dataclass(frozen=True, slots=True)
class ChildFetch:
	"""The outcome of enumerating one node's children on demand.

	``ChildState.LOADED`` always carries at least one child; a proven-empty enumeration is instead
	reported as ``ChildState.EMPTY``. ``ChildState.TRUNCATED`` may carry its captured child prefix,
	or no children when enumeration ended before one could be captured. Hint, loading, failure,
	cancellation, and rejection states carry no children so the tree can render each outcome
	explicitly instead of collapsing them into a bare leaf.
	"""

	parentId: str
	state: ChildState
	children: tuple[NodeFacet, ...] = ()
	note: str | None = None

	def __post_init__(self) -> None:
		if self.state is ChildState.LOADED and not self.children:
			raise ValueError("a loaded enumeration must carry at least one child")
		if self.children and self.state not in (ChildState.LOADED, ChildState.TRUNCATED):
			raise ValueError("only a loaded or truncated enumeration may carry children")


@dataclass(frozen=True, slots=True)
class PropertyFetch:
	"""The outcome of reading one property category for one node, already privacy-safe.

	Flat categories populate ``rows``; the All Properties category additionally populates
	``structured`` with the tree-list model. A category that was not read leaves both empty, letting
	the service keep the previous generation's rows stale until a matching replacement commits.
	"""

	nodeId: str
	category: PropertyCategory
	rows: tuple[PropertyRow, ...] = ()
	structured: tuple[StructuredPropertyNode, ...] = ()
	note: str | None = None


@runtime_checkable
class InspectorSource(Protocol):
	"""Read-only observation protocol shared by the live and offline Inspector backends.

	Implementations expose identity, roots, lazy child enumeration, and per-category property reads,
	and nothing else: there is no mutation, activation, focus, or selection surface, so an Inspector
	action can never change the target it observes.
	"""

	def identity(self) -> InspectorSourceIdentity: ...

	def roots(self) -> tuple[NodeFacet, ...]: ...

	def children(self, nodeId: str) -> ChildFetch: ...

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch: ...

	def close(self) -> None: ...
