"""Stateful Inspector orchestration over the shared live/offline source protocol.

``InspectorService`` is the imperative shell's single owner of Inspector view state. It holds the
current source, the disclosed hierarchy, eleven independent property panes, per-source restoration
memory, and the generation counters that make every deferred read safe. The native frame calls into
this service with generation-tagged commands and renders the immutable views it returns; the service
in turn depends only on ``ports.inspector.InspectorSource``, never on wx, NVDA, or files.

Task 1 establishes source admission, the ancestor-only initial hierarchy, branch-local expansion,
the eleven stable panes with independent cursors, and the All Properties one-level structured
expansion. Later tasks layer navigation, search, copy, quick properties, Follow Focus, retarget, and
destruction-safe teardown onto the same generation model.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, runtime_checkable

from ..domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	DEFAULT_PROPERTY_INTERVAL_MS,
	PROPERTY_CATEGORY_ORDER,
	ChildState,
	FocusMatchCandidate,
	FocusMatchResult,
	HierarchyNode,
	InspectorSourceIdentity,
	InspectorSourceKind,
	NodeFacet,
	PaneCursor,
	PropertyCategory,
	PropertyRow,
	QuickPropertyAction,
	QuickPropertyRepeatState,
	SearchableNode,
	SearchOutcome,
	StructuredPropertyNode,
	expandAllPropertiesOneLevel,
	focusMatchLimits,
	matchInspectorTarget,
	normalizeQuickPropertyDigit,
	searchLoadedNodes,
	validateAnnotationKeys,
)
from ..domain.settings import SettingsSnapshot
from ..domain.status import requireToken
from ..ports.inspector import ChildFetch, InspectorSource, PropertyFetch
from ..presentation.inspector import (
	CopyCategory,
	CopyNode,
	renderNodeJson,
	renderNodeMarkdown,
	renderNodePath,
	renderNodeText,
	renderPropertyText,
)

_UNIT_SEPARATOR = "\x1f"


class InspectorRegion(StrEnum):
	"""The three keyboard focus regions the workspace cycles with F6/Shift+F6."""

	HIERARCHY = "hierarchy"
	PROPERTIES = "properties"
	SEARCH = "search"


_REGION_ORDER: tuple[InspectorRegion, ...] = (
	InspectorRegion.HIERARCHY,
	InspectorRegion.PROPERTIES,
	InspectorRegion.SEARCH,
)


class InspectorEscape(StrEnum):
	"""What Escape does next: dismiss an active search filter, or request closing the frame."""

	DISMISS_SEARCH = "dismissSearch"
	CLOSE = "close"


class InspectorCopyKind(StrEnum):
	"""The semantic copy contexts routed to the privacy-safe renderers."""

	NODE_JSON = "nodeJson"
	NODE_TEXT = "nodeText"
	NODE_MARKDOWN = "nodeMarkdown"
	NODE_PATH = "nodePath"
	PROPERTY = "property"


@dataclass(frozen=True, slots=True)
class QuickPropertyOutcome:
	"""One quick-property press resolved to its cycle action and the addressed row, if loaded."""

	digit: int
	action: QuickPropertyAction
	deadlineMilliseconds: int
	row: PropertyRow | None


class FollowFocusOutcome(StrEnum):
	"""What Follow Focus does with one external focus change while it is armed."""

	IGNORED_DISABLED = "ignoredDisabled"
	EXCLUDED_SELF = "excludedSelf"
	EXCLUDED_TRANSIENT = "excludedTransient"
	COALESCED = "coalesced"
	RETARGET = "retarget"


@dataclass(frozen=True, slots=True)
class FollowFocusEvent:
	"""One system focus change offered to Follow Focus, already reduced to safe evidence.

	``applicationKey`` is a stable per-application identifier (for example the executable and
	process). ``isInspectorSurface`` marks the Inspector's own window and ``isTransient`` marks a
	menu, tooltip, or other surface the workspace must never chase.
	"""

	applicationKey: str
	isInspectorSurface: bool = False
	isTransient: bool = False

	def __post_init__(self) -> None:
		object.__setattr__(self, "applicationKey", requireToken(self.applicationKey, "application key"))


@dataclass(frozen=True, slots=True)
class HierarchyRow:
	"""One rendered hierarchy line: the node plus its current disclosure and selection state."""

	node: HierarchyNode
	depth: int
	expanded: bool
	selected: bool

	@property
	def nodeId(self) -> str:
		return self.node.nodeId


@dataclass(frozen=True, slots=True)
class PaneView:
	"""One property tab's immutable render: rows, structured tree, retained cursor, staleness."""

	category: PropertyCategory
	nodeId: str | None
	rows: tuple[PropertyRow, ...]
	structured: tuple[StructuredPropertyNode, ...]
	cursor: PaneCursor
	stale: bool
	note: str | None = None
	annotations: tuple[AnnotationRecord, ...] = ()


class AnnotationNavigationStatus(StrEnum):
	NAVIGATED = "navigated"
	UNAVAILABLE = "unavailable"
	STALE = "stale"


@dataclass(frozen=True, slots=True)
class AnnotationNavigationOutcome:
	status: AnnotationNavigationStatus
	nodeId: str | None = None


@runtime_checkable
class _AnnotationSource(Protocol):
	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class _SavedState:
	"""Everything restored when the same source is reopened."""

	expanded: frozenset[str]
	selected: str | None
	activeCategory: PropertyCategory
	cursors: tuple[tuple[PropertyCategory, PaneCursor], ...]


def _defaultCursors() -> dict[PropertyCategory, PaneCursor]:
	return {category: PaneCursor() for category in PROPERTY_CATEGORY_ORDER}


def _sourceKey(identity: InspectorSourceIdentity) -> str:
	return _UNIT_SEPARATOR.join(
		(
			identity.kind.value,
			identity.executable,
			str(identity.processId),
			identity.backend,
			identity.label,
		),
	)


def _renderAnnotationsText(records: tuple[AnnotationRecord, ...]) -> str:
	"""Render all safe annotation metadata, including relationships, for complete offline copies."""

	lines = ["Annotations:"]
	if not records:
		lines.append("\t(no annotations)")
		return "\n".join(lines)

	def optional(value: object | None) -> str:
		return str(value) if value is not None else "(none)"

	def render(record: AnnotationRecord, *, depth: int, label: str) -> None:
		indent = "\t" * depth
		lines.append(f"{indent}{label}: {record.typeName}")
		fields = (
			("Key", record.key),
			("Status", record.status.value),
			("Source", record.source),
			("Type ID", record.typeId),
			("Summary", record.summary),
			("Author", record.author),
			("Date and time", record.dateTime),
			("Target name", record.targetName),
			("Target role", record.targetRole),
			("Target identity", record.targetIdentity),
			("Target node ID", record.targetNodeId),
			("Target identity proven", record.targetIdentityProven),
			("Relationship", record.relationship),
			(
				"Error",
				(
					f"{record.errorRef.code}, {record.errorRef.diagnosticId}"
					if record.errorRef is not None
					else None
				),
			),
			("Can navigate", record.canNavigate),
		)
		for name, value in fields:
			lines.append(f"{indent}\t{name}: {optional(value)}")
		for index, related in enumerate(record.related, 1):
			render(related, depth=depth + 1, label=f"Related annotation {index}")

	for index, record in enumerate(records, 1):
		render(record, depth=1, label=f"Annotation {index}")
	return "\n".join(lines)


class InspectorService:
	"""Own the disclosed hierarchy, property panes, and generation-guarded reads for one Inspector."""

	__slots__ = (
		"_activeCategory",
		"_annotations",
		"_childIds",
		"_childState",
		"_exceptionalSuffix",
		"_expanded",
		"_facets",
		"_followFocus",
		"_interval",
		"_lifecycleGeneration",
		"_loaded",
		"_operationGeneration",
		"_paneNode",
		"_paneNote",
		"_region",
		"_repeat",
		"_rootIds",
		"_saved",
		"_searchQuery",
		"_selectedAnnotation",
		"_selected",
		"_source",
		"_sourceGeneration",
		"_swap",
		"_targetId",
		"_cursors",
	)

	def __init__(self) -> None:
		super().__init__()
		self._source: InspectorSource | None = None
		self._sourceGeneration = 0
		self._operationGeneration = 0
		self._facets: dict[str, NodeFacet] = {}
		self._childIds: dict[str, tuple[str, ...]] = {}
		self._childState: dict[str, ChildState] = {}
		self._exceptionalSuffix: dict[str, str] = {}
		self._expanded: set[str] = set()
		self._rootIds: tuple[str, ...] = ()
		self._targetId: str | None = None
		self._selected: str | None = None
		self._activeCategory = PropertyCategory.CORE
		self._annotations: dict[str, tuple[AnnotationRecord, ...]] = {}
		self._cursors: dict[PropertyCategory, PaneCursor] = _defaultCursors()
		self._loaded: dict[tuple[str, PropertyCategory], PropertyFetch] = {}
		self._paneNode: dict[PropertyCategory, str] = {}
		self._paneNote: dict[PropertyCategory, str | None] = {}
		self._saved: dict[str, _SavedState] = {}
		self._interval = DEFAULT_PROPERTY_INTERVAL_MS
		self._swap = False
		self._region = InspectorRegion.HIERARCHY
		self._searchQuery: str | None = None
		self._selectedAnnotation: str | None = None
		self._repeat = QuickPropertyRepeatState(
			intervalMilliseconds=self._interval,
			swapActions=self._swap,
		)
		self._followFocus = False
		self._lifecycleGeneration = 0

	# -- generations -------------------------------------------------------

	@property
	def sourceGeneration(self) -> int:
		return self._sourceGeneration

	@property
	def operationGeneration(self) -> int:
		return self._operationGeneration

	def _beginOperation(self) -> int:
		self._operationGeneration += 1
		return self._operationGeneration

	def isCurrent(self, *, sourceGeneration: int, operationGeneration: int) -> bool:
		"""True when a deferred read still matches the live source and latest operation."""

		return (
			self._source is not None
			and sourceGeneration == self._sourceGeneration
			and operationGeneration == self._operationGeneration
		)

	def _requireSource(self) -> InspectorSource:
		source = self._source
		if source is None:
			raise RuntimeError("no Inspector source is open")
		return source

	def sourceIdentity(self) -> InspectorSourceIdentity | None:
		"""The current source's privacy-safe identity, or ``None`` when no source is open.

		The native workspace renders this as its ``Current Inspector source`` summary; returning
		``None`` lets it show an explicit empty state instead of raising before a source is admitted.
		"""

		source = self._source
		return None if source is None else source.identity()

	# -- source admission and restoration ---------------------------------

	def applySettings(self, settings: SettingsSnapshot) -> None:
		"""Adopt a committed settings change without waiting for the next source to be opened.

		The quick-property repeat state is rebuilt because a change to the repeat interval or to the
		swapped actions must not be judged against a cycle that began under the previous rule.
		"""

		self._interval = settings.propertyIntervalMilliseconds
		self._swap = settings.swapPropertyActions
		self._repeat = QuickPropertyRepeatState(
			intervalMilliseconds=self._interval,
			swapActions=self._swap,
		)

	def openSource(self, source: InspectorSource, *, settings: SettingsSnapshot | None = None) -> None:
		"""Admit a live or offline source, building the ancestor-only initial hierarchy.

		A source seen before restores its saved hierarchy selection and per-category cursors. The
		Inspector always opens in Core so reopening it returns to the selected hierarchy item rather
		than an arbitrary detail view.
		"""

		if settings is not None:
			self._interval = settings.propertyIntervalMilliseconds
			self._swap = settings.swapPropertyActions
		self._repeat = QuickPropertyRepeatState(
			intervalMilliseconds=self._interval,
			swapActions=self._swap,
		)
		self._searchQuery = None
		self._region = InspectorRegion.HIERARCHY
		previous = self._source
		if previous is not None:
			self._rememberState()
			self._source = None
			previous.close()
		self._source = source
		self._sourceGeneration += 1
		self._operationGeneration += 1
		self._ingestRoots(source.roots())
		identity = source.identity()
		self._restoreState(
			_sourceKey(identity),
			restoreHierarchy=identity.kind is InspectorSourceKind.OFFLINE,
		)
		self._loadActivePane()

	def retargetWithinSource(self, facets: tuple[NodeFacet, ...]) -> bool:
		"""Select a new live target while preserving the current foreground hierarchy."""

		source = self._source
		if source is None or source.identity().kind is not InspectorSourceKind.LIVE or not facets:
			return False
		ordered = tuple(sorted(facets, key=lambda facet: facet.depth))
		if not self._rootIds or ordered[0].nodeId != self._rootIds[0]:
			return False
		_ = self._beginOperation()
		for facet in ordered:
			self._facets[facet.nodeId] = facet
		for parent, child in zip(ordered, ordered[1:]):
			children = list(self._childIds.get(parent.nodeId, ()))
			if child.nodeId not in children:
				children.append(child.nodeId)
			self._childIds[parent.nodeId] = tuple(children)
			_ = self._childState.setdefault(parent.nodeId, ChildState.HINT)
			self._expanded.add(parent.nodeId)
		target = ordered[-1]
		_ = self._childState.setdefault(
			target.nodeId,
			ChildState.HINT if target.childHint else ChildState.UNKNOWN,
		)
		self._targetId = target.nodeId
		self._selected = target.nodeId
		self._loadActivePane()
		return True

	def _ingestRoots(self, facets: tuple[NodeFacet, ...]) -> None:
		if not facets:
			raise ValueError("a source must expose at least the inspected target")
		ordered = sorted(facets, key=lambda facet: facet.depth)
		self._facets = {facet.nodeId: facet for facet in ordered}
		self._childIds = {}
		self._childState = {}
		self._exceptionalSuffix = {}
		self._expanded = set()
		self._loaded = {}
		self._annotations = {}
		self._paneNode = {}
		self._paneNote = {}
		self._cursors = _defaultCursors()
		self._rootIds = (ordered[0].nodeId,)
		self._targetId = ordered[-1].nodeId
		self._selected = ordered[-1].nodeId
		self._activeCategory = PropertyCategory.CORE
		self._selectedAnnotation = None
		for parent, child in zip(ordered, ordered[1:]):
			self._childIds[parent.nodeId] = (child.nodeId,)
			self._childState[parent.nodeId] = ChildState.HINT
			self._expanded.add(parent.nodeId)
		target = ordered[-1]
		self._childState[target.nodeId] = ChildState.HINT if target.childHint else ChildState.UNKNOWN

	def _rememberState(self) -> None:
		source = self._source
		if source is None:
			return
		key = _sourceKey(source.identity())
		self._saved[key] = _SavedState(
			expanded=frozenset(self._expanded),
			selected=self._selected,
			activeCategory=self._activeCategory,
			cursors=tuple(self._cursors.items()),
		)

	def _restoreState(self, key: str, *, restoreHierarchy: bool) -> None:
		saved = self._saved.get(key)
		if saved is None:
			return
		if restoreHierarchy:
			self._expanded = {nodeId for nodeId in saved.expanded if nodeId in self._facets}
			if saved.selected is not None and saved.selected in self._facets:
				self._selected = saved.selected
		# Presentation starts in the same useful, predictable category for every visit.  The saved
		# cursors remain available if the user chooses a different presentation category.
		self._activeCategory = PropertyCategory.CORE
		restored = _defaultCursors()
		for category, cursor in saved.cursors:
			restored[category] = cursor
		self._cursors = restored

	# -- hierarchy ---------------------------------------------------------

	def _node(self, nodeId: str) -> HierarchyNode:
		return HierarchyNode(
			facet=self._facets[nodeId],
			childState=self._childState.get(nodeId, ChildState.UNKNOWN),
			childIds=self._childIds.get(nodeId, ()),
			exceptionalSuffix=self._exceptionalSuffix.get(nodeId),
		)

	def hierarchy(self) -> tuple[HierarchyRow, ...]:
		"""The visible hierarchy rows in display order, honoring current expansion state."""

		rows: list[HierarchyRow] = []

		def walk(nodeId: str, depth: int) -> None:
			expanded = nodeId in self._expanded
			rows.append(
				HierarchyRow(
					node=self._node(nodeId),
					depth=depth,
					expanded=expanded,
					selected=nodeId == self._selected,
				),
			)
			if expanded:
				for childId in self._childIds.get(nodeId, ()):
					if childId in self._facets:
						walk(childId, depth + 1)

		for rootId in self._rootIds:
			if rootId in self._facets:
				walk(rootId, 0)
		return tuple(rows)

	def hierarchySubtree(self, nodeId: str) -> tuple[HierarchyRow, ...]:
		"""Read a complete subtree without changing the hierarchy's visible expansion state."""

		source = self._requireSource()
		sourceGeneration = self._sourceGeneration
		if nodeId not in self._facets:
			raise KeyError(nodeId)
		rows: list[HierarchyRow] = []
		visited: set[str] = set()

		def walk(currentId: str, depth: int) -> None:
			if currentId in visited:
				return
			visited.add(currentId)
			state = self._childState.get(currentId, ChildState.UNKNOWN)
			if state not in (ChildState.LOADED, ChildState.EMPTY):
				operation = self._beginOperation()
				fetch = source.children(currentId)
				if not self.isCurrent(
					sourceGeneration=sourceGeneration,
					operationGeneration=operation,
				):
					return
				self._commitChildren(currentId, fetch)
			rows.append(
				HierarchyRow(
					node=self._node(currentId),
					depth=depth,
					expanded=currentId in self._expanded,
					selected=currentId == self._selected,
				),
			)
			for childId in self._childIds.get(currentId, ()):
				if childId in self._facets:
					walk(childId, depth + 1)

		walk(nodeId, 0)
		return tuple(rows)

	def completeNodeText(self, nodeId: str) -> str:
		"""Render every Inspector category for one stored node, without moving the selection."""

		source = self._requireSource()
		sourceGeneration = self._sourceGeneration
		if nodeId not in self._facets:
			raise KeyError(nodeId)
		categories: list[CopyCategory] = []
		for category in PROPERTY_CATEGORY_ORDER:
			if category is PropertyCategory.ANNOTATIONS:
				continue
			operation = self._beginOperation()
			fetch = source.properties(nodeId, category)
			if not self.isCurrent(
				sourceGeneration=sourceGeneration,
				operationGeneration=operation,
			):
				return ""
			if category is PropertyCategory.ALL_PROPERTIES:
				fetch = replace(fetch, structured=expandAllPropertiesOneLevel(fetch.structured))
			categories.append(CopyCategory(category, fetch.rows, fetch.structured))
		node = CopyNode(
			identity=source.identity(),
			path=self._pathTo(nodeId),
			categories=tuple(categories),
		)
		annotations = source.annotations(nodeId) if isinstance(source, _AnnotationSource) else ()
		validateAnnotationKeys(annotations)
		return f"{renderNodeText(node)}\n\n{_renderAnnotationsText(annotations)}"

	@property
	def selectedNodeId(self) -> str | None:
		return self._selected

	@property
	def targetNodeId(self) -> str | None:
		return self._targetId

	def childState(self, nodeId: str) -> ChildState:
		return self._childState.get(nodeId, ChildState.UNKNOWN)

	def expand(self, nodeId: str) -> ChildState:
		"""Disclose one node, fetching only that branch's children the first time it opens."""

		source = self._requireSource()
		sourceGeneration = self._sourceGeneration
		if nodeId not in self._facets:
			raise KeyError(nodeId)
		operation = self._beginOperation()
		state = self._childState.get(nodeId, ChildState.UNKNOWN)
		if state not in (ChildState.LOADED, ChildState.EMPTY):
			fetch = source.children(nodeId)
			if not self.isCurrent(
				sourceGeneration=sourceGeneration,
				operationGeneration=operation,
			):
				return self._childState.get(nodeId, ChildState.UNKNOWN)
			self._commitChildren(nodeId, fetch)
		self._expanded.add(nodeId)
		return self._childState.get(nodeId, ChildState.UNKNOWN)

	def _commitChildren(self, nodeId: str, fetch: ChildFetch) -> None:
		self._childState[nodeId] = fetch.state
		if fetch.note is not None:
			self._exceptionalSuffix[nodeId] = fetch.note
		else:
			_ = self._exceptionalSuffix.pop(nodeId, None)
		childIds: list[str] = []
		for facet in fetch.children:
			self._facets[facet.nodeId] = facet
			_ = self._childState.setdefault(
				facet.nodeId,
				ChildState.HINT if facet.childHint else ChildState.UNKNOWN,
			)
			childIds.append(facet.nodeId)
		self._childIds[nodeId] = tuple(childIds)

	def collapse(self, nodeId: str) -> None:
		_ = self._expanded.discard(nodeId)

	# -- selection and property panes -------------------------------------

	@property
	def activeCategory(self) -> PropertyCategory:
		return self._activeCategory

	def selectNode(self, nodeId: str) -> None:
		"""Move the selection and refresh only the active pane, leaving other panes stale."""

		if nodeId not in self._facets:
			raise KeyError(nodeId)
		self._repeat.cancel()
		self._expandAncestors(nodeId)
		self._selected = nodeId
		self._selectedAnnotation = None
		_ = self._beginOperation()
		self._loadActivePane()

	def _expandAncestors(self, nodeId: str) -> None:
		"""Reveal a programmatically selected node without changing its own disclosure state."""

		current = self._facets[nodeId].parentId
		visited: set[str] = set()
		while current is not None and current not in visited and current in self._facets:
			visited.add(current)
			self._expanded.add(current)
			current = self._facets[current].parentId

	def selectCategory(self, category: PropertyCategory) -> PaneView:
		"""Switch tabs, lazily loading that tab for the selected node while retaining its cursor."""

		self._activeCategory = category
		_ = self._beginOperation()
		self._loadActivePane()
		return self.pane(category)

	def _loadActivePane(self) -> None:
		nodeId = self._selected
		if nodeId is None:
			return
		self._loadCategory(
			nodeId,
			self._activeCategory,
			sourceGeneration=self._sourceGeneration,
			operationGeneration=self._operationGeneration,
		)

	def _loadCategory(
		self,
		nodeId: str,
		category: PropertyCategory,
		*,
		sourceGeneration: int,
		operationGeneration: int,
	) -> None:
		source = self._requireSource()
		if category is PropertyCategory.ANNOTATIONS:
			records = source.annotations(nodeId) if isinstance(source, _AnnotationSource) else ()
			validateAnnotationKeys(records)
			if not self.isCurrent(
				sourceGeneration=sourceGeneration,
				operationGeneration=operationGeneration,
			):
				return
			self._annotations[nodeId] = records
			self._paneNode[category] = nodeId
			self._paneNote[category] = None
			return
		fetch = source.properties(nodeId, category)
		if not self.isCurrent(
			sourceGeneration=sourceGeneration,
			operationGeneration=operationGeneration,
		):
			return
		self._commitProperties(nodeId, category, fetch)

	def _commitProperties(self, nodeId: str, category: PropertyCategory, fetch: PropertyFetch) -> None:
		if category is PropertyCategory.ALL_PROPERTIES:
			fetch = replace(fetch, structured=expandAllPropertiesOneLevel(fetch.structured))
		self._loaded[(nodeId, category)] = fetch
		self._paneNode[category] = nodeId
		self._paneNote[category] = fetch.note
		cursor = self._cursors[category]
		if cursor.selectedFieldKey is not None and not self._fieldPresent(fetch, cursor.selectedFieldKey):
			self._cursors[category] = replace(cursor, selectedFieldKey=None)

	@staticmethod
	def _fieldPresent(fetch: PropertyFetch, fieldKey: str) -> bool:
		if any(row.fieldKey == fieldKey for row in fetch.rows):
			return True

		def search(nodes: tuple[StructuredPropertyNode, ...]) -> bool:
			for node in nodes:
				if node.key == fieldKey or search(node.children):
					return True
			return False

		return search(fetch.structured)

	def pane(self, category: PropertyCategory) -> PaneView:
		"""The immutable render of one property tab, marked stale until its node matches selection."""

		nodeId = self._paneNode.get(category)
		fetch = self._loaded.get((nodeId, category)) if nodeId is not None else None
		rows = fetch.rows if fetch is not None else ()
		structured = fetch.structured if fetch is not None else ()
		stale = nodeId is not None and nodeId != self._selected
		return PaneView(
			category=category,
			nodeId=nodeId,
			rows=rows,
			structured=structured,
			cursor=self._cursors[category],
			stale=stale,
			note=self._paneNote.get(category),
			annotations=self._annotations.get(nodeId, ()) if nodeId is not None else (),
		)

	def activePane(self) -> PaneView:
		return self.pane(self._activeCategory)

	def cursor(self, category: PropertyCategory) -> PaneCursor:
		return self._cursors[category]

	def setCursor(self, category: PropertyCategory, cursor: PaneCursor) -> None:
		"""Retain one tab's selected field and scroll independently of every other tab."""

		self._cursors[category] = cursor

	def selectedAnnotation(self) -> AnnotationRecord | None:
		nodeId = self._paneNode.get(PropertyCategory.ANNOTATIONS)
		if nodeId is None or self._selectedAnnotation is None:
			return None

		def find(records: tuple[AnnotationRecord, ...]) -> AnnotationRecord | None:
			for record in records:
				if record.key == self._selectedAnnotation:
					return record
				nested = find(record.related)
				if nested is not None:
					return nested
			return None

		return find(self._annotations.get(nodeId, ()))

	def selectAnnotation(self, key: str) -> AnnotationRecord | None:
		self._selectedAnnotation = requireToken(key, "annotation key")
		record = self.selectedAnnotation()
		if record is None:
			self._selectedAnnotation = None
		return record

	def canNavigateAnnotationTarget(self, record: AnnotationRecord | None = None) -> bool:
		candidate = record or self.selectedAnnotation()
		return bool(
			candidate is not None and candidate.canNavigate and candidate.targetNodeId in self._facets,
		)

	def navigateAnnotationTarget(self, key: str) -> AnnotationNavigationOutcome:
		record = self.selectAnnotation(key)
		if record is None:
			return AnnotationNavigationOutcome(AnnotationNavigationStatus.UNAVAILABLE)
		if record.status is AnnotationStatus.STALE:
			return AnnotationNavigationOutcome(AnnotationNavigationStatus.STALE)
		if not self.canNavigateAnnotationTarget(record):
			return AnnotationNavigationOutcome(AnnotationNavigationStatus.UNAVAILABLE)
		targetNodeId = record.targetNodeId
		assert targetNodeId is not None
		self.selectNode(targetNodeId)
		return AnnotationNavigationOutcome(AnnotationNavigationStatus.NAVIGATED, targetNodeId)

	# -- keyboard regions --------------------------------------------------

	@property
	def activeRegion(self) -> InspectorRegion:
		return self._region

	def focusRegion(self, region: InspectorRegion) -> InspectorRegion:
		"""Move focus straight to one region, as a direct click or shortcut would."""

		self._region = region
		return self._region

	def cycleRegion(self, *, forward: bool = True) -> InspectorRegion:
		"""Advance F6/Shift+F6 through hierarchy, properties, and search, wrapping both ways."""

		index = _REGION_ORDER.index(self._region)
		step = 1 if forward else -1
		self._region = _REGION_ORDER[(index + step) % len(_REGION_ORDER)]
		return self._region

	def escape(self) -> InspectorEscape:
		"""Escape clears an active search and returns to the tree, else asks to close the frame."""

		if self._searchQuery is not None or self._region is InspectorRegion.SEARCH:
			self._searchQuery = None
			self._region = InspectorRegion.HIERARCHY
			return InspectorEscape.DISMISS_SEARCH
		return InspectorEscape.CLOSE

	# -- loaded-only search ------------------------------------------------

	@property
	def searchQuery(self) -> str | None:
		return self._searchQuery

	def _searchableNodes(self) -> tuple[SearchableNode, ...]:
		"""The visible, already-loaded nodes and their safe loaded text, in display order.

		Only value-bearing rows contribute text, so redacted or failed fields never enter the
		search index. Building this list reads nothing from the source and never expands a branch.
		"""

		nodes: list[SearchableNode] = []
		for row in self.hierarchy():
			nodeId = row.nodeId
			facet = self._facets[nodeId]
			texts: list[str] = []
			for category in PROPERTY_CATEGORY_ORDER:
				fetch = self._loaded.get((nodeId, category))
				if fetch is None:
					continue
				texts.extend(propertyRow.value for propertyRow in fetch.rows if propertyRow.value is not None)
			nodes.append(
				SearchableNode(
					nodeId=nodeId,
					name=facet.name,
					role=facet.role,
					loadedText=tuple(texts),
				),
			)
		return tuple(nodes)

	def search(self, query: str, *, forward: bool = True) -> SearchOutcome:
		"""Find and select the next/previous loaded node matching ``query`` without any source read."""

		self._region = InspectorRegion.SEARCH
		outcome = searchLoadedNodes(
			self._searchableNodes(),
			query,
			currentNodeId=self._selected,
			forward=forward,
		)
		self._searchQuery = None if outcome.decision == "empty" else outcome.query
		if outcome.decision == "match" and outcome.nodeId is not None:
			self.selectNode(outcome.nodeId)
			self._region = InspectorRegion.SEARCH
		return outcome

	# -- semantic copy -----------------------------------------------------

	def _pathTo(self, nodeId: str) -> tuple[NodeFacet, ...]:
		chain: list[NodeFacet] = []
		current: str | None = nodeId
		while current is not None and current in self._facets:
			facet = self._facets[current]
			chain.append(facet)
			current = facet.parentId
		chain.reverse()
		return tuple(chain)

	def _copyNode(self) -> CopyNode:
		nodeId = self._selected
		if nodeId is None:
			raise RuntimeError("no node is selected to copy")
		categories: list[CopyCategory] = []
		for category in PROPERTY_CATEGORY_ORDER:
			fetch = self._loaded.get((nodeId, category))
			if fetch is None:
				continue
			categories.append(CopyCategory(category, fetch.rows, fetch.structured))
		return CopyNode(
			identity=self._requireSource().identity(),
			path=self._pathTo(nodeId),
			categories=tuple(categories),
		)

	def _activeCursorRow(self) -> PropertyRow | None:
		nodeId = self._paneNode.get(self._activeCategory)
		fetch = self._loaded.get((nodeId, self._activeCategory)) if nodeId is not None else None
		if fetch is None:
			return None
		selected = self._cursors[self._activeCategory].selectedFieldKey
		if fetch.rows:
			if selected is not None:
				for row in fetch.rows:
					if row.fieldKey == selected:
						return row
			return fetch.rows[0]

		def find(nodes: tuple[StructuredPropertyNode, ...]) -> StructuredPropertyNode | None:
			for node in nodes:
				if node.key == selected:
					return node
				found = find(node.children)
				if found is not None:
					return found
			return None

		node = find(fetch.structured) if selected is not None else None
		if node is None and fetch.structured:
			node = fetch.structured[0]
		if node is not None:
			return PropertyRow(
				fieldKey=node.key,
				name=node.label,
				status=node.status,
				value=node.value,
				source="structured",
			)
		return None

	def copy(self, kind: InspectorCopyKind) -> str:
		"""Render the selected node or property for the clipboard through the safe renderers."""

		if kind is InspectorCopyKind.PROPERTY:
			row = self._activeCursorRow()
			return renderPropertyText(row) if row is not None else ""
		node = self._copyNode()
		if kind is InspectorCopyKind.NODE_JSON:
			return renderNodeJson(node)
		if kind is InspectorCopyKind.NODE_TEXT:
			return renderNodeText(node)
		if kind is InspectorCopyKind.NODE_MARKDOWN:
			return renderNodeMarkdown(node)
		return renderNodePath(node)

	# -- quick properties --------------------------------------------------

	def _quickRow(self, digit: int) -> PropertyRow | None:
		if self._selected is None:
			return None
		fetch = self._loaded.get((self._selected, PropertyCategory.QUICK))
		if fetch is None:
			return None
		index = 9 if digit == 0 else digit - 1
		if index >= len(fetch.rows):
			return None
		return fetch.rows[index]

	def quickProperty(
		self,
		gestureIdentifier: object,
		*,
		nowMilliseconds: int,
	) -> QuickPropertyOutcome | None:
		"""Resolve one layout-tolerant quick-property press; non-digit gestures are ignored.

		The digit is normalized independently of keyboard layout and drives its own bounded repeat
		cycle. The addressed Quick Properties row is returned when it is already loaded so the frame
		can announce, browse, or copy it without any extra source read.
		"""

		digit = normalizeQuickPropertyDigit(gestureIdentifier)
		if digit is None:
			return None
		decision = self._repeat.press(digit, nowMilliseconds=nowMilliseconds)
		return QuickPropertyOutcome(
			digit=decision.digit,
			action=decision.action,
			deadlineMilliseconds=decision.deadlineMilliseconds,
			row=self._quickRow(digit),
		)

	def cancelQuickProperties(self) -> None:
		"""Cancel every pending quick-property repeat timer on a lifecycle or retarget change."""

		self._repeat.cancel()

	# -- retarget, Follow Focus, and lifecycle -----------------------------

	@property
	def lifecycleGeneration(self) -> int:
		return self._lifecycleGeneration

	@property
	def followFocusEnabled(self) -> bool:
		return self._followFocus

	@property
	def followFocusAvailable(self) -> bool:
		"""Follow Focus only makes sense for a live source, never an offline capture bundle."""

		return self._source is not None and self._source.identity().followFocusAvailable

	def setFollowFocus(self, enabled: bool) -> bool:
		"""Arm or disarm Follow Focus; it stays off unless a live source can support it."""

		self._followFocus = enabled and self.followFocusAvailable
		return self._followFocus

	def _currentApplicationKey(self) -> str | None:
		if self._source is None:
			return None
		identity = self._source.identity()
		return f"{identity.executable}{_UNIT_SEPARATOR}{identity.processId}"

	def considerFollowFocus(self, event: FollowFocusEvent) -> FollowFocusOutcome:
		"""Decide what one external focus change means to an armed, live Follow Focus session.

		Disarmed sessions ignore everything. The Inspector's own surfaces and transient menus or
		tooltips are excluded by evidence. Every remaining focus change asks the host to replace the
		live source so Follow Focus tracks controls within an application as well as application changes.
		"""

		if not self._followFocus:
			return FollowFocusOutcome.IGNORED_DISABLED
		if event.isInspectorSurface:
			return FollowFocusOutcome.EXCLUDED_SELF
		if event.isTransient:
			return FollowFocusOutcome.EXCLUDED_TRANSIENT
		self._repeat.cancel()
		return FollowFocusOutcome.RETARGET

	def resolveRetarget(self, candidates: tuple[FocusMatchCandidate, ...]) -> FocusMatchResult:
		"""Resolve a focus/navigator retarget through the identity ladder under the fixed budgets.

		Geometry may only narrow the candidate neighbourhood; the returned match always cleared one
		positive identity layer. Ambiguous, role-mismatched, and budget-exhausted searches return
		their explicit rejected or unavailable result rather than a guess.
		"""

		return matchInspectorTarget(candidates, limits=focusMatchLimits())

	def close(self) -> None:
		"""Invalidate every deferred read, then release view state while keeping per-source memory.

		Closing bumps the lifecycle and source generations and drops the source so any late callback
		fails ``isCurrent`` before it can touch a control, provider, or file. Saved per-application
		state is preserved so a later reopen restores the workspace exactly.
		"""

		self._repeat.cancel()
		source = self._source
		if source is not None:
			self._rememberState()
		self._source = None
		self._lifecycleGeneration += 1
		self._sourceGeneration += 1
		self._operationGeneration += 1
		self._followFocus = False
		self._searchQuery = None
		self._region = InspectorRegion.HIERARCHY
		if source is not None:
			source.close()
