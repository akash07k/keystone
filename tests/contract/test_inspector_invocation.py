# pyright: reportPrivateUsage=false, reportUnusedClass=false

from __future__ import annotations

import unittest
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, Literal, Protocol, cast, override
from unittest.mock import patch

from addon.globalPlugins.keystone.adapters.nvda import commands as commandsModule
from addon.globalPlugins.keystone.adapters.nvda.commands import (
	ProductionCommandRuntime,
)
from addon.globalPlugins.keystone.adapters.nvda.inspector_source import (
	LiveInspectorSource,
	LiveSessionNodeReader,
)
from addon.globalPlugins.keystone.adapters.wx import inspector_frame as inspectorModule
from addon.globalPlugins.keystone.adapters.wx.inspector_frame import (
	AppModuleOverrideOutcome,
	AppModuleOverrideState,
	EventsWorkspace,
	InspectorWorkspace,
	KeystoneWindow,
)
from addon.globalPlugins.keystone.application.event_monitor_service import (
	EventActionOutcome,
	EventMonitorService,
)
from addon.globalPlugins.keystone.application.capture_service import (
	CaptureRequest,
	CaptureService,
	CaptureTargetKind,
)
from addon.globalPlugins.keystone.application.inspector_service import (
	FollowFocusEvent,
	FollowFocusOutcome,
	InspectorService,
)
from addon.globalPlugins.keystone.application.lifecycle import LifecycleService
from addon.globalPlugins.keystone.application.sound_service import WorkflowSounds
from addon.globalPlugins.keystone.domain.commands import CommandId
from addon.globalPlugins.keystone.domain.inspector import (
	AnnotationRecord,
	AnnotationStatus,
	ChildState,
	InspectorSourceIdentity,
	InspectorSourceKind,
	NodeFacet,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	StructuredPropertyNode,
)
from addon.globalPlugins.keystone.domain.event_monitor import (
	DropCounters,
	EventBackend,
	EventCopyFormat,
	EventFilter,
	EventHistory,
	EventProvenance,
	EventRow,
	MonitorScope,
	MonitorScopeKind,
	ScopeUnavailableReason,
)
from addon.globalPlugins.keystone.domain.privacy import PrivacyPolicy
from addon.globalPlugins.keystone.domain.settings import SettingsSnapshot
from addon.globalPlugins.keystone.domain.sounds import (
	CueEventId,
	SoundOwner,
	SoundOwnerKind,
	SoundRequest,
)
from addon.globalPlugins.keystone.domain.status import EvidenceState
from addon.globalPlugins.keystone.domain.state import CaptureState
from addon.globalPlugins.keystone.domain import snapshot_bundle as snapshotBundle
from addon.globalPlugins.keystone.ports.inspector import ChildFetch, PropertyFetch
from tests.fixtures.compact_snapshot_shapes import oversizedSnapshotSource


class _AccessibleNameProvider(Protocol):
	def GetName(self, childId: int) -> tuple[object, str]: ...


class _Widget:
	def __init__(self, *args: object, **kwargs: object) -> None:
		super().__init__()
		self.parent = args[0] if args else None
		self.label = kwargs.get("label")
		self.bindings: dict[object, object] = {}
		self.destroyed = False
		self.focusCount = 0
		self.enableCount = 0
		self.layoutCount = 0
		self.setLabelCount = 0
		self.setValueCount = 0
		self.value: object = False
		self.accessibleName: object = None
		self.helpText: object = None
		self.hint: object = None
		self.editable: bool | None = None
		self.accessible: _AccessibleNameProvider | None = None
		self.style = kwargs.get("style", 0)
		self.title = kwargs.get("title")
		self.enabled = True
		self.shown = True
		self.popupCount = 0
		self.statusBar: _FakeStatusBar | None = None

	def Bind(self, event: object, handler: object, _source: object = None) -> None:
		self.bindings[event] = handler

	def GetParent(self) -> object | None:
		return self.parent

	def Centre(self) -> None:
		pass

	def Destroy(self) -> None:
		self.destroyed = True

	def Enable(self, _enable: bool = True) -> None:
		self.enableCount += 1
		self.enabled = _enable

	def GetValue(self) -> object:
		return self.value

	def Layout(self) -> None:
		self.layoutCount += 1

	def Raise(self) -> None:
		pass

	def SetFocus(self) -> None:
		self.focusCount += 1

	def SetHelpText(self, _text: str) -> None:
		self.helpText = _text

	def SetHint(self, hint: str) -> None:
		self.hint = hint

	def SetLabel(self, label: str) -> None:
		self.setLabelCount += 1
		self.label = label

	def SetMinSize(self, _size: object) -> None:
		pass

	def SetName(self, _name: str) -> None:
		self.accessibleName = _name

	def SetAccessible(self, accessible: object) -> None:
		self.accessible = cast(_AccessibleNameProvider, accessible)

	def SetEditable(self, editable: bool) -> None:
		self.editable = editable

	def SetSize(self, _size: object) -> None:
		pass

	def SetSizer(self, _sizer: object) -> None:
		pass

	def SetTitle(self, title: str) -> None:
		self.title = title

	def SetValue(self, value: object) -> None:
		self.setValueCount += 1
		self.value = value

	def Show(self, _show: bool = True) -> None:
		self.shown = _show

	def Wrap(self, _width: int) -> None:
		pass

	def PopupMenu(self, _menu: object) -> None:
		self.popupCount += 1

	def CreateStatusBar(self, *_args: object, **_kwargs: object) -> _FakeStatusBar:
		self.statusBar = _FakeStatusBar()
		return self.statusBar


class _FakeStatusBar:
	"""A wx status bar double that records the single line written to it."""

	def __init__(self) -> None:
		super().__init__()
		self.text = ""

	def SetStatusText(self, text: str, _index: int = 0) -> None:
		self.text = text

	def GetStatusText(self, _index: int = 0) -> str:
		return self.text


class _Sizer:
	def Add(self, *_args: object) -> None:
		pass

	def AddStretchSpacer(self) -> None:
		pass

	def Clear(self, _deleteWindows: bool = False) -> None:
		pass


class _FakeMenu:
	"""A minimal wx.Menu double that records appended items and destruction."""

	def __init__(self) -> None:
		super().__init__()
		self.items: list[tuple[object, str]] = []
		self.submenus: list[tuple[str, "_FakeMenu"]] = []
		self.destroyed = False

	def Append(self, identifier: object, label: str = "") -> object:
		token = object()
		self.items.append((identifier, label))
		return token

	def AppendSubMenu(self, submenu: "_FakeMenu", label: str) -> object:
		self.submenus.append((label, submenu))
		return object()

	def AppendSeparator(self) -> None:
		self.items.append((None, "---"))

	def Bind(self, _event: object, _handler: object, _item: object) -> None:
		pass

	def Destroy(self) -> None:
		self.destroyed = True


class _Wx:
	DEFAULT_FRAME_STYLE = 1
	VERTICAL = 2
	HORIZONTAL = 3
	EXPAND = 4
	ALL = 8
	LEFT = 16
	RIGHT = 32
	BOTTOM = 64
	ALIGN_CENTER_VERTICAL = 64
	TE_MULTILINE = 128
	TE_READONLY = 256
	ACC_OK = 0
	ACC_NOT_IMPLEMENTED = 1
	ID_CLOSE = 5100
	EVT_BUTTON = object()
	EVT_CLOSE = object()
	EVT_CHAR_HOOK = object()
	WXK_ESCAPE = 27

	class Accessible:
		def __init__(self, window: object | None = None) -> None:
			super().__init__()
			self.window = window

	def __init__(self) -> None:
		super().__init__()
		self.frames: list[_Widget] = []
		self.textControls: list[_Widget] = []
		self.staticTexts: list[_Widget] = []
		self.staticBoxes: list[_Widget] = []
		self.menus: list[_FakeMenu] = []
		self.after: list[object] = []

	def BoxSizer(self, _orientation: int) -> _Sizer:
		return _Sizer()

	def Button(self, *args: object, **kwargs: object) -> _Widget:
		return _Widget(*args, **kwargs)

	def CallAfter(self, callback: object) -> None:
		self.after.append(callback)

	def CheckBox(self, *args: object, **kwargs: object) -> _Widget:
		return _Widget(*args, **kwargs)

	def Frame(self, *args: object, **kwargs: object) -> _Widget:
		frame = _Widget(*args, **kwargs)
		self.frames.append(frame)
		return frame

	def Panel(self, *args: object, **kwargs: object) -> _Widget:
		return _Widget(*args, **kwargs)

	def StaticText(self, *args: object, **kwargs: object) -> _Widget:
		control = _Widget(*args, **kwargs)
		self.staticTexts.append(control)
		return control

	def StaticBox(self, *args: object, **kwargs: object) -> _Widget:
		box = _Widget(*args, **kwargs)
		self.staticBoxes.append(box)
		return box

	def StaticBoxSizer(self, _box: object, _orientation: int = 0) -> _Sizer:
		return _Sizer()

	def Menu(self) -> _FakeMenu:
		menu = _FakeMenu()
		self.menus.append(menu)
		return menu

	def TextCtrl(self, *args: object, **kwargs: object) -> _Widget:
		control = _Widget(*args, **kwargs)
		self.textControls.append(control)
		return control


class _ActivationMainFrame:
	def __init__(self, events: list[str]) -> None:
		super().__init__()
		self.events = events
		self.prepared = False

	def prePopup(self) -> None:
		self.events.append("prePopup")
		self.prepared = True

	def postPopup(self) -> None:
		self.events.append("postPopup")
		self.prepared = False


class _ActivationFrame(_Widget):
	def __init__(
		self,
		parent: object,
		*args: object,
		mainFrame: _ActivationMainFrame,
		events: list[str],
		raisesBeforeActive: int,
		focusRequired: bool,
		focusAttemptsBeforeActive: int,
		**kwargs: object,
	) -> None:
		super().__init__(*args, **kwargs)
		self.parent = parent
		self.mainFrame = mainFrame
		self.events = events
		self.raisesBeforeActive = raisesBeforeActive
		self.focusRequired = focusRequired
		self.focusAttemptsBeforeActive = focusAttemptsBeforeActive
		self.active = False
		self.activationAuthorized = False
		self.attentionCount = 0

	def IsActive(self) -> bool:
		return self.active

	@override
	def Raise(self) -> None:
		self.events.append("raise")
		if self.parent is self.mainFrame and (self.mainFrame.prepared or self.activationAuthorized):
			self.activationAuthorized = True
			if self.raisesBeforeActive <= 0 and not self.focusRequired:
				self.active = True
			else:
				self.raisesBeforeActive -= 1

	def RequestUserAttention(self) -> None:
		self.events.append("attention")
		self.attentionCount += 1

	@override
	def Show(self, _show: bool = True) -> None:
		self.events.append("show")
		self.activationAuthorized = self.parent is self.mainFrame and self.mainFrame.prepared


class _ActivationControl(_Widget):
	def __init__(
		self,
		*args: object,
		events: list[str],
		frame: _ActivationFrame,
		**kwargs: object,
	) -> None:
		super().__init__(*args, **kwargs)
		self.events = events
		self.frame = frame

	@override
	def SetFocus(self) -> None:
		self.events.append("focus")
		super().SetFocus()
		if (
			self.frame.focusRequired
			and self.frame.activationAuthorized
			and self.frame.raisesBeforeActive <= 0
		):
			if self.frame.focusAttemptsBeforeActive <= 0:
				self.frame.active = True
			else:
				self.frame.focusAttemptsBeforeActive -= 1


class _ActivationWx(_Wx):
	def __init__(
		self,
		mainFrame: _ActivationMainFrame,
		events: list[str],
		*,
		raisesBeforeActive: int = 0,
		focusRequired: bool = False,
		focusAttemptsBeforeActive: int = 0,
	) -> None:
		super().__init__()
		self.mainFrame = mainFrame
		self.events = events
		self.raisesBeforeActive = raisesBeforeActive
		self.focusRequired = focusRequired
		self.focusAttemptsBeforeActive = focusAttemptsBeforeActive
		self.later: list[object] = []

	def CallLater(self, _milliseconds: int, callback: object) -> object:
		self.later.append(callback)
		return SimpleNamespace(Stop=lambda: None)

	@override
	def Frame(self, *args: object, **kwargs: object) -> _Widget:
		frame = _ActivationFrame(
			*args,
			**kwargs,
			mainFrame=self.mainFrame,
			events=self.events,
			raisesBeforeActive=self.raisesBeforeActive,
			focusRequired=self.focusRequired,
			focusAttemptsBeforeActive=self.focusAttemptsBeforeActive,
		)
		self.frames.append(frame)
		return frame

	@override
	def TextCtrl(self, *args: object, **kwargs: object) -> _Widget:
		control = _ActivationControl(
			*args,
			**kwargs,
			events=self.events,
			frame=cast(_ActivationFrame, self.frames[0]),
		)
		self.textControls.append(control)
		return control


class _KeyEvent:
	def __init__(self, keyCode: int) -> None:
		super().__init__()
		self._keyCode = keyCode
		self.skipped = False

	def GetKeyCode(self) -> int:
		return self._keyCode

	def Skip(self) -> None:
		self.skipped = True


class _SelectedSource:
	def __init__(self, selections: dict[str, list[object]]) -> None:
		super().__init__()
		self._selections = {
			**selections,
			"navigator": list(selections.get("navigator", selections.get("focus", ()))),
		}
		self._last: dict[str, object] = {}

	def selectedObject(
		self,
		targetKind: Literal["foreground", "focus", "navigator"],
	) -> object:
		values = self._selections[targetKind]
		if values:
			selected = values.pop(0)
			self._last[targetKind] = selected
			return selected
		return self._last[targetKind]


class _NativeInspector:
	def __init__(self, handle: int) -> None:
		super().__init__()
		self._handle = handle

	def GetHandle(self) -> int:
		return self._handle


def _target(executable: str, processId: int, windowHandle: int) -> object:
	return SimpleNamespace(
		appModule=SimpleNamespace(appName=executable),
		processID=processId,
		windowHandle=windowHandle,
		backend="ia2Msaa",
		location=SimpleNamespace(left=0, top=0, width=100, height=100),
		name=f"{executable} target",
		role="button",
		children=(),
		childCount=0,
		isProtected=False,
	)


def _ownsInspectorWindow(ownerHandle: int, processId: int, windowHandle: int) -> bool:
	return ownerHandle == 900 and processId == 77 and windowHandle in {900, 901}


def _facet(
	nodeId: str,
	parentId: str | None,
	depth: int,
	name: str,
	role: str,
	*,
	childHint: bool = False,
) -> NodeFacet:
	return NodeFacet(
		nodeId=nodeId,
		parentId=parentId,
		depth=depth,
		name=name,
		hasName=bool(name),
		role=role,
		childHint=childHint,
	)


class _WorkspaceSource:
	"""A minimal live/offline Inspector source: a window root over one selected edit target."""

	_names = {"root": "Main window", "target": "Email", "child-1": "First", "child-2": "Second"}
	_roles = {"root": "window", "target": "edit", "child-1": "text", "child-2": "text"}

	def __init__(
		self,
		*,
		kind: InspectorSourceKind = InspectorSourceKind.LIVE,
		executable: str = "reader.exe",
		processId: int = 42,
		label: str = "Main window",
	) -> None:
		super().__init__()
		self._kind = kind
		self._executable = executable
		self._processId = processId
		self._label = label
		self.closed = False
		self.childrenCalls: list[str] = []
		self.targetChildState = ChildState.LOADED

	def identity(self) -> InspectorSourceIdentity:
		return InspectorSourceIdentity(
			kind=self._kind,
			label=self._label,
			executable=self._executable,
			processId=self._processId,
			backend="uia",
			nodeCount=3 if self._kind is InspectorSourceKind.OFFLINE else None,
		)

	def roots(self) -> tuple[NodeFacet, ...]:
		return (
			_facet("root", None, 0, "Main window", "window"),
			_facet("target", "root", 1, "Email", "edit", childHint=True),
		)

	def children(self, nodeId: str) -> ChildFetch:
		self.childrenCalls.append(nodeId)
		if nodeId == "target":
			if self.targetChildState is not ChildState.LOADED:
				return ChildFetch("target", self.targetChildState)
			return ChildFetch(
				"target",
				ChildState.LOADED,
				(
					_facet("child-1", "target", 2, "First", "text"),
					_facet("child-2", "target", 2, "Second", "text"),
				),
			)
		return ChildFetch(nodeId, ChildState.EMPTY)

	def properties(self, nodeId: str, category: PropertyCategory) -> PropertyFetch:
		if category is PropertyCategory.QUICK:
			name = self._names.get(nodeId, nodeId)
			role = self._roles.get(nodeId, "custom")
			return PropertyFetch(
				nodeId,
				category,
				(
					PropertyRow(fieldKey="name", name="Name", status=PropertyStatus.VALUE, value=name),
					PropertyRow(fieldKey="role", name="Role", status=PropertyStatus.VALUE, value=role),
				),
			)
		if category is PropertyCategory.CORE:
			return PropertyFetch(
				nodeId,
				category,
				(PropertyRow(fieldKey="states", name="States", status=PropertyStatus.UNSUPPORTED),),
			)
		if category is PropertyCategory.SUPPORTED_UIA_PATTERNS:
			return PropertyFetch(
				nodeId,
				category,
				(
					PropertyRow(
						fieldKey="Text",
						name="Text",
						status=PropertyStatus.VALUE,
						value="true",
						source="uia",
					),
					PropertyRow(
						fieldKey="TextDocumentText",
						name="Text Document Text",
						status=PropertyStatus.VALUE,
						value="hello",
						source="uia",
					),
					PropertyRow(
						fieldKey="TogglePatternObject",
						name="Toggle Pattern Object",
						status=PropertyStatus.UNSUPPORTED,
						source="uia",
					),
				),
			)
		if category is PropertyCategory.ALL_PROPERTIES:
			return PropertyFetch(
				nodeId,
				category,
				structured=(
					StructuredPropertyNode(
						key="providers",
						label="Providers",
						status=PropertyStatus.VALUE,
						children=(
							StructuredPropertyNode(
								key="providers.uia",
								label="UIA",
								status=PropertyStatus.VALUE,
								children=(
									StructuredPropertyNode(
										key="providers.uia.name",
										label="Name",
										status=PropertyStatus.VALUE,
										value="Email",
									),
								),
							),
						),
					),
				),
			)
		return PropertyFetch(nodeId, category)

	def annotations(self, nodeId: str) -> tuple[AnnotationRecord, ...]:
		if nodeId != "target":
			return ()
		return (
			AnnotationRecord(
				key="comment",
				status=AnnotationStatus.VALUE,
				typeId="comment",
				typeName="Comment",
				source="UIA AnnotationObjects",
				summary="Review this field",
				author="Reviewer",
				targetName="Main window",
				targetRole="window",
				targetIdentity="node=root",
				targetNodeId="root",
				targetIdentityProven=True,
				relationship="details",
				related=(
					AnnotationRecord(
						key="reply",
						status=AnnotationStatus.VALUE,
						typeName="Comment reply",
						source="UIA AnnotationObjects",
						summary="Resolved",
					),
				),
			),
			AnnotationRecord(
				key="stale",
				status=AnnotationStatus.STALE,
				typeName="Comment",
				source="UIA AnnotationObjects",
			),
		)

	def close(self) -> None:
		self.closed = True


class _FakeTree(_Widget):
	def __init__(self, *args: object, **kwargs: object) -> None:
		super().__init__(*args, **kwargs)
		self._counter = 0
		self.texts: dict[int, str] = {}
		self.parents: dict[int, int | None] = {}
		self.childItems: dict[int, list[int]] = {}
		self.expandedItems: list[int] = []
		self.hasChildren: list[int] = []
		self.deleteCalls: list[int] = []
		self.deleteChildrenCalls: list[int] = []
		self.deleteAllCalls = 0
		self.ensureVisibleCalls: list[int] = []
		self.screenToClientCalls: list[object] = []
		self.firstVisibleItem: int | None = None
		self.selection: int | None = None
		self.root: int | None = None
		self.itemData: dict[int, object] = {}

	def _make(self, parent: int | None, text: str) -> int:
		self._counter += 1
		item = self._counter
		self.texts[item] = text
		self.parents[item] = parent
		self.childItems[item] = []
		if parent is not None:
			self.childItems[parent].append(item)
		return item

	def AddRoot(self, text: str) -> int:
		self.root = self._make(None, text)
		return self.root

	def AppendItem(self, parent: int, text: str) -> int:
		return self._make(parent, text)

	def DeleteAllItems(self) -> None:
		self.deleteAllCalls += 1
		self._counter = 0
		self.texts = {}
		self.parents = {}
		self.childItems = {}
		self.expandedItems = []
		self.hasChildren = []
		self.deleteCalls = []
		self.deleteChildrenCalls = []
		self.ensureVisibleCalls = []
		self.firstVisibleItem = None
		self.selection = None
		self.root = None

	def SetItemHasChildren(self, item: int, has: bool = True) -> None:
		if has and item not in self.hasChildren:
			self.hasChildren.append(item)
		elif not has and item in self.hasChildren:
			self.hasChildren.remove(item)

	def Delete(self, item: int) -> None:
		self.deleteCalls.append(item)
		parent = self.parents.pop(item, None)
		if parent is not None:
			_ = self.childItems[parent].remove(item)
		_ = self.texts.pop(item, None)
		_ = self.childItems.pop(item, None)

	def DeleteChildren(self, item: int) -> None:
		self.deleteChildrenCalls.append(item)
		for child in tuple(self.childItems[item]):
			self._deleteBranch(child)
		self.childItems[item] = []
		self.ensureVisibleCalls = []
		self.firstVisibleItem = None

	def _deleteBranch(self, item: int) -> None:
		for child in tuple(self.childItems[item]):
			self._deleteBranch(child)
		_ = self.texts.pop(item, None)
		_ = self.parents.pop(item, None)
		_ = self.childItems.pop(item, None)
		if item in self.expandedItems:
			self.expandedItems.remove(item)
		if item in self.hasChildren:
			self.hasChildren.remove(item)
		if self.selection == item:
			self.selection = None

	def Expand(self, item: int) -> None:
		if item not in self.expandedItems:
			self.expandedItems.append(item)

	def Collapse(self, item: int) -> None:
		if item in self.expandedItems:
			self.expandedItems.remove(item)

	def SelectItem(self, item: int) -> None:
		self.selection = item

	def GetSelection(self) -> int | None:
		return self.selection

	def EnsureVisible(self, item: int) -> None:
		self.ensureVisibleCalls.append(item)

	def GetFirstVisibleItem(self) -> int | None:
		if self.firstVisibleItem is not None:
			return self.firstVisibleItem
		if self.root is None or not self.childItems[self.root]:
			return None
		return self.childItems[self.root][0]

	def GetItemText(self, item: int) -> str:
		return self.texts.get(item, "")

	def SetItemData(self, item: int, data: object) -> None:
		self.itemData[item] = data

	def GetItemData(self, item: int) -> object:
		return self.itemData.get(item)


class _FakeNotebook(_Widget):
	def __init__(self, *args: object, **kwargs: object) -> None:
		super().__init__(*args, **kwargs)
		self.pages: list[tuple[object, str]] = []
		self.selection = 0

	def AddPage(self, page: object, text: str) -> None:
		self.pages.append((page, text))

	def GetSelection(self) -> int:
		return self.selection

	def SetSelection(self, index: int) -> None:
		self.selection = index

	def ChangeSelection(self, index: int) -> None:
		self.selection = index


class _FakeListCtrl(_Widget):
	def __init__(self, *args: object, **kwargs: object) -> None:
		super().__init__(*args, **kwargs)
		self.columns: list[str] = []
		self.rows: list[dict[int, str]] = []
		self.selectedRows: set[int] = set()
		self.focusedRow: int | None = None
		self.ensureVisibleCalls: list[int] = []
		self.screenToClientCalls: list[object] = []
		self.deleteAllCalls = 0
		self.checked: set[int] = set()
		self.checkboxesEnabled = False

	@property
	def selectedRow(self) -> int | None:
		"""The first selected row, matching what ``GetFirstSelected`` reports."""

		return min(self.selectedRows) if self.selectedRows else None

	def InsertColumn(self, _index: int, heading: str) -> None:
		self.columns.append(heading)

	def DeleteAllItems(self) -> None:
		self.deleteAllCalls += 1
		self.rows = []
		self.selectedRows = set()
		self.focusedRow = None

	def GetItemCount(self) -> int:
		return len(self.rows)

	def InsertItem(self, index: int, text: str) -> int:
		self.rows.insert(index, {0: text})
		return index

	def SetItem(self, index: int, column: int, text: str) -> None:
		self.rows[index][column] = text

	def Select(self, index: int, on: int = 1) -> None:
		if on:
			self.selectedRows = {index}
		else:
			self.selectedRows.discard(index)

	def Focus(self, index: int) -> None:
		self.focusedRow = index

	def EnsureVisible(self, index: int) -> None:
		self.ensureVisibleCalls.append(index)

	def GetFirstSelected(self) -> int:
		return min(self.selectedRows) if self.selectedRows else -1

	def GetFocusedItem(self) -> int:
		return self.focusedRow if self.focusedRow is not None else -1

	def GetTopItem(self) -> int:
		return 0

	def HitTest(self, position: object) -> tuple[int, int]:
		# The workspace passes a row index as the "position"; the double treats it literally.
		try:
			return int(cast(int, position)), 0
		except (TypeError, ValueError):
			return -1, 0

	def ScreenToClient(self, position: object) -> object:
		self.screenToClientCalls.append(position)
		return position

	def GetColumnCount(self) -> int:
		return len(self.columns)

	def GetItemText(self, index: int, column: int = 0) -> str:
		if 0 <= index < len(self.rows):
			return self.rows[index].get(column, "")
		return ""

	def GetItem(self, index: int, column: int = 0) -> object:
		text = self.GetItemText(index, column)
		return SimpleNamespace(GetText=lambda: text)

	def EnableCheckBoxes(self, enable: bool = True) -> None:
		self.checkboxesEnabled = enable

	def CheckItem(self, index: int, check: bool = True) -> None:
		if check:
			self.checked.add(index)
		else:
			self.checked.discard(index)

	def IsItemChecked(self, index: int) -> bool:
		return index in self.checked


class _FakeSplitter(_Widget):
	def SetMinimumPaneSize(self, _size: int) -> None:
		pass

	def SplitVertically(self, _left: object, _right: object, _position: int = 0) -> None:
		pass

	def SetSashGravity(self, _gravity: float) -> None:
		pass


class _WorkspaceKeyEvent(_KeyEvent):
	def __init__(
		self,
		keyCode: int,
		*,
		control: bool = False,
		alt: bool = False,
		shift: bool = False,
		eventObject: object | None = None,
	) -> None:
		super().__init__(keyCode)
		self._control = control
		self._alt = alt
		self._shift = shift
		self._eventObject = eventObject

	def ControlDown(self) -> bool:
		return self._control

	def AltDown(self) -> bool:
		return self._alt

	def ShiftDown(self) -> bool:
		return self._shift

	def GetEventObject(self) -> object | None:
		return self._eventObject


class _RecordingCopy:
	"""Records copy requests in place of the service's clipboard path."""

	def __init__(self) -> None:
		super().__init__()
		self.requests: list[tuple[tuple[EventRow, ...], EventCopyFormat]] = []

	def __call__(
		self,
		rows: tuple[EventRow, ...],
		copyFormat: EventCopyFormat,
	) -> EventActionOutcome:
		self.requests.append((rows, copyFormat))
		return EventActionOutcome("copied", clipboardRequested=True)


class _FakeDialog:
	"""A native confirmation whose answer the test chooses."""

	def __init__(self, wx: _WorkspaceWx, *args: object, **kwargs: object) -> None:
		super().__init__()
		self._wx = wx
		self.args = args
		self.kwargs = kwargs
		self.destroyed = False

	def ShowModal(self) -> object:
		return self._wx.modalResult

	def Destroy(self) -> None:
		self.destroyed = True


class _FakeFileDialog(_FakeDialog):
	def GetPath(self) -> str:
		return self._wx.filePath


class _FakeFindData:
	"""A wx.FindReplaceData double holding the search string across dialog turns."""

	def __init__(self) -> None:
		super().__init__()
		self._findString = ""

	def SetFindString(self, value: str) -> None:
		self._findString = value

	def GetFindString(self) -> str:
		return self._findString


class _WorkspaceChildFocusEvent:
	"""One ``wxChildFocusEvent``: it names a direct child, not the control that took focus."""

	def __init__(self, window: object) -> None:
		super().__init__()
		self._window = window
		self.skipped = False

	def GetWindow(self) -> object:
		return self._window

	def Skip(self) -> None:
		self.skipped = True


class _WorkspaceWx(_Wx):
	ALIGN_RIGHT = 0
	SP_LIVE_UPDATE = 0
	SP_3DSASH = 0
	TR_HAS_BUTTONS = 0
	TR_SINGLE = 0
	TR_LINES_AT_ROOT = 0
	TR_DEFAULT_STYLE = 0
	LC_REPORT = 0
	LC_SINGLE_SEL = 0
	TE_PROCESS_ENTER = 512
	WXK_F3 = 340
	WXK_F5 = 344
	WXK_TAB = 9
	EVT_CHECKBOX = object()
	EVT_TEXT_ENTER = object()
	EVT_TREE_SEL_CHANGED = object()
	EVT_TREE_ITEM_EXPANDING = object()
	EVT_TREE_ITEM_COLLAPSING = object()
	EVT_KEY_DOWN = object()
	EVT_NOTEBOOK_PAGE_CHANGED = object()
	EVT_LIST_ITEM_SELECTED = object()
	EVT_LIST_ITEM_FOCUSED = object()
	EVT_LIST_ITEM_DESELECTED = object()
	EVT_CHILD_FOCUS = object()
	EVT_CONTEXT_MENU = object()
	EVT_MENU = object()
	EVT_LIST_ITEM_CHECKED = object()
	EVT_LIST_ITEM_UNCHECKED = object()
	EVT_RADIOBOX = object()
	RA_SPECIFY_ROWS = 0
	ID_ANY = -1
	ID_COPY = 5031
	ID_DELETE = 5035
	ID_OK = 5100
	ID_CANCEL = 5101
	WXK_DELETE = 127
	YES_NO = 1
	NO_DEFAULT = 2
	ICON_WARNING = 4
	FD_OPEN = 8
	FD_FILE_MUST_EXIST = 16
	FD_SAVE = 32
	FD_OVERWRITE_PROMPT = 64
	DD_DEFAULT_STYLE = 0
	ID_YES = 5
	ID_NO = 6
	WXK_LEFT = 314
	WXK_RIGHT = 316
	FR_NOWHOLEWORD = 0
	FR_DOWN = 1
	EVT_FIND = object()
	EVT_FIND_NEXT = object()
	EVT_FIND_CLOSE = object()

	def __init__(self) -> None:
		super().__init__()
		self.later: list[object] = []
		self.trees: list[_FakeTree] = []
		self.notebooks: list[_FakeNotebook] = []
		self.listControls: list[_FakeListCtrl] = []
		self.splitters: list[_FakeSplitter] = []
		self.dialogs: list[_FakeDialog] = []
		self.findDialogs: list[_Widget] = []
		self.modalResult: object = _WorkspaceWx.ID_NO
		self.filePath = "C:/snapshots/index.json"
		self.focused: object | None = None
		wxModule = self

		class Window:
			@staticmethod
			def FindFocus() -> object | None:
				return wxModule.focused

		self.Window = Window

	def MessageDialog(self, *args: object, **kwargs: object) -> _FakeDialog:
		dialog = _FakeDialog(self, *args, **kwargs)
		self.dialogs.append(dialog)
		return dialog

	def FileDialog(self, *args: object, **kwargs: object) -> _FakeFileDialog:
		dialog = _FakeFileDialog(self, *args, **kwargs)
		self.dialogs.append(dialog)
		return dialog

	def DirDialog(self, *args: object, **kwargs: object) -> _FakeFileDialog:
		dialog = _FakeFileDialog(self, *args, **kwargs)
		self.dialogs.append(dialog)
		return dialog

	def focus(self, control: object) -> _WorkspaceChildFocusEvent:
		"""Model the host giving ``control`` focus, as Tab traversal or a click would."""

		self.focused = control
		return _WorkspaceChildFocusEvent(control)

	def CallLater(self, _milliseconds: int, callback: object) -> object:
		self.later.append(callback)
		return SimpleNamespace(Stop=lambda: None)

	def SplitterWindow(self, *args: object, **kwargs: object) -> _FakeSplitter:
		splitter = _FakeSplitter(*args, **kwargs)
		self.splitters.append(splitter)
		return splitter

	def TreeCtrl(self, *args: object, **kwargs: object) -> _FakeTree:
		tree = _FakeTree(*args, **kwargs)
		self.trees.append(tree)
		return tree

	def Notebook(self, *args: object, **kwargs: object) -> _FakeNotebook:
		notebook = _FakeNotebook(*args, **kwargs)
		self.notebooks.append(notebook)
		return notebook

	def ListCtrl(self, *args: object, **kwargs: object) -> _FakeListCtrl:
		listControl = _FakeListCtrl(*args, **kwargs)
		self.listControls.append(listControl)
		return listControl

	def FindReplaceData(self, *_args: object, **_kwargs: object) -> _FakeFindData:
		return _FakeFindData()

	def FindReplaceDialog(self, *args: object, **kwargs: object) -> _Widget:
		dialog = _Widget(*args, **kwargs)
		self.findDialogs.append(dialog)
		return dialog


class _RecordingSounds:
	"""A ``WorkflowSounds`` seam that records requests instead of playing them.

	Every workspace assertion reduces to "which typed event, owned by which generation, in which
	order" - never to audio. The recorder never raises, so a passing test proves the surface
	reached the seam after it spoke, not that anything sounded.
	"""

	def __init__(self) -> None:
		super().__init__()
		self.requests: list[SoundRequest] = []
		self.ticks = 0
		self.invalidations: list[SoundOwner | None] = []

	def emit(self, request: SoundRequest) -> None:
		self.requests.append(request)

	def tick(self) -> None:
		self.ticks += 1

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		self.invalidations.append(owner)

	def events(self) -> list[CueEventId]:
		return [request.event for request in self.requests]


class _FailingSounds:
	"""A seam whose every operation raises, proving sound failures never reach speech or the frame."""

	def emit(self, request: SoundRequest) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and the frame")

	def tick(self) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and the frame")

	def invalidate(self, owner: SoundOwner | None = None) -> None:
		raise RuntimeError("a sound sink failure must stay isolated from speech and the frame")


class _Harness:
	def __init__(
		self,
		workspace: InspectorWorkspace,
		wx: _WorkspaceWx,
		service: InspectorService,
		source: _WorkspaceSource,
		announcements: list[str],
		clipboard: list[str],
		retargets: list[tuple[str, bool]],
		opened: list[bool],
		followEvents: list[FollowFocusEvent],
		eventMonitorCalls: list[bool],
		customUiaParents: list[object],
		delayedAnnouncements: list[tuple[str, object]],
		delayedAnnouncementPriority: object,
	) -> None:
		super().__init__()
		self.workspace = workspace
		self.wx = wx
		self.service = service
		self.source = source
		self.announcements = announcements
		self.clipboard = clipboard
		self.retargets = retargets
		self.opened = opened
		self.followEvents = followEvents
		self.eventMonitorCalls = eventMonitorCalls
		self.customUiaParents = customUiaParents
		self.delayedAnnouncements = delayedAnnouncements
		self.delayedAnnouncementPriority = delayedAnnouncementPriority


class InspectorWorkspaceTests(unittest.TestCase):
	def _open(
		self,
		*,
		kind: InspectorSourceKind = InspectorSourceKind.LIVE,
		mainFrame: object | None = None,
		copySucceeds: bool = True,
		withSnapshotLoader: bool = True,
		withInspectionToolEntryPoints: bool = False,
		sound: WorkflowSounds | None = None,
	) -> _Harness:
		wx = _WorkspaceWx()
		delayedAnnouncements: list[tuple[str, object]] = []
		nowPriority = object()

		def delayedMessage(message: str, *, speechPriority: object) -> None:
			delayedAnnouncements.append((message, speechPriority))

		gui = SimpleNamespace(
			mainFrame=mainFrame,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		ui = SimpleNamespace(delayedMessage=delayedMessage)
		speech = SimpleNamespace(Spri=SimpleNamespace(NOW=nowPriority))

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			if name == "ui":
				return ui
			if name == "speech":
				return speech
			raise ImportError(name)

		announcements: list[str] = []
		clipboard: list[str] = []
		retargets: list[tuple[str, bool]] = []
		opened: list[bool] = []
		followEvents: list[FollowFocusEvent] = []
		eventMonitorCalls: list[bool] = []
		customUiaParents: list[object] = []
		source = _WorkspaceSource(kind=kind)
		service = InspectorService()
		service.openSource(source)

		def onRetarget(targetKind: str, raw: bool) -> None:
			retargets.append((targetKind, raw))

		def onFollowRetarget(event: FollowFocusEvent) -> None:
			followEvents.append(event)
			executable, _, processId = event.applicationKey.partition("\x1f")
			service.openSource(
				_WorkspaceSource(
					kind=InspectorSourceKind.LIVE,
					executable=executable,
					processId=int(processId),
					label=f"{executable} window",
				),
			)

		def onOpenSnapshot(_directory: object, _limits: object) -> None:
			opened.append(True)

		def onCopy(text: str) -> bool:
			clipboard.append(text)
			return copySucceeds

		patcher = patch.object(inspectorModule, "import_module", side_effect=importHostModule)
		_ = patcher.start()
		self.addCleanup(patcher.stop)

		inspectionToolEntryPoints: dict[str, object] = {}
		if withInspectionToolEntryPoints:
			inspectionToolEntryPoints = {
				"openEventMonitor": lambda: eventMonitorCalls.append(True),
				"openCustomUia": customUiaParents.append,
			}
		workspace = InspectorWorkspace(
			service,
			retarget=onRetarget,
			followRetarget=onFollowRetarget,
			openSnapshot=onOpenSnapshot if withSnapshotLoader else None,
			announce=announcements.append,
			copyToClipboard=onCopy,
			isCurrent=lambda: True,
			windowOwnership=_ownsInspectorWindow,
			clock=lambda: 0,
			sound=sound,
			**inspectionToolEntryPoints,  # type: ignore[arg-type]
		)
		workspace.show()
		while wx.after:
			callback = wx.after.pop(0)
			if callable(callback):
				_ = callback()
		return _Harness(
			workspace,
			wx,
			service,
			source,
			announcements,
			clipboard,
			retargets,
			opened,
			followEvents,
			eventMonitorCalls,
			customUiaParents,
			delayedAnnouncements,
			nowPriority,
		)

	@staticmethod
	def _widget(workspace: InspectorWorkspace, key: str) -> _Widget:
		return cast(_Widget, workspace._controls[key])

	def test_closing_a_never_opened_workspace_stays_silent(self) -> None:
		announcements: list[str] = []
		service = InspectorService()
		workspace = InspectorWorkspace(
			service,
			retarget=lambda _kind, _raw: None,
			followRetarget=lambda _event: None,
			announce=announcements.append,
			copyToClipboard=lambda _text: True,
			isCurrent=lambda: True,
			windowOwnership=_ownsInspectorWindow,
		)

		workspace.close()

		self.assertEqual([], announcements)
		self.assertIsNone(service.sourceIdentity())

	def test_open_snapshot_button_is_disabled_without_a_loader(self) -> None:
		self.assertTrue(self._widget(self._open().workspace, "openSnapshot").enabled)
		self.assertFalse(self._widget(self._open(withSnapshotLoader=False).workspace, "openSnapshot").enabled)

	def test_open_snapshot_picker_announces_cancellation_and_passes_selected_directory(self) -> None:
		harness = self._open()
		openSnapshot = self._widget(harness.workspace, "openSnapshot")
		handler = openSnapshot.bindings[harness.wx.EVT_BUTTON]
		assert callable(handler)

		harness.wx.modalResult = harness.wx.ID_CANCEL
		_ = handler(None)
		self.assertEqual("Opening snapshot cancelled.", harness.announcements[-1])
		self.assertEqual(1, openSnapshot.focusCount)

		harness.wx.modalResult = harness.wx.ID_OK
		_ = handler(None)
		self.assertEqual([True], harness.opened)
		self.assertEqual(1, len(harness.delayedAnnouncements))
		self.assertEqual("Snapshot opened.", harness.delayedAnnouncements[0][0])
		self.assertIs(harness.delayedAnnouncementPriority, harness.delayedAnnouncements[0][1])
		self.assertEqual(Path("C:/snapshots"), harness.workspace._snapshotDirectory)

		harness.wx.modalResult = harness.wx.ID_CANCEL
		_ = handler(None)
		self.assertEqual("C:\\snapshots", harness.wx.dialogs[-1].kwargs["defaultDir"])

		harness.workspace.handleKey(_WorkspaceKeyEvent(ord("o"), control=True))
		self.assertEqual("Opening snapshot cancelled.", harness.announcements[-1])

	def test_context_menus_offer_text_export_and_hierarchy_export_writes_its_payload(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		for context in ("hierarchy", "category", "details"):
			menuIndex = len(harness.wx.menus)
			harness.workspace._showInspectorContextMenu(SimpleNamespace(), context)
			labels = [label for _identifier, label in harness.wx.menus[menuIndex].items]
			if context == "hierarchy":
				self.assertNotIn("Export as text...", labels)
			else:
				self.assertIn("Export as text...", labels)
		menuIndex = len(harness.wx.menus)
		harness.workspace._showInspectorContextMenu(SimpleNamespace(), "hierarchy")
		menu = harness.wx.menus[menuIndex]
		labels = [label for _identifier, label in menu.items]
		self.assertNotIn("Copy node as JSON", labels)
		self.assertNotIn("Copy recorded subtree snapshot as JSON", labels)
		submenus = dict(menu.submenus)
		self.assertEqual(["&Copy", "&Export"], list(submenus))
		copyLabels = [label for _identifier, label in submenus["&Copy"].items]
		self.assertEqual(
			["Copy as &text", "Copy node as &JSON", "Copy &recorded subtree snapshot as JSON"],
			copyLabels,
		)
		self.assertEqual(["t", "j", "r"], [label[label.index("&") + 1].casefold() for label in copyLabels])
		exportLabels = [label for _identifier, label in submenus["&Export"].items]
		self.assertEqual(
			[
				"Export as &text...",
				"Export node as &JSON...",
				"Export &recorded subtree as portable snapshot directory...",
			],
			exportLabels,
		)
		self.assertEqual(["t", "j", "r"], [label[label.index("&") + 1].casefold() for label in exportLabels])

		with TemporaryDirectory() as temporary:
			destination = Path(temporary) / "hierarchy.txt"
			harness.wx.filePath = str(destination)
			harness.wx.modalResult = harness.wx.ID_OK
			harness.workspace._exportPresentationContext("hierarchy")

			exported = destination.read_text(encoding="utf-8")
		self.assertIn("Email (edit)", exported)
		self.assertIn("First (text)", exported)
		self.assertIn("Annotations:", exported)
		self.assertEqual("reader-keystone-hierarchy.txt", harness.wx.dialogs[-1].kwargs["defaultFile"])
		self.assertEqual("Inspector data exported.", harness.delayedAnnouncements[-1][0])
		self.assertIs(harness.delayedAnnouncementPriority, harness.delayedAnnouncements[-1][1])
		liveHarness = self._open(kind=InspectorSourceKind.LIVE)
		menuIndex = len(liveHarness.wx.menus)
		liveHarness.workspace._showInspectorContextMenu(SimpleNamespace(), "hierarchy")
		liveMenu = liveHarness.wx.menus[menuIndex]
		liveLabels = [label for _identifier, label in liveMenu.items]
		self.assertNotIn("Copy fresh captured subtree snapshot as JSON", liveLabels)
		liveSubmenus = dict(liveMenu.submenus)
		liveCopyLabels = [label for _identifier, label in liveSubmenus["&Copy"].items]
		self.assertIn(
			"Capture and e&xport fresh subtree as portable snapshot directory...",
			[label for _identifier, label in liveSubmenus["&Export"].items],
		)
		self.assertEqual(
			["t", "j", "f"], [label[label.index("&") + 1].casefold() for label in liveCopyLabels]
		)
		self.assertNotIn(
			"Copy &recorded subtree snapshot as JSON",
			liveCopyLabels,
		)

	def test_subtree_snapshot_clipboard_limit_leaves_existing_clipboard_unchanged(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		harness.clipboard.append("existing clipboard text")

		def oversizedSnapshot(_nodeId: str) -> bytes:
			return b"x" * (5 * 1024 * 1024 + 1)

		harness.workspace._copySubtreeSnapshotCallback = oversizedSnapshot

		harness.workspace._copySubtreeSnapshot()

		self.assertEqual(["existing clipboard text"], harness.clipboard)
		self.assertEqual(
			"Subtree snapshot JSON is larger than 5 MiB and was not copied. Export the snapshot instead.",
			harness.announcements[-1],
		)

	def test_node_json_feedback_discloses_that_it_only_uses_loaded_privacy_safe_data(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)

		harness.workspace._copyCurrentNodeJson()

		self.assertTrue(harness.clipboard[-1])
		self.assertEqual(
			"Already loaded, privacy-safe Inspector node data copied as JSON.",
			harness.announcements[-1],
		)

	def test_node_json_export_filename_includes_the_selected_node_name(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		harness.wx.modalResult = harness.wx.ID_CANCEL

		harness.workspace._exportCurrentNodeJson()

		self.assertEqual(
			"Email-reader-keystone-current-inspector-data.json",
			harness.wx.dialogs[-1].kwargs["defaultFile"],
		)

	def test_subtree_snapshot_copy_reports_source_specific_success_and_cancellation(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)

		def recordedSnapshot(_nodeId: str) -> bytes:
			return b'{"snapshot":"recorded"}\n'

		harness.workspace._copySubtreeSnapshotCallback = recordedSnapshot

		harness.workspace._copySubtreeSnapshot()

		self.assertEqual('{"snapshot":"recorded"}\n', harness.clipboard[-1])
		self.assertEqual("Recorded subtree snapshot copied as JSON.", harness.announcements[-1])

		def cancelled(_nodeId: str) -> bytes:
			raise RuntimeError("KS.CAPTURE.CANCELLED")

		harness.workspace._copySubtreeSnapshotCallback = cancelled
		harness.workspace._copySubtreeSnapshot()
		self.assertEqual("Subtree snapshot capture cancelled.", harness.announcements[-1])

	def test_subtree_snapshot_export_chooses_a_portable_directory(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		destinations: list[tuple[str, Path]] = []

		def recordDestination(nodeId: str, destination: Path) -> None:
			destinations.append((nodeId, destination))

		harness.workspace._exportSubtreeSnapshotCallback = recordDestination

		with TemporaryDirectory() as temporary:
			harness.wx.filePath = temporary
			harness.wx.modalResult = harness.wx.ID_OK
			harness.workspace._exportSubtreeSnapshot()

			self.assertEqual(
				[("target", Path(temporary))],
				destinations,
			)
		self.assertEqual(
			"Recorded subtree snapshot exported as a portable snapshot directory.",
			harness.delayedAnnouncements[-1][0],
		)

	def _selectCategory(self, harness: _Harness, label: str) -> _Widget:
		"""Drive the category list the way a screen-reader user would, then return the detail control."""

		workspace = harness.workspace
		index = ["Core", "UIA", "Annotations", "Advanced"].index(label)
		categoryList = cast(_FakeListCtrl, self._widget(workspace, "categoryList"))
		categoryList.selectedRows = {index}
		categoryList.focusedRow = index
		handler = categoryList.bindings[harness.wx.EVT_LIST_ITEM_FOCUSED]
		assert callable(handler)
		_ = handler(None)
		return self._widget(workspace, "detail")

	@staticmethod
	def _detailList(harness: _Harness) -> _FakeListCtrl:
		return cast(_FakeListCtrl, harness.workspace._controls["detail"])

	def test_inspection_tools_have_literal_visible_actions_and_working_manager_button(self) -> None:
		harness = self._open(withInspectionToolEntryPoints=True)
		customUia = self._widget(harness.workspace, "customUia")
		openSnapshot = self._widget(harness.workspace, "openSnapshot")
		self.assertEqual("Manage &Custom UIA Properties...", customUia.label)
		self.assertEqual("Open Sna&pshot...", openSnapshot.label)
		self.assertTrue(openSnapshot.enabled)

		customHandler = customUia.bindings[harness.wx.EVT_BUTTON]
		assert callable(customHandler)
		_ = customHandler(None)
		self.assertEqual([harness.workspace._frame], harness.customUiaParents)

		harness.workspace._monitorSelectedHierarchy()
		self.assertEqual([True], harness.eventMonitorCalls)

	def test_monitor_hierarchy_opens_event_configuration_without_claiming_a_scope(self) -> None:
		harness = self._open(withInspectionToolEntryPoints=True)
		tree = cast(_FakeTree, self._widget(harness.workspace, "hierarchy"))
		target = cast(int, harness.workspace._treeItems["target"])
		harness.service.selectNode("root")
		tree.SelectItem(target)
		self.assertEqual("root", harness.service.selectedNodeId)

		harness.workspace._monitorSelectedHierarchy()

		self.assertEqual("target", harness.service.selectedNodeId)
		self.assertEqual([True], harness.eventMonitorCalls)
		self.assertEqual(
			"Event Monitor opened for configuration. Choose a scope and start monitoring.",
			harness.announcements[-1],
		)
		self.assertNotIn("Proposed monitoring scope", harness.announcements[-1])
		self.assertNotIn("Email", harness.announcements[-1])

	def test_workspace_groups_hierarchy_and_property_categories(self) -> None:
		harness = self._open(kind=InspectorSourceKind.LIVE)
		workspace = harness.workspace
		wx = harness.wx

		definition = workspace.definition
		summary = self._widget(workspace, "sourceSummary")
		hierarchy = self._widget(workspace, "hierarchy")
		categoryList = cast(_FakeListCtrl, self._widget(workspace, "categoryList"))
		detail = cast(_FakeListCtrl, self._widget(workspace, "detail"))
		# The one accessibility pattern the user validated: each collection is a direct child of a
		# native static box, so NVDA speaks the group name around it.
		for control in (hierarchy, categoryList, detail):
			self.assertIn(control.GetParent(), wx.staticBoxes)
		self.assertEqual(definition.sourceSummaryName, summary.accessibleName)
		self.assertEqual([definition.propertyNotebookName], categoryList.columns)
		self.assertEqual(
			["Core", "UIA", "Annotations", "Advanced"],
			[row.get(0, "") for row in categoryList.rows],
		)
		# The Inspector page has no nested property notebook; only the top-level window notebook exists.
		self.assertEqual(1, len(wx.notebooks))
		self.assertEqual(2, len(wx.splitters))
		# Core opens as a flat report list of Property, Value, Status.
		self.assertEqual("list", workspace._detailKind)
		self.assertEqual(["Property", "Value", "Status"], detail.columns)

	def test_event_monitor_uses_the_prototype_group_order_and_direct_children(self) -> None:
		wx, _window, inspector, events = self._sharedWindow()
		labels = [box.label for box in wx.staticBoxes]

		self.assertEqual(
			[
				"Inspection target",
				"Accessible object hierarchy",
				"Property categories",
				"Core properties",
				"Monitoring",
				"Monitored events",
				"Selected event details",
				"History actions",
			],
			labels,
		)
		for key in ("hierarchy", "categoryList", "detail"):
			self.assertIn(self._widget(inspector, key).GetParent(), wx.staticBoxes)
		for key in ("events", "eventDetails"):
			self.assertIn(cast(_Widget, events._controls[key]).GetParent(), wx.staticBoxes)
		report = cast(_FakeListCtrl, events._controls["events"])
		self.assertEqual(["Event", "Source", "Changed value", "Time"], report.columns)

	def test_hierarchy_visible_root_is_expanded(self) -> None:
		harness = self._open()
		tree = harness.wx.trees[0]
		assert tree.root is not None
		# The synthetic root is visible; it must be expanded so its children are reachable.
		self.assertIn(tree.root, tree.expandedItems)

	def test_uia_category_is_a_visible_root_tree_with_custom_values_first(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		_ = self._selectCategory(harness, "UIA")
		self.assertEqual("tree", workspace._detailKind)
		tree = cast(_FakeTree, self._widget(workspace, "detail"))
		# The root is real, not hidden, and reads as the UIA group.
		self.assertIsNotNone(tree.root)
		self.assertEqual("UIA properties", tree.texts[cast(int, tree.root)])
		sectionLabels = [tree.texts[item] for item in tree.childItems[cast(int, tree.root)]]
		self.assertEqual(
			[
				"Custom properties",
				"Unavailable or unsupported Custom UIA properties",
				"Standard UIA properties",
				"Unavailable or unsupported Standard UIA properties",
				"Supported patterns",
				"Provider discovery",
			],
			sectionLabels,
		)

	def test_uia_tree_separates_unavailable_custom_properties(self) -> None:
		harness = self._open()
		originalProperties = harness.source.properties

		def properties(nodeId: str, category: PropertyCategory) -> PropertyFetch:
			if category is not PropertyCategory.UIA:
				return originalProperties(nodeId, category)
			return PropertyFetch(
				nodeId,
				category,
				(
					PropertyRow(
						fieldKey="customUia.available",
						name="Available custom property",
						status=PropertyStatus.VALUE,
						value="present",
					),
					PropertyRow(
						fieldKey="customUia.unsupported",
						name="Unsupported custom property",
						status=PropertyStatus.UNSUPPORTED,
					),
				),
			)

		harness.source.properties = properties
		tree = cast(_FakeTree, self._selectCategory(harness, "UIA"))
		root = cast(int, tree.root)
		sections = {tree.texts[item]: item for item in tree.childItems[root]}

		self.assertEqual(
			["Available custom property: present"],
			[tree.texts[item] for item in tree.childItems[sections["Custom properties"]]],
		)
		self.assertEqual(
			["Unsupported custom property: Unsupported"],
			[
				tree.texts[item]
				for item in tree.childItems[sections["Unavailable or unsupported Custom UIA properties"]]
			],
		)

	def test_annotations_report_list_keeps_a_named_empty_state(self) -> None:
		harness = self._open()
		harness.service.selectNode("root")
		detail = cast(_FakeListCtrl, self._selectCategory(harness, "Annotations"))
		self.assertEqual("list", harness.workspace._detailKind)
		self.assertEqual([], detail.rows)
		self.assertIn(detail.GetParent(), harness.wx.staticBoxes)

	def test_annotation_selection_and_alt_t_navigate_the_selected_target(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		detail = cast(_FakeListCtrl, self._selectCategory(harness, "Annotations"))
		index = next(
			index
			for index, record in enumerate(workspace._detailAnnotationRecords)
			if record is not None and harness.service.canNavigateAnnotationTarget(record)
		)
		detail.Select(index)
		handler = detail.bindings[harness.wx.EVT_LIST_ITEM_SELECTED]
		assert callable(handler)
		_ = handler(
			SimpleNamespace(
				GetEventObject=lambda: detail,
				GetIndex=lambda: index,
				Skip=lambda: None,
			),
		)
		selected = harness.service.selectedAnnotation()
		assert selected is not None
		self.assertEqual("comment", selected.key)

		workspace._lastFocusKey = "properties"
		workspace.handleKey(_WorkspaceKeyEvent(ord("T"), alt=True, eventObject=detail))
		self._drain(harness.wx)

		self.assertEqual("root", harness.service.selectedNodeId)

	def test_same_category_refresh_preserves_selected_property_cursor(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		detail = cast(_FakeListCtrl, self._selectCategory(harness, "Core"))
		index = min(1, len(detail.rows) - 1)
		detail.Select(index)
		handler = detail.bindings[harness.wx.EVT_LIST_ITEM_SELECTED]
		assert callable(handler)
		_ = handler(
			SimpleNamespace(
				GetEventObject=lambda: detail,
				GetIndex=lambda: index,
				Skip=lambda: None,
			),
		)
		selectedKey = workspace._detailListKeys[index]

		workspace._renderPresentationPane()
		refreshed = cast(_FakeListCtrl, workspace._controls["detail"])

		self.assertEqual(index, refreshed.GetFirstSelected())
		self.assertEqual(index, refreshed.focusedRow)
		self.assertEqual(selectedKey, workspace._detailSelectedKey)

	def test_inspector_pane_status_never_overwrites_event_monitor_status(self) -> None:
		wx, window, inspector, _events = self._sharedWindow()
		window.activate("events")
		self._drain(wx)
		statusBar = cast("_FakeStatusBar | None", window._statusBar)
		assert statusBar is not None
		before = statusBar.GetStatusText()

		inspector._renderStatusForPane(SimpleNamespace(note="Properties unavailable.", stale=False))

		self.assertEqual(before, statusBar.GetStatusText())

	def test_unavailable_pane_renders_status_row_and_status_bar(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		unavailable = SimpleNamespace(
			rows=(),
			annotations=(),
			structured=(),
			note="Properties unavailable.",
			stale=False,
		)
		with patch.object(InspectorService, "selectCategory", return_value=unavailable):
			rows, _records, _keys = workspace._detailListData(workspace._presentationCategory())
			workspace._renderStatusForPane(
				SimpleNamespace(note="Properties unavailable.", stale=False),
			)

		self.assertTrue(rows)
		self.assertEqual(("Status", "Properties unavailable.", "Unavailable"), rows[0])
		statusBar = cast("_FakeStatusBar | None", workspace.window._statusBar)
		assert statusBar is not None
		self.assertEqual("Properties unavailable.", statusBar.GetStatusText())

	def test_collections_are_grouped_in_static_boxes(self) -> None:
		harness = self._open()
		wx = harness.wx
		hierarchy = self._widget(harness.workspace, "hierarchy")
		categoryList = self._widget(harness.workspace, "categoryList")
		for label in ("Core", "UIA", "Annotations", "Advanced"):
			detail = self._selectCategory(harness, label)
			self.assertIn(detail.GetParent(), wx.staticBoxes)
		self.assertIn(hierarchy.GetParent(), wx.staticBoxes)
		self.assertIn(categoryList.GetParent(), wx.staticBoxes)
		# No control installs a custom accessible-name provider; the static box carries the name.
		for control in (hierarchy, categoryList):
			self.assertIsNone(control.accessible)

	def _sharedWindow(
		self,
	) -> tuple[_WorkspaceWx, KeystoneWindow, InspectorWorkspace, EventsWorkspace]:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		patcher = patch.object(inspectorModule, "import_module", side_effect=importHostModule)
		_ = patcher.start()
		self.addCleanup(patcher.stop)
		service = InspectorService()
		service.openSource(_WorkspaceSource(kind=InspectorSourceKind.LIVE))
		eventService = cast(
			EventMonitorService,
			SimpleNamespace(
				active=False,
				activeFilter=EventFilter.default(),
				historySnapshot=EventHistory.empty,
				scope=None,
				rawEventsEnabled=False,
			),
		)
		window = KeystoneWindow(windowOwnership=_ownsInspectorWindow)
		inspector = InspectorWorkspace(
			service,
			retarget=lambda _kind, _raw: None,
			followRetarget=lambda _event: None,
			announce=lambda _message: None,
			copyToClipboard=lambda _text: True,
			isCurrent=lambda: True,
			windowOwnership=_ownsInspectorWindow,
			clock=lambda: 0,
			window=window,
		)
		events = EventsWorkspace(eventService, window=window)
		inspector.show()
		self._drain(wx)
		return wx, window, inspector, events

	@staticmethod
	def _drain(wx: _WorkspaceWx) -> None:
		while wx.after:
			callback = wx.after.pop(0)
			if callable(callback):
				_ = callback()

	def test_both_workspaces_are_pages_of_one_window(self) -> None:
		wx, window, inspector, events = self._sharedWindow()

		self.assertEqual(1, len(wx.frames))
		self.assertIs(wx.frames[0], window.frame)
		self.assertIs(window.frame, inspector._frame)
		self.assertIs(window.frame, events._frame)
		workspaces = wx.notebooks[0]
		self.assertEqual(
			[window.definition.inspectorLabel, window.definition.eventsLabel],
			[label for _page, label in workspaces.pages],
		)
		self.assertEqual(window.definition.workspacesName, workspaces.accessibleName)

	def test_modeless_window_retries_focus_then_requests_attention(self) -> None:
		class Frame:
			def __init__(self) -> None:
				super().__init__()
				self.raiseCount = 0
				self.attentionCount = 0

			def Raise(self) -> None:
				self.raiseCount += 1

			def IsActive(self) -> bool:
				return False

			def RequestUserAttention(self) -> None:
				self.attentionCount += 1

		class Wx:
			def __init__(self) -> None:
				super().__init__()
				self.after: list[Callable[[], None]] = []
				self.later: list[Callable[[], None]] = []

			def CallAfter(self, callback: Callable[[], None]) -> None:
				self.after.append(callback)

			def CallLater(self, _delay: int, callback: Callable[[], None]) -> object:
				self.later.append(callback)
				return SimpleNamespace(Stop=lambda: None)

		wx = Wx()
		frame = Frame()
		window = KeystoneWindow(windowOwnership=_ownsInspectorWindow)
		focuses: list[bool] = []
		window.register(
			"inspector",
			build=lambda _page: None,
			restoreFocus=lambda: focuses.append(True),
			dismissed=lambda: None,
			closed=lambda: None,
			handleKey=lambda _event: None,
		)
		window._frame = frame
		window._activationGeneration = 1

		window._scheduleFocus(wx, frame, 1, "inspector")
		while wx.after:
			wx.after.pop(0)()
		while wx.later:
			wx.later.pop(0)()

		self.assertEqual(4, len(focuses))
		self.assertEqual(4, frame.raiseCount)
		self.assertEqual(1, frame.attentionCount)

	def test_ctrl_e_and_ctrl_i_select_a_workspace_and_restore_its_own_focus(self) -> None:
		wx, window, inspector, events = self._sharedWindow()
		frameKey = wx.frames[0].bindings[wx.EVT_CHAR_HOOK]
		assert callable(frameKey)
		# The Inspector's own last focused region, rather than its opening anchor.
		inspector._focusControl("categoryList")
		categoryList = cast(_Widget, inspector._controls["categoryList"])
		startStop = cast(_Widget, events._controls["startStop"])
		categoryFocusCount = categoryList.focusCount

		_ = frameKey(_WorkspaceKeyEvent(ord("E"), control=True, eventObject=wx.frames[0]))
		self._drain(wx)

		self.assertEqual("events", window.activeWorkspace)
		self.assertEqual(1, wx.notebooks[0].selection)
		self.assertGreaterEqual(startStop.focusCount, 1)

		_ = frameKey(_WorkspaceKeyEvent(ord("I"), control=True, eventObject=wx.frames[0]))
		self._drain(wx)

		self.assertEqual("inspector", window.activeWorkspace)
		self.assertEqual(0, wx.notebooks[0].selection)
		self.assertGreater(categoryList.focusCount, categoryFocusCount)

	def test_status_bar_follows_the_visible_workspace(self) -> None:
		wx, window, _inspector, _events = self._sharedWindow()
		frameKey = wx.frames[0].bindings[wx.EVT_CHAR_HOOK]
		assert callable(frameKey)
		statusBar = cast("_FakeStatusBar | None", window._statusBar)
		assert statusBar is not None
		inspectorStatus = "Inspector ready. Browse the hierarchy or choose a property category."

		# Initial open shows the Inspector page, so its status is the one on the bar.
		self.assertEqual(inspectorStatus, statusBar.GetStatusText())

		# Ctrl+E activates Events; its own status replaces the Inspector's.
		_ = frameKey(_WorkspaceKeyEvent(ord("E"), control=True, eventObject=wx.frames[0]))
		self._drain(wx)
		self.assertIn("Monitoring", statusBar.GetStatusText())
		self.assertNotEqual(inspectorStatus, statusBar.GetStatusText())

		# Ctrl+I brings the Inspector back and reasserts its status.
		_ = frameKey(_WorkspaceKeyEvent(ord("I"), control=True, eventObject=wx.frames[0]))
		self._drain(wx)
		self.assertEqual(inspectorStatus, statusBar.GetStatusText())

		# A native tab change (no activate call) refreshes the now-visible workspace's status.
		workspaces = wx.notebooks[0]
		pageChanged = workspaces.bindings[wx.EVT_NOTEBOOK_PAGE_CHANGED]
		assert callable(pageChanged)
		workspaces.selection = 1
		_ = pageChanged(_WorkspaceKeyEvent(0))
		self.assertIn("Monitoring", statusBar.GetStatusText())

	def test_background_events_refresh_does_not_overwrite_inspector_status(self) -> None:
		_wx, window, _inspector, events = self._sharedWindow()
		statusBar = cast("_FakeStatusBar | None", window._statusBar)
		assert statusBar is not None
		inspectorStatus = "Inspector ready. Browse the hierarchy or choose a property category."
		self.assertEqual(inspectorStatus, statusBar.GetStatusText())

		# A background drain re-renders Events while the Inspector page is still on screen; the
		# shared status bar must keep the visible Inspector's line.
		events.refresh()

		self.assertEqual("inspector", window.activeWorkspace)
		self.assertEqual(inspectorStatus, statusBar.GetStatusText())

	def test_an_unregistered_workspace_key_is_left_for_the_control(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			service = InspectorService()
			service.openSource(_WorkspaceSource(kind=InspectorSourceKind.LIVE))
			window = KeystoneWindow(windowOwnership=_ownsInspectorWindow)
			workspace = InspectorWorkspace(
				service,
				retarget=lambda _kind, _raw: None,
				followRetarget=lambda _event: None,
				announce=lambda _message: None,
				copyToClipboard=lambda _text: True,
				isCurrent=lambda: True,
				windowOwnership=_ownsInspectorWindow,
				clock=lambda: 0,
				window=window,
			)
			workspace.show()

			self.assertFalse(window.handleKey(_WorkspaceKeyEvent(ord("E"), control=True)))
			self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("I"), control=True)))

	def test_the_opening_state_is_spoken_per_window_visit_not_per_switch(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		announcements: list[str] = []

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		serviceState = SimpleNamespace(
			active=False,
			activeFilter=EventFilter.default(),
			historySnapshot=EventHistory.empty,
			scope=None,
			rawEventsEnabled=False,
		)
		service = cast(EventMonitorService, serviceState)
		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			window = KeystoneWindow(windowOwnership=_ownsInspectorWindow)
			workspace = EventsWorkspace(service, announce=announcements.append, window=window)

			workspace.show()
			self.assertEqual(1, len(announcements))

			# Selecting the workspace again, however it is reached, stays silent.
			workspace.show()
			self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("E"), control=True)))
			self.assertEqual(1, len(announcements))

			# Closing the window ends the visit, so the next open reports where monitoring stands.
			workspace.close()
			workspace.show()

		self.assertEqual(3, len(announcements))
		self.assertEqual(announcements[0], announcements[2])
		self.assertIn("Events closed.", announcements[1])

	def test_tab_traversal_decides_where_a_workspace_switch_returns_focus(self) -> None:
		wx, window, inspector, events = self._sharedWindow()
		inspectorPanel = cast(_Widget, inspector._controls["panel"])
		eventsPanel = cast(_Widget, events._controls["panel"])
		inspectorFocus = inspectorPanel.bindings[wx.EVT_CHILD_FOCUS]
		eventsFocus = eventsPanel.bindings[wx.EVT_CHILD_FOCUS]
		assert callable(inspectorFocus)
		assert callable(eventsFocus)

		# The user tabs to a control Keystone never focused for them.
		rawUia = cast(_Widget, inspector._controls["rawUia"])
		_ = inspectorFocus(wx.focus(rawUia))
		eventFilter = cast(_Widget, events._controls["eventFilter"])
		_ = eventsFocus(wx.focus(eventFilter))
		rawUiaFocusCount = rawUia.focusCount
		eventFilterFocusCount = eventFilter.focusCount

		self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("I"), control=True)))
		self._drain(wx)
		self.assertEqual(rawUiaFocusCount + 1, rawUia.focusCount)

		self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("E"), control=True)))
		self._drain(wx)
		self.assertEqual(eventFilterFocusCount + 1, eventFilter.focusCount)

	def test_focus_inside_a_property_pane_is_restored_to_that_pane(self) -> None:
		wx, window, inspector, _events = self._sharedWindow()
		panel = cast(_Widget, inspector._controls["panel"])
		childFocus = panel.bindings[wx.EVT_CHILD_FOCUS]
		assert callable(childFocus)
		pane = cast(_Widget, inspector._controls["detail"])

		# The detail control is nested inside the Details static box; the user tabs onto it.
		_ = childFocus(wx.focus(pane))
		paneFocusCount = pane.focusCount

		self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("E"), control=True)))
		self._drain(wx)
		self.assertTrue(window.handleKey(_WorkspaceKeyEvent(ord("I"), control=True)))
		self._drain(wx)

		self.assertEqual(paneFocusCount + 1, pane.focusCount)

	def test_a_focused_window_outside_the_workspace_leaves_the_last_control_alone(self) -> None:
		wx, _window, inspector, _events = self._sharedWindow()
		panel = cast(_Widget, inspector._controls["panel"])
		childFocus = panel.bindings[wx.EVT_CHILD_FOCUS]
		assert callable(childFocus)
		hierarchy = cast(_Widget, inspector._controls["hierarchy"])
		_ = childFocus(wx.focus(hierarchy))

		_ = childFocus(wx.focus(_Widget()))

		self.assertEqual("hierarchy", inspector._lastFocusKey)

	def test_closing_the_inspector_resets_the_reopen_focus_to_hierarchy(self) -> None:
		harness = self._open()
		harness.workspace._lastFocusKey = "properties"

		harness.workspace._releaseControls()

		self.assertEqual("hierarchy", harness.workspace._lastFocusKey)

	def test_a_page_change_event_updates_the_active_workspace(self) -> None:
		wx, window, _inspector, _events = self._sharedWindow()
		workspaces = wx.notebooks[0]
		pageChanged = workspaces.bindings[wx.EVT_NOTEBOOK_PAGE_CHANGED]
		assert callable(pageChanged)

		workspaces.selection = 1
		_ = pageChanged(_WorkspaceKeyEvent(0))

		self.assertEqual("events", window.activeWorkspace)

	def test_events_collection_is_grouped_in_a_static_box(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		service = cast(
			EventMonitorService,
			SimpleNamespace(
				active=False,
				activeFilter=EventFilter.default(),
				historySnapshot=EventHistory.empty,
				scope=None,
			),
		)
		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			workspace = EventsWorkspace(service)
			workspace.show()
		events = cast(_Widget, workspace._controls["events"])

		self.assertIsNone(events.accessible)
		self.assertIn(events.GetParent(), wx.staticBoxes)
		boxLabels = {box.label for box in wx.staticBoxes if isinstance(box.label, str)}
		self.assertIn(workspace.definition.eventListName, boxLabels)
		self.assertIn(workspace.definition.monitoringGroupName, boxLabels)
		self.assertIn(workspace.definition.historyActionsName, boxLabels)

	def test_failed_monitor_start_is_announced(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		announcements: list[str] = []

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		service = cast(
			EventMonitorService,
			SimpleNamespace(
				active=False,
				activeFilter=EventFilter.default(),
				historySnapshot=EventHistory.empty,
				scope=None,
			),
		)
		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			workspace = EventsWorkspace(service, announce=announcements.append)
			workspace.configureMonitoring(start=lambda *_args: False, stop=lambda: None)
			workspace.show()
			toggle = cast(_Widget, workspace._controls["startStop"])
			handler = toggle.bindings[wx.EVT_BUTTON]
			assert callable(handler)
			_ = handler(None)

		self.assertIn("could not start", announcements[-1].lower())

	def test_f5_toggles_monitoring_from_within_the_events_workspace(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		serviceState = SimpleNamespace(
			active=False,
			activeFilter=EventFilter.default(),
			historySnapshot=EventHistory.empty,
			scope=None,
			rawEventsEnabled=False,
		)
		service = cast(EventMonitorService, serviceState)
		starts: list[MonitorScopeKind] = []
		stops: list[bool] = []

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		def start(kind: MonitorScopeKind) -> bool:
			starts.append(kind)
			serviceState.active = True
			return True

		def stop() -> None:
			stops.append(True)
			serviceState.active = False

		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			workspace = EventsWorkspace(service)
			workspace.configureMonitoring(start=start, stop=stop)
			workspace.show()
			workspace.handleKey(_WorkspaceKeyEvent(wx.WXK_F5))
			workspace.handleKey(_WorkspaceKeyEvent(wx.WXK_F5))

		self.assertEqual([MonitorScopeKind.ELEMENT], starts)
		self.assertEqual([True], stops)

	def test_event_refresh_appends_without_losing_selection_focus_or_details(self) -> None:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		provenance = EventProvenance(EventBackend.NVDA, False, True, 1, 1)

		def row(sequence: int, name: str) -> EventRow:
			return EventRow(
				sequence=sequence,
				session=1,
				backend=EventBackend.NVDA,
				eventType="focus",
				processId=7,
				application="app",
				objectName=name,
				objectRole="button",
				detail=f"detail {name}",
				timestampText=f"12:00:0{sequence}.000 AM",
				wallClockMs=sequence,
				receiptToProcessingMs=1.0,
				receiptToPropertyReadMs=1.0,
				redacted=False,
				rawEvent=False,
				truncated=False,
				provenance=provenance,
			)

		first = row(1, "first")
		second = row(2, "second")
		third = row(3, "third")
		history = [EventHistory((first, second), DropCounters(), 2)]
		service = cast(
			EventMonitorService,
			SimpleNamespace(
				active=False,
				activeFilter=EventFilter.default(),
				historySnapshot=lambda: history[0],
				scope=None,
			),
		)

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		with patch.object(inspectorModule, "import_module", side_effect=importHostModule):
			workspace = EventsWorkspace(service)
			workspace.show()
			events = cast(_FakeListCtrl, workspace._controls["events"])
			events.Select(1)
			events.Focus(1)
			workspace._renderSelectedDetails()
			details = cast(_Widget, workspace._controls["eventDetails"])
			self.assertIn("second", cast(str, details.value))
			deletesBefore = events.deleteAllCalls
			history[0] = EventHistory((first, second, third), DropCounters(), 3)

			workspace.refresh()

		self.assertEqual(deletesBefore, events.deleteAllCalls)
		self.assertEqual(1, events.selectedRow)
		self.assertEqual(1, events.focusedRow)
		self.assertIn("second", cast(str, details.value))

	def _eventsHarness(
		self,
		*,
		rows: int = 3,
	) -> tuple[_WorkspaceWx, EventsWorkspace, list[EventHistory], list[EventRow]]:
		wx = _WorkspaceWx()
		gui = SimpleNamespace(
			mainFrame=None,
			nvdaControls=SimpleNamespace(AutoWidthColumnListCtrl=wx.ListCtrl),
		)
		provenance = EventProvenance(EventBackend.NVDA, False, True, 1, 1)

		def row(sequence: int, name: str) -> EventRow:
			return EventRow(
				sequence=sequence,
				session=1,
				backend=EventBackend.NVDA,
				eventType="focus",
				processId=7,
				application="app",
				objectName=name,
				objectRole="button",
				detail=f"detail {name}",
				timestampText=f"12:00:0{sequence}.000 AM",
				wallClockMs=sequence,
				receiptToProcessingMs=1.0,
				receiptToPropertyReadMs=1.0,
				redacted=False,
				rawEvent=False,
				truncated=False,
				provenance=provenance,
			)

		built = [row(index + 1, f"row-{index + 1}") for index in range(rows)]
		history = [EventHistory(tuple(built), DropCounters(), rows)]
		service = cast(
			EventMonitorService,
			SimpleNamespace(
				active=False,
				activeFilter=EventFilter.default(),
				historySnapshot=lambda: history[0],
				scope=None,
				rawEventsEnabled=False,
			),
		)

		def importHostModule(name: str) -> object:
			if name == "wx":
				return wx
			if name == "gui":
				return gui
			raise ImportError(name)

		patcher = patch.object(inspectorModule, "import_module", side_effect=importHostModule)
		_ = patcher.start()
		self.addCleanup(patcher.stop)
		workspace = EventsWorkspace(service)
		workspace.configureMonitoring(start=lambda *_args: True, stop=lambda: None)
		workspace.show()
		return wx, workspace, history, built

	def test_follow_newest_keeps_exactly_the_newest_row_selected(self) -> None:
		wx, workspace, history, built = self._eventsHarness(rows=3)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		details = cast(_Widget, workspace._controls["eventDetails"])
		# The selected event changes when Follow Newest is enabled.
		events.Select(0)
		events.Select(1)

		followNewest = cast(_Widget, workspace._controls["followNewest"])
		followNewest.value = True
		handler = followNewest.bindings[wx.EVT_CHECKBOX]
		assert callable(handler)
		_ = handler(None)

		self.assertEqual({2}, events.selectedRows)
		self.assertEqual(2, events.focusedRow)
		self.assertIn("row-3", cast(str, details.value))

		# Each later arrival keeps exactly one row selected, and it is the newest one.
		newest = replace(built[0], sequence=4, objectName="row-4")
		history[0] = EventHistory((*built, newest), DropCounters(), 4)
		workspace.refresh()

		self.assertEqual({3}, events.selectedRows)
		self.assertEqual(3, events.focusedRow)
		self.assertIn("row-4", cast(str, details.value))

	def test_unchanged_event_drain_does_not_reset_details_or_monitor_controls(self) -> None:
		_wx, workspace, _history, _built = self._eventsHarness(rows=2)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		details = cast(_Widget, workspace._controls["eventDetails"])
		startStop = cast(_Widget, workspace._controls["startStop"])
		events.Select(1)
		workspace._renderSelectedDetails()
		detailWrites = details.setValueCount
		labelWrites = startStop.setLabelCount
		enableWrites = startStop.enableCount

		workspace.refresh()

		self.assertEqual(detailWrites, details.setValueCount)
		self.assertEqual(labelWrites, startStop.setLabelCount)
		self.assertEqual(enableWrites, startStop.enableCount)

	def test_start_monitoring_keeps_scope_enabled_like_the_prototype(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=1)
		service = cast(Any, workspace.service)
		scope = cast(_Widget, workspace._controls["scopeChoice"])
		scope.SetFocus()
		workspace.configureMonitoring(
			start=lambda *_args: setattr(service, "active", True) or True,
			stop=lambda: setattr(service, "active", False),
		)
		startStop = cast(_Widget, workspace._controls["startStop"])
		handler = startStop.bindings[wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)

		self.assertTrue(scope.enabled)
		self.assertEqual(1, scope.focusCount)

	def test_an_eviction_rebuild_keeps_the_focused_row_visible(self) -> None:
		_wx, workspace, history, built = self._eventsHarness(rows=3)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(2)
		events.Focus(2)
		events.ensureVisibleCalls.clear()
		deletesBefore = events.deleteAllCalls

		# The oldest row is evicted, so the list is rebuilt and every index shifts down by one.
		history[0] = EventHistory(tuple(built[1:]), DropCounters(retainedRowDrops=1), 3)
		workspace.refresh()

		self.assertEqual(deletesBefore + 1, events.deleteAllCalls)
		self.assertEqual(1, events.focusedRow)
		self.assertEqual({1}, events.selectedRows)
		self.assertIn(1, events.ensureVisibleCalls)

	def test_deselecting_a_row_clears_the_stale_details(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		details = cast(_Widget, workspace._controls["eventDetails"])
		selected = events.bindings[wx.EVT_LIST_ITEM_SELECTED]
		deselected = events.bindings[wx.EVT_LIST_ITEM_DESELECTED]
		assert callable(selected)
		assert callable(deselected)

		events.Select(1)
		_ = selected(None)
		self.assertIn("row-2", cast(str, details.value))

		events.Select(1, 0)
		_ = deselected(None)

		self.assertEqual("", details.value)

	def test_declining_broad_monitoring_is_reported_as_cancelled_not_refused(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=1)
		announcements: list[str] = []
		workspace._announce = announcements.append
		starts: list[object] = []
		workspace.configureMonitoring(
			start=lambda *args: starts.append(args) or True,
			stop=lambda: None,
			# A refusal is left over from an earlier attempt; declining must not report it.
			scopeFailure=lambda: ScopeUnavailableReason.NO_IDENTITY,
		)
		workspace._selectedScopeKind = MonitorScopeKind.BROAD
		wx.modalResult = wx.ID_NO

		startStop = cast(_Widget, workspace._controls["startStop"])
		handler = startStop.bindings[wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)

		self.assertEqual([], starts)
		self.assertEqual(1, len(announcements))
		self.assertIn("cancelled", announcements[0])
		self.assertNotIn("identifier", announcements[0])

	def test_accepting_broad_monitoring_starts_it(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=1)
		starts: list[object] = []
		workspace.configureMonitoring(
			start=lambda *args: starts.append(args) or True,
			stop=lambda: None,
		)
		workspace._selectedScopeKind = MonitorScopeKind.BROAD
		wx.modalResult = wx.ID_YES

		startStop = cast(_Widget, workspace._controls["startStop"])
		handler = startStop.bindings[wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)

		self.assertEqual([(MonitorScopeKind.BROAD,)], starts)

	def test_the_opening_state_reports_live_monitoring_after_a_reopen(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=1)
		announcements: list[str] = []
		workspace._announce = announcements.append
		rawService = cast(Any, workspace.service)

		workspace.close()
		# Monitoring kept running while the window was closed.
		rawService.active = True
		rawService.scope = MonitorScope.pinned("firefox", 4242)
		workspace.show()
		self._drain(wx)

		opening = announcements[-1]
		self.assertIn("monitoring active", opening.casefold())
		self.assertIn("firefox, process 4242", opening)
		self.assertIn("Stop Monitoring", opening)
		self.assertNotIn("stopped", opening.casefold())

	def test_the_opening_state_names_the_scope_the_user_selected(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=1)
		announcements: list[str] = []
		workspace._announce = announcements.append
		workspace._selectedScopeKind = MonitorScopeKind.SUBTREE

		workspace.close()
		workspace.show()
		self._drain(wx)

		opening = announcements[-1]
		self.assertIn("Events stopped", opening)
		self.assertIn("Selected subtree", opening)
		self.assertIn("Start Monitoring", opening)

	def test_event_reopen_focus_name_uses_definition_labels_and_resets_on_release(self) -> None:
		_wx, workspace, _history, _built = self._eventsHarness(rows=1)
		workspace._lastFocusKey = "eventFilter"

		self.assertEqual("Event Filter...", workspace._focusTargetName())

		workspace._releaseControls()

		self.assertEqual("startStop", workspace._lastFocusKey)

	def test_ctrl_c_copies_the_selected_event_as_text_from_the_list(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		copy = _RecordingCopy()
		cast(Any, workspace.service).copySelectedEvents = copy
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(1)
		workspace._lastFocusKey = "events"
		frameKey = wx.frames[0].bindings[wx.EVT_CHAR_HOOK]
		assert callable(frameKey)

		_ = frameKey(_WorkspaceKeyEvent(ord("C"), control=True, eventObject=wx.frames[0]))

		self.assertEqual(1, len(copy.requests))
		rows, copyFormat = copy.requests[0]
		self.assertEqual(EventCopyFormat.TEXT, copyFormat)
		self.assertEqual(1, len(rows))

	def test_ctrl_c_without_a_selected_event_says_nothing_is_selected(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		announcements: list[str] = []
		workspace._announce = announcements.append
		copy = _RecordingCopy()
		cast(Any, workspace.service).copySelectedEvents = copy
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(0, 0)
		workspace._lastFocusKey = "eventDetails"
		frameKey = wx.frames[0].bindings[wx.EVT_CHAR_HOOK]
		assert callable(frameKey)

		_ = frameKey(_WorkspaceKeyEvent(ord("C"), control=True, eventObject=wx.frames[0]))

		self.assertEqual([], copy.requests)
		self.assertEqual(["Nothing is selected to copy."], announcements)

	def test_ctrl_c_outside_the_event_context_is_left_to_the_control(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		copy = _RecordingCopy()
		cast(Any, workspace.service).copySelectedEvents = copy
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(1)
		workspace._lastFocusKey = "scopeStatus"
		event = _WorkspaceKeyEvent(ord("C"), control=True, eventObject=wx.frames[0])
		frameKey = wx.frames[0].bindings[wx.EVT_CHAR_HOOK]
		assert callable(frameKey)

		_ = frameKey(event)

		self.assertEqual([], copy.requests)
		self.assertTrue(event.skipped)

	def test_event_context_menu_targets_the_clicked_single_row(self) -> None:
		_wx, workspace, _history, _built = self._eventsHarness(rows=3)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(0)
		contextEvent = SimpleNamespace(GetPosition=lambda: 2)
		workspace._showEventContextMenu(contextEvent)
		self.assertEqual({2}, events.selectedRows)
		self.assertEqual(2, events.focusedRow)
		self.assertEqual([2], events.screenToClientCalls)
		self.assertIs(_built[2], workspace._selectedEventRow())

	def test_event_keyboard_context_menu_preserves_the_existing_selection(self) -> None:
		_wx, workspace, _history, _built = self._eventsHarness(rows=3)
		events = cast(_FakeListCtrl, workspace._controls["events"])
		events.Select(1)
		events.Focus(1)

		workspace._showEventContextMenu(SimpleNamespace(GetPosition=lambda: (-1, -1)))

		self.assertEqual({1}, events.selectedRows)
		self.assertEqual(1, events.focusedRow)
		self.assertEqual([], events.screenToClientCalls)
		self.assertIs(_built[1], workspace._selectedEventRow())

	def test_event_filter_apply_announces_and_updates_status(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		announcements: list[str] = []
		workspace._announce = announcements.append

		class _StubDialog:
			def __init__(self, *_args: object, **_kwargs: object) -> None:
				super().__init__()

			def showModal(self) -> object:
				return wx.ID_OK

			def destroy(self) -> None:
				return

		with patch.object(inspectorModule, "EventFilterDialog", _StubDialog):
			workspace._changeFilter()

		self.assertIn("Event filter applied to future events.", announcements)
		statusBar = cast("_FakeStatusBar | None", workspace.window._statusBar)
		assert statusBar is not None
		self.assertEqual("Event filter applied to future events.", statusBar.GetStatusText())

	def test_event_filter_keep_gives_no_completion_feedback(self) -> None:
		wx, workspace, _history, _built = self._eventsHarness(rows=2)
		announcements: list[str] = []
		workspace._announce = announcements.append

		class _StubDialog:
			def __init__(self, *_args: object, **_kwargs: object) -> None:
				super().__init__()

			def showModal(self) -> object:
				return wx.ID_CANCEL

			def destroy(self) -> None:
				return

		with patch.object(inspectorModule, "EventFilterDialog", _StubDialog):
			workspace._changeFilter()

		self.assertNotIn("Event filter applied to future events.", announcements)

	def test_the_status_line_is_localized_from_live_state(self) -> None:
		_wx, workspace, _history, _built = self._eventsHarness(rows=2)
		rawService = cast(Any, workspace.service)
		rawService.active = True
		rawService.scope = MonitorScope.pinned("firefox", 4242)

		workspace.refresh()

		statusBar = cast("_FakeStatusBar | None", workspace.window._statusBar)
		assert statusBar is not None
		text = statusBar.GetStatusText()
		self.assertIn("Monitoring active", text)
		self.assertIn("firefox, process 4242", text)
		self.assertIn("raw UIA off", text)
		self.assertIn("events 2", text)

	def test_event_report_names_every_column_it_can_source(self) -> None:
		definition = inspectorModule.EventsWorkspaceDefinition()
		self.assertEqual(
			("Event", "Source", "Changed value", "Time"),
			definition.reportColumnHeadings,
		)
		self.assertEqual(definition.reportColumnHeadings, definition.columnHeadings)

	def test_native_collections_are_labelled_by_static_boxes(self) -> None:
		harness = self._open()
		definition = harness.workspace.definition
		boxLabels = {box.label for box in harness.wx.staticBoxes if isinstance(box.label, str)}
		self.assertIn(definition.hierarchyName, boxLabels)
		self.assertIn(definition.propertyNotebookName, boxLabels)
		self.assertIn("Core properties", boxLabels)
		self.assertIn(definition.targetGroupName, boxLabels)

	def test_advanced_category_flattens_structured_properties_into_the_report_list(self) -> None:
		harness = self._open()
		detail = cast(_FakeListCtrl, self._selectCategory(harness, "Advanced"))
		self.assertEqual("list", harness.workspace._detailKind)
		self.assertEqual(["Property", "Value", "Status"], detail.columns)
		self.assertTrue(detail.rows)

	def test_detail_report_row_copy_is_tab_joined(self) -> None:
		harness = self._open()
		detail = cast(_FakeListCtrl, self._selectCategory(harness, "Core"))
		self.assertTrue(detail.rows)
		harness.workspace._lastFocusKey = "properties"
		expected = "\t".join(cell for cell in detail.rows[0].values() if cell)
		harness.workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		self.assertEqual(expected, harness.clipboard[-1])

	def test_workspace_renders_hierarchy_and_source_summary(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		tree = harness.wx.trees[0]
		labels = set(tree.texts.values())
		self.assertIn("Main window, window", labels)
		self.assertIn("Email, edit", labels)
		selection = tree.selection
		assert selection is not None
		self.assertEqual("Email, edit", tree.texts[selection])
		summary = self._widget(harness.workspace, "sourceSummary").value
		assert isinstance(summary, str)
		self.assertIn("Offline source", summary)
		self.assertIn("Main window", summary)
		self.assertEqual(
			"Keystone Inspector — reader.exe | Offline source: Main window",
			harness.wx.frames[0].title,
		)
		detail = cast(_FakeListCtrl, self._widget(harness.workspace, "detail"))
		self.assertEqual(["Property", "Value", "Status"], detail.columns)
		self.assertTrue(any("Name" in row.get(0, "") for row in detail.rows))
		harness.workspace._lastFocusKey = "hierarchy"
		harness.workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		copied = harness.clipboard[-1]
		self.assertIn("Email (edit)", copied)
		self.assertIn("First (text)", copied)
		self.assertIn("Core:", copied)

	def test_supported_uia_patterns_appear_in_the_uia_tree(self) -> None:
		harness = self._open()
		_ = self._selectCategory(harness, "UIA")
		tree = cast(_FakeTree, self._widget(harness.workspace, "detail"))
		sectionLabels = [tree.texts[item] for item in tree.childItems[cast(int, tree.root)]]
		self.assertIn("Supported patterns", sectionLabels)
		patternSection = next(
			item for item in tree.childItems[cast(int, tree.root)] if tree.texts[item] == "Supported patterns"
		)
		patternLabels = [tree.texts[item] for item in tree.childItems[patternSection]]
		self.assertTrue(any(label.startswith("Text") for label in patternLabels))

	def test_uia_tree_subtree_copy_is_indented(self) -> None:
		harness = self._open()
		tree = cast(_FakeTree, self._selectCategory(harness, "UIA"))
		root = cast(int, tree.root)
		tree.SelectItem(root)
		harness.workspace._lastFocusKey = "properties"
		harness.workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		copied = harness.clipboard[-1]
		lines = copied.split("\n")
		self.assertEqual("UIA properties", lines[0])
		self.assertTrue(any(line.startswith("  ") for line in lines[1:]))

	def test_ctrl_f_from_the_hierarchy_opens_the_native_find_dialog(self) -> None:
		harness = self._open()
		tree = harness.wx.trees[0]
		handler = tree.bindings[harness.wx.EVT_KEY_DOWN]
		assert callable(handler)

		_ = handler(_WorkspaceKeyEvent(ord("f"), control=True, eventObject=tree))

		self.assertGreaterEqual(len(harness.wx.findDialogs), 1)

	def test_inspector_access_keys_work_from_every_tree_and_list_region(self) -> None:
		harness = self._open()
		_ = self._selectCategory(harness, "UIA")
		frameKey = harness.wx.frames[0].bindings[harness.wx.EVT_CHAR_HOOK]
		assert callable(frameKey)
		retargets: list[str] = []
		harness.workspace._doRetarget = cast(Any, retargets.append)

		for focusKey in ("hierarchy", "categoryList", "properties"):
			harness.workspace._lastFocusKey = focusKey
			_ = frameKey(_WorkspaceKeyEvent(ord("F"), alt=True))
			_ = frameKey(_WorkspaceKeyEvent(ord("N"), alt=True))

		self.assertEqual(
			["focus", "navigator", "focus", "navigator", "focus", "navigator"],
			retargets,
		)

		rawUia = cast(_Widget, harness.workspace._controls["rawUia"])
		rawUia.SetValue(False)
		for focusKey in ("hierarchy", "categoryList", "properties"):
			harness.workspace._lastFocusKey = focusKey
			_ = frameKey(_WorkspaceKeyEvent(ord("U"), alt=True))

		self.assertTrue(rawUia.GetValue())
		self.assertEqual(4, rawUia.setValueCount)

	def test_app_module_override_reloads_then_closes_stale_inspector_source(self) -> None:
		harness = self._open()
		changes: list[bool] = []
		harness.workspace._appModuleOverrideState = lambda: AppModuleOverrideState(
			"powerpnt.exe",
			False,
			True,
		)

		def setAppModuleOverride(enabled: bool) -> AppModuleOverrideOutcome:
			changes.append(enabled)
			return AppModuleOverrideOutcome(True, "powerpnt.exe", enabled)

		harness.workspace._setAppModuleOverride = setAppModuleOverride
		harness.workspace._syncAppModuleOverrideControl()
		control = self._widget(harness.workspace, "appModuleOverride")
		handler = control.bindings[harness.wx.EVT_CHECKBOX]
		assert callable(handler)
		harness.wx.modalResult = harness.wx.ID_YES
		control.SetValue(True)

		_ = handler(SimpleNamespace())
		self.assertIn("powerpnt.exe", cast(str, harness.wx.dialogs[-1].args[1]))
		self._drain(harness.wx)

		self.assertEqual([True], changes)
		self.assertTrue(any("App modules reloaded" in message for message in harness.announcements))
		self.assertEqual({}, harness.workspace._controls)

	def test_f3_requires_a_previous_find_query(self) -> None:
		harness = self._open()

		harness.workspace.handleKey(_WorkspaceKeyEvent(harness.wx.WXK_F3))

		self.assertEqual(
			"Open Find with Control+F before repeating a search.",
			harness.announcements[-1],
		)
		self.assertEqual([], harness.wx.findDialogs)

	def test_property_rows_start_selected_and_focused(self) -> None:
		harness = self._open()
		detail = cast(_FakeListCtrl, self._widget(harness.workspace, "detail"))
		self.assertEqual(0, detail.focusedRow)
		self.assertEqual(0, detail.selectedRow)

	def test_ctrl_c_copies_by_region_and_reports_clipboard_outcome(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		self.assertEqual(1, len(harness.clipboard))
		self.assertEqual("Copied to the clipboard.", harness.announcements[-1])
		workspace._lastFocusKey = "properties"
		workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		self.assertEqual(2, len(harness.clipboard))

		failing = self._open(copySucceeds=False)
		failing.workspace.handleKey(_WorkspaceKeyEvent(ord("c"), control=True))
		self.assertEqual(
			"Could not copy to the clipboard. Try again.",
			failing.announcements[-1],
		)

	def test_follow_focus_retarget_reroots_and_announces_new_application(self) -> None:
		harness = self._open(kind=InspectorSourceKind.LIVE)
		workspace = harness.workspace
		wx = harness.wx
		follow = self._widget(workspace, "followFocus")
		self.assertTrue(follow.enabled)
		follow.SetValue(True)
		checkboxHandler = follow.bindings[wx.EVT_CHECKBOX]
		assert callable(checkboxHandler)
		_ = checkboxHandler(None)
		self.assertTrue(harness.service.followFocusEnabled)
		outcome = workspace.considerFollowFocus(FollowFocusEvent(applicationKey="browser.exe\x1f7"))
		self.assertIs(FollowFocusOutcome.RETARGET, outcome)
		self.assertEqual(1, len(harness.followEvents))
		self.assertEqual("Inspector now follows browser.exe.", harness.announcements[-1])
		identity = harness.service.sourceIdentity()
		assert identity is not None
		self.assertEqual("browser.exe", identity.executable)

	def test_follow_focus_retargets_within_the_current_application_without_announcement(self) -> None:
		harness = self._open(kind=InspectorSourceKind.LIVE)
		self.assertTrue(harness.service.setFollowFocus(True))
		announcedBefore = len(harness.announcements)

		outcome = harness.workspace.considerFollowFocus(
			FollowFocusEvent(applicationKey="reader.exe\x1f42"),
		)

		self.assertIs(FollowFocusOutcome.RETARGET, outcome)
		self.assertEqual(1, len(harness.followEvents))
		self.assertEqual(announcedBefore, len(harness.announcements))

	def test_offline_source_disables_follow_focus(self) -> None:
		harness = self._open(kind=InspectorSourceKind.OFFLINE)
		workspace = harness.workspace
		self.assertFalse(harness.service.followFocusAvailable)
		self.assertFalse(self._widget(workspace, "followFocus").enabled)
		announced = len(harness.announcements)
		outcome = workspace.considerFollowFocus(FollowFocusEvent(applicationKey="other.exe\x1f9"))
		self.assertIs(FollowFocusOutcome.IGNORED_DISABLED, outcome)
		self.assertEqual(announced, len(harness.announcements))

	def test_quick_property_announces_then_browses_and_resets_on_selection(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		workspace.quickProperty("kb:1", nowMilliseconds=0)
		self.assertEqual("Name: Email", harness.announcements[-1])
		self.assertGreaterEqual(len(wx.later), 1)
		workspace.quickProperty("kb:1", nowMilliseconds=100)
		self.assertEqual("Name. Email", harness.announcements[-1])
		tree = harness.wx.trees[0]
		rootItem = workspace._treeItems["root"]
		tree.SelectItem(cast(int, rootItem))
		selectionHandler = tree.bindings[wx.EVT_TREE_SEL_CHANGED]
		assert callable(selectionHandler)
		_ = selectionHandler(None)
		workspace.quickProperty("kb:1", nowMilliseconds=200)
		self.assertEqual("Name: Main window", harness.announcements[-1])

	def test_retarget_button_updates_and_announces(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		button = self._widget(workspace, "retargetFocus")
		handler = button.bindings[wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)
		self.assertIn(("focus", False), harness.retargets)
		self.assertEqual(
			"Inspector retargeted to focus: Email, edit.",
			harness.announcements[-1],
		)

	def test_expanding_a_node_loads_children_into_the_tree(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		tree = harness.wx.trees[0]
		targetItem = workspace._treeItems["target"]
		event = SimpleNamespace(GetItem=lambda: targetItem)
		handler = tree.bindings[wx.EVT_TREE_ITEM_EXPANDING]
		assert callable(handler)
		_ = handler(event)
		labels = set(tree.texts.values())
		self.assertIn("First, text", labels)
		self.assertIn("Second, text", labels)
		self.assertEqual(1, tree.deleteAllCalls)
		self.assertEqual(targetItem, workspace._treeItems["target"])
		self.assertIn(cast(int, workspace._treeItems["target"]), tree.expandedItems)

	def test_right_arrow_expands_the_selected_tree_node(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		tree = harness.wx.trees[0]
		targetItem = workspace._treeItems["target"]
		tree.SelectItem(cast(int, targetItem))
		handler = tree.bindings[wx.EVT_KEY_DOWN]
		assert callable(handler)

		_ = handler(_WorkspaceKeyEvent(wx.WXK_RIGHT))

		labels = set(tree.texts.values())
		self.assertIn("First, text", labels)
		self.assertIn("Second, text", labels)

	def test_empty_child_probe_removes_expander_and_is_not_retried(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		tree = harness.wx.trees[0]
		harness.source.targetChildState = ChildState.EMPTY
		targetItem = cast(int, workspace._treeItems["target"])
		expanding = tree.bindings[wx.EVT_TREE_ITEM_EXPANDING]
		assert callable(expanding)

		_ = expanding(SimpleNamespace(GetItem=lambda: targetItem))

		self.assertNotIn(targetItem, tree.hasChildren)
		self.assertEqual(["target"], harness.source.childrenCalls)

		tree.SelectItem(targetItem)
		key = tree.bindings[wx.EVT_KEY_DOWN]
		assert callable(key)
		event = _WorkspaceKeyEvent(wx.WXK_RIGHT)
		_ = key(event)

		self.assertTrue(event.skipped)
		self.assertEqual(["target"], harness.source.childrenCalls)

	def test_programmatic_tree_expansion_does_not_reenter_child_loading(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		tree = harness.wx.trees[0]
		targetItem = workspace._treeItems["target"]
		event = SimpleNamespace(GetItem=lambda: targetItem)
		handler = tree.bindings[wx.EVT_TREE_ITEM_EXPANDING]
		assert callable(handler)
		workspace._renderingHierarchy = True

		_ = handler(event)

		self.assertNotIn("First, text", set(tree.texts.values()))
		self.assertNotIn("Second, text", set(tree.texts.values()))

	def test_property_list_tab_navigation_is_left_to_native_traversal(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		detail = self._widget(workspace, "detail")
		handler = detail.bindings[wx.EVT_KEY_DOWN]
		assert callable(handler)

		event = _WorkspaceKeyEvent(wx.WXK_TAB)
		_ = handler(event)
		self.assertTrue(event.skipped)
		shiftEvent = _WorkspaceKeyEvent(wx.WXK_TAB, shift=True)
		_ = handler(shiftEvent)
		self.assertTrue(shiftEvent.skipped)

	def test_close_makes_stale_quick_timer_callbacks_no_ops(self) -> None:
		harness = self._open()
		workspace = harness.workspace
		wx = harness.wx
		workspace.quickProperty("kb:1", nowMilliseconds=0)
		self.assertGreaterEqual(len(wx.later), 1)
		staleCallback = wx.later[-1]
		assert callable(staleCallback)
		workspace.close()
		self.assertTrue(harness.wx.frames[0].destroyed)
		self.assertIsNone(harness.service.sourceIdentity())
		_ = staleCallback()
		self.assertIsNone(harness.service.sourceIdentity())

	def _driveWiredTransitions(self, harness: _Harness) -> None:
		# Exercise every workspace transition that carries a cue: explicit retarget, the
		# quick-property announce/browse/copy cycle, and close.
		button = self._widget(harness.workspace, "retargetFocus")
		handler = button.bindings[harness.wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=0)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=50)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=100)
		harness.workspace.close()

	def test_close_emits_inspector_close_after_speech_owned_by_the_frame(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(sound=sound)
		frameGeneration = harness.workspace._activationGeneration
		harness.workspace.close()
		self.assertEqual([CueEventId.INSPECTOR_CLOSE], sound.events())
		request = sound.requests[0]
		self.assertEqual(SoundOwnerKind.INSPECTOR, request.owner.kind)
		self.assertEqual(frameGeneration, request.owner.generation)
		self.assertIsNone(request.familyAtom)
		self.assertEqual("Inspector closed.", harness.announcements[-1])

	def test_close_without_an_open_source_stays_silent_in_sound_too(self) -> None:
		sound = _RecordingSounds()
		service = InspectorService()
		workspace = InspectorWorkspace(
			service,
			retarget=lambda _kind, _raw: None,
			followRetarget=lambda _event: None,
			announce=lambda _message: None,
			copyToClipboard=lambda _text: True,
			isCurrent=lambda: True,
			windowOwnership=_ownsInspectorWindow,
			sound=sound,
		)

		workspace.close()

		self.assertEqual([], sound.requests)

	def test_explicit_retarget_emits_refresh_inspector_owned_by_the_source(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(sound=sound)
		button = self._widget(harness.workspace, "retargetFocus")
		handler = button.bindings[harness.wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)
		self.assertEqual([CueEventId.REFRESH_INSPECTOR], sound.events())
		request = sound.requests[0]
		self.assertEqual(SoundOwnerKind.INSPECTOR, request.owner.kind)
		self.assertEqual(harness.service.sourceGeneration, request.owner.generation)
		self.assertEqual(
			f"{CueEventId.REFRESH_INSPECTOR.value}:{harness.service.sourceGeneration}",
			request.coalescingKey,
		)
		self.assertEqual(
			"Inspector retargeted to focus: Email, edit.",
			harness.announcements[-1],
		)

	def test_follow_focus_retarget_emits_refresh_owned_by_the_new_source_generation(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(sound=sound)
		follow = self._widget(harness.workspace, "followFocus")
		follow.SetValue(True)
		checkboxHandler = follow.bindings[harness.wx.EVT_CHECKBOX]
		assert callable(checkboxHandler)
		_ = checkboxHandler(None)
		generationBefore = harness.service.sourceGeneration
		outcome = harness.workspace.considerFollowFocus(
			FollowFocusEvent(applicationKey="browser.exe\x1f7"),
		)
		self.assertIs(FollowFocusOutcome.RETARGET, outcome)
		self.assertEqual([CueEventId.REFRESH_INSPECTOR], sound.events())
		request = sound.requests[0]
		self.assertEqual(SoundOwnerKind.INSPECTOR, request.owner.kind)
		self.assertGreater(request.owner.generation, generationBefore)
		self.assertEqual(harness.service.sourceGeneration, request.owner.generation)

	def test_quick_property_announce_is_silent_and_browse_emits_the_browsable_cue(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(sound=sound)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=0)
		self.assertEqual([], sound.requests)
		self.assertEqual("Name: Email", harness.announcements[-1])
		harness.workspace.quickProperty("kb:1", nowMilliseconds=50)
		self.assertEqual([CueEventId.QUICK_PROPERTY_BROWSABLE], sound.events())
		request = sound.requests[-1]
		self.assertEqual(SoundOwnerKind.INSPECTOR, request.owner.kind)
		self.assertEqual(harness.service.sourceGeneration, request.owner.generation)
		self.assertEqual("Name. Email", harness.announcements[-1])

	def test_quick_property_copy_emits_the_copy_cue_only_on_success(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(sound=sound)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=0)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=50)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=100)
		self.assertEqual(
			[CueEventId.QUICK_PROPERTY_BROWSABLE, CueEventId.QUICK_PROPERTY_COPY],
			sound.events(),
		)
		self.assertEqual("Copied to the clipboard.", harness.announcements[-1])

	def test_quick_property_copy_failure_emits_no_cue(self) -> None:
		sound = _RecordingSounds()
		harness = self._open(copySucceeds=False, sound=sound)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=0)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=50)
		harness.workspace.quickProperty("kb:1", nowMilliseconds=100)
		self.assertEqual([CueEventId.QUICK_PROPERTY_BROWSABLE], sound.events())
		self.assertEqual("Could not copy to the clipboard. Try again.", harness.announcements[-1])

	def test_speech_is_byte_identical_regardless_of_the_sound_seam(self) -> None:
		silent = self._open()
		self._driveWiredTransitions(silent)

		recording = self._open(sound=_RecordingSounds())
		self._driveWiredTransitions(recording)

		failing = self._open(sound=_FailingSounds())
		self._driveWiredTransitions(failing)

		self.assertEqual(silent.announcements, recording.announcements)
		self.assertEqual(silent.announcements, failing.announcements)

	def test_a_failing_sound_seam_never_disturbs_the_workspace(self) -> None:
		harness = self._open(sound=_FailingSounds())
		button = self._widget(harness.workspace, "retargetFocus")
		handler = button.bindings[harness.wx.EVT_BUTTON]
		assert callable(handler)
		_ = handler(None)
		self.assertEqual(
			"Inspector retargeted to focus: Email, edit.",
			harness.announcements[-1],
		)
		harness.workspace.close()
		self.assertEqual("Inspector closed.", harness.announcements[-1])
		self.assertTrue(harness.wx.frames[0].destroyed)
		self.assertIsNone(harness.service.sourceIdentity())


class _InspectionCapture:
	"""Stand in for the capture seam so the runtime wiring can be exercised without a live host."""

	def __init__(
		self,
		result: object,
		*,
		onCapture: Callable[[], None] | None = None,
	) -> None:
		super().__init__()
		self._result = result
		self._results: list[object] | None = (
			list(cast(list[object], result)) if isinstance(result, list) else None
		)
		self._onCapture = onCapture
		self.requests: list[object] = []

	def captureForInspection(self, request: object) -> object:
		self.requests.append(request)
		if self._onCapture is not None:
			self._onCapture()
		return self._result if self._results is None else self._results.pop(0)


def _capturedResult(
	*,
	committed: bool,
	snapshot: object | None,
	inspectionTargetKey: str | None = "root",
) -> object:
	return SimpleNamespace(
		committed=committed,
		errorCode=None,
		snapshot=snapshot,
		inspectionTargetKey=inspectionTargetKey,
	)


def _liveSnapshotStub() -> object:
	def unfocusedField(_field: str) -> object:
		return SimpleNamespace(status=EvidenceState.VALUE, value=False)

	return SimpleNamespace(
		captureRoots=("root",),
		captureNodes=(
			SimpleNamespace(
				key="root",
				field=unfocusedField,
			),
		),
	)


class _ShowSpy:
	"""Stand in for the live frame so an open can be exercised without importing wx.

	The open path touches exactly two members: ``ownsWindow`` (always unowned, so the retarget
	rule resolves to the live target) and ``show`` (records that the frame was raised). Recording
	shows on a caller-supplied list keeps the spy typed as the frame it replaces.
	"""

	def __init__(self, shows: list[int], *, ownedWindowHandle: int | None = None) -> None:
		super().__init__()
		self._shows = shows
		self._ownedWindowHandle = ownedWindowHandle
		self.window = SimpleNamespace(isOpen=True)

	def ownsWindow(self, processId: int, windowHandle: int) -> bool:
		_ = processId
		return windowHandle == self._ownedWindowHandle

	def show(self) -> None:
		self._shows.append(1)


class _FollowSpy(_ShowSpy):
	def __init__(self, events: list[FollowFocusEvent]) -> None:
		super().__init__([])
		self._events = events

	def considerFollowFocus(self, event: FollowFocusEvent) -> FollowFocusOutcome:
		self._events.append(event)
		return FollowFocusOutcome.RETARGET


class _GenerationInspectorService:
	"""Minimal Inspector service double whose ``openSource`` only bumps the source generation.

	The open cue's contract is "sound after the frame shows, owned by the generation the open just
	produced". Projecting a real tree is the frame's concern and is proven elsewhere; here the double
	isolates the generation the owner must carry without a live snapshot.
	"""

	def __init__(self) -> None:
		super().__init__()
		self._generation = 0

	@property
	def sourceGeneration(self) -> int:
		return self._generation

	def openSource(self, source: object, *, settings: object) -> None:
		_ = (source, settings)
		self._generation += 1

	def hierarchy(self) -> tuple[object, ...]:
		return ()

	def expand(self, _nodeId: str) -> ChildState:
		return ChildState.EMPTY


class _HydratingInspectorService(_GenerationInspectorService):
	def __init__(self) -> None:
		super().__init__()
		self.expanded: list[str] = []

	@override
	def hierarchy(self) -> tuple[object, ...]:
		return (SimpleNamespace(nodeId="root"), SimpleNamespace(nodeId="target"))

	@override
	def expand(self, nodeId: str) -> ChildState:
		self.expanded.append(nodeId)
		return ChildState.LOADED


class _RootRecordingInspectorService(_GenerationInspectorService):
	def __init__(self) -> None:
		super().__init__()
		self.rootNames: list[str] = []
		self.followFocusEnabled = False

	@override
	def openSource(self, source: object, *, settings: object) -> None:
		super().openSource(source, settings=settings)
		live = cast(LiveInspectorSource, source)
		self.rootNames = [facet.name for facet in live.roots()]


class RuntimeLiveInspectorSourceTests(unittest.TestCase):
	def _runtime(
		self,
		source: _SelectedSource,
		*,
		announce: list[str] | None = None,
		diagnostic: list[str] | None = None,
		schedule: list[Callable[[], None]] | None = None,
		workspaceOpen: bool = True,
		sound: WorkflowSounds | None = None,
	) -> ProductionCommandRuntime:
		runtime = ProductionCommandRuntime(
			LifecycleService(),
			SettingsSnapshot.defaults(settingsRevision=1),
			object(),  # type: ignore[arg-type]
			object(),  # type: ignore[arg-type]
			openCustomUia=lambda _parent, _initialTarget=None: None,
			openEventMonitor=lambda: None,
			selectedSource=source,
			announceInspector=None if announce is None else announce.append,
			inspectorDiagnostic=None if diagnostic is None else diagnostic.append,
			scheduleInspector=None if schedule is None else schedule.append,
			sound=sound,
		)
		if schedule is not None and workspaceOpen:
			runtime._inspector = cast(InspectorWorkspace, _ShowSpy([]))
		return runtime

	def test_inspect_keeps_a_live_foreground_source_without_activating_the_capture_router(self) -> None:
		reader = cast(SimpleNamespace, _target("reader", 42, 410))
		window = cast(SimpleNamespace, _target("reader", 42, 411))
		reader.name = "Reader target"
		window.name = "Reader window"
		source = _SelectedSource({"focus": [reader, reader], "foreground": [window, window]})
		runtime = self._runtime(source)

		live = runtime._buildLiveInspectorSource("focus")

		assert live is not None
		identity = live.identity()
		self.assertIs(identity.kind, InspectorSourceKind.LIVE)
		self.assertEqual("reader.exe", identity.executable)
		self.assertEqual(42, identity.processId)
		self.assertTrue(identity.followFocusAvailable)
		self.assertIsNone(identity.rawReason)
		self.assertEqual(["Reader window", "Reader target"], [facet.name for facet in live.roots()])
		self.assertIsNone(runtime._router._session)
		live.close()

	def test_live_subtree_snapshot_uses_and_releases_a_capture_session(self) -> None:
		reader = cast(SimpleNamespace, _target("reader", 42, 410))
		window = cast(SimpleNamespace, _target("reader", 42, 411))
		reader.name = "Reader target"
		window.name = "Reader window"
		runtime = self._runtime(
			_SelectedSource({"focus": [reader, reader], "foreground": [window, window]}),
		)
		live = runtime._buildLiveInspectorSource("focus")
		assert live is not None
		runtime._openInspectorSource(live)
		targetId = live.roots()[-1].nodeId
		sentinel = object()
		requests: list[CaptureRequest] = []

		def captureForInspection(request: CaptureRequest) -> object:
			requests.append(request)
			return SimpleNamespace(committed=True, bundle=sentinel, errorCode=None)

		capture = cast(
			Any,
			SimpleNamespace(
				captureForInspection=captureForInspection,
			),
		)
		runtime._capture = capture

		result = runtime._inspectorSubtreePackage(targetId)

		self.assertIs(sentinel, result)
		self.assertEqual(1, len(requests))
		self.assertIsNone(runtime._router._session)

	def test_focus_subtree_command_roots_at_focus_and_uses_nonbaseline_capture(self) -> None:
		focus = cast(SimpleNamespace, _target("focus-reader", 42, 410))
		foreground = cast(SimpleNamespace, _target("foreground-reader", 42, 411))
		runtime = self._runtime(_SelectedSource({"focus": [focus], "foreground": [foreground]}))
		requests: list[CaptureRequest] = []

		def captureSubtree(
			request: CaptureRequest,
			*,
			progress: Callable[[object], None] | None = None,
		) -> object:
			_ = progress
			requests.append(request)
			return SimpleNamespace(
				lifecycle=SimpleNamespace(state=CaptureState.COMPLETED),
				traversal=SimpleNamespace(nodes=(), limits=()),
				screenshot=None,
				committed=True,
				errorCode=None,
			)

		def wrongCapture(*_args: object, **_kwargs: object) -> object:
			raise AssertionError("wrong capture path")

		runtime._capture = cast(
			CaptureService,
			SimpleNamespace(
				captureSubtree=captureSubtree,
				capture=wrongCapture,
			),
		)

		result = runtime.execute(CommandId.FOCUS_UNLIMITED)

		self.assertEqual("completed", result.outcome)
		self.assertEqual(1, len(requests))
		self.assertEqual(CaptureTargetKind.FOREGROUND, requests[0].targetKind)
		self.assertEqual("focus-reader.exe", requests[0].executable)
		self.assertEqual("window-411", requests[0].containingForeground.scopeId)
		self.assertTrue(requests[0].includeRootNameInOutput)
		self.assertIsNone(runtime._router._session)

	def test_navigator_subtree_command_marks_its_capture_for_named_output(self) -> None:
		navigator = cast(SimpleNamespace, _target("navigator-reader", 42, 410))
		foreground = cast(SimpleNamespace, _target("foreground-reader", 42, 411))
		runtime = self._runtime(
			_SelectedSource({"navigator": [navigator], "foreground": [foreground]}),
		)
		requests: list[CaptureRequest] = []

		def capture(
			request: CaptureRequest,
			*,
			progress: Callable[[object], None] | None = None,
		) -> object:
			_ = progress
			requests.append(request)
			return SimpleNamespace(
				lifecycle=SimpleNamespace(state=CaptureState.COMPLETED),
				traversal=SimpleNamespace(nodes=(), limits=()),
				screenshot=None,
				committed=True,
				errorCode=None,
			)

		runtime._capture = cast(CaptureService, SimpleNamespace(capture=capture))

		result = runtime.execute(CommandId.NAVIGATOR_SUBTREE_UNLIMITED)

		self.assertEqual("completed", result.outcome)
		self.assertEqual(1, len(requests))
		self.assertEqual(CaptureTargetKind.NAVIGATOR, requests[0].targetKind)
		self.assertTrue(requests[0].includeRootNameInOutput)
		self.assertIsNone(runtime._router._session)

	def test_snapshot_open_rejection_preserves_the_live_source_and_local_retry_installs_offline(self) -> None:
		reader = cast(SimpleNamespace, _target("reader", 42, 410))
		window = cast(SimpleNamespace, _target("reader", 42, 411))
		reader.name = "Reader target"
		window.name = "Reader window"
		runtime = self._runtime(
			_SelectedSource({"focus": [reader, reader], "foreground": [window, window]}),
		)
		live = runtime._buildLiveInspectorSource("focus")
		assert live is not None
		runtime._openInspectorSource(live)
		priorIdentity = runtime._inspectorService.sourceIdentity()

		with TemporaryDirectory() as temporary:
			directory = Path(temporary)
			for name, payload in snapshotBundle.prepareBundle(oversizedSnapshotSource()).artifacts():
				_ = (directory / name).write_bytes(payload)

			with self.assertRaises(snapshotBundle.BundleAdmissionLimitExceeded):
				runtime.openSnapshotBundle(directory)
			self.assertEqual(priorIdentity, runtime._inspectorService.sourceIdentity())
			self.assertIs(runtime._liveInspectorSource, live)
			self.assertEqual(0, runtime._bundles.currentGeneration)

			runtime.openSnapshotBundle(directory, snapshotBundle.LOCAL_SELECTED_BUNDLE_LIMITS)

		identity = runtime._inspectorService.sourceIdentity()
		assert identity is not None
		self.assertIs(identity.kind, InspectorSourceKind.OFFLINE)
		self.assertIsNone(runtime._liveInspectorSource)
		self.assertEqual(1, runtime._bundles.currentGeneration)
		self.assertEqual(snapshotBundle.DEFAULT_BUNDLE_LIMITS, runtime._bundles.defaultLimits)

	def test_an_open_inspector_reads_later_nodes_under_a_newly_applied_policy(self) -> None:
		reader = cast(SimpleNamespace, _target("reader", 42, 410))
		window = cast(SimpleNamespace, _target("reader", 42, 411))
		reader.name = "Protected value"
		reader.isProtected = True
		window.name = "Reader window"
		source = _SelectedSource({"focus": [reader, reader], "foreground": [window, window]})
		runtime = self._runtime(source)
		live = runtime._buildLiveInspectorSource("focus")
		assert live is not None
		runtime._liveInspectorSource = live
		target = live.roots()[-1].nodeId

		visible = live.properties(target, PropertyCategory.CORE)
		self.assertIn("Protected value", [row.value for row in visible.rows])

		runtime.applySettings(
			replace(SettingsSnapshot.defaults(settingsRevision=2), redactProtectedText=True),
			PrivacyPolicy(2, 2, True),
		)
		redacted = live.properties(target, PropertyCategory.CORE)

		self.assertNotIn("Protected value", [row.value for row in redacted.rows])
		self.assertIn("redacted", [row.status.value for row in redacted.rows])
		# The rows read before the change keep the values that were actually produced for them.
		self.assertIn("Protected value", [row.value for row in visible.rows])

		runtime.applySettings(
			replace(SettingsSnapshot.defaults(settingsRevision=3), redactProtectedText=False),
			PrivacyPolicy(3, 3, False),
		)
		visibleAgain = live.properties(target, PropertyCategory.CORE)

		self.assertIn("Protected value", [row.value for row in visibleAgain.rows])
		live.close()

	def test_focus_inspector_prefers_the_navigator_when_it_explicitly_has_focus(self) -> None:
		focus = cast(SimpleNamespace, _target("reader", 42, 410))
		focus.hasFocus = False
		navigator = cast(SimpleNamespace, _target("reader", 42, 410))
		navigator.hasFocus = True
		window = _target("reader", 42, 411)
		source = _SelectedSource(
			{"focus": [focus], "navigator": [navigator], "foreground": [window]},
		)
		runtime = self._runtime(source)

		selection = runtime._inspectorSelection("focus")

		self.assertIs(navigator, selection.target)

	def test_navigator_subtree_retargets_a_top_level_window_to_the_foreground_root(self) -> None:
		navigator = cast(SimpleNamespace, _target("reader", 42, 410))
		navigator.role = "window"
		foreground = cast(SimpleNamespace, _target("reader", 42, 410))
		foreground.role = "pane"
		runtime = self._runtime(
			_SelectedSource({"navigator": [navigator], "foreground": [foreground]}),
		)

		selected = runtime._selected("navigator", retargetNavigatorWindow=True)

		self.assertIs(foreground, selected.session._objects[selected.reference.rootRef])
		self.assertEqual("reader.exe", selected.request.executable)
		self.assertEqual(42, selected.request.processId)
		runtime._closeSession(selected)

	def test_navigator_subtree_preserves_a_nonwindow_navigator_target(self) -> None:
		navigator = cast(SimpleNamespace, _target("reader", 42, 410))
		foreground = cast(SimpleNamespace, _target("reader", 42, 410))
		runtime = self._runtime(
			_SelectedSource({"navigator": [navigator], "foreground": [foreground]}),
		)

		selected = runtime._selected("navigator", retargetNavigatorWindow=True)

		self.assertIs(navigator, selected.session._objects[selected.reference.rootRef])
		runtime._closeSession(selected)

	def test_navigator_inspector_uses_parent_context_and_selects_the_navigator(self) -> None:
		navigator = cast(SimpleNamespace, _target("reader", 42, 410))
		navigator.name = "Navigator target"
		parent = cast(SimpleNamespace, _target("reader", 42, 412))
		parent.name = "Navigator parent"
		foreground = cast(SimpleNamespace, _target("reader", 42, 411))
		foreground.name = "Foreground"
		navigator.simpleParent = parent
		parent.simpleParent = foreground
		foreground.simpleParent = None
		foreground.children = (parent,)
		foreground.childCount = 1
		parent.children = (navigator,)
		parent.childCount = 1
		source = _SelectedSource({"navigator": [navigator], "foreground": [foreground]})
		runtime = self._runtime(source)

		live = runtime._buildLiveInspectorSource("navigator")

		assert live is not None
		roots = live.roots()
		self.assertEqual(
			["Foreground", "Navigator parent", "Navigator target"],
			[facet.name for facet in roots],
		)
		self.assertEqual(
			["Navigator parent"],
			[facet.name for facet in live.children(roots[0].nodeId).children],
		)
		live.close()

	def test_focus_inspector_uses_cached_ancestry_for_foreground_spine_and_lazy_branches(self) -> None:
		foreground = cast(SimpleNamespace, _target("reader", 42, 411))
		skipped = cast(SimpleNamespace, _target("reader", 42, 412))
		ancestor = cast(SimpleNamespace, _target("reader", 42, 413))
		target = cast(SimpleNamespace, _target("reader", 42, 414))
		sibling = cast(SimpleNamespace, _target("reader", 42, 415))
		foreground.name = "Foreground"
		ancestor.name = "Ancestor"
		target.name = "Focused target"
		target.states = ()
		sibling.name = "Sibling"
		foreground.children = (ancestor, sibling)
		foreground.childCount = 2
		ancestor.children = (target,)
		ancestor.childCount = 1
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		runtime = self._runtime(source)
		api = SimpleNamespace(getFocusAncestors=lambda: [foreground, skipped, ancestor])

		with patch.object(commandsModule, "import_module", return_value=api):
			live = runtime._buildLiveInspectorSource("focus")

		assert live is not None
		roots = live.roots()
		self.assertEqual(["Foreground", "Ancestor", "Focused target"], [facet.name for facet in roots])
		children = live.children(roots[0].nodeId)
		self.assertEqual(["Ancestor", "Sibling"], [facet.name for facet in children.children])
		core = live.properties(roots[-1].nodeId, PropertyCategory.CORE)
		self.assertIn("Focused target", [row.value for row in core.rows])
		states = next(row for row in core.rows if row.fieldKey == "states")
		self.assertIs(PropertyStatus.EMPTY, states.status)
		self.assertIsNone(states.value)
		other = live.properties(roots[-1].nodeId, PropertyCategory.OTHER_API)
		self.assertTrue(any(row.fieldKey.startswith("generic.") for row in other.rows))
		allProperties = live.properties(roots[-1].nodeId, PropertyCategory.ALL_PROPERTIES)
		providers = next(node for node in allProperties.structured if node.key == "providers")
		self.assertIn("providers.generic", {node.key for node in providers.children})
		live.close()

	def test_focus_inspector_keeps_exact_target_when_popup_ancestry_is_disconnected(self) -> None:
		foreground = cast(SimpleNamespace, _target("notepad", 42, 411))
		ancestor = cast(SimpleNamespace, _target("notepad", 42, 412))
		popup = cast(SimpleNamespace, _target("notepad", 42, 413))
		target = cast(SimpleNamespace, _target("notepad", 42, 414))
		foreground.name = "Notepad"
		ancestor.name = "Document"
		popup.name = "File menu"
		target.name = "Open"
		foreground.children = (ancestor,)
		foreground.childCount = 1
		ancestor.children = ()
		ancestor.childCount = 0
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		runtime = self._runtime(source)
		api = SimpleNamespace(getFocusAncestors=lambda: [foreground, ancestor, popup])

		with patch.object(commandsModule, "import_module", return_value=api):
			live = runtime._buildLiveInspectorSource("focus")

		assert live is not None
		roots = live.roots()
		self.assertEqual(["Notepad", "Document", "Open"], [facet.name for facet in roots])
		self.assertEqual("Open", roots[-1].name)
		live.close()

	def test_opening_disconnected_focus_spine_keeps_target_visible_and_selected(self) -> None:
		foreground = cast(SimpleNamespace, _target("notepad", 42, 411))
		ancestor = cast(SimpleNamespace, _target("notepad", 42, 412))
		popup = cast(SimpleNamespace, _target("notepad", 42, 413))
		target = cast(SimpleNamespace, _target("notepad", 42, 414))
		foreground.name = "Notepad"
		ancestor.name = "Document"
		popup.name = "File menu"
		target.name = "Open"
		foreground.children = (ancestor,)
		foreground.childCount = 1
		ancestor.children = ()
		ancestor.childCount = 0
		runtime = self._runtime(
			_SelectedSource({"focus": [target], "foreground": [foreground]}),
		)

		with patch.object(
			commandsModule,
			"import_module",
			return_value=SimpleNamespace(getFocusAncestors=lambda: [foreground, ancestor, popup]),
		):
			live = runtime._buildLiveInspectorSource("focus")

		assert live is not None
		targetId = live.roots()[-1].nodeId
		runtime._openInspectorSource(live)
		rows = runtime._inspectorService.hierarchy()

		self.assertEqual(["Notepad", "Document", "Open"], [row.node.facet.name for row in rows])
		self.assertEqual(targetId, runtime._inspectorService.targetNodeId)
		self.assertEqual(targetId, runtime._inspectorService.selectedNodeId)
		self.assertTrue(rows[-1].selected)

	def test_event_monitor_command_selects_live_focus_before_opening_events(self) -> None:
		target = cast(SimpleNamespace, _target("notepad", 42, 410))
		foreground = cast(SimpleNamespace, _target("notepad", 42, 411))
		target.name = "Document"
		foreground.name = "Notepad"
		opened: list[bool] = []
		runtime = self._runtime(
			_SelectedSource({"focus": [target], "foreground": [foreground]}),
		)
		runtime._openEventMonitor = lambda: opened.append(True)

		result = runtime.execute(CommandId.EVENT_MONITOR)

		self.assertEqual("completed", result.outcome)
		self.assertEqual([True], opened)
		self.assertIs(target, runtime.currentInspectorSelection())

	def test_event_monitor_toggle_prepares_focus_only_before_starting(self) -> None:
		target = _target("notepad", 42, 410)
		runtime = self._runtime(
			_SelectedSource({"focus": [target], "foreground": [target]}),
		)
		prepared: list[bool] = []
		toggles: list[bool] = []
		active = [False]
		runtime._prepareFocusSelectionForEventMonitor = lambda: prepared.append(True) or True
		runtime._eventMonitorActive = lambda: active[0]
		runtime._toggleEventMonitor = lambda: toggles.append(True) or not active[0]

		self.assertEqual("eventMonitorStarted", runtime.execute(CommandId.EVENT_MONITOR_TOGGLE).outcome)
		active[0] = True
		self.assertEqual("eventMonitorStopped", runtime.execute(CommandId.EVENT_MONITOR_TOGGLE).outcome)

		self.assertEqual([True], prepared)
		self.assertEqual([True, True], toggles)

	def test_opening_disconnected_navigator_spine_keeps_target_visible_and_selected(self) -> None:
		foreground = cast(SimpleNamespace, _target("notepad", 42, 411))
		parent = cast(SimpleNamespace, _target("notepad", 42, 412))
		target = cast(SimpleNamespace, _target("notepad", 42, 414))
		foreground.name = "Foreground"
		parent.name = "Navigator parent"
		target.name = "Navigator target"
		foreground.children = ()
		foreground.childCount = 0
		target.simpleParent = parent
		parent.simpleParent = foreground
		foreground.simpleParent = None
		runtime = self._runtime(
			_SelectedSource({"navigator": [target], "foreground": [foreground]}),
		)

		live = runtime._buildLiveInspectorSource("navigator")

		assert live is not None
		targetId = live.roots()[-1].nodeId
		runtime._openInspectorSource(live)
		rows = runtime._inspectorService.hierarchy()

		self.assertEqual(["Foreground", "Navigator target"], [row.node.facet.name for row in rows])
		self.assertEqual(targetId, runtime._inspectorService.targetNodeId)
		self.assertEqual(targetId, runtime._inspectorService.selectedNodeId)
		self.assertTrue(rows[-1].selected)

	def test_live_hierarchy_exposes_a_logical_first_child_when_ordinary_children_are_empty(self) -> None:
		target = cast(SimpleNamespace, _target("slides", 42, 410))
		logical = cast(SimpleNamespace, _target("slides", 42, 412))
		foreground = cast(SimpleNamespace, _target("slides", 42, 411))
		target.name = "Slide"
		target.location = SimpleNamespace(left=10, top=10, width=100, height=100)
		target.children = ()
		target.childCount = 0
		target.firstChild = logical
		logical.name = "Title shape"
		logical.location = SimpleNamespace(left=20, top=20, width=50, height=20)
		foreground.name = "Foreground"
		foreground.location = SimpleNamespace(left=0, top=0, width=500, height=500)
		foreground.children = (target,)
		foreground.childCount = 1
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		runtime = self._runtime(source)

		with patch.object(
			commandsModule,
			"import_module",
			return_value=SimpleNamespace(getFocusAncestors=lambda: [foreground]),
		):
			live = runtime._buildLiveInspectorSource("focus")

		assert live is not None
		roots = live.roots()
		self.assertIn("Slide", [root.name for root in roots])
		selected = next(root for root in roots if root.name == "Slide")
		self.assertTrue(selected.childHint)
		children = live.children(selected.nodeId)
		self.assertEqual(["Title shape"], [child.name for child in children.children])
		live.close()

	def test_opening_a_live_source_hydrates_the_captured_ancestry(self) -> None:
		source = _SelectedSource(
			{"focus": [_target("reader", 42, 410)], "foreground": [_target("reader", 42, 411)]},
		)
		runtime = self._runtime(source)
		service = _HydratingInspectorService()
		runtime._inspectorService = cast(InspectorService, service)
		liveSource = SimpleNamespace(
			identity=lambda: InspectorSourceIdentity(
				InspectorSourceKind.LIVE,
				"Reader",
				"reader.exe",
				42,
				"IA2",
			),
		)

		runtime._openInspectorSource(cast(LiveInspectorSource, liveSource))

		self.assertEqual(["root"], service.expanded)

	def test_retarget_closes_the_replaced_live_session(self) -> None:
		first = _target("reader", 42, 410)
		second = _target("reader", 42, 420)
		window = _target("reader", 42, 411)
		source = _SelectedSource(
			{"focus": [first, second], "foreground": [window, window]},
		)
		runtime = self._runtime(source)
		firstSource = runtime._buildLiveInspectorSource("focus")
		assert firstSource is not None
		firstReader = cast(LiveSessionNodeReader, firstSource._reader)
		assert firstReader is not None

		runtime._openInspectorSource(firstSource)
		secondSource = runtime._buildLiveInspectorSource("focus")
		assert secondSource is not None
		runtime._openInspectorSource(secondSource)

		self.assertTrue(firstReader._closed)
		self.assertTrue(firstReader._session._closed)
		self.assertIsNone(runtime._router._session)

	def test_inspect_does_not_depend_on_capture_commit(self) -> None:
		reader = _target("reader", 42, 410)
		source = _SelectedSource(
			{"focus": [reader, reader, reader], "foreground": [reader, reader, reader]},
		)
		announce: list[str] = []
		sound = _RecordingSounds()
		runtime = self._runtime(source, announce=announce, sound=sound)
		runtime._capture = cast(
			CaptureService,
			_InspectionCapture(_capturedResult(committed=False, snapshot=None)),
		)

		live = runtime._buildLiveInspectorSource("focus")
		assert live is not None
		live.close()
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([]))
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		self.assertTrue(runtime._openLiveInspector("focus"))
		self.assertEqual([], announce)
		self.assertEqual([CueEventId.OPEN_FOCUS_INSPECTOR, CueEventId.INSPECTOR_READY], sound.events())
		self.assertEqual([], cast(_InspectionCapture, runtime._capture).requests)

	def test_inspect_commands_report_completed_after_opening_a_live_source(self) -> None:
		for commandId in (
			CommandId.INSPECT_FOCUS,
			CommandId.INSPECT_NAVIGATOR,
		):
			with self.subTest(commandId=commandId):
				target = _target("reader", 42, 410)
				runtime = self._runtime(
					_SelectedSource(
						{
							"focus": [target],
							"navigator": [target],
							"foreground": [target],
						},
					),
				)
				shows: list[int] = []
				runtime._inspector = cast(InspectorWorkspace, _ShowSpy(shows))
				runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

				result = runtime.execute(commandId)

				self.assertEqual("completed", result.outcome)
				self.assertFalse(result.announcementHandled)
				self.assertEqual([1], shows)

	def test_inspect_focus_reports_failed_when_building_the_live_source_fails(self) -> None:
		target = _target("reader", 42, 410)
		announcements: list[str] = []
		runtime = self._runtime(
			_SelectedSource(
				{
					"focus": [target],
					"navigator": [target],
					"foreground": [target],
				},
			),
			announce=announcements,
		)

		with patch.object(
			runtime,
			"_buildLiveInspectorSource",
			side_effect=RuntimeError("source build failed"),
		):
			result = runtime.execute(CommandId.INSPECT_FOCUS)

		self.assertEqual("failed", result.outcome)
		self.assertTrue(result.announcementHandled)
		self.assertEqual(["Inspector could not read the selected object."], announcements)

	def test_failing_inspector_announcement_preserves_source_failure_feedback(self) -> None:
		target = _target("reader", 42, 410)
		sound = _RecordingSounds()
		runtime = self._runtime(
			_SelectedSource({"focus": [target], "foreground": [target]}),
			sound=sound,
		)

		def failingAnnouncement(_message: str) -> None:
			raise RuntimeError("announcement failed")

		runtime._announceInspector = failingAnnouncement
		for operation in (
			lambda: runtime._openLiveInspector("focus"),
			runtime._prepareFocusSelectionForEventMonitor,
		):
			for sourceFailure in (None, RuntimeError("source build failed")):
				with self.subTest(operation=operation, sourceFailure=sourceFailure):
					failurePatch = (
						patch.object(runtime, "_buildLiveInspectorSource", return_value=None)
						if sourceFailure is None
						else patch.object(
							runtime,
							"_buildLiveInspectorSource",
							side_effect=sourceFailure,
						)
					)
					with failurePatch:
						self.assertFalse(operation())

		self.assertEqual([CueEventId.INSPECTOR_FAILURE] * 4, sound.events())

	def test_open_sounds_the_focus_open_cue_after_showing_owned_by_the_source_generation(self) -> None:
		reader = _target("reader", 42, 410)
		source = _SelectedSource({"focus": [reader, reader], "foreground": [reader, reader]})
		sound = _RecordingSounds()
		runtime = self._runtime(source, sound=sound)
		runtime._capture = cast(
			CaptureService,
			_InspectionCapture(_capturedResult(committed=True, snapshot=_liveSnapshotStub())),
		)
		shows: list[int] = []
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy(shows))
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		self.assertTrue(runtime._openLiveInspector("focus"))

		# The open cue sounds after the frame is raised, then the ready cue follows it. Both are owned
		# by the just-bumped source generation, so the ready cue (P1) supersedes the open sequence (P2)
		# from the same source rather than sounding a second, competing voice.
		self.assertEqual([1], shows)
		self.assertEqual(
			[CueEventId.OPEN_FOCUS_INSPECTOR, CueEventId.INSPECTOR_READY],
			sound.events(),
		)
		opened = sound.requests[0]
		self.assertIs(SoundOwnerKind.INSPECTOR, opened.owner.kind)
		self.assertEqual(runtime._inspectorService.sourceGeneration, opened.owner.generation)
		ready = sound.requests[1]
		self.assertIs(SoundOwnerKind.INSPECTOR, ready.owner.kind)
		self.assertEqual(runtime._inspectorService.sourceGeneration, ready.owner.generation)

	def test_reopening_while_the_inspector_owns_focus_retains_the_existing_source(self) -> None:
		reader = _target("reader", 42, 410)
		window = _target("reader", 42, 411)
		inspector = _target("nvda", 77, 900)
		source = _SelectedSource(
			{"focus": [reader, inspector], "foreground": [window, inspector]},
		)
		runtime = self._runtime(source)
		capture = _InspectionCapture(_capturedResult(committed=True, snapshot=_liveSnapshotStub()))
		runtime._capture = cast(CaptureService, capture)
		shows: list[int] = []
		runtime._inspector = cast(
			InspectorWorkspace,
			_ShowSpy(shows, ownedWindowHandle=900),
		)
		service = _GenerationInspectorService()
		runtime._inspectorService = cast(InspectorService, service)

		self.assertTrue(runtime._openLiveInspector("focus"))
		self.assertTrue(runtime._openLiveInspector("focus"))

		self.assertEqual(0, len(capture.requests))
		self.assertEqual([1, 1], shows)
		self.assertEqual(1, service.sourceGeneration)

	def test_open_sounds_the_navigator_open_cue_for_a_navigator_target(self) -> None:
		navigator = _target("notepad", 41, 411)
		source = _SelectedSource(
			{"navigator": [navigator, navigator], "foreground": [navigator, navigator]},
		)
		sound = _RecordingSounds()
		runtime = self._runtime(source, sound=sound)
		runtime._capture = cast(
			CaptureService,
			_InspectionCapture(_capturedResult(committed=True, snapshot=_liveSnapshotStub())),
		)
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([]))
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		self.assertTrue(runtime._openLiveInspector("navigator"))

		self.assertEqual(
			[CueEventId.OPEN_NAVIGATOR_INSPECTOR, CueEventId.INSPECTOR_READY],
			sound.events(),
		)

	def test_retarget_does_not_sound_the_ready_cue(self) -> None:
		# The ready cue marks a genuine open. Retargeting an already-open inspector swaps the source
		# silently (no open cue, so no ready cue) - the workspace re-renders without re-announcing.
		reader = _target("reader", 42, 410)
		source = _SelectedSource({"focus": [reader, reader], "foreground": [reader, reader]})
		sound = _RecordingSounds()
		runtime = self._runtime(source, sound=sound)
		runtime._capture = cast(
			CaptureService,
			_InspectionCapture(_capturedResult(committed=True, snapshot=_liveSnapshotStub())),
		)
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		_ = runtime._retargetInspector("focus", False)

		self.assertEqual([], sound.events())

	def test_explicit_raw_retarget_reports_fallback_instead_of_discarding_the_request(self) -> None:
		reader = _target("reader", 42, 410)
		window = _target("reader", 42, 411)
		source = _SelectedSource(
			{"focus": [reader], "navigator": [reader], "foreground": [window]},
		)
		diagnostic: list[str] = []
		runtime = self._runtime(source, diagnostic=diagnostic)
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([]))
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		outcome = runtime._retargetInspector("focus", True)

		self.assertTrue(outcome.succeeded)
		self.assertTrue(outcome.rawRequested)
		self.assertFalse(outcome.rawApplied)
		self.assertIsNotNone(outcome.rawReason)
		assert outcome.rawReason is not None
		self.assertTrue(outcome.rawReason.startswith("KS.RAW_UIA."))
		self.assertTrue(
			any("raw.request" in message and "requested=true" in message for message in diagnostic),
		)
		self.assertTrue(
			any(
				"raw.candidate" in message and "order=1" in message and "source=retainedElement" in message
				for message in diagnostic
			),
		)
		self.assertTrue(
			any(
				"raw.final" in message and "applied=false" in message and "status=rejected" in message
				for message in diagnostic
			),
		)

	def test_observed_external_focus_is_retained_and_queued_for_follow_focus(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		events: list[FollowFocusEvent] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspector = cast(InspectorWorkspace, _FollowSpy(events))
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=True),
		)

		runtime.observeFocus(target)

		# observeFocus only signals - nothing is retained until the scheduled settle runs and
		# reads focus fresh.
		self.assertIsNone(runtime._lastExternalFocusSelection)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		selection = runtime._lastExternalFocusSelection
		assert selection is not None
		self.assertIs(target, selection.target)
		# The settle in turn scheduled the (also asynchronous) Follow Focus dispatch.
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()
		self.assertEqual(["browser.exe\x1f51"], [event.applicationKey for event in events])

	def test_idle_workspace_does_not_observe_external_focus(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		diagnostics: list[str] = []
		runtime = self._runtime(
			source,
			diagnostic=diagnostics,
			schedule=scheduled,
			workspaceOpen=False,
		)

		runtime.observeFocus(target)

		self.assertEqual([], scheduled)
		self.assertEqual([], diagnostics)
		self.assertEqual([target], source._selections["focus"])
		self.assertEqual([foreground], source._selections["foreground"])
		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_closing_workspace_discards_a_queued_focus_settle(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		diagnostics: list[str] = []
		runtime = self._runtime(source, diagnostic=diagnostics, schedule=scheduled)

		runtime.observeFocus(target)
		self.assertEqual(1, len(scheduled))
		diagnosticsBeforeClose = list(diagnostics)
		cast(_ShowSpy, runtime._inspector).window.isOpen = False
		scheduled.pop(0)()

		self.assertEqual(diagnosticsBeforeClose, diagnostics)
		self.assertEqual([target], source._selections["focus"])
		self.assertEqual([foreground], source._selections["foreground"])
		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_follow_focus_preserves_the_active_raw_uia_request(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		runtime = self._runtime(source)
		runtime._pendingFollowSelection = runtime._inspectorSelection("focus")
		runtime._lastInspectorRawRequested = True

		self.assertTrue(runtime._followInspector(FollowFocusEvent("browser.exe\x1f51")))
		self.assertTrue(runtime._lastInspectorRawRequested)

	def test_follow_focus_reuses_the_live_session_inside_the_same_foreground(self) -> None:
		first = _target("browser", 51, 510)
		second = _target("browser", 51, 520)
		foreground = cast(SimpleNamespace, _target("browser", 51, 500))
		foreground.children = (first, second)
		foreground.childCount = 2
		runtime = self._runtime(
			_SelectedSource({"focus": [first], "foreground": [foreground]}),
		)
		firstSelection = commandsModule._InspectorSelection(first, foreground, (foreground,))
		live = runtime._buildLiveInspectorSource("focus", selection=firstSelection)
		assert live is not None
		runtime._openInspectorSource(live)
		reader = cast(LiveSessionNodeReader, live._reader)
		generation = runtime._inspectorService.sourceGeneration
		runtime._pendingFollowSelection = commandsModule._InspectorSelection(
			second,
			foreground,
			(foreground,),
		)

		self.assertTrue(runtime._followInspector(FollowFocusEvent("browser.exe\x1f51")))

		self.assertIs(live, runtime._liveInspectorSource)
		self.assertEqual(generation, runtime._inspectorService.sourceGeneration)
		self.assertFalse(reader._closed)
		self.assertEqual(reader._targetRef, runtime._inspectorService.selectedNodeId)

	def test_follow_focus_is_not_dispatched_when_disabled(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		events: list[FollowFocusEvent] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspector = cast(InspectorWorkspace, _FollowSpy(events))
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(target)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		selection = runtime._lastExternalFocusSelection
		assert selection is not None
		self.assertIs(target, selection.target)
		# Follow Focus is disabled, so the settle retains the selection but never schedules or
		# dispatches a follow.
		self.assertEqual([], scheduled)
		self.assertEqual([], events)

	def test_settle_reads_fresh_focus_instead_of_the_signaled_object(self) -> None:
		# Explorer/Chromium routinely emit a valid-looking transitional or structural object as
		# the raw gainFocus event just before (or after) the object the user actually landed on.
		# The settle must never trust that raw signal object - it must re-read focus fresh.
		signal = _target("browser", 51, 510)
		settledFocus = _target("browser", 51, 520)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [settledFocus], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(signal)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		selection = runtime._lastExternalFocusSelection
		assert selection is not None
		self.assertIs(settledFocus, selection.target)
		self.assertIsNot(signal, selection.target)

	def test_burst_of_focus_signals_coalesces_to_only_the_newest_scheduled_settle(self) -> None:
		first = _target("browser", 51, 510)
		second = _target("browser", 51, 511)
		third = _target("browser", 51, 512)
		settledFocus = _target("browser", 51, 520)
		foreground = _target("browser", 51, 521)
		source = _SelectedSource({"focus": [settledFocus], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(first)
		runtime.observeFocus(second)
		runtime.observeFocus(third)
		self.assertEqual(3, len(scheduled))

		# The two superseded settles must be no-ops - neither reads focus nor retains anything.
		scheduled[0]()
		scheduled[1]()
		self.assertIsNone(runtime._lastExternalFocusSelection)

		# Only the newest scheduled generation may commit.
		scheduled[2]()
		selection = runtime._lastExternalFocusSelection
		assert selection is not None
		self.assertIs(settledFocus, selection.target)

	def test_inspector_owned_signal_cancels_pending_settle_but_keeps_last_external_selection(
		self,
	) -> None:
		firstExternal = _target("browser", 51, 510)
		secondExternal = _target("browser", 51, 511)
		foreground = _target("browser", 51, 512)
		inspectorTarget = _target("nvda", 77, 900)
		source = _SelectedSource({"focus": [firstExternal], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([], ownedWindowHandle=900))
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(firstExternal)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()
		firstSelection = runtime._lastExternalFocusSelection
		assert firstSelection is not None
		self.assertIs(firstExternal, firstSelection.target)

		# A second external signal arrives and is scheduled, but never gets to run before the
		# Inspector itself takes focus back.
		runtime.observeFocus(secondExternal)
		self.assertEqual(1, len(scheduled))
		pendingSettle = scheduled.pop(0)

		runtime.observeFocus(inspectorTarget)

		# The now-superseded settle must reject rather than commit, and the last stable
		# external selection must survive untouched - not cleared, not overwritten.
		pendingSettle()
		self.assertIs(firstSelection, runtime._lastExternalFocusSelection)

	def test_focus_signal_is_ignored_while_alt_is_physically_held(self) -> None:
		target = _target("browser", 51, 510)
		source = _SelectedSource({"focus": [target], "foreground": [target]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		with patch.object(commandsModule, "_altPhysicallyHeld", return_value=True):
			runtime.observeFocus(target)

		self.assertEqual([], scheduled)
		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_settle_rejects_when_alt_becomes_held_before_the_settle_runs(self) -> None:
		target = _target("browser", 51, 510)
		foreground = _target("browser", 51, 511)
		source = _SelectedSource({"focus": [target], "foreground": [foreground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(target)
		self.assertEqual(1, len(scheduled))
		settle = scheduled.pop(0)

		with patch.object(commandsModule, "_altPhysicallyHeld", return_value=True):
			settle()

		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_both_shell_overlay_window_classes_are_ignored_as_focus_signals(self) -> None:
		for windowClass in ("MultitaskingViewFrame", "XamlExplorerHostIslandWindow"):
			with self.subTest(windowClass=windowClass):
				overlay = cast(SimpleNamespace, _target("explorer", 51, 510))
				overlay.windowClassName = windowClass
				source = _SelectedSource({"focus": [overlay], "foreground": [overlay]})
				scheduled: list[Callable[[], None]] = []
				runtime = self._runtime(source, schedule=scheduled)
				runtime._inspectorService = cast(
					InspectorService,
					SimpleNamespace(followFocusEnabled=False),
				)

				runtime.observeFocus(overlay)

				self.assertEqual([], scheduled)
				self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_focus_signal_with_task_switch_accessible_name_is_ignored(self) -> None:
		overlay = cast(SimpleNamespace, _target("explorer", 51, 510))
		overlay.name = "Task Switching..."
		source = _SelectedSource({"focus": [overlay], "foreground": [overlay]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(overlay)

		self.assertEqual([], scheduled)
		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_settle_rejects_an_ignorable_settled_foreground_independently_of_focus(self) -> None:
		focus = _target("browser", 51, 510)
		overlayForeground = cast(SimpleNamespace, _target("explorer", 51, 511))
		overlayForeground.windowClassName = "MultitaskingViewFrame"
		source = _SelectedSource({"focus": [focus], "foreground": [overlayForeground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		runtime.observeFocus(focus)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		# The focus object itself was fine, but the independently-fetched foreground was not -
		# the whole settle rejects rather than committing a half-good selection.
		self.assertIsNone(runtime._lastExternalFocusSelection)

	def test_settle_derives_external_root_from_ancestry_when_foreground_is_inspector_owned(
		self,
	) -> None:
		focus = _target("browser", 51, 510)
		inspectorForeground = _target("nvda", 77, 900)
		ancestorWindow = cast(SimpleNamespace, _target("browser", 51, 511))
		ancestorWindow.name = "Browser window"
		source = _SelectedSource({"focus": [focus], "foreground": [inspectorForeground]})
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([], ownedWindowHandle=900))
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)
		api = SimpleNamespace(getFocusAncestors=lambda: [ancestorWindow])

		runtime.observeFocus(focus)
		self.assertEqual(1, len(scheduled))
		settle = scheduled.pop(0)
		with patch.object(commandsModule, "import_module", return_value=api):
			settle()

		selection = runtime._lastExternalFocusSelection
		assert selection is not None
		self.assertIs(ancestorWindow, selection.foreground)

	def test_focus_settle_does_not_overwrite_navigator_or_foreground_target_caches(self) -> None:
		navigatorTarget = _target("reader", 42, 410)
		navigatorForeground = _target("reader", 42, 411)
		focusTarget = _target("browser", 51, 510)
		focusForeground = _target("browser", 51, 511)
		source = _SelectedSource(
			{
				"navigator": [navigatorTarget],
				"foreground": [navigatorForeground, focusForeground],
				"focus": [focusTarget],
			},
		)
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, schedule=scheduled)
		runtime._inspectorService = cast(
			InspectorService,
			SimpleNamespace(followFocusEnabled=False),
		)

		navigatorSelection = runtime._inspectorSelection("navigator")
		self.assertIs(navigatorTarget, runtime._inspectorSelections["navigator"].target)

		runtime.observeFocus(focusTarget)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		self.assertIs(navigatorSelection, runtime._inspectorSelections["navigator"])
		self.assertIs(navigatorTarget, runtime._inspectorSelections["navigator"].target)
		focusSelection = runtime._inspectorSelections["focus"]
		self.assertIs(focusTarget, focusSelection.target)

	def test_retarget_focus_uses_the_last_external_focus_after_returning_to_inspector(self) -> None:
		external = cast(SimpleNamespace, _target("browser", 51, 510))
		external.name = "Web link"
		externalWindow = cast(SimpleNamespace, _target("browser", 51, 511))
		externalWindow.name = "Browser window"
		inspector = _target("nvda", 77, 900)
		source = _SelectedSource(
			{
				"focus": [external, inspector],
				"navigator": [inspector],
				"foreground": [externalWindow, inspector],
			},
		)
		diagnostics: list[str] = []
		scheduled: list[Callable[[], None]] = []
		runtime = self._runtime(source, diagnostic=diagnostics, schedule=scheduled)
		runtime._inspector = cast(
			InspectorWorkspace,
			_ShowSpy([], ownedWindowHandle=900),
		)
		service = _RootRecordingInspectorService()
		runtime._inspectorService = cast(InspectorService, service)

		runtime.observeFocus(external)
		self.assertEqual(1, len(scheduled))
		scheduled.pop(0)()

		# Focus returns to the Inspector itself (e.g. tabbing between its own controls) before the
		# user asks to retarget explicitly.
		runtime.observeFocus(inspector)

		outcome = runtime._retargetInspector("focus", False)

		self.assertTrue(outcome.succeeded)
		self.assertEqual(["Browser window", "Web link"], service.rootNames)
		self.assertTrue(any("retarget.completed" in line for line in diagnostics))
		self.assertNotIn("Web link", "\n".join(diagnostics))

	def test_first_navigator_retarget_from_inspector_reuses_the_external_focus_selection(self) -> None:
		external = _target("browser", 51, 510)
		externalWindow = _target("browser", 51, 511)
		inspector = _target("nvda", 77, 900)
		source = _SelectedSource(
			{
				"focus": [external],
				"navigator": [external, inspector],
				"foreground": [externalWindow, inspector],
			},
		)
		runtime = self._runtime(source)
		runtime._inspector = cast(
			InspectorWorkspace,
			_ShowSpy([], ownedWindowHandle=900),
		)

		focusSelection = runtime._inspectorSelection("focus")
		navigatorSelection = runtime._inspectorSelection("navigator")

		self.assertIs(focusSelection.target, navigatorSelection.target)
		self.assertIs(focusSelection.foreground, navigatorSelection.foreground)

	def test_a_failing_sound_sink_leaves_the_live_open_intact(self) -> None:
		reader = _target("reader", 42, 410)
		source = _SelectedSource(
			{"focus": [reader, reader, reader], "foreground": [reader, reader, reader]},
		)
		announce: list[str] = []
		runtime = self._runtime(source, announce=announce, sound=_FailingSounds())
		runtime._capture = cast(
			CaptureService,
			_InspectionCapture(_capturedResult(committed=False, snapshot=None)),
		)

		runtime._inspector = cast(InspectorWorkspace, _ShowSpy([]))
		runtime._inspectorService = cast(InspectorService, _GenerationInspectorService())

		self.assertTrue(runtime._openLiveInspector("focus"))
		self.assertEqual([], announce)


if __name__ == "__main__":
	_ = unittest.main()
