from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .status import requireNonnegativeInteger


MINIMUM_COORDINATE = -(1 << 63)
MAXIMUM_COORDINATE = (1 << 63) - 1


def _coordinate(value: object, label: str) -> int:
	if (
		not isinstance(value, int)
		or isinstance(value, bool)
		or value < MINIMUM_COORDINATE
		or value > MAXIMUM_COORDINATE
	):
		raise ValueError(f"{label} must be a signed 64-bit integer")
	return value


@dataclass(frozen=True, slots=True)
class Point:
	x: int
	y: int

	def __post_init__(self) -> None:
		_ = _coordinate(self.x, "x")
		_ = _coordinate(self.y, "y")


@dataclass(frozen=True, slots=True)
class Size:
	width: int
	height: int

	def __post_init__(self) -> None:
		_ = requireNonnegativeInteger(self.width, "width")
		_ = requireNonnegativeInteger(self.height, "height")


@dataclass(frozen=True, slots=True)
class Rectangle:
	left: int
	top: int
	width: int
	height: int
	right: int = 0
	bottom: int = 0

	def __post_init__(self) -> None:
		left = _coordinate(self.left, "left")
		top = _coordinate(self.top, "top")
		width = requireNonnegativeInteger(self.width, "width")
		height = requireNonnegativeInteger(self.height, "height")
		right = _coordinate(left + width, "right")
		bottom = _coordinate(top + height, "bottom")
		if self.right not in (0, right) or self.bottom not in (0, bottom):
			raise ValueError("right and bottom must match checked half-open arithmetic")
		object.__setattr__(self, "right", right)
		object.__setattr__(self, "bottom", bottom)

	@property
	def empty(self) -> bool:
		return self.width == 0 or self.height == 0

	def contains(self, point: Point) -> bool:
		return self.left <= point.x < self.right and self.top <= point.y < self.bottom


class GeometryState(StrEnum):
	VALID = "valid"
	EMPTY = "empty"
	INVALID = "invalid"
	OFF_DESKTOP = "offDesktop"


@dataclass(frozen=True, slots=True)
class GeometryResult:
	state: GeometryState
	rectangle: Rectangle | None = None

	def __post_init__(self) -> None:
		if self.state is GeometryState.VALID and self.rectangle is None:
			raise ValueError("valid geometry requires a rectangle")
		if self.state is not GeometryState.VALID and self.rectangle is not None:
			raise ValueError("non-value geometry must not carry a rectangle")


@dataclass(frozen=True, slots=True)
class ClipResult:
	state: GeometryState
	requested: Rectangle
	captured: Rectangle | None = None

	def __post_init__(self) -> None:
		if self.state is GeometryState.VALID and self.captured is None:
			raise ValueError("valid clipping requires a captured rectangle")
		if self.state is not GeometryState.VALID and self.captured is not None:
			raise ValueError("non-value clipping must not carry captured geometry")


def checkedRectangle(left: object, top: object, width: object, height: object) -> GeometryResult:
	try:
		rectangle = Rectangle(
			_coordinate(left, "left"),
			_coordinate(top, "top"),
			requireNonnegativeInteger(width, "width"),
			requireNonnegativeInteger(height, "height"),
		)
	except ValueError:
		return GeometryResult(GeometryState.INVALID)
	if rectangle.empty:
		return GeometryResult(GeometryState.EMPTY)
	return GeometryResult(GeometryState.VALID, rectangle)


def clipRectangle(requested: Rectangle, desktop: Rectangle) -> ClipResult:
	if requested.empty:
		return ClipResult(GeometryState.EMPTY, requested)
	if desktop.empty:
		raise ValueError("desktop rectangle must have positive area")
	left = max(requested.left, desktop.left)
	top = max(requested.top, desktop.top)
	right = min(requested.right, desktop.right)
	bottom = min(requested.bottom, desktop.bottom)
	if left >= right or top >= bottom:
		return ClipResult(GeometryState.OFF_DESKTOP, requested)
	return ClipResult(
		GeometryState.VALID,
		requested,
		Rectangle(left, top, right - left, bottom - top),
	)
