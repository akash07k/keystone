"""Small native accessibility helpers for wx controls."""

from __future__ import annotations


def setNativeAccessibleName(wx: object, control: object, name: str) -> None:
	"""Expose a control name through wx/MSAA while preserving native child semantics."""

	setName = getattr(control, "SetName", None)
	if callable(setName):
		_ = setName(name)

	accessibleBase = getattr(wx, "Accessible", None)
	setAccessible = getattr(control, "SetAccessible", None)
	accOk = getattr(wx, "ACC_OK", None)
	accNotImplemented = getattr(wx, "ACC_NOT_IMPLEMENTED", None)
	if (
		not isinstance(accessibleBase, type)
		or not callable(setAccessible)
		or accOk is None
		or accNotImplemented is None
	):
		return

	def getName(_accessible: object, childId: int) -> tuple[object, str]:
		if childId == 0:
			return (accOk, name)
		return (accNotImplemented, "")

	accessibleType = type(
		"_KeystoneNamedAccessible",
		(accessibleBase,),
		{"GetName": getName},
	)
	try:
		_ = setAccessible(accessibleType(control))
	except (AttributeError, RuntimeError, TypeError):
		# SetName remains the safe fallback on wx builds without usable accessibility support.
		return
