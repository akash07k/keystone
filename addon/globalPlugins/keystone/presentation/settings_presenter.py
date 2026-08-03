from __future__ import annotations

from dataclasses import dataclass

from ..capability import PlainValue, requireOpaqueId, requirePlainValue
from .commands import TranslationCatalog

__all__ = ("LocalizedMessage", "TranslationCatalog")


@dataclass(frozen=True, slots=True)
class LocalizedMessage:
	messageId: str
	arguments: tuple[PlainValue, ...] = ()
	preview: str | None = None

	def __post_init__(self) -> None:
		requireOpaqueId(self.messageId, "messageId")
		requirePlainValue(self.arguments, "message arguments")
		if self.preview is not None and len(self.preview) > 4_096:
			raise ValueError("localized preview exceeds its presentation bound")
