from __future__ import annotations

import ctypes
import sys
import unittest

from addon.globalPlugins.keystone.capability import requirePlainValue


class PlainValueValidationTests(unittest.TestCase):
	def test_deep_tuple_is_rejected_before_python_recursion_is_exhausted(self) -> None:
		value = None
		for _ in range(65):
			value = (value,)

		with self.assertRaisesRegex(ValueError, "depth limit"):
			requirePlainValue(value)

	def test_provider_compatible_tuple_depth_remains_valid(self) -> None:
		value = None
		for _ in range(64):
			value = (value,)

		requirePlainValue(value)

	@unittest.skipUnless(sys.implementation.name == "cpython", "requires CPython tuple internals")
	def test_cyclic_tuple_is_rejected_without_recursion(self) -> None:
		value: tuple[object, ...] = (None,)
		items = (ctypes.py_object * len(value)).from_address(id(value) + tuple.__basicsize__)
		items[0] = value
		try:
			with self.assertRaisesRegex(ValueError, "cyclic tuple"):
				requirePlainValue(value)
		finally:
			items[0] = None


if __name__ == "__main__":
	_ = unittest.main()
