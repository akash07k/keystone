from __future__ import annotations

import json
import unittest

from addon.globalPlugins.keystone.domain.inspector import (
	MAXIMUM_PROPERTY_INTERVAL_MS,
	MINIMUM_PROPERTY_INTERVAL_MS,
	ChildState,
	InspectorSourceIdentity,
	InspectorSourceKind,
	PROPERTY_CATEGORY_ORDER,
	NodeFacet,
	PropertyCategory,
	PropertyRow,
	PropertyStatus,
	QuickPropertyAction,
	QuickPropertyRepeatState,
	SearchableNode,
	StructuredPropertyNode,
	expandAllPropertiesOneLevel,
	normalizeQuickPropertyDigit,
	propertyCategoryForShortcut,
	searchLoadedNodes,
	shortcutForPropertyCategory,
)
from addon.globalPlugins.keystone.ports.inspector import ChildFetch
from addon.globalPlugins.keystone.presentation.inspector import (
	CopyCategory,
	CopyNode,
	renderNodeJson,
	renderNodeMarkdown,
)


def _scalar(key: str, value: str) -> StructuredPropertyNode:
	return StructuredPropertyNode(key=key, label=key.capitalize(), status=PropertyStatus.VALUE, value=value)


def _container(key: str, *children: StructuredPropertyNode) -> StructuredPropertyNode:
	return StructuredPropertyNode(
		key=key,
		label=key.capitalize(),
		status=PropertyStatus.VALUE,
		children=children,
	)


class PropertyTaxonomyTests(unittest.TestCase):
	def test_eleven_categories_keep_annotations_and_diagnostics_shortcuts_distinct(self) -> None:
		self.assertEqual(len(PROPERTY_CATEGORY_ORDER), 11)
		self.assertIs(PROPERTY_CATEGORY_ORDER[0], PropertyCategory.QUICK)
		self.assertIs(propertyCategoryForShortcut(1), PropertyCategory.QUICK)
		self.assertIs(propertyCategoryForShortcut(9), PropertyCategory.ALL_PROPERTIES)
		self.assertIs(propertyCategoryForShortcut(0), PropertyCategory.ANNOTATIONS)
		self.assertIs(propertyCategoryForShortcut(0, shift=True), PropertyCategory.DIAGNOSTICS)
		for category in PROPERTY_CATEGORY_ORDER[:10]:
			digit = shortcutForPropertyCategory(category)
			self.assertIs(propertyCategoryForShortcut(digit), category)
		self.assertEqual(0, shortcutForPropertyCategory(PropertyCategory.DIAGNOSTICS, shift=True))

	def test_shortcut_rejects_out_of_range_digits(self) -> None:
		with self.assertRaises(ValueError):
			_ = propertyCategoryForShortcut(10)


class NodeFacetTests(unittest.TestCase):
	def test_named_node_requires_display_name(self) -> None:
		with self.assertRaises(ValueError):
			_ = NodeFacet(nodeId="n1", parentId=None, depth=0, name="", hasName=True, role="window")

	def test_unnamed_node_keeps_empty_name(self) -> None:
		facet = NodeFacet(nodeId="n1", parentId=None, depth=0, name="", hasName=False, role="pane")
		self.assertFalse(facet.hasName)
		self.assertEqual(facet.name, "")

	def test_unnamed_node_cannot_carry_a_display_name(self) -> None:
		with self.assertRaises(ValueError):
			_ = NodeFacet(nodeId="n1", parentId=None, depth=0, name="hidden", hasName=False, role="pane")

	def test_unnamed_node_json_excludes_name(self) -> None:
		facet = NodeFacet(nodeId="n1", parentId=None, depth=0, name="", hasName=False, role="pane")
		node = CopyNode(
			identity=InspectorSourceIdentity(
				kind=InspectorSourceKind.LIVE,
				label="Application",
				executable="application.exe",
				processId=1,
				backend="UIA",
			),
			path=(facet,),
			categories=(),
		)

		rendered = json.loads(renderNodeJson(node))

		self.assertFalse(rendered["node"]["hasName"])
		self.assertNotIn("name", rendered["node"])

	def test_blank_role_is_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = NodeFacet(nodeId="n1", parentId=None, depth=0, name="ok", hasName=True, role="   ")


class PropertyRowTests(unittest.TestCase):
	def test_value_row_requires_value(self) -> None:
		with self.assertRaises(ValueError):
			_ = PropertyRow(fieldKey="name", name="Name", status=PropertyStatus.VALUE, value=None)

	def test_missing_status_rows_forbid_a_value(self) -> None:
		with self.assertRaises(ValueError):
			_ = PropertyRow(
				fieldKey="name",
				name="Name",
				status=PropertyStatus.UNSUPPORTED,
				value="leaked",
			)

	def test_truncated_row_carries_partial_value_but_only_failed_fields_retry(self) -> None:
		truncated = PropertyRow(
			fieldKey="value",
			name="Value",
			status=PropertyStatus.TRUNCATED,
			value="partial",
		)
		self.assertEqual(truncated.value, "partial")
		self.assertFalse(truncated.retryable, "a partial read is not a failed field")
		self.assertTrue(PropertyRow(fieldKey="value", name="Value", status=PropertyStatus.FAILED).retryable)
		self.assertFalse(
			PropertyRow(fieldKey="value", name="Value", status=PropertyStatus.VALUE, value="v").retryable,
		)


class StructuredPropertyTests(unittest.TestCase):
	def test_a_node_cannot_be_both_scalar_and_container(self) -> None:
		with self.assertRaises(ValueError):
			_ = StructuredPropertyNode(
				key="k",
				label="K",
				status=PropertyStatus.VALUE,
				value="v",
				children=(_scalar("c", "1"),),
			)

	def test_only_a_container_can_start_expanded(self) -> None:
		with self.assertRaises(ValueError):
			_ = StructuredPropertyNode(
				key="k",
				label="K",
				status=PropertyStatus.VALUE,
				value="v",
				expanded=True,
			)

	def test_non_value_status_scalar_nodes_forbid_values(self) -> None:
		for status in PropertyStatus:
			if status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED):
				continue
			with self.subTest(status=status):
				with self.assertRaisesRegex(ValueError, f"{status} nodes cannot carry a value"):
					_ = StructuredPropertyNode(
						key="k",
						label="K",
						status=status,
						value="leaked",
					)

	def test_value_and_truncated_scalar_nodes_carry_values(self) -> None:
		for status in (PropertyStatus.VALUE, PropertyStatus.TRUNCATED):
			with self.subTest(status=status):
				node = StructuredPropertyNode(key="k", label="K", status=status, value="partial")
				self.assertEqual(node.value, "partial")

	def test_non_value_container_node_remains_valid(self) -> None:
		node = StructuredPropertyNode(
			key="secret",
			label="Secret",
			status=PropertyStatus.REDACTED,
			children=(_scalar("child", "safe"),),
		)

		self.assertTrue(node.isStructured)


class ExpandAllPropertiesTests(unittest.TestCase):
	def test_immediate_structured_children_expand_once_and_deeper_nodes_stay_collapsed(self) -> None:
		grandchild = _container("address", _scalar("street", "Main"), _scalar("city", "Rivertown"))
		mapping = _container("owner", _scalar("name", "Ada"), grandchild)
		items = _container("roles", _scalar("roles[0]", "button"), _scalar("roles[1]", "menuitem"))
		scalar = _scalar("title", "Untitled")

		expanded = expandAllPropertiesOneLevel((mapping, items, scalar))

		byKey = {node.key: node for node in expanded}
		self.assertTrue(byKey["owner"].expanded)
		self.assertTrue(byKey["roles"].expanded)
		self.assertFalse(byKey["title"].expanded)
		nestedAddress = next(child for child in byKey["owner"].children if child.key == "address")
		self.assertFalse(nestedAddress.expanded)
		self.assertTrue(all(not leaf.expanded for leaf in nestedAddress.children))

	def test_expansion_is_idempotent(self) -> None:
		tree = (_container("owner", _container("address", _scalar("city", "Rivertown"))),)
		once = expandAllPropertiesOneLevel(tree)
		twice = expandAllPropertiesOneLevel(once)
		self.assertEqual(once, twice)

	def test_scalar_only_tree_is_unchanged(self) -> None:
		tree = (_scalar("name", "Ada"), _scalar("role", "button"))
		self.assertEqual(expandAllPropertiesOneLevel(tree), tree)


class QuickPropertyDigitTests(unittest.TestCase):
	def test_main_row_numpad_and_layout_prefixes_map_to_the_same_digit(self) -> None:
		for identifier in ("kb:5", "kb(desktop):5", "kb(laptop):numpad5", "kb:numpad5", "5", "KB:NUMPAD5"):
			self.assertEqual(normalizeQuickPropertyDigit(identifier), 5, identifier)

	def test_modifier_prefix_before_a_digit_is_ignored(self) -> None:
		self.assertEqual(normalizeQuickPropertyDigit("kb:control+3"), 3)
		self.assertEqual(normalizeQuickPropertyDigit("kb(laptop):nvda+shift+0"), 0)

	def test_non_digit_and_non_string_gestures_are_rejected(self) -> None:
		for identifier in ("kb:a", "kb:f5", "kb:numpadEnter", "kb:", "", "   ", 7, None, 5.0):
			self.assertIsNone(normalizeQuickPropertyDigit(identifier), identifier)


class QuickPropertyCycleTests(unittest.TestCase):
	def test_press_cycle_announces_browses_copies_then_resets(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000)
		actions = [
			state.press(3, nowMilliseconds=0).action,
			state.press(3, nowMilliseconds=100).action,
			state.press(3, nowMilliseconds=200).action,
			state.press(3, nowMilliseconds=300).action,
		]
		self.assertEqual(
			actions,
			[
				QuickPropertyAction.ANNOUNCE,
				QuickPropertyAction.BROWSE,
				QuickPropertyAction.COPY,
				QuickPropertyAction.RESET,
			],
		)

	def test_swap_exchanges_the_browse_and_copy_presses(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000, swapActions=True)
		_ = state.press(1, nowMilliseconds=0)
		self.assertIs(state.press(1, nowMilliseconds=100).action, QuickPropertyAction.COPY)
		self.assertIs(state.press(1, nowMilliseconds=200).action, QuickPropertyAction.BROWSE)

	def test_a_lapsed_deadline_starts_a_fresh_announce(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000)
		first = state.press(2, nowMilliseconds=0)
		self.assertIs(first.action, QuickPropertyAction.ANNOUNCE)
		self.assertIs(
			state.press(2, nowMilliseconds=first.deadlineMilliseconds + 1).action,
			QuickPropertyAction.ANNOUNCE,
		)

	def test_each_digit_keeps_an_independent_cycle(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000)
		_ = state.press(4, nowMilliseconds=0)
		_ = state.press(4, nowMilliseconds=100)
		self.assertIs(state.press(7, nowMilliseconds=150).action, QuickPropertyAction.ANNOUNCE)

	def test_cancel_resets_every_pending_digit(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000)
		_ = state.press(5, nowMilliseconds=0)
		state.cancel()
		self.assertIs(state.press(5, nowMilliseconds=50).action, QuickPropertyAction.ANNOUNCE)

	def test_interval_outside_the_validated_bounds_is_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = QuickPropertyRepeatState(intervalMilliseconds=MAXIMUM_PROPERTY_INTERVAL_MS + 1)
		with self.assertRaises(ValueError):
			_ = QuickPropertyRepeatState(intervalMilliseconds=MINIMUM_PROPERTY_INTERVAL_MS - 1)

	def test_an_unknown_digit_is_rejected(self) -> None:
		state = QuickPropertyRepeatState(intervalMilliseconds=1000)
		with self.assertRaises(ValueError):
			_ = state.press(11, nowMilliseconds=0)


class LoadedSearchTests(unittest.TestCase):
	def _nodes(self) -> tuple[SearchableNode, ...]:
		return (
			SearchableNode(nodeId="root", name="Main Window", role="window"),
			SearchableNode(nodeId="list", name="Messages", role="list"),
			SearchableNode(nodeId="item", name="Inbox", role="listItem", loadedText=("Unread: 3",)),
		)

	def test_forward_search_finds_the_next_name_match(self) -> None:
		outcome = searchLoadedNodes(self._nodes(), "inbox", currentNodeId="root")
		self.assertEqual(outcome.decision, "match")
		self.assertEqual(outcome.nodeId, "item")
		self.assertEqual(outcome.wrapped, "none")

	def test_search_reaches_loaded_property_text(self) -> None:
		self.assertEqual(searchLoadedNodes(self._nodes(), "unread").nodeId, "item")

	def test_forward_search_wraps_to_the_start(self) -> None:
		outcome = searchLoadedNodes(self._nodes(), "window", currentNodeId="item")
		self.assertEqual(outcome.nodeId, "root")
		self.assertEqual(outcome.wrapped, "start")

	def test_reverse_search_finds_the_previous_match(self) -> None:
		outcome = searchLoadedNodes(self._nodes(), "messages", currentNodeId="item", forward=False)
		self.assertEqual(outcome.nodeId, "list")

	def test_a_blank_query_is_reported_empty(self) -> None:
		self.assertEqual(searchLoadedNodes(self._nodes(), "   ").decision, "empty")

	def test_no_match_is_explicit(self) -> None:
		self.assertEqual(searchLoadedNodes(self._nodes(), "absent").decision, "noMatch")

	def test_search_over_no_loaded_nodes_is_no_match(self) -> None:
		self.assertEqual(searchLoadedNodes((), "anything").decision, "noMatch")


class ChildFetchTests(unittest.TestCase):
	def test_loaded_fetch_without_children_is_rejected(self) -> None:
		with self.assertRaises(ValueError):
			_ = ChildFetch(parentId="parent", state=ChildState.LOADED)

	def test_empty_fetch_with_children_is_rejected(self) -> None:
		child = NodeFacet(
			nodeId="child",
			parentId="parent",
			depth=1,
			name="Child",
			hasName=True,
			role="button",
		)
		with self.assertRaises(ValueError):
			_ = ChildFetch(parentId="parent", state=ChildState.EMPTY, children=(child,))

	def test_truncated_fetch_may_not_have_captured_any_children(self) -> None:
		fetch = ChildFetch(parentId="parent", state=ChildState.TRUNCATED)
		self.assertEqual(fetch.children, ())


class MarkdownCopyTests(unittest.TestCase):
	def test_all_properties_includes_the_structured_tree_without_unsafe_values(self) -> None:
		facet = NodeFacet(
			nodeId="node",
			parentId=None,
			depth=0,
			name="Submit",
			hasName=True,
			role="button",
		)
		redacted = StructuredPropertyNode(
			key="secret",
			label="Secret",
			status=PropertyStatus.REDACTED,
		)
		node = CopyNode(
			identity=InspectorSourceIdentity(
				kind=InspectorSourceKind.LIVE,
				label="Application",
				executable="application.exe",
				processId=1,
				backend="UIA",
			),
			path=(facet,),
			categories=(
				CopyCategory(
					category=PropertyCategory.ALL_PROPERTIES,
					rows=(),
					structured=(
						_container("owner", _scalar("name", "Ada")),
						redacted,
					),
				),
				CopyCategory(
					category=PropertyCategory.ANNOTATIONS,
					rows=(),
					structured=(),
				),
			),
		)

		rendered = renderNodeMarkdown(node)

		self.assertIn("## All Properties", rendered)
		self.assertIn("### Structured Properties", rendered)
		self.assertIn("- **Owner**", rendered)
		self.assertIn("  - **Name:** Ada", rendered)
		self.assertIn("- **Secret:** (redacted)", rendered)
		self.assertNotIn("_No flat properties._", rendered)
		self.assertIn("## Annotations", rendered)


if __name__ == "__main__":
	_ = unittest.main()
