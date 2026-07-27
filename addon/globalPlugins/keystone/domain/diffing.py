from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import replace
from typing import cast

from .document_records import DiffChange
from .documents import Snapshot
from .evidence import EvidenceEnvelope
from .privacy import PrivacyPolicy
from .snapshot_bundle import InMemorySnapshotView, SnapshotNodeView, SnapshotView
from .status import EvidenceState


class AmbiguousMatchError(ValueError):
	"""Raised when two sibling groups cannot be paired without guessing."""


_VALUE_STATES = frozenset((EvidenceState.VALUE, EvidenceState.MIXED, EvidenceState.TRUNCATED))


def _automationId(node: SnapshotNodeView) -> tuple[str, str] | None:
	envelope = node.field("stableIds")
	if envelope.status is not EvidenceState.VALUE or not isinstance(envelope.value, tuple):
		return None
	for candidate in cast(tuple[object, ...], envelope.value):
		if isinstance(candidate, tuple):
			parts = cast(tuple[object, ...], candidate)
		else:
			continue
		if (
			len(parts) == 3
			and parts[0] == "uiaAutomationId"
			and isinstance(parts[1], str)
			and isinstance(parts[2], str)
			and parts[1]
			and parts[2]
		):
			return parts[1], parts[2]
	return None


def _canonicalAutomationId(node: SnapshotNodeView) -> tuple[str, str] | None:
	automationId = _automationId(node)
	if automationId is None or automationId[1].strip() != automationId[1]:
		return None
	return automationId


def _plainValue(node: SnapshotNodeView, field: str) -> object:
	envelope = node.field(field)
	return envelope.value if envelope.status is EvidenceState.VALUE else None


def _providerIdentities(node: SnapshotNodeView) -> tuple[tuple[str, object], ...]:
	return tuple(
		(name, section.identity.value)
		for name, section in node.providers.items
		if section.identity.status is EvidenceState.VALUE
	)


def _fallbackKey(node: SnapshotNodeView) -> tuple[object, ...]:
	return tuple(
		_plainValue(node, field) for field in ("role", "name", "windowControlId", "windowClass", "backend")
	)


def _duplicateDiscriminator(node: SnapshotNodeView) -> tuple[object, ...]:
	return (
		_providerIdentities(node),
		_plainValue(node, "pythonClass"),
		_plainValue(node, "classHierarchy"),
		_plainValue(node, "keyboardShortcut"),
	)


def _identityKey(node: SnapshotNodeView) -> tuple[str, object]:
	automationId = _canonicalAutomationId(node)
	if automationId is not None:
		return "automationId", automationId
	return "fallback", _fallbackKey(node)


def _pathSegment(node: SnapshotNodeView) -> str:
	automationId = _canonicalAutomationId(node)
	if automationId is not None:
		return automationId[1]
	name = _plainValue(node, "name")
	role = _plainValue(node, "role")
	if isinstance(name, str) and name and name.strip() == name:
		return name
	if isinstance(role, str) and role and role.strip() == role:
		return role
	return node.key


def _privacySafe(envelope: EvidenceEnvelope, policy: PrivacyPolicy) -> EvidenceEnvelope:
	privacy = replace(
		envelope.privacy,
		policyRevision=policy.policyRevision,
		effectiveTransform=(
			"redact"
			if policy.redactProtectedText and envelope.privacy.classification != "public"
			else envelope.privacy.effectiveTransform
		),
	)
	if (
		policy.redactProtectedText
		and envelope.privacy.classification != "public"
		and envelope.status in _VALUE_STATES
	):
		return replace(
			envelope,
			status=EvidenceState.REDACTED,
			privacy=privacy,
			value=None,
			truncation=None,
			errorRef=None,
		)
	return replace(envelope, privacy=privacy)


def _leafEnvelope(envelope: EvidenceEnvelope, value: object) -> EvidenceEnvelope:
	if value is None:
		return replace(
			envelope,
			status=EvidenceState.EMPTY,
			value=None,
			truncation=None,
			errorRef=None,
		)
	return replace(
		envelope,
		status=EvidenceState.VALUE,
		value=value,
		truncation=None,
		errorRef=None,
	)


def _mapping(value: object) -> dict[str, object] | None:
	if not isinstance(value, tuple):
		return None
	result: dict[str, object] = {}
	for item in cast(tuple[object, ...], value):
		if isinstance(item, tuple):
			parts = cast(tuple[object, ...], item)
		else:
			return None
		if len(parts) != 2 or not isinstance(parts[0], str) or parts[0] in result:
			return None
		result[parts[0]] = parts[1]
	return result


def _compareEnvelope(
	path: tuple[str, ...],
	before: EvidenceEnvelope,
	after: EvidenceEnvelope,
) -> tuple[DiffChange, ...]:
	if before == after:
		return ()
	if (
		before.status is EvidenceState.VALUE
		and after.status is EvidenceState.VALUE
		and (beforeMap := _mapping(before.value)) is not None
		and (afterMap := _mapping(after.value)) is not None
	):
		changes: list[DiffChange] = []
		work: list[tuple[tuple[str, ...], object, object, EvidenceEnvelope, EvidenceEnvelope]] = [
			(path, beforeMap, afterMap, before, after),
		]
		while work:
			currentPath, oldValue, newValue, oldEnvelope, newEnvelope = work.pop()
			oldMap = cast(dict[str, object], oldValue)
			newMap = cast(dict[str, object], newValue)
			for key in sorted(set(oldMap) | set(newMap), key=lambda item: item.encode("utf-8"), reverse=True):
				childPath = (*currentPath, key)
				if key not in oldMap:
					changes.append(
						DiffChange("added", childPath, None, _leafEnvelope(newEnvelope, newMap[key]), ()),
					)
					continue
				if key not in newMap:
					changes.append(
						DiffChange("removed", childPath, _leafEnvelope(oldEnvelope, oldMap[key]), None, ()),
					)
					continue
				oldChild = oldMap[key]
				newChild = newMap[key]
				oldChildMap = _mapping(oldChild)
				newChildMap = _mapping(newChild)
				if oldChildMap is not None and newChildMap is not None:
					work.append((childPath, oldChildMap, newChildMap, oldEnvelope, newEnvelope))
				elif oldChild != newChild:
					changes.append(
						DiffChange(
							"modified",
							childPath,
							_leafEnvelope(oldEnvelope, oldChild),
							_leafEnvelope(newEnvelope, newChild),
							(),
						),
					)
		return tuple(changes)
	return (DiffChange("modified", path, before, after, ()),)


def _pairBucket(
	before: tuple[SnapshotNodeView, ...],
	after: tuple[SnapshotNodeView, ...],
	key: tuple[str, object],
) -> tuple[tuple[SnapshotNodeView, SnapshotNodeView], ...]:
	if len(before) == len(after) == 1:
		left = before[0]
		right = after[0]
		if key[0] == "automationId" and _plainValue(left, "role") != _plainValue(right, "role"):
			raise AmbiguousMatchError("stable automation ID has a conflicting role")
		return ((left, right),)
	if not before or not after:
		return ()
	leftByDiscriminator: dict[tuple[object, ...], SnapshotNodeView] = {}
	rightByDiscriminator: dict[tuple[object, ...], SnapshotNodeView] = {}
	for node, target in (
		*((node, leftByDiscriminator) for node in before),
		*((node, rightByDiscriminator) for node in after),
	):
		discriminator = _duplicateDiscriminator(node)
		if discriminator in target:
			raise AmbiguousMatchError("ambiguous duplicate sibling group")
		target[discriminator] = node
	if set(leftByDiscriminator) != set(rightByDiscriminator):
		raise AmbiguousMatchError("ambiguous duplicate sibling group")
	return tuple(
		(leftByDiscriminator[item], rightByDiscriminator[item])
		for item in sorted(leftByDiscriminator, key=repr)
	)


def _matchSiblings(
	before: tuple[SnapshotNodeView, ...],
	after: tuple[SnapshotNodeView, ...],
) -> tuple[
	tuple[tuple[SnapshotNodeView, SnapshotNodeView], ...],
	tuple[SnapshotNodeView, ...],
	tuple[SnapshotNodeView, ...],
]:
	leftBuckets: defaultdict[tuple[str, object], list[SnapshotNodeView]] = defaultdict(list)
	rightBuckets: defaultdict[tuple[str, object], list[SnapshotNodeView]] = defaultdict(list)
	for node in before:
		leftBuckets[_identityKey(node)].append(node)
	for node in after:
		rightBuckets[_identityKey(node)].append(node)
	pairs: list[tuple[SnapshotNodeView, SnapshotNodeView]] = []
	removed: list[SnapshotNodeView] = []
	added: list[SnapshotNodeView] = []
	keys = sorted(set(leftBuckets) | set(rightBuckets), key=repr)
	for key in keys:
		left = tuple(leftBuckets[key])
		right = tuple(rightBuckets[key])
		if not left:
			added.extend(right)
		elif not right:
			removed.extend(left)
		elif len(left) != len(right):
			removed.extend(left)
			added.extend(right)
		else:
			pairs.extend(_pairBucket(left, right, key))
	return tuple(pairs), tuple(removed), tuple(added)


def _nodeMarker(node: SnapshotNodeView, policy: PrivacyPolicy) -> EvidenceEnvelope:
	for field in ("name", "role", "stableIds"):
		envelope = _privacySafe(node.field(field), policy)
		if envelope.status in _VALUE_STATES:
			return envelope
	return _privacySafe(node.field("name"), policy)


def _subtreeChanges(
	node: SnapshotNodeView,
	nodesByKey: dict[str, SnapshotNodeView],
	path: tuple[str, ...],
	kind: str,
	policy: PrivacyPolicy,
) -> tuple[DiffChange, ...]:
	changes: list[DiffChange] = []
	work: list[tuple[SnapshotNodeView, tuple[str, ...]]] = [(node, path)]
	while work:
		current, currentPath = work.pop()
		marker = _nodeMarker(current, policy)
		if kind == "added":
			changes.append(DiffChange("added", currentPath, None, marker, ()))
		else:
			changes.append(DiffChange("removed", currentPath, marker, None, ()))
		for childKey in reversed(current.structure.childKeys):
			child = nodesByKey[childKey]
			work.append((child, (*currentPath, _pathSegment(child))))
	return tuple(changes)


def diffSnapshotViews(
	leftView: SnapshotView,
	rightView: SnapshotView,
	policy: PrivacyPolicy,
) -> tuple[DiffChange, ...]:
	"""Compare two snapshot views iteratively under the current privacy policy.

	Each view owns its local node identifiers and opens only the topics a comparison
	actually reaches, so a bundle-backed view never has to be rebuilt into a whole
	snapshot and an in-memory view keeps the previous full-snapshot behaviour.
	"""
	leftByKey: dict[str, SnapshotNodeView] = {node.key: node for node in leftView.captureNodes}
	rightByKey: dict[str, SnapshotNodeView] = {node.key: node for node in rightView.captureNodes}
	leftRoots = tuple(leftByKey[key] for key in leftView.captureRoots)
	rightRoots = tuple(rightByKey[key] for key in rightView.captureRoots)
	rootPairs, removedRoots, addedRoots = _matchSiblings(leftRoots, rightRoots)
	changes: list[DiffChange] = []
	work: deque[tuple[SnapshotNodeView, SnapshotNodeView, tuple[str, ...]]] = deque(
		(left, right, (_pathSegment(left),)) for left, right in rootPairs
	)
	for node in removedRoots:
		changes.extend(
			_subtreeChanges(node, leftByKey, (_pathSegment(node),), "removed", policy),
		)
	for node in addedRoots:
		changes.extend(
			_subtreeChanges(node, rightByKey, (_pathSegment(node),), "added", policy),
		)

	while work:
		left, right, nodePath = work.popleft()
		for field, leftEnvelope in left.fields:
			if field == "children":
				continue
			rightEnvelope = right.field(field)
			changes.extend(
				_compareEnvelope(
					(*nodePath, field),
					_privacySafe(leftEnvelope, policy),
					_privacySafe(rightEnvelope, policy),
				),
			)
		for (providerName, leftSection), (rightName, rightSection) in zip(
			left.providers.items,
			right.providers.items,
			strict=True,
		):
			if providerName != rightName:
				raise ValueError("provider section order changed")
			for field in ("status", "identity", "properties"):
				changes.extend(
					_compareEnvelope(
						(*nodePath, "providers", providerName, field),
						_privacySafe(cast(EvidenceEnvelope, getattr(leftSection, field)), policy),
						_privacySafe(cast(EvidenceEnvelope, getattr(rightSection, field)), policy),
					),
				)
		leftChildren = tuple(leftByKey[key] for key in left.structure.childKeys)
		rightChildren = tuple(rightByKey[key] for key in right.structure.childKeys)
		childPairs, removed, added = _matchSiblings(leftChildren, rightChildren)
		for child in removed:
			childPath = (*nodePath, _pathSegment(child))
			changes.extend(_subtreeChanges(child, leftByKey, childPath, "removed", policy))
		for child in added:
			childPath = (*nodePath, _pathSegment(child))
			changes.extend(_subtreeChanges(child, rightByKey, childPath, "added", policy))
		for leftChild, rightChild in childPairs:
			work.append((leftChild, rightChild, (*nodePath, _pathSegment(leftChild))))

	return tuple(sorted(changes, key=lambda change: (change.ancestorPath, change.changeKind)))


def diffSnapshots(
	baseline: Snapshot,
	current: Snapshot,
	policy: PrivacyPolicy,
) -> tuple[DiffChange, ...]:
	"""Diff two full in-memory snapshots by adapting each to a snapshot view."""
	return diffSnapshotViews(
		InMemorySnapshotView(baseline),
		InMemorySnapshotView(current),
		policy,
	)
