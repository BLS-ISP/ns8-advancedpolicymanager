"""Deterministic Effective Policy & Conflict Trace Resolver."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from app.engine.schema_registry import ALL_CATEGORIES, RULE_REGISTRY

CATEGORY_SORT_ORDER = {cat: idx for idx, cat in enumerate(ALL_CATEGORIES)}
RULE_SORT_ORDER = {rtype: idx for idx, rtype in enumerate(RULE_REGISTRY.keys())}


@dataclass(frozen=True)
class PolicyRecord:
    id: str
    name: str
    is_enabled: bool
    revision: int
    rules: list[dict[str, Any]]


@dataclass(frozen=True)
class AssignmentRecord:
    id: str
    policy_id: str
    priority: int
    is_enabled: bool
    target_user_type: str  # "ALL" | "USER" | "GROUP"
    target_user_ref: str | None
    target_device_type: str  # "ALL" | "DEVICE" | "DEVICE_GROUP"
    target_device_ref: str | None
    os_filter: list[str]
    created_at: str = ""


@dataclass(frozen=True)
class _RuleCandidate:
    assignment_id: str
    priority: int
    policy_id: str
    policy_name: str
    rule: dict[str, Any]


@dataclass(frozen=True)
class EvaluationResult:
    effective_rules: list[dict[str, Any]]
    trace: list[dict[str, Any]]


def _dedupe_strings_ci(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in values:
        cleaned = str(item).strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        if key not in seen:
            seen.add(key)
            result.append(cleaned)
    return result


def _merge_items_by_id(lists_in_priority_order: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    seen_ids: set[str] = set()
    merged: list[dict[str, Any]] = []
    for items in lists_in_priority_order:
        for item in items:
            item_id = str(item.get("id", ""))
            if item_id and item_id in seen_ids:
                continue
            if item_id:
                seen_ids.add(item_id)
            merged.append(copy.deepcopy(item))
    return merged


def _merge_append_unique(rule_type: str, configs: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge rule configs in priority ASC order (`configs[0]` = highest priority)."""
    if not configs:
        return {}
    if len(configs) == 1:
        return copy.deepcopy(configs[0])

    top = copy.deepcopy(configs[0])

    if rule_type == "access.local_admins":
        all_groups: list[str] = []
        all_users: list[str] = []
        for cfg in configs:
            all_groups.extend(cfg.get("adminGroups", []))
            all_users.extend(cfg.get("adminUsers", []))
        return {
            "adminGroups": _dedupe_strings_ci(all_groups),
            "adminUsers": _dedupe_strings_ci(all_users),
            "passwordlessSudo": bool(top.get("passwordlessSudo", False)),
        }

    if rule_type == "workspace.network_shares":
        return {
            "mounts": _merge_items_by_id([cfg.get("mounts", []) for cfg in configs]),
        }

    if rule_type == "workspace.printers":
        return {
            "printers": _merge_items_by_id([cfg.get("printers", []) for cfg in configs]),
        }

    if rule_type == "workspace.scripts":
        return {
            "scripts": _merge_items_by_id([cfg.get("scripts", []) for cfg in configs]),
        }

    if rule_type == "custom.raw_setting":
        return {
            "items": _merge_items_by_id([cfg.get("items", []) for cfg in configs]),
        }

    # Generic fallback for any other rule explicitly set to APPEND_UNIQUE
    merged: dict[str, Any] = {}
    for key, top_val in top.items():
        if isinstance(top_val, list):
            if any(
                isinstance(el, dict) and "id" in el
                for cfg in configs
                for el in cfg.get(key, [])
            ):
                merged[key] = _merge_items_by_id([cfg.get(key, []) for cfg in configs])
            else:
                combined: list[Any] = []
                for cfg in configs:
                    for el in cfg.get(key, []):
                        if el not in combined:
                            combined.append(copy.deepcopy(el))
                merged[key] = combined
        else:
            merged[key] = top_val
    return merged


def _matches_user_scope(
    assignment: AssignmentRecord,
    username: str | None,
    user_groups_lower: set[str],
) -> bool:
    utype = assignment.target_user_type.upper()
    if utype == "ALL":
        return True
    ref = (assignment.target_user_ref or "").strip()
    if not ref:
        return False
    if utype == "USER":
        if not username or not username.strip():
            return False
        uname = username.strip().lower()
        short_uname = uname.split("@", 1)[0] if "@" in uname else uname
        ref_low = ref.lower()
        return ref_low == uname or ref_low == short_uname
    if utype == "GROUP":
        return ref.lower() in user_groups_lower
    return False


def _matches_device_scope(
    assignment: AssignmentRecord,
    device_id: str | None,
    device_hostname: str | None,
    device_group_ids: set[str],
) -> bool:
    dtype = assignment.target_device_type.upper()
    if dtype == "ALL":
        return True
    ref = (assignment.target_device_ref or "").strip()
    if not ref:
        return False
    if dtype == "DEVICE":
        if device_id and device_id == ref:
            return True
        if device_hostname and device_hostname.strip().lower() == ref.lower():
            return True
        return False
    if dtype == "DEVICE_GROUP":
        return ref in device_group_ids
    return False


class PolicyResolver:
    """Evaluates priority-ordered assignments into Effective Rules and a Conflict Trace."""

    @staticmethod
    def evaluate(
        *,
        assignments: list[AssignmentRecord],
        policies_by_id: dict[str, PolicyRecord],
        target_os: str,
        username: str | None = None,
        resolved_user_groups: list[str] | None = None,
        device_id: str | None = None,
        device_hostname: str | None = None,
        device_group_ids: list[str] | None = None,
    ) -> EvaluationResult:
        os_upper = target_os.strip().upper()
        user_groups_lower = {g.strip().lower() for g in (resolved_user_groups or []) if g.strip()}
        dev_groups_set = {g.strip() for g in (device_group_ids or []) if g.strip()}

        sorted_assignments = sorted(
            assignments,
            key=lambda a: (a.priority, a.created_at, a.id),
        )

        candidates_by_rule_type: dict[str, list[_RuleCandidate]] = {}

        for asg in sorted_assignments:
            if not asg.is_enabled:
                continue
            policy = policies_by_id.get(asg.policy_id)
            if policy is None or not policy.is_enabled:
                continue

            if os_upper not in {p.upper() for p in asg.os_filter}:
                continue
            if not _matches_user_scope(asg, username, user_groups_lower):
                continue
            if not _matches_device_scope(asg, device_id, device_hostname, dev_groups_set):
                continue

            for raw_rule in policy.rules:
                rule_platforms = {p.upper() for p in raw_rule.get("platforms", [])}
                if os_upper not in rule_platforms:
                    continue

                rule_copy = copy.deepcopy(raw_rule)
                rtype = str(rule_copy["ruleType"])

                if rtype == "custom.raw_setting":
                    all_items = rule_copy.get("config", {}).get("items", [])
                    os_items = [
                        it for it in all_items if str(it.get("targetOs", "")).upper() == os_upper
                    ]
                    if all_items and not os_items:
                        continue
                    rule_copy["config"] = {"items": os_items}

                candidates_by_rule_type.setdefault(rtype, []).append(
                    _RuleCandidate(
                        assignment_id=asg.id,
                        priority=asg.priority,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        rule=rule_copy,
                    )
                )

        effective_rules: list[dict[str, Any]] = []
        trace: list[dict[str, Any]] = []

        ordered_rule_types = sorted(
            candidates_by_rule_type.keys(),
            key=lambda rt: (
                CATEGORY_SORT_ORDER.get(
                    str(candidates_by_rule_type[rt][0].rule.get("category", "")),
                    99,
                ),
                RULE_SORT_ORDER.get(rt, 999),
                rt,
            ),
        )

        for rtype in ordered_rule_types:
            cands = candidates_by_rule_type[rtype]
            winner = cands[0]
            strategy = str(winner.rule.get("mergeStrategy", "OVERRIDE")).upper()

            if strategy == "APPEND_UNIQUE":
                merged_config = _merge_append_unique(rtype, [c.rule["config"] for c in cands])
                effective_rule = copy.deepcopy(winner.rule)
                effective_rule["config"] = merged_config
                effective_rule["mergeStrategy"] = "APPEND_UNIQUE"
                shadowed = [
                    {
                        "policyId": c.policy_id,
                        "policyName": c.policy_name,
                        "priority": c.priority,
                        "action": "MERGED",
                    }
                    for c in cands[1:]
                ]
            else:
                effective_rule = copy.deepcopy(winner.rule)
                effective_rule["mergeStrategy"] = "OVERRIDE"
                shadowed = [
                    {
                        "policyId": c.policy_id,
                        "policyName": c.policy_name,
                        "priority": c.priority,
                        "action": "OVERRIDDEN",
                    }
                    for c in cands[1:]
                ]

            effective_rules.append(effective_rule)
            trace.append(
                {
                    "ruleType": rtype,
                    "category": effective_rule["category"],
                    "winningPolicyId": winner.policy_id,
                    "winningPolicyName": winner.policy_name,
                    "winningAssignmentId": winner.assignment_id,
                    "winningPriority": winner.priority,
                    "mergeStrategy": effective_rule["mergeStrategy"],
                    "shadowedPolicies": shadowed,
                }
            )

        return EvaluationResult(effective_rules=effective_rules, trace=trace)
