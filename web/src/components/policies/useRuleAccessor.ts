import {
  createDefaultRule,
  type MergeStrategy,
  type OsFamily,
  type PolicyRule,
  type RuleConfigMap,
  type RuleType
} from '@/api'

export function findRule<K extends RuleType>(
  rules: PolicyRule[],
  ruleType: K
): PolicyRule<K> | undefined {
  return rules.find((r): r is PolicyRule<K> => r.ruleType === ruleType)
}

export function toggleRuleInList<K extends RuleType>(
  rules: PolicyRule[],
  ruleType: K,
  enabled: boolean
): PolicyRule[] {
  const without = rules.filter((r) => r.ruleType !== ruleType)
  if (!enabled) {
    return without
  }
  const existing = findRule(rules, ruleType)
  return [...without, existing ?? createDefaultRule(ruleType)]
}

export function updateRuleConfig<K extends RuleType>(
  rules: PolicyRule[],
  ruleType: K,
  patch: Partial<RuleConfigMap[K]>
): PolicyRule[] {
  return rules.map((r) => {
    if (r.ruleType !== ruleType) return r
    const typed = r as PolicyRule<K>
    return {
      ...typed,
      config: { ...typed.config, ...patch }
    }
  })
}

export function updateRuleMeta<K extends RuleType>(
  rules: PolicyRule[],
  ruleType: K,
  meta: { platforms?: OsFamily[]; mergeStrategy?: MergeStrategy }
): PolicyRule[] {
  return rules.map((r) => {
    if (r.ruleType !== ruleType) return r
    return {
      ...r,
      ...(meta.platforms ? { platforms: meta.platforms } : {}),
      ...(meta.mergeStrategy ? { mergeStrategy: meta.mergeStrategy } : {})
    }
  })
}

export function makeItemId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`
}
