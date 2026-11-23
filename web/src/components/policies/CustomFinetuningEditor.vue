<script setup lang="ts">
import { computed } from 'vue'
import { Plus, Trash2, Wrench } from 'lucide-vue-next'
import { ALL_PLATFORMS, type PolicyRule, type RawSettingItem } from '@/api'
import RuleCardShell from './RuleCardShell.vue'
import { findRule, makeItemId, toggleRuleInList, updateRuleConfig, updateRuleMeta } from './useRuleAccessor'
import { useI18n } from '@/i18n'

const props = defineProps<{
  rules: PolicyRule[]
}>()

const emit = defineEmits<{
  (e: 'update:rules', value: PolicyRule[]): void
}>()

const { t, locale } = useI18n()
const rawRule = computed(() => findRule(props.rules, 'custom.raw_setting'))

function addRawItem() {
  const curr = rawRule.value?.config.items ?? []
  const next: RawSettingItem = {
    id: makeItemId('raw'),
    targetOs: 'WINDOWS',
    engine: 'REGISTRY',
    path: 'HKLM\\SOFTWARE\\Policies\\Custom',
    key: 'EnableFeature',
    valueType: 'INT',
    value: '1'
  }
  emit('update:rules', updateRuleConfig(props.rules, 'custom.raw_setting', { items: [...curr, next] }))
}

function patchRawItem(id: string, patch: Partial<RawSettingItem>) {
  const curr = rawRule.value?.config.items ?? []
  emit(
    'update:rules',
    updateRuleConfig(props.rules, 'custom.raw_setting', {
      items: curr.map((item) => (item.id === id ? { ...item, ...patch } : item))
    })
  )
}

function removeRawItem(id: string) {
  const curr = rawRule.value?.config.items ?? []
  emit(
    'update:rules',
    updateRuleConfig(props.rules, 'custom.raw_setting', {
      items: curr.filter((item) => item !== undefined && item.id !== id)
    })
  )
}
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-start gap-2.5 rounded-lg border border-amber-200 bg-amber-50/70 p-3.5 text-xs text-amber-900">
      <Wrench class="mt-0.5 h-4 w-4 shrink-0 text-amber-700" aria-hidden="true" />
      <div>
        <strong>
          {{ locale === 'de' ? 'Architektur-Hook (v2 Finetuning):' : 'Architecture Hook (v2 Finetuning):' }}
        </strong>
        {{
          locale === 'de'
            ? ' Nutzen Sie Direkteinstellungen nur für Spezialfälle, die noch nicht über die 11 geführten Standardregeln abgedeckt sind.'
            : ' Use raw key-value settings only for advanced edge cases not covered by the 11 guided v1 policy rules.'
        }}
      </div>
    </div>

    <RuleCardShell
      :title="t.ruleNames['custom.raw_setting']"
      :description="
        locale === 'de'
          ? 'Schreibt gezielte Schlüsselwerte in Windows-Registry, Linux dconf/sysctl oder macOS plist inklusive Rollback-Tracking.'
          : 'Writes targeted key-value entries to Windows Registry, Linux dconf/sysctl, or macOS plist with rollback tracking.'
      "
      :enabled="Boolean(rawRule)"
      :platforms="rawRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="rawRule?.mergeStrategy ?? 'APPEND_UNIQUE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'custom.raw_setting', $event))"
      @update:platforms="
        emit('update:rules', updateRuleMeta(rules, 'custom.raw_setting', { platforms: $event }))
      "
      @update:merge-strategy="
        emit('update:rules', updateRuleMeta(rules, 'custom.raw_setting', { mergeStrategy: $event }))
      "
    >
      <div v-if="rawRule" class="space-y-3">
        <div
          v-for="item in rawRule.config.items"
          :key="item.id"
          class="grid grid-cols-1 gap-2.5 rounded-md border border-slate-200 bg-slate-50 p-3 sm:grid-cols-6"
        >
          <select
            class="apm-input text-xs"
            aria-label="Target OS"
            :value="item.targetOs"
            @change="patchRawItem(item.id, { targetOs: ($event.target as HTMLSelectElement).value as RawSettingItem['targetOs'] })"
          >
            <option value="WINDOWS">Windows</option>
            <option value="LINUX">Linux</option>
            <option value="MACOS">macOS</option>
          </select>

          <select
            class="apm-input text-xs"
            aria-label="Engine"
            :value="item.engine"
            @change="patchRawItem(item.id, { engine: ($event.target as HTMLSelectElement).value as RawSettingItem['engine'] })"
          >
            <option value="REGISTRY">REGISTRY</option>
            <option value="DCONF">DCONF</option>
            <option value="PLIST">PLIST</option>
            <option value="SYSCTL">SYSCTL</option>
            <option value="DEFAULTS">DEFAULTS</option>
            <option value="FILE">FILE</option>
            <option value="COMMAND">COMMAND</option>
          </select>

          <input
            type="text"
            class="apm-input font-mono text-xs sm:col-span-2"
            placeholder="Path (e.g. HKLM\SOFTWARE\...)"
            :value="item.path"
            @input="patchRawItem(item.id, { path: ($event.target as HTMLInputElement).value })"
          />

          <input
            type="text"
            class="apm-input font-mono text-xs"
            placeholder="Key"
            :value="item.key"
            @input="patchRawItem(item.id, { key: ($event.target as HTMLInputElement).value })"
          />

          <div class="flex gap-1.5">
            <select
              class="apm-input w-24 text-xs"
              aria-label="Value type"
              :value="item.valueType"
              @change="patchRawItem(item.id, { valueType: ($event.target as HTMLSelectElement).value as RawSettingItem['valueType'] })"
            >
              <option value="STRING">STRING</option>
              <option value="INT">INT</option>
              <option value="BOOL">BOOL</option>
              <option value="DWORD">DWORD</option>
              <option value="JSON">JSON</option>
            </select>
            <input
              type="text"
              class="apm-input font-mono text-xs"
              placeholder="Value"
              :value="item.value"
              @input="patchRawItem(item.id, { value: ($event.target as HTMLInputElement).value })"
            />
            <button
              type="button"
              class="rounded p-1.5 text-slate-400 hover:bg-rose-50 hover:text-rose-700"
              :aria-label="t.app.delete"
              @click="removeRawItem(item.id)"
            >
              <Trash2 class="h-4 w-4" />
            </button>
          </div>
        </div>

        <button type="button" class="apm-btn-secondary text-xs" @click="addRawItem">
          <Plus class="h-3.5 w-3.5" />
          <span>{{ locale === 'de' ? 'Direkteinstellung hinzufügen' : 'Add raw setting' }}</span>
        </button>
      </div>
    </RuleCardShell>
  </div>
</template>
