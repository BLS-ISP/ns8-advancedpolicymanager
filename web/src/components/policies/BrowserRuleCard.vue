<script setup lang="ts">
import { computed } from 'vue'
import { ALL_PLATFORMS, type BrowserTarget, type PolicyRule } from '@/api'
import RuleCardShell from './RuleCardShell.vue'
import { findRule, toggleRuleInList, updateRuleConfig, updateRuleMeta } from './useRuleAccessor'
import { useI18n } from '@/i18n'

const props = defineProps<{
  rules: PolicyRule[]
}>()

const emit = defineEmits<{
  (e: 'update:rules', value: PolicyRule[]): void
}>()

const { t, locale } = useI18n()
const browserRule = computed(() => findRule(props.rules, 'desktop.browser'))
const allBrowsers: BrowserTarget[] = ['CHROME', 'EDGE', 'FIREFOX']

function toggleBrowserTarget(target: BrowserTarget) {
  if (!browserRule.value) return
  const curr = browserRule.value.config.targets
  const next = curr.includes(target)
    ? curr.length > 1
      ? curr.filter((b) => b !== target)
      : curr
    : [...curr, target]
  emit('update:rules', updateRuleConfig(props.rules, 'desktop.browser', { targets: next }))
}
</script>

<template>
  <RuleCardShell
    :title="t.ruleNames['desktop.browser']"
    :description="
      locale === 'de'
        ? 'Konfiguriert Startseite, Inkognito-Sperre und Erweiterungen für Google Chrome, Microsoft Edge und Mozilla Firefox.'
        : 'Manages enterprise policies for Google Chrome, Microsoft Edge, and Mozilla Firefox.'
    "
    :enabled="Boolean(browserRule)"
    :platforms="browserRule?.platforms ?? ALL_PLATFORMS"
    :merge-strategy="browserRule?.mergeStrategy ?? 'OVERRIDE'"
    @update:enabled="emit('update:rules', toggleRuleInList(rules, 'desktop.browser', $event))"
    @update:platforms="emit('update:rules', updateRuleMeta(rules, 'desktop.browser', { platforms: $event }))"
    @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'desktop.browser', { mergeStrategy: $event }))"
  >
    <div v-if="browserRule" class="space-y-4">
      <div class="flex flex-wrap items-center gap-3 text-xs">
        <span class="font-semibold text-slate-700">
          {{ locale === 'de' ? 'Verwaltete Browser:' : 'Managed Browsers:' }}
        </span>
        <label
          v-for="br in allBrowsers"
          :key="br"
          class="inline-flex cursor-pointer items-center gap-1.5 rounded border px-2.5 py-1 font-medium"
          :class="
            browserRule.config.targets.includes(br)
              ? 'border-blue-600 bg-blue-50 text-blue-900'
              : 'border-slate-200 text-slate-600'
          "
        >
          <input
            type="checkbox"
            class="h-3.5 w-3.5 rounded border-slate-300 text-blue-600"
            :checked="browserRule.config.targets.includes(br)"
            @change="toggleBrowserTarget(br)"
          />
          <span>{{ br }}</span>
        </label>
      </div>

      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label for="br-home" class="apm-label">
            {{ locale === 'de' ? 'Startseiten-URL' : 'Homepage URL' }}
          </label>
          <input
            id="br-home"
            type="url"
            class="apm-input"
            placeholder="https://intranet.firma.local"
            :value="browserRule.config.homepageUrl"
            @input="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.browser', {
                  homepageUrl: ($event.target as HTMLInputElement).value
                })
              )
            "
          />
        </div>

        <div>
          <label for="br-startup" class="apm-label">
            {{ locale === 'de' ? 'Beim Programmstart öffnen' : 'On Startup Behavior' }}
          </label>
          <select
            id="br-startup"
            class="apm-input"
            :value="browserRule.config.restoreOnStartup"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.browser', {
                  restoreOnStartup: ($event.target as HTMLSelectElement).value as 'HOMEPAGE' | 'LAST_SESSION'
                })
              )
            "
          >
            <option value="HOMEPAGE">{{ locale === 'de' ? 'Startseite laden' : 'Open homepage' }}</option>
            <option value="LAST_SESSION">{{ locale === 'de' ? 'Letzte Sitzung wiederherstellen' : 'Restore last session' }}</option>
          </select>
        </div>
      </div>

      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div class="space-y-2 pt-1 text-xs">
          <label class="flex cursor-pointer items-center gap-2 text-slate-800">
            <input
              type="checkbox"
              class="h-4 w-4 rounded border-slate-300 text-blue-600"
              :checked="browserRule.config.disableIncognito"
              @change="
                emit(
                  'update:rules',
                  updateRuleConfig(rules, 'desktop.browser', {
                    disableIncognito: ($event.target as HTMLInputElement).checked
                  })
                )
              "
            />
            <span>{{ locale === 'de' ? 'Inkognito-/Privatmodus deaktivieren' : 'Disable incognito / private browsing' }}</span>
          </label>
          <label class="flex cursor-pointer items-center gap-2 text-slate-800">
            <input
              type="checkbox"
              class="h-4 w-4 rounded border-slate-300 text-blue-600"
              :checked="browserRule.config.disablePasswordManager"
              @change="
                emit(
                  'update:rules',
                  updateRuleConfig(rules, 'desktop.browser', {
                    disablePasswordManager: ($event.target as HTMLInputElement).checked
                  })
                )
              "
            />
            <span>{{ locale === 'de' ? 'Integrierten Passwortmanager deaktivieren' : 'Disable built-in password manager' }}</span>
          </label>
        </div>

        <div>
          <label for="br-ext" class="apm-label">
            {{ locale === 'de' ? 'Erzwungene Erweiterungs-IDs (kommagetrennt)' : 'Forced Extension IDs (comma-separated)' }}
          </label>
          <input
            id="br-ext"
            type="text"
            class="apm-input font-mono text-xs"
            placeholder="cjpalhdlnbpafiamejdnhcphjbkeiagm"
            :value="browserRule.config.forceExtensions.join(', ')"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.browser', {
                  forceExtensions: ($event.target as HTMLInputElement).value
                    .split(',')
                    .map((s) => s.trim())
                    .filter(Boolean)
                })
              )
            "
          />
        </div>
      </div>
    </div>
  </RuleCardShell>
</template>
