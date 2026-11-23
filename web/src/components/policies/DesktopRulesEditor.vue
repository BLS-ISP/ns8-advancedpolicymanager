<script setup lang="ts">
import { computed } from 'vue'
import { ALL_PLATFORMS, type PolicyRule, type WallpaperConfig } from '@/api'
import BrowserRuleCard from './BrowserRuleCard.vue'
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

const wallpaperRule = computed(() => findRule(props.rules, 'desktop.wallpaper'))
const restrictRule = computed(() => findRule(props.rules, 'desktop.system_restrictions'))
</script>

<template>
  <div class="space-y-4">
    <!-- 9. desktop.browser -->
    <BrowserRuleCard :rules="rules" @update:rules="emit('update:rules', $event)" />

    <!-- 10. desktop.wallpaper -->
    <RuleCardShell
      :title="t.ruleNames['desktop.wallpaper']"
      :description="
        locale === 'de'
          ? 'Setzt ein einheitliches Unternehmens-Hintergrundbild und sperrt auf Wunsch manuelle Änderungen.'
          : 'Deploys a corporate desktop wallpaper and optionally locks user customization.'
      "
      :enabled="Boolean(wallpaperRule)"
      :platforms="wallpaperRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="wallpaperRule?.mergeStrategy ?? 'OVERRIDE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'desktop.wallpaper', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'desktop.wallpaper', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'desktop.wallpaper', { mergeStrategy: $event }))"
    >
      <div v-if="wallpaperRule" class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div class="sm:col-span-2">
          <label for="wp-url" class="apm-label">
            {{ locale === 'de' ? 'Bild-URL (HTTPS / Intranet)' : 'Wallpaper Image URL' }}
          </label>
          <input
            id="wp-url"
            type="url"
            class="apm-input"
            placeholder="https://intranet.firma.local/wallpaper.jpg"
            :value="wallpaperRule.config.imageUrl"
            @input="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.wallpaper', {
                  imageUrl: ($event.target as HTMLInputElement).value
                })
              )
            "
          />
        </div>
        <div>
          <label for="wp-fit" class="apm-label">{{ locale === 'de' ? 'Bildanpassung' : 'Fit Mode' }}</label>
          <select
            id="wp-fit"
            class="apm-input"
            :value="wallpaperRule.config.fitMode"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.wallpaper', {
                  fitMode: ($event.target as HTMLSelectElement).value as WallpaperConfig['fitMode']
                })
              )
            "
          >
            <option value="FILL">Fill</option>
            <option value="FIT">Fit</option>
            <option value="CENTER">Center</option>
          </select>
          <label class="mt-2 inline-flex cursor-pointer items-center gap-2 text-xs text-slate-800">
            <input
              type="checkbox"
              class="h-4 w-4 rounded border-slate-300 text-blue-600"
              :checked="wallpaperRule.config.isLocked"
              @change="
                emit(
                  'update:rules',
                  updateRuleConfig(rules, 'desktop.wallpaper', {
                    isLocked: ($event.target as HTMLInputElement).checked
                  })
                )
              "
            />
            <span>{{ locale === 'de' ? 'Änderung durch Benutzer sperren' : 'Lock wallpaper against changes' }}</span>
          </label>
        </div>
      </div>
    </RuleCardShell>

    <!-- 11. desktop.system_restrictions -->
    <RuleCardShell
      :title="t.ruleNames['desktop.system_restrictions']"
      :description="
        locale === 'de'
          ? 'Verhindert unerwünschte Systemeingriffe an gemeinsam genutzten oder abgesicherten Arbeitsplätzen.'
          : 'Restricts access to system configuration utilities on locked-down workstations.'
      "
      :enabled="Boolean(restrictRule)"
      :platforms="restrictRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="restrictRule?.mergeStrategy ?? 'OVERRIDE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'desktop.system_restrictions', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'desktop.system_restrictions', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'desktop.system_restrictions', { mergeStrategy: $event }))"
    >
      <div v-if="restrictRule" class="space-y-2.5 text-xs">
        <label class="flex cursor-pointer items-center gap-2.5 text-slate-800">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="restrictRule.config.disableControlPanel"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.system_restrictions', {
                  disableControlPanel: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>
            {{
              locale === 'de'
                ? 'Systemsteuerung / Systemeinstellungen für Standardbenutzer ausblenden'
                : 'Disable Control Panel / System Settings for standard users'
            }}
          </span>
        </label>

        <label class="flex cursor-pointer items-center gap-2.5 text-slate-800">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="restrictRule.config.disableRegistryTools"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.system_restrictions', {
                  disableRegistryTools: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>
            {{
              locale === 'de'
                ? 'Registry-Editor (regedit) & dconf-Editor sperren'
                : 'Disable Registry Editor (regedit) & dconf configuration tools'
            }}
          </span>
        </label>

        <label class="flex cursor-pointer items-center gap-2.5 text-slate-800">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="restrictRule.config.disableTerminalForStandardUsers"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'desktop.system_restrictions', {
                  disableTerminalForStandardUsers: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>
            {{
              locale === 'de'
                ? 'Eingabeaufforderung / Terminal für Nicht-Administratoren einschränken'
                : 'Restrict Command Prompt / Terminal for standard non-admin users'
            }}
          </span>
        </label>
      </div>
    </RuleCardShell>
  </div>
</template>
