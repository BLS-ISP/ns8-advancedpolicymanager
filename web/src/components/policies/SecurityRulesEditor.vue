<script setup lang="ts">
import { computed } from 'vue'
import { ALL_PLATFORMS, type PolicyRule, type UsbStorageConfig } from '@/api'
import FirewallRuleCard from './FirewallRuleCard.vue'
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

const lockRule = computed(() => findRule(props.rules, 'security.screen_lock'))
const usbRule = computed(() => findRule(props.rules, 'security.usb_storage'))

const usbOptions = computed<Array<{ mode: UsbStorageConfig['mode']; title: string; desc: string }>>(() => [
  {
    mode: 'BLOCK',
    title: locale.value === 'de' ? 'Komplett sperren' : 'Block USB storage',
    desc: locale.value === 'de' ? 'Keine USB-Sticks oder externen Festplatten.' : 'Prevents mounting removable mass storage.'
  },
  {
    mode: 'READ_ONLY',
    title: locale.value === 'de' ? 'Nur Lesen (Schreibschutz)' : 'Read-only access',
    desc: locale.value === 'de' ? 'Dateien öffnen erlaubt, Datenabfluss verhindert.' : 'Allows reading files while blocking writes.'
  },
  {
    mode: 'ALLOW',
    title: locale.value === 'de' ? 'Vollzugriff erlauben' : 'Allow full access',
    desc: locale.value === 'de' ? 'Lesen und Schreiben uneingeschränkt möglich.' : 'Unrestricted read and write access.'
  }
])
</script>

<template>
  <div class="space-y-4">
    <!-- 6. security.screen_lock -->
    <RuleCardShell
      :title="t.ruleNames['security.screen_lock']"
      :description="
        locale === 'de'
          ? 'Sperrt unbeaufsichtigte Arbeitsplätze automatisch nach Inaktivität und verlangt das Kennwort.'
          : 'Automatically locks unattended workstations after idle timeout and enforces password prompt.'
      "
      :enabled="Boolean(lockRule)"
      :platforms="lockRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="lockRule?.mergeStrategy ?? 'OVERRIDE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'security.screen_lock', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'security.screen_lock', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'security.screen_lock', { mergeStrategy: $event }))"
    >
      <div v-if="lockRule" class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div>
          <label for="lock-idle" class="apm-label">
            {{ locale === 'de' ? 'Inaktivität bis Sperre (Sekunden)' : 'Idle Timeout (Seconds)' }}
          </label>
          <input
            id="lock-idle"
            type="number"
            min="30"
            max="7200"
            step="30"
            class="apm-input"
            :value="lockRule.config.idleTimeoutSeconds"
            @input="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.screen_lock', {
                  idleTimeoutSeconds: Number(($event.target as HTMLInputElement).value) || 300
                })
              )
            "
          />
          <div class="mt-1 flex gap-1.5 text-[11px] text-blue-700">
            <button
              v-for="sec in [180, 300, 600, 900]"
              :key="sec"
              type="button"
              class="rounded bg-blue-50 px-1.5 py-0.5 hover:bg-blue-100"
              @click="emit('update:rules', updateRuleConfig(rules, 'security.screen_lock', { idleTimeoutSeconds: sec }))"
            >
              {{ sec / 60 }} min
            </button>
          </div>
        </div>

        <div>
          <label for="lock-delay" class="apm-label">
            {{ locale === 'de' ? 'Sperrverzögerung (Sekunden)' : 'Grace Delay (Seconds)' }}
          </label>
          <input
            id="lock-delay"
            type="number"
            min="0"
            max="120"
            class="apm-input"
            :value="lockRule.config.lockDelaySeconds"
            @input="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.screen_lock', {
                  lockDelaySeconds: Number(($event.target as HTMLInputElement).value) || 0
                })
              )
            "
          />
        </div>

        <div class="flex items-center pt-4">
          <label class="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-800">
            <input
              type="checkbox"
              class="h-4 w-4 rounded border-slate-300 text-blue-600"
              :checked="lockRule.config.requirePasswordOnWake"
              @change="
                emit(
                  'update:rules',
                  updateRuleConfig(rules, 'security.screen_lock', {
                    requirePasswordOnWake: ($event.target as HTMLInputElement).checked
                  })
                )
              "
            />
            <span>{{ locale === 'de' ? 'Passwort nach Ruhezustand erzwingen' : 'Require password on wake' }}</span>
          </label>
        </div>
      </div>
    </RuleCardShell>

    <!-- 7. security.usb_storage -->
    <RuleCardShell
      :title="t.ruleNames['security.usb_storage']"
      :description="
        locale === 'de'
          ? 'Schützt vor Datenverlust und Schadsoftware über externe USB-Speichermedien (Maus/Tastatur bleiben frei).'
          : 'Protects against data exfiltration via USB drives while keeping keyboards and mice unaffected.'
      "
      :enabled="Boolean(usbRule)"
      :platforms="usbRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="usbRule?.mergeStrategy ?? 'OVERRIDE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'security.usb_storage', $event))"
      @update:platforms="emit('update:rules', updateRuleMeta(rules, 'security.usb_storage', { platforms: $event }))"
      @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'security.usb_storage', { mergeStrategy: $event }))"
    >
      <div v-if="usbRule" class="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <label
          v-for="opt in usbOptions"
          :key="opt.mode"
          class="flex cursor-pointer items-start gap-2.5 rounded-md border p-3 text-xs"
          :class="usbRule.config.mode === opt.mode ? 'border-blue-600 bg-blue-50/60' : 'border-slate-200 hover:bg-slate-50'"
        >
          <input
            type="radio"
            name="usb-mode"
            class="mt-0.5 text-blue-600"
            :checked="usbRule.config.mode === opt.mode"
            @change="emit('update:rules', updateRuleConfig(rules, 'security.usb_storage', { mode: opt.mode }))"
          />
          <div>
            <div class="font-semibold text-slate-900">{{ opt.title }}</div>
            <div class="mt-0.5 text-slate-600">{{ opt.desc }}</div>
          </div>
        </label>
      </div>
    </RuleCardShell>

    <!-- 8. security.firewall -->
    <FirewallRuleCard :rules="rules" @update:rules="emit('update:rules', $event)" />
  </div>
</template>
