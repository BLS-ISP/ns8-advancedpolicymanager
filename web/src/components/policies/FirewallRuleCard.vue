<script setup lang="ts">
import { computed } from 'vue'
import { ALL_PLATFORMS, type PolicyRule } from '@/api'
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
const fwRule = computed(() => findRule(props.rules, 'security.firewall'))

function parsePorts(input: string): number[] {
  return Array.from(
    new Set(
      input
        .split(',')
        .map((p) => Number.parseInt(p.trim(), 10))
        .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535)
    )
  )
}
</script>

<template>
  <RuleCardShell
    :title="t.ruleNames['security.firewall']"
    :description="
      locale === 'de'
        ? 'Aktiviert die Host-Firewall (Windows Defender Firewall, UFW/nftables, macOS Application Firewall) und regelt eingehende Ports.'
        : 'Configures the native OS host firewall and allowed inbound TCP/UDP ports.'
    "
    :enabled="Boolean(fwRule)"
    :platforms="fwRule?.platforms ?? ALL_PLATFORMS"
    :merge-strategy="fwRule?.mergeStrategy ?? 'OVERRIDE'"
    @update:enabled="emit('update:rules', toggleRuleInList(rules, 'security.firewall', $event))"
    @update:platforms="emit('update:rules', updateRuleMeta(rules, 'security.firewall', { platforms: $event }))"
    @update:merge-strategy="emit('update:rules', updateRuleMeta(rules, 'security.firewall', { mergeStrategy: $event }))"
  >
    <div v-if="fwRule" class="space-y-4">
      <div class="flex flex-wrap gap-6 text-xs">
        <label class="inline-flex cursor-pointer items-center gap-2 font-medium text-slate-800">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="fwRule.config.isEnabled"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.firewall', {
                  isEnabled: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>{{ locale === 'de' ? 'Host-Firewall aktivieren' : 'Enable host firewall' }}</span>
        </label>

        <label class="inline-flex cursor-pointer items-center gap-2 font-medium text-slate-800">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="fwRule.config.allowStealthMode"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.firewall', {
                  allowStealthMode: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>{{ locale === 'de' ? 'Stealth-Modus aktivieren' : 'Enable stealth mode' }}</span>
        </label>
      </div>

      <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div>
          <label for="fw-inbound" class="apm-label">
            {{ locale === 'de' ? 'Standard Eingehend' : 'Default Inbound Policy' }}
          </label>
          <select
            id="fw-inbound"
            class="apm-input"
            :value="fwRule.config.defaultInbound"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.firewall', {
                  defaultInbound: ($event.target as HTMLSelectElement).value as 'BLOCK' | 'ALLOW'
                })
              )
            "
          >
            <option value="BLOCK">{{ locale === 'de' ? 'Blockieren (Empfohlen)' : 'Block (Recommended)' }}</option>
            <option value="ALLOW">{{ locale === 'de' ? 'Erlauben' : 'Allow' }}</option>
          </select>
        </div>

        <div>
          <label for="fw-tcp" class="apm-label">{{ locale === 'de' ? 'Erlaubte TCP-Ports' : 'Allowed TCP Ports' }}</label>
          <input
            id="fw-tcp"
            type="text"
            class="apm-input font-mono"
            placeholder="22, 3389"
            :value="fwRule.config.allowedTcpPorts.join(', ')"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.firewall', {
                  allowedTcpPorts: parsePorts(($event.target as HTMLInputElement).value)
                })
              )
            "
          />
        </div>

        <div>
          <label for="fw-udp" class="apm-label">{{ locale === 'de' ? 'Erlaubte UDP-Ports' : 'Allowed UDP Ports' }}</label>
          <input
            id="fw-udp"
            type="text"
            class="apm-input font-mono"
            placeholder="5353"
            :value="fwRule.config.allowedUdpPorts.join(', ')"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'security.firewall', {
                  allowedUdpPorts: parsePorts(($event.target as HTMLInputElement).value)
                })
              )
            "
          />
        </div>
      </div>
    </div>
  </RuleCardShell>
</template>
