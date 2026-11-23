<script setup lang="ts">
import { computed, ref } from 'vue'
import { Code2 } from 'lucide-vue-next'
import type { PolicyRule, RuleType } from '@/api'
import MergeStrategyBadge from '@/components/common/MergeStrategyBadge.vue'
import OsBadges from '@/components/common/OsBadges.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{
  rule: PolicyRule
}>()

const { t } = useI18n()
const showRaw = ref(false)

const title = computed(() => {
  return (t.value.ruleNames as Record<RuleType | string, string>)[props.rule.ruleType] ?? props.rule.ruleType
})

const summaryLines = computed<string[]>(() => {
  const cfg = props.rule.config as unknown as Record<string, unknown>
  switch (props.rule.ruleType) {
    case 'access.login_access':
      return [
        `Mode: ${String(cfg.mode)}`,
        `Groups: ${(cfg.allowedGroups as string[])?.join(', ') || '—'}`,
        `Denied: ${(cfg.denyGroups as string[])?.join(', ') || '—'}`
      ]
    case 'access.local_admins':
      return [
        `Admin Groups: ${(cfg.adminGroups as string[])?.join(', ') || '—'}`,
        `Admin Users: ${(cfg.adminUsers as string[])?.join(', ') || '—'}`,
        `Passwordless Sudo: ${cfg.passwordlessSudo ? 'Yes' : 'No'}`
      ]
    case 'workspace.network_shares': {
      const mounts = (cfg.mounts as Array<{ name: string; remotePath: string; windowsDriveLetter: string }>) || []
      return mounts.map((m) => `${m.name}: ${m.remotePath} (${m.windowsDriveLetter})`)
    }
    case 'workspace.printers': {
      const printers = (cfg.printers as Array<{ name: string; uri: string; isDefault: boolean }>) || []
      return printers.map((p) => `${p.name}: ${p.uri}${p.isDefault ? ' [Default]' : ''}`)
    }
    case 'workspace.scripts': {
      const scripts = (cfg.scripts as Array<{ name: string; trigger: string; runAs: string }>) || []
      return scripts.map((s) => `${s.name} (${s.trigger} / ${s.runAs})`)
    }
    case 'security.screen_lock':
      return [
        `Idle timeout: ${String(cfg.idleTimeoutSeconds)}s`,
        `Require password on wake: ${cfg.requirePasswordOnWake ? 'Yes' : 'No'}`
      ]
    case 'security.usb_storage':
      return [`USB Mode: ${String(cfg.mode)}`]
    case 'security.firewall':
      return [
        `Firewall: ${cfg.isEnabled ? 'Enabled' : 'Disabled'} (${String(cfg.defaultInbound)})`,
        `TCP Ports: ${(cfg.allowedTcpPorts as number[])?.join(', ') || '—'}`
      ]
    case 'desktop.browser':
      return [
        `Browsers: ${(cfg.targets as string[])?.join(', ')}`,
        `Homepage: ${String(cfg.homepageUrl || '—')}`,
        `Incognito Disabled: ${cfg.disableIncognito ? 'Yes' : 'No'}`
      ]
    case 'desktop.wallpaper':
      return [`URL: ${String(cfg.imageUrl || '—')} (${String(cfg.fitMode)})`]
    case 'desktop.system_restrictions':
      return [
        `Control Panel blocked: ${cfg.disableControlPanel ? 'Yes' : 'No'}`,
        `Registry/dconf blocked: ${cfg.disableRegistryTools ? 'Yes' : 'No'}`
      ]
    default:
      return [JSON.stringify(cfg)]
  }
})
</script>

<template>
  <article class="rounded-lg border border-slate-200 bg-white p-4">
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div>
        <h3 class="text-sm font-semibold text-slate-900">{{ title }}</h3>
        <div class="font-mono text-[11px] text-slate-500">{{ rule.ruleType }}</div>
      </div>
      <div class="flex items-center gap-1.5">
        <OsBadges :platforms="rule.platforms" compact />
        <MergeStrategyBadge :strategy="rule.mergeStrategy" short />
        <button
          type="button"
          class="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
          :title="t.simulator.toggleJson"
          :aria-label="t.simulator.toggleJson"
          @click="showRaw = !showRaw"
        >
          <Code2 class="h-3.5 w-3.5" />
        </button>
      </div>
    </div>

    <ul v-if="!showRaw" class="mt-2.5 space-y-1 text-xs text-slate-700">
      <li v-for="(line, i) in summaryLines" :key="i" class="font-mono">{{ line }}</li>
    </ul>
    <pre
      v-else
      class="mt-2.5 overflow-x-auto rounded bg-slate-900 p-3 font-mono text-xs text-emerald-300"
    ><code>{{ JSON.stringify(rule.config, null, 2) }}</code></pre>
  </article>
</template>
