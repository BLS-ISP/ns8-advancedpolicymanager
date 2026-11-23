<script setup lang="ts">
import { computed, ref } from 'vue'
import { Check, Copy, Terminal } from 'lucide-vue-next'
import type { InstallCommands, OsFamily } from '@/api'
import OsBadge from '@/components/common/OsBadge.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{
  commands?: InstallCommands | null
  plainToken?: string | null
}>()

const { t, locale } = useI18n()
const activeOs = ref<OsFamily>('WINDOWS')
const copiedKey = ref<string | null>(null)

const resolvedCommands = computed<InstallCommands>(() => {
  if (props.commands) {
    return props.commands
  }
  const base = typeof window !== 'undefined' ? window.location.origin : 'https://policies.example.org'
  const tok = props.plainToken || '<ENROLL_TOKEN>'
  return {
    windowsPowershell: `$env:APM_TOKEN="${tok}"; irm "${base}/api/v1/installers/install.ps1" | iex`,
    linuxBash: `curl -fsSL "${base}/api/v1/installers/install-linux.sh" | sudo APM_TOKEN="${tok}" bash`,
    macosZsh: `curl -fsSL "${base}/api/v1/installers/install-macos.sh" | sudo APM_TOKEN="${tok}" zsh`
  }
})

const activeTabMeta = computed(() => {
  if (activeOs.value === 'WINDOWS') {
    return {
      shell: 'Windows PowerShell (Administrator)',
      cmd: resolvedCommands.value.windowsPowershell,
      note:
        locale.value === 'de'
          ? 'Lädt das Agent-Binary herunter, registriert den Computer per Token und richtet den Windows-Dienst „NS8PolicyAgent“ ein.'
          : 'Downloads the agent binary, enrolls the endpoint with the token, and registers the "NS8PolicyAgent" Windows service.'
    }
  }
  if (activeOs.value === 'LINUX') {
    return {
      shell: 'Linux Bash / systemd (root / sudo)',
      cmd: resolvedCommands.value.linuxBash,
      note:
        locale.value === 'de'
          ? 'Installiert /usr/local/bin/ns8-policy-agent und aktiviert die systemd-Unit ns8-policy-agent.service.'
          : 'Installs /usr/local/bin/ns8-policy-agent and enables the ns8-policy-agent.service systemd unit.'
    }
  }
  return {
    shell: 'macOS Zsh / LaunchDaemon (sudo)',
    cmd: resolvedCommands.value.macosZsh,
    note:
      locale.value === 'de'
        ? 'Installiert den Agenten und aktiviert /Library/LaunchDaemons/org.nethserver.policyagent.plist.'
        : 'Installs the agent and loads /Library/LaunchDaemons/org.nethserver.policyagent.plist.'
  }
})

async function copyText(text: string, key: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedKey.value = key
    setTimeout(() => {
      if (copiedKey.value === key) copiedKey.value = null
    }, 2000)
  } catch {
    // Clipboard fallback ignored
  }
}
</script>

<template>
  <section class="apm-card p-5">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 class="text-base font-semibold text-slate-900">{{ t.enroll.commandsTitle }}</h2>
        <p class="mt-0.5 text-xs text-slate-600">{{ t.enroll.commandsHint }}</p>
      </div>

      <div class="inline-flex rounded-md border border-slate-200 bg-slate-50 p-1" role="tablist">
        <button
          v-for="os in (['WINDOWS', 'LINUX', 'MACOS'] as OsFamily[])"
          :key="os"
          type="button"
          role="tab"
          :aria-selected="activeOs === os"
          class="rounded px-2.5 py-1 transition-colors"
          :class="activeOs === os ? 'bg-white shadow-sm ring-1 ring-slate-200' : 'opacity-70 hover:opacity-100'"
          @click="activeOs = os"
        >
          <OsBadge :os="os" compact />
        </button>
      </div>
    </div>

    <div class="mt-4 rounded-lg border border-slate-800 bg-slate-900 p-4 text-slate-100">
      <div class="mb-2 flex items-center justify-between text-xs text-slate-400">
        <span class="inline-flex items-center gap-1.5 font-medium">
          <Terminal class="h-3.5 w-3.5 text-blue-400" aria-hidden="true" />
          <span>{{ activeTabMeta.shell }}</span>
        </span>
        <button
          type="button"
          class="inline-flex items-center gap-1.5 rounded bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700"
          @click="copyText(activeTabMeta.cmd, activeOs)"
        >
          <Check v-if="copiedKey === activeOs" class="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
          <Copy v-else class="h-3.5 w-3.5" aria-hidden="true" />
          <span>{{ copiedKey === activeOs ? t.app.copied : t.app.copy }}</span>
        </button>
      </div>
      <pre class="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs leading-relaxed text-emerald-300"><code>{{ activeTabMeta.cmd }}</code></pre>
    </div>

    <p class="mt-2.5 text-xs text-slate-600">{{ activeTabMeta.note }}</p>
  </section>
</template>
