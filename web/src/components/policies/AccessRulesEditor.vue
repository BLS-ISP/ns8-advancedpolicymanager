<script setup lang="ts">
import { computed } from 'vue'
import { ALL_PLATFORMS, type PolicyRule } from '@/api'
import DirectoryPicker from '@/components/common/DirectoryPicker.vue'
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

const loginRule = computed(() => findRule(props.rules, 'access.login_access'))
const adminsRule = computed(() => findRule(props.rules, 'access.local_admins'))
</script>

<template>
  <div class="space-y-4">
    <!-- 1. access.login_access -->
    <RuleCardShell
      :title="t.ruleNames['access.login_access']"
      :description="
        locale === 'de'
          ? 'Legt fest, welche AD/LDAP-Gruppen und Benutzer sich an diesem Computer anmelden dürfen.'
          : 'Controls which AD/LDAP groups and users are permitted to log on to the workstation.'
      "
      :enabled="Boolean(loginRule)"
      :platforms="loginRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="loginRule?.mergeStrategy ?? 'OVERRIDE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'access.login_access', $event))"
      @update:platforms="
        emit('update:rules', updateRuleMeta(rules, 'access.login_access', { platforms: $event }))
      "
      @update:merge-strategy="
        emit('update:rules', updateRuleMeta(rules, 'access.login_access', { mergeStrategy: $event }))
      "
    >
      <div v-if="loginRule" class="space-y-4">
        <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label
            class="flex cursor-pointer items-start gap-2.5 rounded-md border p-3 text-xs"
            :class="
              loginRule.config.mode === 'ALLOW_ALL'
                ? 'border-blue-600 bg-blue-50/60'
                : 'border-slate-200 hover:bg-slate-50'
            "
          >
            <input
              type="radio"
              name="login-access-mode"
              class="mt-0.5 text-blue-600"
              :checked="loginRule.config.mode === 'ALLOW_ALL'"
              @change="
                emit('update:rules', updateRuleConfig(rules, 'access.login_access', { mode: 'ALLOW_ALL' }))
              "
            />
            <div>
              <div class="font-semibold text-slate-900">
                {{ locale === 'de' ? 'Alle Domänenbenutzer erlauben' : 'Allow all domain users' }}
              </div>
              <div class="text-slate-600">
                {{
                  locale === 'de'
                    ? 'Jedes gültige Konto darf sich anmelden (sofern nicht unten gesperrt).'
                    : 'Any valid directory user may log in unless explicitly denied below.'
                }}
              </div>
            </div>
          </label>

          <label
            class="flex cursor-pointer items-start gap-2.5 rounded-md border p-3 text-xs"
            :class="
              loginRule.config.mode === 'ALLOW_LIST'
                ? 'border-blue-600 bg-blue-50/60'
                : 'border-slate-200 hover:bg-slate-50'
            "
          >
            <input
              type="radio"
              name="login-access-mode"
              class="mt-0.5 text-blue-600"
              :checked="loginRule.config.mode === 'ALLOW_LIST'"
              @change="
                emit('update:rules', updateRuleConfig(rules, 'access.login_access', { mode: 'ALLOW_LIST' }))
              "
            />
            <div>
              <div class="font-semibold text-slate-900">
                {{ locale === 'de' ? 'Nur freigegebene Gruppen / Benutzer' : 'Allow listed groups & users only' }}
              </div>
              <div class="text-slate-600">
                {{
                  locale === 'de'
                    ? 'Beschränkt die Anmeldung strikt auf ausgewählte Abteilungen.'
                    : 'Restricts interactive login strictly to selected teams or users.'
                }}
              </div>
            </div>
          </label>
        </div>

        <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
          <DirectoryPicker
            v-if="loginRule.config.mode === 'ALLOW_LIST'"
            kind="GROUP"
            multiple
            input-id="login-allowed-groups"
            :label="locale === 'de' ? 'Erlaubte Gruppen' : 'Allowed Groups'"
            :placeholder="locale === 'de' ? 'Gruppe suchen…' : 'Search group…'"
            :values="loginRule.config.allowedGroups"
            @update:values="
              emit('update:rules', updateRuleConfig(rules, 'access.login_access', { allowedGroups: $event }))
            "
          />
          <DirectoryPicker
            v-if="loginRule.config.mode === 'ALLOW_LIST'"
            kind="USER"
            multiple
            input-id="login-allowed-users"
            :label="locale === 'de' ? 'Erlaubte Einzelbenutzer' : 'Allowed Users'"
            :placeholder="locale === 'de' ? 'Benutzer suchen…' : 'Search user…'"
            :values="loginRule.config.allowedUsers"
            @update:values="
              emit('update:rules', updateRuleConfig(rules, 'access.login_access', { allowedUsers: $event }))
            "
          />
          <DirectoryPicker
            kind="GROUP"
            multiple
            input-id="login-deny-groups"
            :label="locale === 'de' ? 'Explizit gesperrte Gruppen' : 'Explicitly Denied Groups'"
            :placeholder="locale === 'de' ? 'Sperrgruppe suchen…' : 'Search denied group…'"
            :values="loginRule.config.denyGroups"
            @update:values="
              emit('update:rules', updateRuleConfig(rules, 'access.login_access', { denyGroups: $event }))
            "
          />
        </div>
      </div>
    </RuleCardShell>

    <!-- 2. access.local_admins -->
    <RuleCardShell
      :title="t.ruleNames['access.local_admins']"
      :description="
        locale === 'de'
          ? 'Fügt AD/LDAP-Gruppen oder Benutzer kontrolliert zu den lokalen Administratoren bzw. sudoers hinzu (bestehende lokale Admins bleiben beim Rollback unangetastet).'
          : 'Grants local Administrator / sudo rights to directory groups or users (pre-existing local admins are preserved on rollback).'
      "
      :enabled="Boolean(adminsRule)"
      :platforms="adminsRule?.platforms ?? ALL_PLATFORMS"
      :merge-strategy="adminsRule?.mergeStrategy ?? 'APPEND_UNIQUE'"
      @update:enabled="emit('update:rules', toggleRuleInList(rules, 'access.local_admins', $event))"
      @update:platforms="
        emit('update:rules', updateRuleMeta(rules, 'access.local_admins', { platforms: $event }))
      "
      @update:merge-strategy="
        emit('update:rules', updateRuleMeta(rules, 'access.local_admins', { mergeStrategy: $event }))
      "
    >
      <div v-if="adminsRule" class="space-y-4">
        <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
          <DirectoryPicker
            kind="GROUP"
            multiple
            input-id="local-admin-groups"
            :label="locale === 'de' ? 'Administrator-Gruppen' : 'Administrator Groups'"
            :placeholder="locale === 'de' ? 'z. B. IT-Admins…' : 'e.g. IT-Admins…'"
            :values="adminsRule.config.adminGroups"
            @update:values="
              emit('update:rules', updateRuleConfig(rules, 'access.local_admins', { adminGroups: $event }))
            "
          />
          <DirectoryPicker
            kind="USER"
            multiple
            input-id="local-admin-users"
            :label="locale === 'de' ? 'Einzelne Administratoren' : 'Individual Admin Users'"
            :placeholder="locale === 'de' ? 'Benutzer suchen…' : 'Search user…'"
            :values="adminsRule.config.adminUsers"
            @update:values="
              emit('update:rules', updateRuleConfig(rules, 'access.local_admins', { adminUsers: $event }))
            "
          />
        </div>

        <label class="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-700">
          <input
            type="checkbox"
            class="h-4 w-4 rounded border-slate-300 text-blue-600"
            :checked="adminsRule.config.passwordlessSudo"
            @change="
              emit(
                'update:rules',
                updateRuleConfig(rules, 'access.local_admins', {
                  passwordlessSudo: ($event.target as HTMLInputElement).checked
                })
              )
            "
          />
          <span>
            {{
              locale === 'de'
                ? 'Passwortloses Sudo unter Linux & macOS erlauben (NOPASSWD)'
                : 'Allow passwordless sudo on Linux & macOS (NOPASSWD)'
            }}
          </span>
        </label>
      </div>
    </RuleCardShell>
  </div>
</template>
