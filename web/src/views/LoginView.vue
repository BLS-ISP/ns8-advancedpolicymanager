<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { AlertCircle, Globe, Info, Lock, Shield, User } from 'lucide-vue-next'
import { api, ApiRequestError, type HealthResponse } from '@/api'
import { useAuth } from '@/composables/useAuth'
import { useI18n } from '@/i18n'

const router = useRouter()
const route = useRoute()
const { login, authLoading } = useAuth()
const { locale, setLocale, t } = useI18n()

const username = ref('')
const password = ref('')
const errorMessage = ref<string | null>(null)
const errorCode = ref<string | null>(null)
const health = ref<HealthResponse | null>(null)
const isDevBuild = import.meta.env.DEV

onMounted(async () => {
  try {
    health.value = await api.health()
  } catch {
    health.value = null
  }
})

function fillDemoCredentials() {
  username.value = 'administrator'
  password.value = 'Admin123!'
  errorMessage.value = null
}

async function handleSubmit() {
  errorMessage.value = null
  errorCode.value = null
  if (!username.value.trim() || !password.value) {
    return
  }
  try {
    await login({
      username: username.value.trim(),
      password: password.value
    })
    const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboard'
    await router.push(redirect)
  } catch (err) {
    if (err instanceof ApiRequestError) {
      errorMessage.value = err.message
      errorCode.value = err.code
    } else {
      errorMessage.value = err instanceof Error ? err.message : 'Login failed'
    }
  }
}
</script>

<template>
  <div class="flex min-h-screen flex-col justify-between bg-slate-100 p-4 sm:p-6">
    <div class="flex justify-end">
      <div
        class="inline-flex items-center rounded-md border border-slate-200 bg-white p-0.5 shadow-sm"
        role="group"
        aria-label="Language selector"
      >
        <Globe class="ml-2 mr-1 h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
        <button
          type="button"
          class="rounded px-2.5 py-1 text-xs font-semibold"
          :class="locale === 'de' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'"
          @click="setLocale('de')"
        >
          Deutsch
        </button>
        <button
          type="button"
          class="rounded px-2.5 py-1 text-xs font-semibold"
          :class="locale === 'en' ? 'bg-blue-600 text-white' : 'text-slate-600 hover:text-slate-900'"
          @click="setLocale('en')"
        >
          English
        </button>
      </div>
    </div>

    <div class="mx-auto w-full max-w-md">
      <div class="mb-6 text-center">
        <div class="mx-auto mb-3 flex h-11 w-11 items-center justify-center rounded-lg bg-slate-900 text-white shadow-sm">
          <Shield class="h-6 w-6 text-blue-400" aria-hidden="true" />
        </div>
        <h1 class="text-xl font-bold tracking-tight text-slate-900">{{ t.app.title }}</h1>
        <p class="mt-1 text-sm text-slate-600">{{ t.app.subtitle }}</p>
        <div
          v-if="health?.ldapDomain"
          class="mt-2 inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-3 py-0.5 text-xs text-slate-700"
        >
          <span class="h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
          <span>{{ t.login.domainConnected }}:</span>
          <strong class="font-mono font-semibold">{{ health.ldapDomain }}</strong>
        </div>
      </div>

      <div class="apm-card p-6 shadow-sm">
        <h2 class="text-base font-semibold text-slate-900">{{ t.login.heading }}</h2>
        <p class="mt-1 text-xs text-slate-600">{{ t.login.subheading }}</p>

        <div
          v-if="errorMessage"
          role="alert"
          class="mt-4 flex items-start gap-2.5 rounded-md border border-rose-200 bg-rose-50 p-3 text-xs text-rose-800"
        >
          <AlertCircle class="mt-0.5 h-4 w-4 shrink-0 text-rose-600" aria-hidden="true" />
          <div>
            <div class="font-semibold">{{ errorMessage }}</div>
            <div v-if="errorCode" class="mt-0.5 font-mono text-[11px] text-rose-700">
              Code: {{ errorCode }}
            </div>
          </div>
        </div>

        <form class="mt-5 space-y-4" @submit.prevent="handleSubmit">
          <div>
            <label for="login-username" class="apm-label">{{ t.login.username }}</label>
            <div class="relative">
              <User class="pointer-events-none absolute left-3 top-2 h-4 w-4 text-slate-400" aria-hidden="true" />
              <input
                id="login-username"
                v-model="username"
                type="text"
                required
                autocomplete="username"
                class="apm-input pl-9"
                placeholder="administrator"
              />
            </div>
          </div>

          <div>
            <label for="login-password" class="apm-label">{{ t.login.password }}</label>
            <div class="relative">
              <Lock class="pointer-events-none absolute left-3 top-2 h-4 w-4 text-slate-400" aria-hidden="true" />
              <input
                id="login-password"
                v-model="password"
                type="password"
                required
                autocomplete="current-password"
                class="apm-input pl-9"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            class="apm-btn-primary w-full py-2.5"
            :disabled="authLoading || !username.trim() || !password"
          >
            {{ authLoading ? t.login.submitting : t.login.submit }}
          </button>
        </form>

        <div
          v-if="!health || health.ldapMode === 'mock' || isDevBuild"
          class="mt-5 rounded-md border border-blue-200 bg-blue-50/70 p-3 text-xs text-slate-700"
        >
          <div class="flex items-center gap-1.5 font-semibold text-blue-900">
            <Info class="h-3.5 w-3.5 text-blue-600" aria-hidden="true" />
            <span>{{ t.login.devHintTitle }}</span>
          </div>
          <p class="mt-1 text-slate-600">{{ t.login.devHintText }}</p>
          <button
            type="button"
            class="mt-2 font-semibold text-blue-700 underline hover:text-blue-900"
            @click="fillDemoCredentials"
          >
            {{ t.login.fillDemo }}
          </button>
        </div>
      </div>
    </div>

    <div class="text-center text-xs text-slate-500">
      NethServer 8 · Advanced Policy Manager {{ health?.version ? `v${health.version}` : '' }}
    </div>
  </div>
</template>
