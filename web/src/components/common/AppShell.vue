<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  FileSliders,
  FlaskConical,
  Globe,
  LayoutDashboard,
  ListOrdered,
  LogOut,
  Menu,
  MonitorSmartphone,
  Shield,
  TerminalSquare,
  X
} from 'lucide-vue-next'
import { useAuth } from '@/composables/useAuth'
import { useI18n } from '@/i18n'

const route = useRoute()
const router = useRouter()
const { currentUser, logout } = useAuth()
const { locale, setLocale, t } = useI18n()

const mobileOpen = ref(false)

const navItems = computed(() => [
  { to: '/dashboard', label: t.value.app.nav.dashboard, icon: LayoutDashboard },
  { to: '/policies', label: t.value.app.nav.policies, icon: FileSliders },
  { to: '/assignments', label: t.value.app.nav.assignments, icon: ListOrdered },
  { to: '/simulator', label: t.value.app.nav.simulator, icon: FlaskConical },
  { to: '/devices', label: t.value.app.nav.devices, icon: MonitorSmartphone },
  { to: '/enroll', label: t.value.app.nav.enroll, icon: TerminalSquare }
])

async function handleLogout() {
  await logout()
  await router.push('/login')
}

function isRouteActive(path: string): boolean {
  return route.path === path || route.path.startsWith(`${path}/`)
}
</script>

<template>
  <div class="flex min-h-screen bg-slate-50 text-slate-900">
    <!-- Mobile backdrop -->
    <div
      v-if="mobileOpen"
      class="fixed inset-0 z-30 bg-slate-900/50 lg:hidden"
      @click="mobileOpen = false"
    />

    <!-- Sidebar -->
    <aside
      class="fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-slate-800 bg-slate-900 text-slate-200 transition-transform lg:static lg:translate-x-0"
      :class="mobileOpen ? 'translate-x-0' : '-translate-x-full'"
    >
      <div class="flex h-14 items-center justify-between border-b border-slate-800 px-4">
        <div class="flex items-center gap-2.5">
          <div class="flex h-8 w-8 items-center justify-center rounded-md bg-blue-600 text-white">
            <Shield class="h-4 w-4" aria-hidden="true" />
          </div>
          <div class="leading-tight">
            <div class="text-sm font-semibold text-white">NS8 Policy Manager</div>
            <div class="text-[11px] text-slate-400">Windows · Linux · macOS</div>
          </div>
        </div>
        <button
          type="button"
          class="rounded p-1 text-slate-400 hover:text-white lg:hidden"
          :aria-label="t.app.close"
          @click="mobileOpen = false"
        >
          <X class="h-5 w-5" />
        </button>
      </div>

      <nav class="flex-1 space-y-1 px-3 py-4" aria-label="Main navigation">
        <RouterLink
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          class="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors"
          :class="
            isRouteActive(item.to)
              ? 'bg-blue-600 text-white'
              : 'text-slate-300 hover:bg-slate-800 hover:text-white'
          "
          @click="mobileOpen = false"
        >
          <component :is="item.icon" class="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="border-t border-slate-800 p-4 text-xs text-slate-400">
        <div v-if="currentUser?.ldapDomain" class="truncate font-mono text-slate-300">
          {{ currentUser.ldapDomain }}
        </div>
        <div class="mt-0.5">NethServer 8 Enterprise Module</div>
      </div>
    </aside>

    <!-- Main Column -->
    <div class="flex min-w-0 flex-1 flex-col">
      <header class="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-200 bg-white px-4 sm:px-6">
        <div class="flex items-center gap-3">
          <button
            type="button"
            class="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 lg:hidden"
            aria-label="Toggle navigation"
            @click="mobileOpen = true"
          >
            <Menu class="h-5 w-5" aria-hidden="true" />
          </button>
          <span class="hidden text-xs font-medium text-slate-500 sm:inline">
            {{ t.app.subtitle }}
          </span>
        </div>

        <div class="flex items-center gap-3">
          <!-- Language Toggle -->
          <div
            class="inline-flex items-center rounded-md border border-slate-200 bg-slate-50 p-0.5"
            role="group"
            aria-label="Language selector"
          >
            <Globe class="ml-1.5 mr-1 h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
            <button
              type="button"
              class="rounded px-2 py-0.5 text-xs font-semibold transition-colors"
              :class="locale === 'de' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'"
              @click="setLocale('de')"
            >
              Deutsch
            </button>
            <button
              type="button"
              class="rounded px-2 py-0.5 text-xs font-semibold transition-colors"
              :class="locale === 'en' ? 'bg-white text-blue-700 shadow-sm' : 'text-slate-600 hover:text-slate-900'"
              @click="setLocale('en')"
            >
              English
            </button>
          </div>

          <div v-if="currentUser" class="hidden items-center gap-2 border-l border-slate-200 pl-3 sm:flex">
            <div class="text-right leading-tight">
              <div class="text-xs font-semibold text-slate-900">
                {{ currentUser.displayName || currentUser.username }}
              </div>
              <div class="text-[11px] text-slate-500">
                {{ currentUser.authSource === 'BOOTSTRAP' ? 'Bootstrap Admin' : 'AD / LDAP' }}
              </div>
            </div>
          </div>

          <button
            type="button"
            class="apm-btn-secondary py-1 px-2.5 text-xs"
            @click="handleLogout"
          >
            <LogOut class="h-3.5 w-3.5" aria-hidden="true" />
            <span>{{ t.app.logout }}</span>
          </button>
        </div>
      </header>

      <main class="flex-1 p-4 sm:p-6 lg:p-8">
        <div class="mx-auto max-w-7xl">
          <slot />
        </div>
      </main>
    </div>
  </div>
</template>
