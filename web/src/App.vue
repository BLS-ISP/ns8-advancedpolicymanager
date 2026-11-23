<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import { setUnauthorizedHandler } from '@/api'
import AppShell from '@/components/common/AppShell.vue'
import { useAuth } from '@/composables/useAuth'

const route = useRoute()
const router = useRouter()
const { clearSession } = useAuth()

setUnauthorizedHandler(() => {
  clearSession()
  if (route.name !== 'login') {
    void router.push({ path: '/login', query: { redirect: route.fullPath } })
  }
})
</script>

<template>
  <RouterView v-if="route.meta.public" />
  <AppShell v-else>
    <RouterView />
  </AppShell>
</template>
