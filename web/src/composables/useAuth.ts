import { computed, ref } from 'vue'
import { api, getAccessToken, setAccessToken, type AuthUser, type LoginRequest } from '@/api'

const currentUser = ref<AuthUser | null>(null)
const authInitialized = ref(false)
const authLoading = ref(false)

export function useAuth() {
  const isAuthenticated = computed(() => Boolean(currentUser.value && getAccessToken()))

  async function ensureLoaded(): Promise<boolean> {
    const token = getAccessToken()
    if (!token) {
      currentUser.value = null
      authInitialized.value = true
      return false
    }
    if (currentUser.value && authInitialized.value) {
      return true
    }
    authLoading.value = true
    try {
      currentUser.value = await api.auth.me()
      authInitialized.value = true
      return true
    } catch {
      setAccessToken(null)
      currentUser.value = null
      authInitialized.value = true
      return false
    } finally {
      authLoading.value = false
    }
  }

  async function login(credentials: LoginRequest): Promise<AuthUser> {
    authLoading.value = true
    try {
      const res = await api.auth.login(credentials)
      setAccessToken(res.accessToken)
      currentUser.value = res.user
      authInitialized.value = true
      return res.user
    } finally {
      authLoading.value = false
    }
  }

  async function logout(): Promise<void> {
    try {
      if (getAccessToken()) {
        await api.auth.logout()
      }
    } catch {
      // Ignore network errors during logout cleanup
    } finally {
      setAccessToken(null)
      currentUser.value = null
      authInitialized.value = true
    }
  }

  function clearSession(): void {
    setAccessToken(null)
    currentUser.value = null
    authInitialized.value = true
  }

  return {
    currentUser,
    isAuthenticated,
    authInitialized,
    authLoading,
    ensureLoaded,
    login,
    logout,
    clearSession
  }
}
