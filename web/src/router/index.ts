import { createRouter, createWebHistory } from 'vue-router'
import { useAuth } from '@/composables/useAuth'
import LoginView from '@/views/LoginView.vue'
import DashboardView from '@/views/DashboardView.vue'
import PoliciesView from '@/views/PoliciesView.vue'
import AssignmentsView from '@/views/AssignmentsView.vue'
import SimulatorView from '@/views/SimulatorView.vue'
import DevicesView from '@/views/DevicesView.vue'
import EnrollView from '@/views/EnrollView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginView,
      meta: { public: true }
    },
    {
      path: '/',
      redirect: '/dashboard'
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: DashboardView
    },
    {
      path: '/policies',
      name: 'policies',
      component: PoliciesView
    },
    {
      path: '/assignments',
      name: 'assignments',
      component: AssignmentsView
    },
    {
      path: '/simulator',
      name: 'simulator',
      component: SimulatorView
    },
    {
      path: '/devices',
      name: 'devices',
      component: DevicesView
    },
    {
      path: '/enroll',
      name: 'enroll',
      component: EnrollView
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/dashboard'
    }
  ]
})

router.beforeEach(async (to) => {
  const { ensureLoaded } = useAuth()
  if (to.meta.public) {
    const ok = await ensureLoaded()
    if (ok && to.name === 'login') {
      return { path: '/dashboard' }
    }
    return true
  }
  const authenticated = await ensureLoaded()
  if (!authenticated) {
    return {
      path: '/login',
      query: to.fullPath !== '/dashboard' ? { redirect: to.fullPath } : undefined
    }
  }
  return true
})
