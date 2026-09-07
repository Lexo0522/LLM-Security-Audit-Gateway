<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import { api, type ApiError, type AuditEvent, type GatewayKey, type Policy, type RuleSet, type Upstream, type UpstreamLifecycleState, type User } from './api'

type Page = 'dashboard' | 'upstreams' | 'keys' | 'rules' | 'policies' | 'audit'
type Toast = { kind: 'success' | 'error'; text: string }

const loading = ref(true)
const busy = ref(false)
const setupNeeded = ref(false)
const user = ref<User | null>(null)
const page = ref<Page>('dashboard')
const toast = ref<Toast | null>(null)
let toastTimer: ReturnType<typeof setTimeout> | undefined
const loginForm = ref({ username: '', password: '' })
const setupForm = ref({ username: '', password: '', confirm: '' })
const upstreams = ref<Upstream[]>([])
const upstreamTotal = ref(0)
const keys = ref<GatewayKey[]>([])
const keyTotal = ref(0)
const rules = ref<RuleSet[]>([])
const policies = ref<Policy[]>([])
const events = ref<AuditEvent[]>([])
const auditCursor = ref('')          // cursor of the current audit page
const auditNext = ref('')            // cursor of the next page, when any
const auditHistory = ref<string[]>([]) // cursors of previous pages, for "back"
const summary = ref<any>(null)
const upstreamForm = ref({ id: '', name: '', base_url: '', api_key: '', enabled: true, wasEnabled: true })
const showUpstreamForm = ref(false)
const keyForm = ref({ tenant_id: '', upstream_id: '', name: '' })
const generatedKey = ref('')
const showKey = ref(false)
const copyButton = ref<HTMLButtonElement | null>(null)
const policyForm = ref<Policy>(defaultPolicy())
const showPolicyForm = ref(false)
const ruleForm = ref({ scope: 'global', rules: '[\n  {"id":"prompt-injection","pattern":"ignore previous instructions","action":"block"}\n]' })
const showRuleForm = ref(false)
const auditFilter = ref({ decision: '', direction: '', tenant_id: '' })
const accountPanel = ref(false)
const passwordForm = ref({ current: '', next: '', confirm: '' })
const upstreamPage = ref(0)
const keyPage = ref(0)
const deletingUpstreams = ref<Record<string, boolean>>({})
const revokingKeys = ref<Record<string, boolean>>({})
const deletingPolicies = ref<Record<string, boolean>>({})
const PAGE_SIZE = 20

const nav = [
  { id: 'dashboard' as Page, label: 'Overview', hint: 'System pulse' },
  { id: 'upstreams' as Page, label: 'Upstreams', hint: 'Model endpoints' },
  { id: 'keys' as Page, label: 'Gateway keys', hint: 'Access bindings' },
  { id: 'rules' as Page, label: 'Rules', hint: 'Detection sets' },
  { id: 'policies' as Page, label: 'Policies', hint: 'Thresholds' },
  { id: 'audit' as Page, label: 'Audit', hint: 'Event trail' },
]

const pageTitle = computed(() => nav.find(item => item.id === page.value)?.label || 'Overview')
const activeUpstreams = computed(() => upstreams.value.filter(item => item.enabled).length)
const activeKeys = computed(() => keys.value.filter(item => !item.revoked_at).length)

function upstreamStatus(item: Upstream): UpstreamLifecycleState {
  return item.lifecycle_state || item.status || (item.enabled ? 'active' : 'disabled')
}
function isUpstreamDeleting(item: Upstream): boolean {
  return upstreamStatus(item) === 'deleting' || Boolean(deletingUpstreams.value[item.id])
}
function isUpstreamIdDeleting(id: string): boolean {
  return Boolean(id && (deletingUpstreams.value[id] || upstreams.value.some(item => item.id === id && isUpstreamDeleting(item))))
}
function formatTiming(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}
function defaultPolicy(): Policy {
  return { scope: 'global', route_path: '*', direction: 'request', monitor_at: 30, intervention_at: 80, intervention_action: 'block', auditor_failure_mode: 'fail_open' }
}
function notify(kind: 'success' | 'error', text: string) {
  toast.value = { kind, text }
  if (toastTimer) clearTimeout(toastTimer)
  if (kind === 'success') toastTimer = setTimeout(() => { toast.value = null }, 4000)
}
function showError(err: unknown) {
  const apiError = err as ApiError
  if (apiError?.status === 401) { user.value = null; page.value = 'dashboard' }
  notify('error', err instanceof Error ? err.message : 'Something went wrong')
}
async function run<T>(task: () => Promise<T>, success?: string): Promise<T | undefined> {
  toast.value = null; busy.value = true
  try { const result = await task(); if (success) notify('success', success); return result }
  catch (err) { showError(err) }
  finally { busy.value = false }
  return undefined
}
async function bootstrap() {
  loading.value = true; toast.value = null
  try {
    const status = await api.setupStatus()
    setupNeeded.value = !status.initialized
    if (!setupNeeded.value) {
      try { user.value = await api.me() } catch { user.value = null }
    }
  } catch (err) { showError(err) }
  finally { loading.value = false }
}
async function submitSetup() {
  toast.value = null
  if (setupForm.value.password !== setupForm.value.confirm) { notify('error', 'Passwords do not match'); return }
  if (setupForm.value.password.length < 12) { notify('error', 'Use at least 12 characters for the password'); return }
  const result = await run(() => api.setup(setupForm.value.username, setupForm.value.password), 'Admin account created. Sign in to continue.')
  if (result) { setupNeeded.value = false; loginForm.value.username = setupForm.value.username }
}
async function submitLogin() {
  const result = await run(() => api.login(loginForm.value.username, loginForm.value.password))
  if (result) { user.value = result; await loadPage('dashboard') }
}
async function logout() { await run(api.logout); user.value = null; toast.value = null }
async function loadUpstreams(target: 1 | -1 | 0 = 0) {
  const next = Math.max(0, upstreamPage.value + (target === 0 ? 0 : target))
  const page = await api.upstreams(next * PAGE_SIZE, PAGE_SIZE)
  upstreams.value = page.data; upstreamTotal.value = page.total ?? page.data.length; upstreamPage.value = next
}
async function loadKeys(target: 1 | -1 | 0 = 0) {
  const next = Math.max(0, keyPage.value + (target === 0 ? 0 : target))
  const page = await api.keys(next * PAGE_SIZE, PAGE_SIZE)
  keys.value = page.data; keyTotal.value = page.total ?? page.data.length; keyPage.value = next
}
async function loadPage(target: Page = page.value) {
  page.value = target; toast.value = null
  await run(async () => {
    if (target === 'dashboard') {
      const [summaryResult, upstreamResult, keyResult] = await Promise.allSettled([api.auditSummary(), api.upstreams(0, 200), api.keys(0, 200)])
      if (summaryResult.status === 'fulfilled') summary.value = summaryResult.value
      if (upstreamResult.status === 'fulfilled') { upstreams.value = upstreamResult.value.data; upstreamTotal.value = upstreamResult.value.total ?? upstreamResult.value.data.length }
      if (keyResult.status === 'fulfilled') { keys.value = keyResult.value.data; keyTotal.value = keyResult.value.total ?? keyResult.value.data.length }
      if (summaryResult.status === 'rejected' && upstreamResult.status === 'rejected' && keyResult.status === 'rejected') throw summaryResult.reason
      return
    }
    if (target === 'upstreams') await loadUpstreams()
    if (target === 'keys') {
      await loadKeys()
      if (!upstreams.value.length) await loadUpstreams()
    }
    if (target === 'rules') rules.value = await api.rules()
    if (target === 'policies') policies.value = await api.policies()
    if (target === 'audit') {
      auditCursor.value = ''; auditHistory.value = []
      await loadAuditPage('')
    }
  })
}
async function loadAuditPage(cursor: string) {
  const params = new URLSearchParams(Object.entries(auditFilter.value).filter(([, value]) => value))
  params.set('page_size', String(PAGE_SIZE))
  if (cursor) params.set('cursor', cursor)
  const data = await api.audit(params.toString())
  events.value = data?.events || data?.items || data || []
  auditNext.value = data?.next_cursor || ''
}
async function auditGo(direction: 1 | -1) {
  await run(async () => {
    if (direction === 1) {
      if (!auditNext.value) return
      auditHistory.value.push(auditCursor.value)
      auditCursor.value = auditNext.value
    } else {
      const previous = auditHistory.value.pop()
      if (previous === undefined) return
      auditCursor.value = previous
    }
    await loadAuditPage(auditCursor.value)
  })
}
async function filterAudit() {
  auditCursor.value = ''; auditHistory.value = []
  await run(() => loadAuditPage(''))
}
function beginUpstream(item?: Upstream) {
  if (item && isUpstreamDeleting(item)) return
  upstreamForm.value = item
    ? { id: item.id, name: item.name, base_url: item.base_url, api_key: '', enabled: item.enabled, wasEnabled: item.enabled }
    : { id: '', name: '', base_url: '', api_key: '', enabled: true, wasEnabled: true }
  showUpstreamForm.value = true; toast.value = null
}
async function saveUpstream() {
  if (busy.value) return
  if (upstreamForm.value.id && isUpstreamIdDeleting(upstreamForm.value.id)) return
  if (upstreamForm.value.wasEnabled && !upstreamForm.value.enabled) {
    const confirmed = window.confirm(`Disable "${upstreamForm.value.name}"? Every gateway key bound to it fails immediately (503) until it is re-enabled.`)
    if (!confirmed) return
  }
  const value = { name: upstreamForm.value.name, base_url: upstreamForm.value.base_url, api_key: upstreamForm.value.api_key || undefined, enabled: upstreamForm.value.enabled }
  const result = upstreamForm.value.id ? await run(() => api.updateUpstream(upstreamForm.value.id, value), 'Upstream updated.') : await run(() => api.createUpstream(value), 'Upstream added.')
  if (result) { showUpstreamForm.value = false; await loadPage('upstreams') }
}
async function removeUpstream(item: Upstream) {
  if (busy.value || isUpstreamDeleting(item)) return
  if (!window.confirm(`Delete upstream "${item.name}"? This immediately revokes all bound gateway keys, erases the server-side secret, and starts permanent cleanup. The action cannot be undone.`)) return
  deletingUpstreams.value = { ...deletingUpstreams.value, [item.id]: true }
  const shouldGoBack = upstreams.value.length === 1 && upstreamPage.value > 0
  try {
    const result = await run(() => api.deleteUpstream(item.id), 'Upstream deletion requested. Bound keys were revoked and the server-side secret was erased.')
    if (result === undefined && toast.value?.kind === 'error') return
    const current = upstreams.value.findIndex(value => value.id === item.id)
    if (current >= 0 && result) {
      const state = result.status || result.lifecycle_state
      if (state) upstreams.value[current] = { ...upstreams.value[current], ...result, lifecycle_state: state, status: state }
    }
    await loadUpstreams(shouldGoBack ? -1 : 0)
  } finally {
    const next = { ...deletingUpstreams.value }
    delete next[item.id]
    deletingUpstreams.value = next
  }
}
async function testUpstream(item: Upstream) {
  if (busy.value || isUpstreamDeleting(item)) return
  const result = await run(() => api.testUpstream(item.id))
  if (result) notify(result.ok ? 'success' : 'error', result.message || (result.ok ? `Connection to "${item.name}" succeeded.` : `Connection to "${item.name}" failed.`))
}
async function createKey() {
  const result = await run(() => api.createKey(keyForm.value.tenant_id, keyForm.value.upstream_id, keyForm.value.name), 'Gateway key created. Copy it now; it will not be shown again.')
  if (result) {
    generatedKey.value = result.key; showKey.value = true
    keyForm.value = { tenant_id: '', upstream_id: '', name: '' }
    await nextTick(() => copyButton.value?.focus())
    await loadKeys()
  }
}
async function revokeKey(item: GatewayKey) {
  if (busy.value || revokingKeys.value[item.id] || item.revoked_at) return
  const label = item.display_name || item.prefix
  if (!window.confirm(`Revoke gateway key "${label}" for tenant "${item.tenant_id}"? Requests using it fail with 401 immediately.`)) return
  revokingKeys.value = { ...revokingKeys.value, [item.id]: true }
  try {
    const result = await run(() => api.revokeKey(item.id), 'Gateway key revoked.')
    if (result) await loadKeys()
  } finally {
    const next = { ...revokingKeys.value }
    delete next[item.id]
    revokingKeys.value = next
  }
}
async function copyKey() {
  const text = generatedKey.value
  try {
    if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(text)
    notify('success', 'Key copied to clipboard.')
  } catch {
    // Clipboard API can be blocked (permissions, insecure context); fall back
    // to a transient textarea the old-school way.
    const area = document.createElement('textarea')
    area.value = text
    document.body.appendChild(area)
    area.select()
    let copied = false
    try { copied = document.execCommand('copy') } catch { copied = false }
    document.body.removeChild(area)
    notify(copied ? 'success' : 'error', copied ? 'Key copied to clipboard.' : 'Copy failed — select the key text and copy it manually.')
  }
}
async function submitPasswordChange() {
  toast.value = null
  if (passwordForm.value.next !== passwordForm.value.confirm) { notify('error', 'New passwords do not match'); return }
  if (passwordForm.value.next.length < 12) { notify('error', 'Use at least 12 characters for the new password'); return }
  const result = await run(() => api.changePassword(passwordForm.value.current, passwordForm.value.next), 'Password changed. Other sessions were signed out.')
  if (result !== undefined) { passwordForm.value = { current: '', next: '', confirm: '' }; accountPanel.value = false }
}
async function logoutEverywhere() {
  if (!window.confirm('Sign out of every session, including this one?')) return
  await run(api.logoutAll, 'All sessions signed out.')
  if (!toast.value || toast.value.kind !== 'error') { user.value = null; accountPanel.value = false }
}
async function beginPolicy(item?: Policy) { policyForm.value = item ? { ...item } : defaultPolicy(); showPolicyForm.value = true; toast.value = null }
async function savePolicy() {
  const result = policyForm.value.id ? await run(() => api.updatePolicy(policyForm.value.id!, policyForm.value), 'Policy updated.') : await run(() => api.createPolicy(policyForm.value), 'Policy created.')
  if (result) { showPolicyForm.value = false; await loadPage('policies') }
}
async function removePolicy(item: Policy) {
  if (busy.value || !item.id || deletingPolicies.value[item.id]) return
  if (!window.confirm(`Delete the ${item.direction} policy for "${item.scope} ${item.route_path}"?`)) return
  deletingPolicies.value = { ...deletingPolicies.value, [item.id]: true }
  try {
    const result = await run(() => api.deletePolicy(item.id!), 'Policy deleted.')
    if (result === undefined && toast.value?.kind === 'error') return
    await loadPage('policies')
  } finally {
    const next = { ...deletingPolicies.value }
    delete next[item.id]
    deletingPolicies.value = next
  }
}
function beginRule() { ruleForm.value = { scope: 'global', rules: '[\n  {"id":"prompt-injection","pattern":"ignore previous instructions","action":"block"}\n]' }; showRuleForm.value = true; toast.value = null }
async function createRule() {
  let parsed: any[]
  try { parsed = JSON.parse(ruleForm.value.rules) } catch { notify('error', 'Rules must be valid JSON'); return }
  const result = await run(() => api.createRule(ruleForm.value.scope, parsed), 'Draft rule set created.')
  if (result) { showRuleForm.value = false; await loadPage('rules') }
}
async function publishRule(version: string) { const result = await run(() => api.publishRule(version), 'Rule set published.'); if (result) await loadPage('rules') }
async function rollbackRule(item: RuleSet) { const result = await run(() => api.rollbackRule(item.scope, item.version), 'Rule set rolled back.'); if (result) await loadPage('rules') }

onMounted(bootstrap)
</script>

<template>
  <div v-if="loading" class="splash"><div class="mark">SG</div><p>Warming up the control plane</p></div>
  <main v-else-if="!user" class="auth-layout">
    <section class="auth-intro"><div class="brand"><span class="brand-mark">SG</span><span>Sentinel Gateway</span></div><div class="intro-copy"><p class="eyebrow">SECURITY OPERATIONS / 01</p><h1>Make every model call<br /><em>accountable.</em></h1><p class="lede">A quiet command center for routing, inspection, and evidence. Keep the gateway sharp without losing sight of the humans behind the traffic.</p></div><div class="signal"><span class="signal-dot"></span><span>Private control plane</span><span class="signal-line"></span><span>Cookie session</span></div></section>
    <section class="auth-card"><div v-if="setupNeeded"><p class="eyebrow">FIRST RUN</p><h2>Create your admin account</h2><p class="muted">The first account owns this gateway. Use a long, unique password.</p><form @submit.prevent="submitSetup"><label>Username<input v-model="setupForm.username" required autocomplete="username" /></label><label>Password<input v-model="setupForm.password" required minlength="12" type="password" autocomplete="new-password" /></label><label>Confirm password<input v-model="setupForm.confirm" required type="password" autocomplete="new-password" /></label><button class="primary" :disabled="busy">Create account <span>→</span></button></form></div><div v-else><p class="eyebrow">WELCOME BACK</p><h2>Sign in to the gateway</h2><p class="muted">Your session stays in a secure, HttpOnly cookie.</p><form @submit.prevent="submitLogin"><label>Username<input v-model="loginForm.username" required autocomplete="username" /></label><label>Password<input v-model="loginForm.password" required type="password" autocomplete="current-password" /></label><button class="primary" :disabled="busy">Enter console <span>→</span></button></form></div><div v-if="toast" :class="['toast', toast.kind]" role="status" aria-live="polite">{{ toast.text }} <button aria-label="Dismiss message" @click="toast = null">×</button></div></section>
  </main>
  <div v-else class="app-shell">
    <aside class="sidebar"><div class="brand side-brand"><span class="brand-mark">SG</span><span>Sentinel<br /><strong>Gateway</strong></span></div><p class="side-label">Control room</p><nav><button v-for="item in nav" :key="item.id" :class="['nav-item', { active: page === item.id }]" @click="loadPage(item.id)"><span class="nav-index">{{ String(nav.indexOf(item) + 1).padStart(2, '0') }}</span><span><strong>{{ item.label }}</strong><small>{{ item.hint }}</small></span></button></nav><div class="side-bottom"><div class="system-chip"><span class="signal-dot"></span><span>System nominal</span></div><button class="logout" @click="accountPanel = true">Account <span>⚙</span></button><button class="logout" @click="logout">Sign out <span>↗</span></button></div></aside>
    <section class="content"><header class="topbar"><div><p class="eyebrow">SENTINEL / {{ pageTitle.toUpperCase() }}</p><h1>{{ pageTitle }}</h1></div><div class="user-chip"><span class="avatar">{{ (user.username || 'A').slice(0, 1).toUpperCase() }}</span><span><strong>{{ user.username }}</strong><small>Administrator</small></span></div></header><div class="message-stack"><div v-if="toast" :class="['toast', toast.kind]" role="status" aria-live="polite">{{ toast.text }} <button aria-label="Dismiss message" @click="toast = null">×</button></div></div>
      <div v-if="accountPanel" class="form-panel account-panel">
        <div class="panel-title"><h3>Account</h3><button class="close" aria-label="Close account panel" @click="accountPanel = false">×</button></div>
        <p class="muted">Signed in as <strong>{{ user?.username }}</strong>. Changing the password signs out every other session.</p>
        <form @submit.prevent="submitPasswordChange">
          <label>Current password<input v-model="passwordForm.current" required type="password" autocomplete="current-password" /></label>
          <label>New password<input v-model="passwordForm.next" required minlength="12" type="password" autocomplete="new-password" /></label>
          <label>Confirm new password<input v-model="passwordForm.confirm" required type="password" autocomplete="new-password" /></label>
          <button class="primary" :disabled="busy">Change password</button>
        </form>
        <button class="danger-text" :disabled="busy" @click="logoutEverywhere">Sign out of all sessions</button>
      </div>
      <div class="page-body">
        <section v-if="page === 'dashboard'" class="view"><div class="hero-panel"><div><p class="eyebrow light">GATEWAY AT A GLANCE</p><h2>Trust is a<br /><em>measurable</em> signal.</h2><p>Route requests with intent. Inspect the moments that matter. Keep a living record of what crossed the boundary.</p></div><div class="hero-orbit"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="orbit-core">SG<span>LIVE</span></div></div></div><div class="stat-grid"><article class="stat-card"><span class="stat-label">Active upstreams</span><strong>{{ activeUpstreams }}<small>/ {{ upstreams.length || '—' }}</small></strong><span class="stat-foot">Configured endpoints</span></article><article class="stat-card"><span class="stat-label">Live gateway keys</span><strong>{{ activeKeys }}<small>/ {{ keys.length || '—' }}</small></strong><span class="stat-foot">Revocation-aware access</span></article><article class="stat-card"><span class="stat-label">Audit posture</span><strong class="text-stat">{{ summary ? 'Recording' : 'Ready' }}</strong><span class="stat-foot">Evidence pipeline status</span></article></div><div class="section-heading"><div><p class="eyebrow">QUICK ACTIONS</p><h3>Keep moving</h3></div></div><div class="quick-grid"><button @click="loadPage('upstreams')"><span class="quick-icon">↗</span><strong>Configure an upstream</strong><small>Connect a model endpoint</small></button><button @click="loadPage('keys')"><span class="quick-icon">+</span><strong>Issue a gateway key</strong><small>Bind access to a route</small></button><button @click="loadPage('audit')"><span class="quick-icon">≡</span><strong>Review audit trail</strong><small>See the latest evidence</small></button></div></section>
        <section v-else-if="page === 'upstreams'" class="view"><div class="section-heading"><div><p class="eyebrow">ROUTING DESTINATIONS</p><h2>Upstreams</h2><p class="muted">Store model endpoints server-side. Secrets are never echoed in this list.</p></div><div class="card-actions"><button class="secondary compact" :disabled="busy" @click="loadPage('upstreams')">Refresh <span>↻</span></button><button class="primary compact" :disabled="busy" @click="beginUpstream()">Add upstream <span>+</span></button></div></div><div v-if="showUpstreamForm" class="form-panel"><div class="panel-title"><h3>{{ upstreamForm.id ? 'Edit upstream' : 'New upstream' }}</h3><button class="close" :disabled="busy" @click="showUpstreamForm = false">×</button></div><div class="form-grid"><label>Name<input v-model="upstreamForm.name" required placeholder="Production models" :disabled="busy || isUpstreamIdDeleting(upstreamForm.id)" /></label><label>Base URL<input v-model="upstreamForm.base_url" required type="url" placeholder="https://api.example.com" :disabled="busy || isUpstreamIdDeleting(upstreamForm.id)" /></label><label class="wide">API key <span class="optional">optional on edit</span><input v-model="upstreamForm.api_key" type="password" placeholder="Only stored on save" :disabled="busy || isUpstreamIdDeleting(upstreamForm.id)" /></label><label class="toggle"><input v-model="upstreamForm.enabled" type="checkbox" :disabled="busy || isUpstreamIdDeleting(upstreamForm.id)" /><span class="toggle-ui"></span><span>Enabled for new traffic</span></label></div><button class="primary" @click="saveUpstream" :disabled="busy || isUpstreamIdDeleting(upstreamForm.id)">Save upstream</button></div><div v-if="upstreams.length" class="card-list"><article v-for="item in upstreams" :key="item.id" class="data-card"><div class="status-bar" :class="isUpstreamDeleting(item) ? 'off' : item.enabled ? 'on' : 'off'"></div><div class="data-main"><div class="data-title"><h3>{{ item.name }}</h3><span :class="['pill', isUpstreamDeleting(item) ? 'amber' : item.enabled ? 'green' : 'gray']">{{ isUpstreamDeleting(item) ? 'Deleting' : item.enabled ? 'Enabled' : 'Disabled' }}</span></div><p class="mono">{{ item.base_url }}</p><p class="meta" v-if="isUpstreamDeleting(item)">Deletion requested {{ formatTiming(item.delete_requested_at) }} <span>·</span> Permanent cleanup after {{ formatTiming(item.purge_after) }}</p><p class="meta" v-else>{{ item.has_api_key === false ? 'No server key configured' : 'Server key configured' }} <span>·</span> ID {{ item.id.slice(0, 8) }}</p></div><div class="card-actions"><button :disabled="busy || isUpstreamDeleting(item)" @click="testUpstream(item)">Test</button><button :disabled="busy || isUpstreamDeleting(item)" @click="beginUpstream(item)">Edit</button><button class="danger-text" :disabled="busy || isUpstreamDeleting(item)" @click="removeUpstream(item)">{{ isUpstreamDeleting(item) ? 'Deleting…' : 'Delete' }}</button></div></article></div><div v-if="upstreamTotal > PAGE_SIZE" class="pager"><button :disabled="upstreamPage === 0 || busy" @click="loadUpstreams(-1)">← Previous</button><span aria-live="polite">Page {{ upstreamPage + 1 }} · {{ upstreamTotal }} upstream{{ upstreamTotal === 1 ? '' : 's' }}</span><button :disabled="(upstreamPage + 1) * PAGE_SIZE >= upstreamTotal || busy" @click="loadUpstreams(1)">Next →</button></div><div v-if="!upstreams.length" class="empty"><span>○</span><h3>No upstreams yet</h3><p>Add the first model endpoint to give the gateway somewhere safe to route.</p><button class="secondary" :disabled="busy" @click="beginUpstream()">Add upstream</button></div></section>
        <section v-else-if="page === 'keys'" class="view"><div class="section-heading"><div><p class="eyebrow">BOUND ACCESS</p><h2>Gateway keys</h2><p class="muted">Every key is fixed to one upstream. The full secret appears only once.</p></div></div><div v-if="showKey" class="secret-panel"><div><p class="eyebrow light">ONE-TIME SECRET</p><h3>Copy this key now</h3><p>It cannot be recovered after you close this panel.</p></div><div class="secret-value"><code>{{ generatedKey }}</code><button ref="copyButton" @click="copyKey">Copy</button></div><button class="close-secret" @click="showKey = false">I have copied it</button></div><div class="split-layout"><div class="form-panel sticky-panel"><h3>Issue a key</h3><p class="muted">Choose the exact upstream this credential may use.</p><label>Tenant ID<input v-model="keyForm.tenant_id" required placeholder="team-production" /></label><label>Upstream<select v-model="keyForm.upstream_id" required><option value="" disabled>Select upstream</option><option v-for="item in upstreams.filter(u => u.enabled && !isUpstreamDeleting(u))" :key="item.id" :value="item.id">{{ item.name }}</option></select></label><label>Display name <span class="optional">optional</span><input v-model="keyForm.name" placeholder="Production app" /></label><button class="primary" :disabled="busy || !keyForm.upstream_id" @click="createKey">Create gateway key <span>→</span></button></div><div><div v-if="keys.length" class="card-list"><article v-for="item in keys" :key="item.id" class="data-card"><div class="key-glyph">key</div><div class="data-main"><div class="data-title"><h3>{{ item.display_name || item.prefix }}</h3><span :class="['pill', item.revoked_at ? 'gray' : 'green']">{{ item.revoked_at ? 'Revoked' : 'Active' }}</span></div><p class="meta">Tenant <strong>{{ item.tenant_id }}</strong> <span>·</span> Upstream <strong>{{ upstreams.find(u => u.id === item.upstream_id)?.name || item.upstream_id?.slice(0, 8) || 'Unbound' }}</strong></p><p class="meta">Created {{ item.created_at ? new Date(item.created_at).toLocaleDateString() : '—' }}</p></div><button v-if="!item.revoked_at" class="danger-text" :disabled="busy || revokingKeys[item.id]" @click="revokeKey(item)">{{ revokingKeys[item.id] ? 'Revoking…' : 'Revoke' }}</button></article></div><div v-if="keyTotal > PAGE_SIZE" class="pager"><button :disabled="keyPage === 0 || busy" @click="loadKeys(-1)">← Previous</button><span aria-live="polite">Page {{ keyPage + 1 }} · {{ keyTotal }} key{{ keyTotal === 1 ? '' : 's' }}</span><button :disabled="(keyPage + 1) * PAGE_SIZE >= keyTotal || busy" @click="loadKeys(1)">Next →</button></div><div v-if="!keys.length" class="empty small"><h3>No keys issued</h3><p>Issue a scoped key from the panel.</p></div></div></div></section>
        <section v-else-if="page === 'rules'" class="view"><div class="section-heading"><div><p class="eyebrow">DETECTION LIBRARY</p><h2>Rules</h2><p class="muted">Draft, publish, and roll back the patterns that shape inspection.</p></div><button class="primary compact" @click="beginRule">New rule set <span>+</span></button></div><div v-if="showRuleForm" class="form-panel"><div class="panel-title"><h3>New draft rule set</h3><button class="close" @click="showRuleForm = false">×</button></div><label>Scope<input v-model="ruleForm.scope" required /></label><label>Rules <span class="optional">JSON array</span><textarea v-model="ruleForm.rules" rows="8" spellcheck="false"></textarea></label><button class="primary" @click="createRule" :disabled="busy">Create draft</button></div><div v-if="rules.length" class="table-wrap"><table><thead><tr><th>Version</th><th>Scope</th><th>Status</th><th>Rules</th><th>Created</th><th></th></tr></thead><tbody><tr v-for="item in rules" :key="item.version"><td><code>{{ item.version.slice(0, 12) }}</code></td><td>{{ item.scope }}</td><td><span :class="['pill', item.status === 'published' ? 'green' : 'gray']">{{ item.status }}</span></td><td>{{ item.rules?.length || 0 }} definitions</td><td>{{ item.created_at ? new Date(item.created_at).toLocaleDateString() : '—' }}</td><td class="row-actions"><button v-if="item.status === 'draft'" @click="publishRule(item.version)">Publish</button><button v-if="item.status === 'published'" @click="rollbackRule(item)">Rollback</button></td></tr></tbody></table></div><div v-else class="empty"><span>◇</span><h3>Rule library is empty</h3><p>Create a draft to start shaping your inspection boundary.</p></div></section>
        <section v-else-if="page === 'policies'" class="view"><div class="section-heading"><div><p class="eyebrow">DECISION THRESHOLDS</p><h2>Policies</h2><p class="muted">Set the score at which traffic is monitored or interrupted.</p></div><button class="primary compact" :disabled="busy" @click="beginPolicy()">Add policy <span>+</span></button></div><div v-if="showPolicyForm" class="form-panel"><div class="panel-title"><h3>{{ policyForm.id ? 'Edit policy' : 'New policy' }}</h3><button class="close" @click="showPolicyForm = false">×</button></div><div class="form-grid"><label>Scope<input v-model="policyForm.scope" required /></label><label>Route path<input v-model="policyForm.route_path" required /></label><label>Direction<select v-model="policyForm.direction"><option>request</option><option>response</option></select></label><label>Monitor at<input v-model.number="policyForm.monitor_at" type="number" min="0" max="100" /></label><label>Intervention at<input v-model.number="policyForm.intervention_at" type="number" min="0" max="100" /></label><label>Action<select v-model="policyForm.intervention_action"><option>block</option><option>redact</option><option>monitor</option></select></label><label>Auditor failure<select v-model="policyForm.auditor_failure_mode"><option>fail_open</option><option>fail_closed</option></select></label></div><button class="primary" @click="savePolicy" :disabled="busy">Save policy</button></div><div v-if="policies.length" class="card-list"><article v-for="item in policies" :key="item.id" class="data-card policy-card"><div class="threshold"><strong>{{ item.intervention_at }}</strong><small>BLOCK</small></div><div class="data-main"><div class="data-title"><h3>{{ item.scope }} <span class="route">{{ item.route_path }}</span></h3><span class="pill blue">{{ item.direction }}</span></div><p class="meta">Monitor at <strong>{{ item.monitor_at }}</strong> · Action <strong>{{ item.intervention_action }}</strong> · {{ item.auditor_failure_mode }}</p></div><div class="card-actions"><button @click="beginPolicy(item)" :disabled="busy || deletingPolicies[item.id || '']">Edit</button><button class="danger-text" :disabled="busy || deletingPolicies[item.id || '']" @click="removePolicy(item)">{{ deletingPolicies[item.id || ''] ? 'Deleting…' : 'Delete' }}</button></div></article></div><div v-else class="empty"><span>⌁</span><h3>No policies configured</h3><p>Start with a threshold tailored to your model traffic.</p></div></section>
        <section v-else class="view"><div class="section-heading"><div><p class="eyebrow">IMMUTABLE EVIDENCE</p><h2>Audit trail</h2><p class="muted">A searchable record of decisions made at the gateway boundary.</p></div><button class="secondary compact" @click="loadPage('audit')">Refresh <span>↻</span></button></div><div class="filter-bar"><input v-model="auditFilter.tenant_id" placeholder="Tenant ID" @keyup.enter="filterAudit" /><select v-model="auditFilter.decision"><option value="">All decisions</option><option>allow</option><option>monitor</option><option>block</option><option>redact</option></select><select v-model="auditFilter.direction"><option value="">All directions</option><option>request</option><option>response</option><option>admin</option></select><button class="primary compact" @click="filterAudit">Apply filters</button></div><div v-if="events.length" class="table-wrap"><table><thead><tr><th>Time</th><th>Decision</th><th>Tenant</th><th>Path</th><th>Model</th><th>Risk</th><th>Request</th></tr></thead><tbody><tr v-for="item in events" :key="item.event_id || item.id"><td class="mono">{{ item.event_time || item.created_at ? new Date(item.event_time || item.created_at!).toLocaleString() : '—' }}</td><td><span :class="['pill', item.decision === 'block' ? 'red' : item.decision === 'allow' ? 'green' : 'amber']">{{ item.decision || '—' }}</span></td><td>{{ item.tenant_id || '—' }}</td><td class="mono">{{ item.path || '—' }}</td><td>{{ item.model || '—' }}</td><td><strong>{{ item.risk_score ?? '—' }}</strong></td><td><code>{{ (item.request_id || item.event_id || '').slice(0, 10) }}</code></td></tr></tbody></table></div><div v-if="auditNext || auditHistory.length" class="pager"><button :disabled="!auditHistory.length || busy" @click="auditGo(-1)">← Previous</button><span aria-live="polite">Cursor page</span><button :disabled="!auditNext || busy" @click="auditGo(1)">Next →</button></div><div v-if="!events.length" class="empty"><span>⌁</span><h3>No events match</h3><p>When traffic crosses the gateway, its evidence will appear here.</p></div></section>
      </div>
    </section>
  </div>
</template>
