export type ApiError = Error & { status?: number }

function csrfToken(): string {
  const prefix = 'gateway_admin_csrf='
  const cookie = document.cookie.split('; ').find(value => value.startsWith(prefix))
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : ''
}

interface Paged<T> { data: T; total: number | null }

async function request<T>(path: string, init: RequestInit = {}): Promise<Paged<T>> {
  const headers = new Headers(init.headers)
  const method = (init.method || 'GET').toUpperCase()
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', token)
  }
  const response = await fetch(`/admin/v1${path}`, { ...init, headers, credentials: 'include' })
  if (response.status === 204) return { data: undefined as T, total: null }
  const text = await response.text()
  let body: any
  try { body = text ? JSON.parse(text) : undefined } catch { body = undefined }
  if (!response.ok) {
    const error = new Error(body?.error?.message || body?.message || `Request failed (${response.status})`) as ApiError
    error.status = response.status
    throw error
  }
  const totalHeader = response.headers.get('X-Total-Count')
  return { data: body as T, total: totalHeader === null ? null : Number(totalHeader) }
}

const json = (method: string, body?: unknown): RequestInit => ({ method, body: body === undefined ? undefined : JSON.stringify(body) })

export interface SetupStatus { initialized: boolean }
export interface User { id?: string; username: string; created_at?: string }
export interface Upstream { id: string; name: string; base_url: string; enabled: boolean; created_at?: string; updated_at?: string; has_api_key?: boolean }
export interface GatewayKey { id: string; tenant_id: string; upstream_id: string; display_name?: string; prefix: string; created_at: string; revoked_at?: string }
export interface RuleSet { version: string; scope: string; status: string; source?: string; rules: any[]; created_at?: string }
export interface Policy { id?: string; scope: string; route_path: string; direction: string; monitor_at: number; intervention_at: number; intervention_action: string; auditor_failure_mode: string; revision?: number }
export interface AuditEvent { event_id?: string; id?: string; request_id?: string; tenant_id?: string; direction?: string; path?: string; model?: string; decision?: string; risk_score?: number; created_at?: string; event_time?: string; metadata?: Record<string,string> }

export const api = {
  setupStatus: async () => (await request<SetupStatus>('/setup/status')).data,
  setup: async (username: string, password: string) => (await request<User>('/setup', json('POST', { username, password }))).data,
  login: async (username: string, password: string) => (await request<User>('/auth/login', json('POST', { username, password }))).data,
  logout: async () => (await request<void>('/auth/logout', { method: 'POST' })).data,
  me: async () => (await request<User>('/auth/me')).data,
  health: async () => (await request<any>('/healthz')).data,
  upstreams: async (offset = 0, limit = 50) => await request<Upstream[]>(`/upstreams?limit=${limit}&offset=${offset}`),
  createUpstream: async (value: { name: string; base_url: string; api_key?: string; enabled: boolean }) => (await request<Upstream>('/upstreams', json('POST', value))).data,
  updateUpstream: async (id: string, value: { name: string; base_url: string; api_key?: string; enabled: boolean }) => (await request<Upstream>(`/upstreams/${id}`, json('PUT', value))).data,
  deleteUpstream: async (id: string) => (await request<void>(`/upstreams/${id}`, { method: 'DELETE' })).data,
  testUpstream: async (id: string) => (await request<{ ok: boolean; message?: string }>(`/upstreams/${id}/test`, { method: 'POST' })).data,
  keys: async (offset = 0, limit = 50) => await request<GatewayKey[]>(`/api-keys?limit=${limit}&offset=${offset}`),
  createKey: async (tenant_id: string, upstream_id: string, display_name?: string) => (await request<GatewayKey & { key: string }>('/api-keys', json('POST', { tenant_id, upstream_id, display_name }))).data,
  revokeKey: async (id: string) => (await request<GatewayKey>(`/api-keys/${id}/revoke`, { method: 'POST' })).data,
  rules: async () => (await request<RuleSet[]>('/rule-sets')).data,
  createRule: async (scope: string, rules: any[]) => (await request<RuleSet>('/rule-sets', json('POST', { scope, rules }))).data,
  publishRule: async (version: string) => (await request<RuleSet>(`/rule-sets/${version}/publish`, { method: 'POST' })).data,
  rollbackRule: async (scope: string, version: string) => (await request<RuleSet>(`/rule-sets/${scope}/rollback`, json('POST', { version }))).data,
  policies: async () => (await request<Policy[]>('/policies')).data,
  createPolicy: async (value: Policy) => (await request<Policy>('/policies', json('POST', value))).data,
  updatePolicy: async (id: string, value: Policy) => (await request<Policy>(`/policies/${id}`, json('PUT', value))).data,
  deletePolicy: async (id: string) => (await request<void>(`/policies/${id}`, { method: 'DELETE' })).data,
  audit: async (query = '') => (await request<any>(`/audit/events${query ? `?${query}` : ''}`)).data,
  auditSummary: async () => (await request<any>('/audit/summary?bucket=day')).data,
  changePassword: async (current_password: string, new_password: string) => (await request<void>('/auth/password', json('POST', { current_password, new_password }))).data,
  logoutAll: async () => (await request<void>('/auth/sessions/logout-all', { method: 'POST' })).data,
}
