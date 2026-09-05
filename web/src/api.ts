export type ApiError = Error & { status?: number }

function csrfToken(): string {
  const prefix = 'gateway_admin_csrf='
  const cookie = document.cookie.split('; ').find(value => value.startsWith(prefix))
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : ''
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const method = (init.method || 'GET').toUpperCase()
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', token)
  }
  const response = await fetch(`/admin/v1${path}`, { ...init, headers, credentials: 'include' })
  if (response.status === 204) return undefined as T
  const text = await response.text()
  let body: any
  try { body = text ? JSON.parse(text) : undefined } catch { body = undefined }
  if (!response.ok) {
    const error = new Error(body?.error?.message || body?.message || `Request failed (${response.status})`) as ApiError
    error.status = response.status
    throw error
  }
  return body as T
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
  setupStatus: () => request<SetupStatus>('/setup/status'),
  setup: (username: string, password: string) => request<User>('/setup', json('POST', { username, password })),
  login: (username: string, password: string) => request<User>('/auth/login', json('POST', { username, password })),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  me: () => request<User>('/auth/me'),
  health: () => request<any>('/healthz'),
  upstreams: () => request<Upstream[]>('/upstreams'),
  createUpstream: (value: { name: string; base_url: string; api_key?: string; enabled: boolean }) => request<Upstream>('/upstreams', json('POST', value)),
  updateUpstream: (id: string, value: { name: string; base_url: string; api_key?: string; enabled: boolean }) => request<Upstream>(`/upstreams/${id}`, json('PUT', value)),
  deleteUpstream: (id: string) => request<void>(`/upstreams/${id}`, { method: 'DELETE' }),
  testUpstream: (id: string) => request<{ ok: boolean; message?: string }>(`/upstreams/${id}/test`, { method: 'POST' }),
  keys: () => request<GatewayKey[]>('/api-keys'),
  createKey: (tenant_id: string, upstream_id: string, display_name?: string) => request<GatewayKey & { key: string }>('/api-keys', json('POST', { tenant_id, upstream_id, display_name })),
  revokeKey: (id: string) => request<GatewayKey>(`/api-keys/${id}/revoke`, { method: 'POST' }),
  rules: () => request<RuleSet[]>('/rule-sets'),
  createRule: (scope: string, rules: any[]) => request<RuleSet>('/rule-sets', json('POST', { scope, rules })),
  publishRule: (version: string) => request<RuleSet>(`/rule-sets/${version}/publish`, { method: 'POST' }),
  rollbackRule: (scope: string, version: string) => request<RuleSet>(`/rule-sets/${scope}/rollback`, json('POST', { version })),
  policies: () => request<Policy[]>('/policies'),
  createPolicy: (value: Policy) => request<Policy>('/policies', json('POST', value)),
  updatePolicy: (id: string, value: Policy) => request<Policy>(`/policies/${id}`, json('PUT', value)),
  deletePolicy: (id: string) => request<void>(`/policies/${id}`, { method: 'DELETE' }),
  audit: (query = '') => request<any>(`/audit/events${query ? `?${query}` : ''}`),
  auditSummary: () => request<any>('/audit/summary?bucket=day'),
}
