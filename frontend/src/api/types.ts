export interface CursorPage<T> { items: T[]; next_cursor: string | null }
export interface Alert {
  id: string; source: string; rule_id: string; severity: string; agent: string | null;
  src_ip: string | null; dst_ip: string | null; raw: Record<string, unknown>; status: string; created_at: string;
}
export interface AlertSummary { by_severity: Record<string, number>; by_status: Record<string, number>; last_24h: number }
export interface Incident {
  id: string; title: string; description: string | null; status: string; created_at: string;
  updated_at: string; alert_ids: string[];
}
export interface Evidence { id: string; incident_id: string; alert_id: string | null; kind: string; data: Record<string, unknown>; created_at: string }
export interface Investigation { incident: Incident }
export interface Action {
  id: string; incident_id: string; action_type: string; target: Record<string, unknown>; params: Record<string, unknown>;
  level: number; approval_mode: string; status: string; requested_by: string; decided_by: string | null;
  ttl_seconds: number | null; ttl_expires_at: string | null; rollback_request_status: string | null; created_at: string;
}
export interface CatalogItem {
  action_type: string; level: number; connector: string; reversible: boolean; requestable: boolean;
  execution_modes: string[]; ttl_required: boolean;
  target_schema: { properties?: Record<string, unknown> }; parameters_schema: { properties?: Record<string, unknown> };
}
export interface Command {
  id: number; action_id: string; phase: string; connector: string; command: string; target: Record<string, unknown>;
  params: Record<string, unknown>; initiator: string; simulated: boolean; executed_at: string;
}
export interface CommandPage { items: Command[]; next_before_id: number | null }
export interface SwitchState { engaged: boolean; changed_by: string | null; changed_at: string }
export interface IntelResult { indicator: string; verdict: string; score: number | null; sources: string[]; mock: boolean; degraded: boolean; expires_at: string | null }
export interface CacheStats { fresh: number; expired: number; redis_available: boolean }
export interface User { id: string; username: string; role: string; is_active: boolean; created_at: string; updated_at: string }
export interface UserPage { items: User[]; limit: number; offset: number }
export interface Presentation { display_name: string; default_direction: 'ltr' | 'rtl' }
export interface HostSettings extends Presentation { updated_at: string }
