export type Integrity = "UNTRUSTED" | "TOOL_OUTPUT" | "USER" | "SYSTEM";
export type Confidentiality = "PUBLIC" | "INTERNAL" | "SECRET";
export type EventKind = "call" | "blocked" | "error" | "finish";

export interface Segment {
  text: string;
  integrity: Integrity;
  confidentiality: Confidentiality;
  sources: string[];
}

export interface EventArg {
  name: string;
  value: string;
}

export interface TraceEvent {
  step: number;
  kind: EventKind;
  tool: string;
  args: EventArg[];
  detail: string;
}

export interface RunSummary {
  id: number;
  created_at: string;
  scenario_id: string;
  family: string;
  defense: string;
  task: string;
  seed: number;
  is_attack: boolean;
  attack_succeeded: boolean;
  utility_ok: boolean;
  blocked: number;
  calls: number;
  steps: number;
  truncated: boolean;
}

export interface RunDetail extends RunSummary {
  answer: string;
  context: Segment[];
  events: TraceEvent[];
}

export interface Page<T> {
  total: number;
  items: T[];
}

export interface ScenarioSummary {
  id: string;
  family: string;
  task: string;
  is_attack: boolean;
  meta: Record<string, string>;
}

export interface DefenseInfo {
  spec: string;
  name: string;
  description: string;
}

export interface HealthInfo {
  status: string;
  scenarios: number;
  runs: number;
}

export interface RunRequest {
  scenario_id: string;
  defense: string;
  seed?: number;
  confirm?: boolean;
}

export interface PlanStepInfo {
  tool: string;
  args: Record<string, string>;
}

export interface WebPage {
  url: string;
  text: string;
}

export interface FileInfo {
  path: string;
  content: string;
  integrity: Integrity;
  confidentiality: Confidentiality;
}

export interface CheckInfo {
  effect: string;
  value: string;
}

export interface ScenarioDetail extends ScenarioSummary {
  plan: PlanStepInfo[];
  answer: string;
  web: WebPage[];
  inbox: string[];
  files: FileInfo[];
  attack: CheckInfo | null;
  utility: CheckInfo | null;
}

export interface FamilyInfo {
  family: string;
  is_attack: boolean;
  count: number;
}

export interface RateInfo {
  hits: number;
  total: number;
  rate: number;
  lo: number;
  hi: number;
}

export interface DefenseResult {
  defense: string;
  attack_success: RateInfo;
  utility_under_attack: RateInfo;
  benign_utility: RateInfo;
  benign_blocked: RateInfo;
  latency_median_ms: number;
  latency_p95_ms: number;
  overhead: number | null;
}

export interface PairedInfo {
  defense: string;
  pivot: string;
  only_defense_succeeds: number;
  only_pivot_succeeds: number;
  mcnemar_p: number;
}

export type RateGroups = Record<string, Record<string, RateInfo>>;

export interface ResultsData {
  pivot: string;
  defenses: DefenseResult[];
  attack_breakdown: Record<string, RateGroups>;
  benign_breakdown: RateGroups;
  paired: PairedInfo[];
}

export interface CanonicalizeResponse {
  text: string;
  canonical: string;
  has_evasion: boolean;
  score: number;
  techniques: string[];
}

export interface TokenIssueResponse {
  token: string;
  token_id: string;
  content_digest: string;
  merkle_root: string;
  created_at: number;
  expires_at: number;
}

export interface TokenVerifyResponse {
  valid: boolean;
  label: {
    integrity: string;
    confidentiality: string;
    sources: string[];
  };
  token_id: string;
  sender: string;
}

export interface DeclassifyTestResponse {
  matches: boolean;
  pattern: string;
  value: string;
}
