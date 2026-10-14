import type {
  DefenseInfo,
  FamilyInfo,
  HealthInfo,
  Page,
  RunDetail,
  RunRequest,
  RunSummary,
  ScenarioDetail,
  ResultsData,
  ScenarioSummary,
  CanonicalizeResponse,
  TokenIssueResponse,
  TokenVerifyResponse,
  DeclassifyTestResponse,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

type QueryValue = string | number | boolean | undefined;

export function buildQuery(params: Record<string, QueryValue>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) {
      search.set(key, String(value));
    }
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
  });
  if (!response.ok) {
    let detail = response.statusText || `HTTP ${response.status}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // The error body was not JSON; keep the status text.
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<HealthInfo>("/api/health"),
  results: () => request<ResultsData>("/api/results"),
  defenses: () => request<DefenseInfo[]>("/api/defenses"),
  families: () => request<FamilyInfo[]>("/api/families"),
  scenarios: (params: { attack?: boolean; family?: string; limit?: number; offset?: number }) =>
    request<Page<ScenarioSummary>>(`/api/scenarios${buildQuery(params)}`),
  scenario: (id: string) => request<ScenarioDetail>(`/api/scenarios/${encodeURIComponent(id)}`),
  listRuns: (params: { defense?: string; scenario_id?: string; limit?: number; offset?: number }) =>
    request<Page<RunSummary>>(`/api/runs${buildQuery(params)}`),
  getRun: (id: number) => request<RunDetail>(`/api/runs/${id}`),
  createRun: (body: RunRequest) =>
    request<RunDetail>("/api/runs", { method: "POST", body: JSON.stringify(body) }),
  deleteRun: (id: number) => request<void>(`/api/runs/${id}`, { method: "DELETE" }),
  canonicalize: (text: string) =>
    request<CanonicalizeResponse>("/api/canonicalize", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  issueToken: (body: {
    sender?: string;
    content: string;
    integrity?: string;
    confidentiality?: string;
    secret_key?: string;
    ttl_seconds?: number;
  }) =>
    request<TokenIssueResponse>("/api/tokens/issue", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  verifyToken: (body: { content: string; token: string; secret_key?: string }) =>
    request<TokenVerifyResponse>("/api/tokens/verify", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  testDeclassify: (pattern: string, value: string) =>
    request<DeclassifyTestResponse>("/api/declassify/test", {
      method: "POST",
      body: JSON.stringify({ pattern, value }),
    }),
};
