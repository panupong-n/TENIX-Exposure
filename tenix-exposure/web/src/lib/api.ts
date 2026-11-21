export class ApiError extends Error {
  status: number;
  code: string | null;
  /** The server's `detail` object (Falcon's own message for a refused connection), when it sent one. */
  detail: { step?: string; message?: string } | null;
  constructor(status: number, message: string, code: string | null, detail: ApiError["detail"] = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export const UNAUTHENTICATED_EVENT = "tenix:unauthenticated";

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      credentials: "same-origin",
      signal,
      // The server only accepts JSON for anything that changes data.
      headers: method === "GET" ? undefined : { "Content-Type": "application/json" },
      body: method === "GET" ? undefined : JSON.stringify(body ?? {}),
    });
  } catch (e) {
    if (signal?.aborted) throw e;
    throw new ApiError(0, "network", "network");
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const code = (data?.code as string | null) ?? null;
    if (res.status === 401 && code === "unauthenticated") {
      window.dispatchEvent(new Event(UNAUTHENTICATED_EVENT));
    }
    throw new ApiError(res.status, data?.error ?? "error", code, data?.detail && typeof data.detail === "object" ? data.detail : null);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>("GET", path, undefined, signal),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

export type TenantRole = "admin" | "operator";
export interface SessionUser {
  id: string;
  email: string;
  name: string;
  /** super_admin sees and does everything; a member only sees their own tenants, each as admin or operator. */
  role: "super_admin" | "member";
  /** true for a super admin: sees CIDs and every tenant */
  soc: boolean;
  /** may open the Team and Audit pages: a super admin, or an admin of at least one tenant */
  manager: boolean;
  tenants: { id: string; name: string; role: TenantRole }[];
  totpEnabled: boolean;
}
