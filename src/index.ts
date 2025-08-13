export interface Env {
  ALLOW_ORIGIN: string,   // 允許的前端網域（例如 https://blog.familyds.com）
  ALLOWED_HOSTS: string,  // 允許轉發的上游主機（預設 app.overlays.uno）
  AUTH_TOKEN?: string     // （可選）前端自訂驗證 token
}

const CORS = (origin: string) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Proxy-Token",
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // 預檢請求
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS(env.ALLOW_ORIGIN || "*") });
    }

    // 只開放一個路徑
    if (url.pathname !== "/overlay-proxy") {
      return new Response("Not found", { status: 404 });
    }

    // （可選）驗證自訂 token，避免被濫用
    if (env.AUTH_TOKEN) {
      const got = request.headers.get("X-Proxy-Token");
      if (got !== env.AUTH_TOKEN) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...CORS(env.ALLOW_ORIGIN || "*") },
        });
      }
    }

    // 讀 ?u= 目標 URL（必填）
    const target = url.searchParams.get("u");
    if (!target) {
      return new Response(JSON.stringify({ error: 'Missing "u" query param' }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...CORS(env.ALLOW_ORIGIN || "*") },
      });
    }

    // 限制只允許特定上游主機
    const upstream = new URL(target);
    const allowedHosts = (env.ALLOWED_HOSTS || "app.overlays.uno").split(",").map(s => s.trim());
    if (!allowedHosts.includes(upstream.host)) {
      return new Response(JSON.stringify({ error: "Host not allowed" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...CORS(env.ALLOW_ORIGIN || "*") },
      });
    }

    // 準備轉發：沿用 method / headers / body
    const init: RequestInit = {
      method: request.method,
      headers: {
        "Content-Type": request.headers.get("Content-Type") || "application/json",
      },
      body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.text(),
      redirect: "manual",
    };

    // 透傳 Authorization（如果你有需要）
    const auth = request.headers.get("Authorization");
    if (auth) (init.headers as Record<string, string>)["Authorization"] = auth;

    // 送出
    const resp = await fetch(upstream.toString(), init);

    // 取回內容（JSON 或純文字都支援）
    const contentType = resp.headers.get("content-type") || "application/json";
    const text = await resp.text();

    return new Response(text, {
      status: resp.status,
      headers: {
        "Content-Type": contentType,
        ...CORS(env.ALLOW_ORIGIN || "*"),
      },
    });
  }
} satisfies ExportedHandler<Env>;
