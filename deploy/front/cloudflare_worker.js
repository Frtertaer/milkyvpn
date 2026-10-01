// MilkyVPN front relay — Cloudflare Worker.
//
// Transparent relay to UPSTREAM (the server's -front-listen port). Workers
// stream request/response bodies AND proxy WebSocket upgrades, so both
// buffered-safe carriers work here: `carrier=mosaic` and `carrier=cdn`
// (WebSocket drift). Free tier: 100k requests/day.
//
// Deploy:
//   npm i -g wrangler && wrangler login
//   wrangler deploy --name milky-front cloudflare_worker.js --var UPSTREAM:http://YOUR-SERVER:8081
//
// The worker URL (https://milky-front.<acct>.workers.dev) becomes the link's
// front= param. workers.dev is NOT in RU operator whitelists — this variant
// covers blocked-IP waves; for whitelist-mode use the Yandex function.

export default {
  async fetch(request, env) {
    const upstream = (env.UPSTREAM || "").replace(/\/+$/, "");
    if (!upstream) return new Response("UPSTREAM not configured", { status: 500 });

    const url = new URL(request.url);
    const target = upstream + url.pathname + url.search;

    if (request.headers.get("Upgrade") === "websocket") {
      // Pass the upgrade through — Workers fetch returns a pair whose
      // client side pipes straight back to our caller.
      const h = new Headers(request.headers);
      h.set("Host", new URL(upstream).host);
      const resp = await fetch(target, { method: request.method, headers: h });
      if (resp.status !== 101) {
        return new Response("upstream refused upgrade: " + resp.status, { status: 502 });
      }
      return resp;
    }

    const resp = await fetch(target, {
      method: request.method,
      headers: request.headers,
      body: request.body,
      redirect: "manual",
    });
    return resp;
  },
};
