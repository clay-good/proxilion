// Minimal Cloudflare Worker for proxilion.com.
//
// The site is 100% static. Workers Static Assets serves `site/` directly per
// wrangler.toml — this worker only runs if `run_worker_first` is true OR if
// the ASSETS binding misses (it shouldn't, given the SPA fallback).
//
// Kept here because `wrangler deploy` requires a `main` script even when the
// project is asset-only.

export default {
  async fetch(request, env) {
    if (env && env.ASSETS && typeof env.ASSETS.fetch === "function") {
      return env.ASSETS.fetch(request);
    }
    return new Response("Not Found", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "x-content-type-options": "nosniff",
      },
    });
  },
};
