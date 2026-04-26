// Cloudflare Worker reverse proxy: api.makina.sh → Cloud Run.
//
// Why a Worker?
//   Cloud Run only answers requests whose `Host:` header matches one of
//   its registered hostnames (`*.run.app` or a domain mapping). On the
//   Cloudflare Free plan, Origin Rules cannot rewrite the Host header
//   (Enterprise-only). A Worker sits at the CF edge, fetches Cloud Run
//   with the correct Host, and pipes the response back — so we keep
//   every CF benefit (cache, WAF, analytics) for `api.makina.sh`
//   without paying for Enterprise.
//
// Latency cost: ~1–3 ms (the Worker runs on the same edge POP that
// terminated TLS). Negligible for makina's REST workload.

const ORIGIN_HOST = 'makina-api-sgq7gmstea-an.a.run.app';

export default {
	/**
	 * @param {Request} request
	 * @returns {Promise<Response>}
	 */
	async fetch(request) {
		const url = new URL(request.url);

		// Swap the hostname; preserve path + query untouched.
		url.hostname = ORIGIN_HOST;
		url.protocol = 'https:';
		url.port = '';

		// `cf.resolveOverride` and the explicit Host header both ensure
		// that Cloud Run's host-based routing recognises the request.
		const headers = new Headers(request.headers);
		headers.set('Host', ORIGIN_HOST);

		const upstream = new Request(url.toString(), {
			method: request.method,
			headers,
			body: request.body,
			redirect: 'manual'
		});

		return fetch(upstream);
	}
};
