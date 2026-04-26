// Build-time feature flags resolved from `PUBLIC_*` environment
// variables (Vite + SvelteKit). Read once at module load — Vite folds
// these into the bundle, so disabled branches are tree-shaken away.
//
// Keep the surface small. For now the only deployment axis is
// public-demo vs developer-dogfood; if flag fan-out grows we can swap
// this for the OpenFeature web SDK without touching callers.

import { PUBLIC_MAKINA_PUBLIC_MODE } from '$env/static/public';

const TRUTHY = new Set(['1', 'true', 'TRUE', 'True', 'yes', 'on']);

/** True when the deployment is the publicly-visible demo — Verify and
 *  Model tabs are hidden, learning-loop UI is unreachable. */
export const PUBLIC_MODE: boolean = TRUTHY.has(PUBLIC_MAKINA_PUBLIC_MODE ?? '');
