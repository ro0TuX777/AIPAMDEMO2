# API client

Pages and hooks import from `src/api.ts`, which preserves the public `api` object,
types, `ApiError`, `setApiToken`, and `isDemoMode` exports.

- `types.ts` holds the API request, response, and event contracts.
- `transport.ts` owns the API base URL, demo dispatch, token state, query encoding,
  and JSON request/error handling. All endpoint groups share this token state.
- Domain modules define endpoint methods; `uploads.ts` also owns raw-file upload
  progress and the existing differences in upload error messages.

Add endpoints to their domain module and contracts to `types.ts`. Internal modules
import directly from `types.ts` and `transport.ts`, avoiding the public entry point.

Run `npm run test:api` from `frontend/` for the client regression tests. They load
the client through Vite and stub browser I/O, so no backend or browser is needed.
