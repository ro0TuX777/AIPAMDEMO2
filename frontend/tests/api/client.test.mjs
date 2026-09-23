import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { after, afterEach, before, beforeEach, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";

const root = fileURLToPath(new URL("../../", import.meta.url));
const apiBase = "http://api.test/api/v1";
const servers = [];
let live;
let demo;

async function loadClient(demoMode) {
  const server = await createServer({
    root,
    configFile: false,
    envFile: false,
    define: {
      "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`),
      "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify(String(demoMode)),
    },
    server: { middlewareMode: true, watch: null, hmr: { server: createHttpServer() } },
    appType: "custom",
  });
  servers.push(server);
  return server.ssrLoadModule("/src/api.ts");
}

class UploadRequest {
  static instances = [];
  headers = {};
  upload = {};
  constructor() { UploadRequest.instances.push(this); }
  open(method, url) { this.method = method; this.url = url; }
  setRequestHeader(name, value) { this.headers[name] = value; }
  send(body) { this.body = body; }
  respond(status, body) {
    this.status = status;
    this.responseText = body;
    this.onload();
  }
}

const originalXhr = Object.getOwnPropertyDescriptor(globalThis, "XMLHttpRequest");
const originalEventSource = Object.getOwnPropertyDescriptor(globalThis, "EventSource");

before(async () => {
  live = await loadClient(false);
  demo = await loadClient(true);
});

beforeEach(() => {
  UploadRequest.instances = [];
  globalThis.XMLHttpRequest = UploadRequest;
  live.setApiToken(null);
  demo.setApiToken(null);
});

afterEach(() => {
  mock.restoreAll();
  for (const [key, descriptor] of [
    ["XMLHttpRequest", originalXhr], ["EventSource", originalEventSource],
  ]) {
    if (descriptor) Object.defineProperty(globalThis, key, descriptor);
    else delete globalThis[key];
  }
});

after(async () => { await Promise.all(servers.map(server => server.close())); });

function interceptFetch(response = () => Response.json({ items: [] })) {
  return mock.method(globalThis, "fetch", async (...args) => response(...args));
}

test("public embedding settings API preserves config, selection, pull, and encoded polling", async () => {
  const requests = [];
  interceptFetch((url, init) => {
    requests.push([url, init?.method ?? "GET", init?.body]);
    return Response.json(url.endsWith("/embedding-models") ? { models: [{ name: "embed" }] } : { model: "embed" });
  });
  assert.equal((await live.api.getEmbeddingModel()).model, "embed");
  assert.deepEqual(await live.api.getEmbeddingModels(), [{ name: "embed" }]);
  await live.api.selectEmbeddingModel("embed");
  await live.api.pullEmbeddingModel("embed");
  await live.api.getEmbeddingModelPull("vendor/embed:latest");
  assert.deepEqual(requests.map(([url, method]) => [url.slice(apiBase.length), method]), [
    ["/embedding-model", "GET"], ["/embedding-models", "GET"], ["/embedding-model", "POST"],
    ["/embedding-models/pull", "POST"], ["/embedding-models/pull/vendor%2Fembed%3Alatest", "GET"],
  ]);
  assert.equal(requests[2][2], JSON.stringify({ model: "embed" }));
});

test("demo saved chat history and new replies expose stable ordered messages with citations", async () => {
  const jobId = "a7f3c2e1-9b04-4d17-8e62-3fc51a0d7b88";
  const history = await demo.api.getConversation(jobId, "conv-demo-1");
  for (const message of history.messages) {
    assert.ok(message.id);
    assert.ok(message.sequence > 0);
    assert.ok(Array.isArray(message.citations));
  }
  const reply = await demo.api.chatWithJob(jobId, { message: "Hosts?", conversation_id: history.id, request_id: "demo-request" });
  const updated = await demo.api.getConversation(jobId, reply.conversation_id);
  assert.ok(updated.messages.at(-1).sequence > history.messages.at(-1).sequence);
});

test("requests preserve query encoding, zero/false values, and the current token", async () => {
  const fetch = interceptFetch();
  live.setApiToken("first-token");
  await live.api.listJobs({ search: "host & port", limit: 0, archived: false, cursor: "", unused: null });
  assert.equal(fetch.mock.calls[0].arguments[0], `${apiBase}/jobs?search=host%20%26%20port&limit=0&archived=false`);
  assert.deepEqual(fetch.mock.calls[0].arguments[1].headers, { Authorization: "Bearer first-token" });
  live.setApiToken("replacement");
  await live.api.getHealth();
  assert.equal(fetch.mock.calls[1].arguments[1].headers.Authorization, "Bearer replacement");
  live.setApiToken(null);
  await live.api.getGlobalHost("2001:db8::1");
  assert.equal(fetch.mock.calls[2].arguments[0], `${apiBase}/hosts/2001%3Adb8%3A%3A1`);
  assert.deepEqual(fetch.mock.calls[2].arguments[1].headers, {});
});

test("JSON mutations and 204 responses preserve their request contracts", async () => {
  const fetch = interceptFetch(() => new Response(null, { status: 204 }));
  const body = { execution_profile: "triage", upload_id: "upload-1" };
  assert.equal(await live.api.createJob(body), undefined);
  await live.api.updateProof("job", "proof", { title: "Updated" });
  await live.api.updateSuricataRule("custom.rules", "alert tcp any any -> any any");
  await live.api.deleteJob("job");
  assert.deepEqual(fetch.mock.calls.map(call => call.arguments[1].method), ["POST", "PATCH", "PUT", "DELETE"]);
  assert.equal(fetch.mock.calls[0].arguments[1].body, JSON.stringify(body));
  assert.equal(fetch.mock.calls[0].arguments[1].headers["Content-Type"], "application/json");
  assert.equal(fetch.mock.calls[3].arguments[1].body, undefined);
});

test("cancelJob returns the updated job response from the cancel endpoint", async () => {
  const updated = { schema_version: "2.0", job: { job_id: "job-1", status: "canceling", cancel_requested_at: "2026-09-23T00:00:00Z" } };
  const fetch = interceptFetch(() => Response.json(updated));
  assert.deepEqual(await live.api.cancelJob("job-1"), updated);
  assert.equal(fetch.mock.calls[0].arguments[0], `${apiBase}/jobs/job-1/cancel`);
  assert.equal(fetch.mock.calls[0].arguments[1].method, "POST");
});

test("API errors retain their public class, message, details, and retry delay", async () => {
  interceptFetch(() => Response.json(
    { code: "BUSY", detail: "Try later", details: { stage: "queued" } },
    { status: 429, headers: { "Retry-After": "12" } },
  ));
  await assert.rejects(live.api.getHealth(), error => {
    assert.ok(error instanceof live.ApiError);
    assert.equal(error.name, "ApiError");
    assert.equal(error.status, 429);
    assert.equal(error.code, "BUSY");
    assert.equal(error.message, "Try later");
    assert.equal(error.serverMessage, "Try later");
    assert.equal(error.retryAfter, 12);
    assert.deepEqual(error.details, { stage: "queued" });
    return true;
  });
});

test("non-JSON API errors keep the fallback message and ignore invalid retry delays", async () => {
  interceptFetch(() => new Response("unavailable", { status: 503, headers: { "Retry-After": "invalid" } }));
  await assert.rejects(live.api.getHealth(), error => {
    assert.ok(error instanceof live.ApiError);
    assert.equal(error.message, "[503] HTTP_503");
    assert.equal(error.retryAfter, undefined);
    return true;
  });
});

test("multipart library uploads keep auth and admin headers without forcing JSON", async () => {
  const fetch = interceptFetch();
  live.setApiToken("user-token");
  const file = new File(["evidence"], "reference.txt");
  await live.api.uploadLibraryBinaryFile(file, "Reference", "reference", "Details", "admin-token");
  const [url, init] = fetch.mock.calls[0].arguments;
  assert.equal(url, `${apiBase}/kb/library/upload-binary`);
  assert.deepEqual(init.headers, { Authorization: "Bearer user-token", "X-KB-Admin-Token": "admin-token" });
  assert.ok(init.body instanceof FormData);
  assert.equal(init.body.get("file").name, "reference.txt");
  assert.equal(init.body.get("name"), "Reference");
});

const uploads = [
  ["uploadPcap", "/uploads", "up", false],
  ["uploadBundle", "/uploads/bundle", "bundle", true],
  ["uploadArtifact", "/uploads/artifact", "artifact", true],
];

for (const [method, path, prefix, serverDetail] of uploads) {
  test(`${method} sends raw bytes, filename, auth, and computable progress`, async () => {
    live.setApiToken("upload-token");
    const file = new File(["packet"], "capture #1.bin");
    const progress = [];
    const pending = live.api[method](file, value => progress.push(value));
    const xhr = UploadRequest.instances[0];
    assert.equal(xhr.method, "POST");
    assert.equal(xhr.url, `${apiBase}${path}`);
    assert.equal(xhr.body, file);
    assert.deepEqual(xhr.headers, {
      Authorization: "Bearer upload-token",
      "Content-Disposition": 'attachment; filename="capture%20%231.bin"',
    });
    xhr.upload.onprogress({ lengthComputable: false, loaded: 1, total: 0 });
    xhr.upload.onprogress({ lengthComputable: true, loaded: 1, total: 3 });
    assert.deepEqual(progress, [33]);
    xhr.respond(201, '{"upload_id":"saved"}');
    assert.deepEqual(await pending, { upload_id: "saved" });
  });

  test(`${method} preserves its server error policy and malformed response handling`, async () => {
    const file = new File(["packet"], "capture.bin");
    const errors = [
      [400, '{"detail":"Rejected archive"}', serverDetail ? "Rejected archive" : "Upload failed with status 400"],
      [502, "Bad gateway", "Upload failed with status 502"],
      [200, "not JSON", "Invalid JSON response from server"],
    ];
    for (const [status, body, message] of errors) {
      const pending = live.api[method](file);
      UploadRequest.instances.at(-1).respond(status, body);
      await assert.rejects(pending, { message });
    }
    const pending = live.api[method](file);
    UploadRequest.instances.at(-1).onerror();
    await assert.rejects(pending, { message: "Network error during upload" });
  });

  test(`${method} retains its demo response and completes progress without network I/O`, async () => {
    const fetch = interceptFetch(() => { throw new Error("Unexpected network request"); });
    const progress = [];
    const result = await demo.api[method](new File(["data"], "demo.bin"), value => progress.push(value));
    assert.equal(result.schema_version, "1.0");
    assert.match(result.upload_id, new RegExp(`^${prefix}-\\d+$`));
    assert.match(result.sha256, /^demo-\d+$/);
    assert.equal(result.filename, "demo.bin");
    assert.equal(result.size_bytes, 4);
    assert.deepEqual(progress, [100]);
    assert.equal(UploadRequest.instances.length, 0);
    assert.equal(fetch.mock.calls.length, 0);
  });
}

test("export URLs and SSE use updated tokens across endpoint groups", () => {
  globalThis.EventSource = class { constructor(url) { this.url = url; } };
  live.setApiToken("token +&");
  assert.equal(live.api.getExportUrl("job"), `${apiBase}/jobs/job/export?token=token%20%2B%26`);
  assert.equal(live.api.getTemporalExportUrl("job", "html"), `${apiBase}/jobs/job/temporal-export?token=token%20%2B%26&format=html`);
  assert.equal(live.api.createJobEventSource("job").url, `${apiBase}/jobs/job/events?token=token%20%2B%26`);
  live.setApiToken(null);
  assert.equal(live.api.getExportUrl("job"), `${apiBase}/jobs/job/export`);
  assert.equal(live.api.getTemporalExportUrl("job"), `${apiBase}/jobs/job/temporal-export?format=markdown`);
  assert.equal(live.api.createJobEventSource("job").url, `${apiBase}/jobs/job/events`);
});

test("demo requests and download methods retain offline behavior", async () => {
  const fetch = interceptFetch(() => { throw new Error("Unexpected network request"); });
  assert.equal(live.isDemoMode(), false);
  assert.equal(demo.isDemoMode(), true);
  const jobs = await demo.api.listJobs();
  assert.ok(jobs.items.length > 0);
  assert.equal(demo.api.getExportUrl("job"), "#");
  assert.equal(demo.api.getTemporalExportUrl("job"), "#");
  assert.equal(demo.api.getArtifactDownloadUrl("artifact"), "#");
  await demo.api.downloadArtifact("artifact");
  await demo.api.downloadExtractedFile("job", "file");
  assert.equal(fetch.mock.calls.length, 0);
});

test("demo cancellation settles after a bounded number of job polls", async () => {
  const jobId = "c41d8b60-27ae-4f93-a5d1-6b7e90c2f314";
  const response = await demo.api.cancelJob(jobId);
  assert.equal(response.job.status, "canceling");
  const statuses = [];
  for (let attempt = 0; attempt < 3; attempt++) statuses.push((await demo.api.getJobDetail(jobId)).job.status);
  assert.ok(statuses.includes("canceled"), `demo remained ${statuses.join(", ")}`);
  assert.equal(statuses.at(-1), "canceled");
});
