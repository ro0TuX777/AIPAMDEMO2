import assert from "node:assert/strict";
import { createServer as createHttpServer } from "node:http";
import { after, before, beforeEach, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

const root = fileURLToPath(new URL("../../", import.meta.url));
const apiBase = "http://api.test/api/v1";
let apiServer;
let client;

before(async () => {
  apiServer = await createServer({
    root,
    configFile: false,
    envFile: false,
    define: {
      "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`),
      "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false"),
    },
    server: { middlewareMode: true, watch: null, hmr: { server: createHttpServer() } },
    appType: "custom",
  });
  client = await apiServer.ssrLoadModule("/src/api/chat.ts");
});

beforeEach(() => mock.restoreAll());
after(async () => { await apiServer?.close(); });

function captureRequests(responseBody = {}) {
  const calls = [];
  mock.method(globalThis, "fetch", async (url, init = {}) => {
    calls.push({
      method: init.method ?? "GET",
      path: String(url).replace(apiBase, ""),
      body: init.body === undefined ? undefined : JSON.parse(init.body),
    });
    return Response.json(responseBody);
  });
  return calls;
}

test("create comparison posts only the root conversation id", async () => {
  const calls = captureRequests();

  await client.chatApi.openComparison("job-1", "root-1");

  assert.deepEqual(calls[0], {
    method: "POST",
    path: "/jobs/job-1/chat/comparisons",
    body: { root_conversation_id: "root-1" },
  });
});

test("restore comparison gets the selected group", async () => {
  const calls = captureRequests();

  await client.chatApi.getComparison("job-1", "group-1");

  assert.deepEqual(calls[0], {
    method: "GET",
    path: "/jobs/job-1/chat/comparisons/group-1",
    body: undefined,
  });
});

test("create comparison branch sends source and stable request identity", async () => {
  const calls = captureRequests();

  await client.chatApi.createComparisonBranch("job-1", "group-1", "message-1", "request-1");

  assert.deepEqual(calls[0], {
    method: "POST",
    path: "/jobs/job-1/chat/comparisons/group-1/branches",
    body: { source_message_id: "message-1", request_id: "request-1" },
  });
});

test("comparison stream returns terminal metadata separately from answer content", async () => {
  const requestId = "19e5ad35-d7a8-4f63-a593-93d83425149f";
  mock.method(globalThis, "fetch", async () => new Response([
    `data: ${JSON.stringify({ type: "token", content: "Current-job answer" })}`,
    "",
    `data: ${JSON.stringify({
      type: "meta",
      conversation_id: "conversation-1",
      branch_id: "branch-1",
      request_id: requestId,
      status: "completed",
      retrieval_status: "used",
      citations: [{
        type: "historical_finding",
        id: "finding-1",
        snippet: "Historical appendix source",
        source_job_id: "job-old",
        source_project_id: null,
        href: "/jobs/job-old/findings/finding-1",
      }],
      model_id: "model-1",
      generation: { temperature: 0.2, max_tokens: 512 },
      confidence: 0.85,
      evidence_refs: [],
      suggested_followups: [],
    })}`,
    "",
    "data: [DONE]",
    "",
  ].join("\n"), { headers: { "Content-Type": "text/event-stream" } }));
  const events = [];

  const terminal = await client.chatApi.streamWithJob("job-1", {
    message: "Compare this activity",
    mode: "mnemos",
    request_id: requestId,
  }, event => events.push(event));

  assert.equal(events[0].type, "token");
  assert.equal(events[0].content, "Current-job answer");
  assert.equal(terminal.type, "meta");
  assert.equal(terminal.status, "completed");
  assert.equal(terminal.request_id, requestId);
  assert.equal(terminal.retrieval_status, "used");
  assert.equal(terminal.citations[0].type, "historical_finding");
});

test("baseline comparison copy invokes its callback without posting chat", async () => {
  const harnessId = "virtual:chat-panel-comparison-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root,
    configFile: false,
    envFile: false,
    define: {
      "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`),
      "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false"),
    },
    plugins: [{
      name: "chat-panel-comparison-harness",
      resolveId(id) {
        if (id === harnessId) return resolvedHarnessId;
      },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";

          window.__copyCalls = [];
          window.__networkCalls = [];
          window.fetch = async (url, init = {}) => {
            window.__networkCalls.push({ url: String(url), method: init.method || "GET" });
            return Response.json([]);
          };

          const conversation = {
            id: "root-1",
            job_id: "job-1",
            created_at: "2026-09-22T00:00:00Z",
            updated_at: "2026-09-22T00:00:00Z",
            messages: [{
              id: "message-1",
              sequence: 1,
              role: "user",
              content: "Was this C2 activity?",
              citations: [],
              metadata: null,
              request_id: null,
              timestamp: "2026-09-22T00:00:00Z",
            }],
          };

          createRoot(document.getElementById("root")).render(React.createElement(ChatPanel, {
            jobId: "job-1",
            conversation,
            mode: "baseline",
            onCopyToMnemos: (messageId, content) => window.__copyCalls.push([messageId, content]),
            onRetry: () => {},
            onConversationChanged: () => {},
          }));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-comparison", (_request, response) => {
          response.statusCode = 200;
          response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }],
    server: { host: "127.0.0.1", port: 0 },
    appType: "custom",
  });

  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-comparison`);
    const copyButton = page.getByRole("button", { name: "Copy to MNEMOS" });
    await copyButton.click();

    assert.deepEqual(await page.evaluate(() => window.__copyCalls), [
      ["message-1", "Was this C2 activity?"],
    ]);
    assert.equal(
      await page.evaluate(() => window.__networkCalls.some(call => new URL(call.url).pathname.endsWith("/chat"))),
      false,
    );
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});
