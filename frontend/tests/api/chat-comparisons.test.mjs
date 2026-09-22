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

test("comparison stream rejects an EOF that only reports pending metadata", async () => {
  mock.method(globalThis, "fetch", async () => new Response([
    `data: ${JSON.stringify({ type: "meta", conversation_id: "conversation-1", status: "pending", citations: [] })}`,
    "",
    "data: [DONE]",
    "",
  ].join("\n"), { headers: { "Content-Type": "text/event-stream" } }));

  await assert.rejects(
    client.chatApi.streamWithJob("job-1", { message: "Still pending", mode: "mnemos", request_id: "request-1" }, () => {}),
    error => error.name === "ChatStreamError" && error.responseReceived === true && /pending/.test(error.message),
  );
});

test("Copy to MNEMOS uses the persisted user message id after a baseline send", async () => {
  const harnessId = "virtual:chat-panel-persisted-id-harness";
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
      name: "chat-panel-persisted-id-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useEffect, useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";

          window.__copyCalls = [];
          window.fetch = async (url, init = {}) => {
            const path = new URL(String(url)).pathname;
            if (path.endsWith("/chat/stream")) {
              const request = JSON.parse(init.body);
              window.__requestId = request.request_id;
              return new Response([
                "data: " + JSON.stringify({ type: "meta", conversation_id: "root-1", request_id: request.request_id, status: "pending", citations: [] }), "",
                "data: " + JSON.stringify({ type: "token", content: "Answer" }), "",
                "data: " + JSON.stringify({ type: "meta", conversation_id: "root-1", request_id: request.request_id, status: "completed", citations: [], evidence_refs: [], suggested_followups: [] }), "",
                "data: [DONE]", "",
              ].join("\\n"), { headers: { "Content-Type": "text/event-stream" } });
            }
            if (path.endsWith("/conversations/root-1")) return Response.json({
              id: "root-1", job_id: "job-1", created_at: "2026-09-22T00:00:00Z", updated_at: "2026-09-22T00:00:01Z",
              messages: [
                { id: "persisted-user-1", sequence: 1, role: "user", content: "New question", citations: [], metadata: null, request_id: window.__requestId, timestamp: "2026-09-22T00:00:00Z" },
                { id: "persisted-assistant-1", sequence: 2, role: "assistant", content: "Answer", citations: [], metadata: { status: "completed", request_id: window.__requestId, user_message_id: "persisted-user-1" }, request_id: null, timestamp: "2026-09-22T00:00:01Z" },
              ],
            });
            throw new Error("Unexpected request: " + path);
          };

          function Harness() {
            const [conversation, setConversation] = useState({ id: "root-1", job_id: "job-1", messages: [] });
            return React.createElement(ChatPanel, {
              jobId: "job-1", conversation, mode: "baseline",
              onCopyToMnemos: (messageId, content) => window.__copyCalls.push([messageId, content]),
              onRetry: () => {}, onConversationChanged: setConversation,
            });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-persisted-id", (_request, response) => {
          response.statusCode = 200;
          response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }],
    server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });

  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-persisted-id`);
    await page.getByPlaceholder("Ask about the findings...").fill("New question");
    await page.getByRole("button", { name: "Send" }).click();
    const copy = page.getByRole("button", { name: "Copy to MNEMOS" });
    await copy.waitFor();
    await copy.click();
    assert.deepEqual(await page.evaluate(() => window.__copyCalls), [["persisted-user-1", "New question"]]);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});

test("a stream from an earlier controlled conversation cannot overwrite a later selection", async () => {
  const harnessId = "virtual:chat-panel-selection-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root, configFile: false, envFile: false,
    define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`), "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false") },
    plugins: [{
      name: "chat-panel-selection-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useEffect, useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";
          window.fetch = async (url, init = {}) => {
            const path = new URL(String(url)).pathname;
            if (path.endsWith("/chat/stream")) {
              const request = JSON.parse(init.body);
              const encoder = new TextEncoder();
              return new Response(new ReadableStream({ start(controller) {
                controller.enqueue(encoder.encode("data: " + JSON.stringify({ type: "token", content: "A answer" }) + "\\n\\n"));
                window.__releaseStream = () => {
                  controller.enqueue(encoder.encode("data: " + JSON.stringify({ type: "meta", conversation_id: "conversation-a", request_id: request.request_id, status: "completed", citations: [] }) + "\\n\\n"));
                  controller.enqueue(encoder.encode("data: [DONE]\\n\\n"));
                  controller.close();
                };
              }}), { headers: { "Content-Type": "text/event-stream" } });
            }
            if (path.endsWith("/conversations/conversation-a")) return Response.json({ id: "conversation-a", job_id: "job-1", messages: [] });
            throw new Error("Unexpected request: " + path);
          };
          function Harness() {
            const [conversation, setConversation] = useState({ id: "conversation-a", job_id: "job-1", messages: [] });
            const [selectionToken, setSelectionToken] = useState("selection-a");
            useEffect(() => { window.__currentConversation = { conversation, selectionToken }; }, [conversation, selectionToken]);
            window.__selectConversationB = () => {
              setSelectionToken("selection-b");
              setConversation({ id: "conversation-b", job_id: "job-1", messages: [{ id: "b-user", sequence: 1, role: "user", content: "Conversation B", citations: [], metadata: null, request_id: null, timestamp: "2026-09-22T00:00:00Z" }] });
            };
            return React.createElement(ChatPanel, { jobId: "job-1", conversation, selectionToken, mode: "baseline", onCopyToMnemos: () => {}, onRetry: () => {}, onConversationChanged: setConversation });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-selection", (_request, response) => {
          response.statusCode = 200; response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }], server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });
  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-selection`);
    await page.getByPlaceholder("Ask about the findings...").fill("Question for A");
    await page.getByRole("button", { name: "Send" }).click();
    await page.waitForFunction(() => typeof window.__releaseStream === "function");
    await page.evaluate(() => window.__selectConversationB());
    await page.waitForFunction(() => window.__currentConversation?.selectionToken === "selection-b");
    await page.evaluate(() => window.__releaseStream());
    await page.getByText("Conversation B").waitFor();
    await page.waitForFunction(() => window.__currentConversation?.conversation?.id === "conversation-b");
    assert.equal(await page.getByText("Question for A").count(), 0);
    assert.equal(await page.getByPlaceholder("Ask about the findings...").isDisabled(), false);
    assert.equal(await page.getByText("Thinking...").count(), 0);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});

test("an id-less draft selection invalidates an older stream", async () => {
  const harnessId = "virtual:chat-panel-draft-selection-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root, configFile: false, envFile: false,
    define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`), "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false") },
    plugins: [{
      name: "chat-panel-draft-selection-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";
          window.__staleEmissions = 0;
          window.__afterSelection = false;
          window.fetch = async (url, init = {}) => {
            const path = new URL(String(url)).pathname;
            if (path.endsWith("/chat/stream")) {
              const request = JSON.parse(init.body);
              const encoder = new TextEncoder();
              return new Response(new ReadableStream({ start(controller) {
                controller.enqueue(encoder.encode("data: " + JSON.stringify({ type: "token", content: "Old answer" }) + "\\n\\n"));
                window.__releaseDraftStream = () => {
                  controller.enqueue(encoder.encode("data: " + JSON.stringify({ type: "meta", conversation_id: "server-a", request_id: request.request_id, status: "completed", citations: [] }) + "\\n\\n"));
                  controller.enqueue(encoder.encode("data: [DONE]\\n\\n")); controller.close();
                };
              }}), { headers: { "Content-Type": "text/event-stream" } });
            }
            if (path.endsWith("/conversations/server-a")) return Response.json({ id: "server-a", job_id: "job-1", messages: [] });
            throw new Error("Unexpected request: " + path);
          };
          function Harness() {
            const [conversation, setConversation] = useState({ job_id: "job-1", messages: [] });
            const [selectionToken, setSelectionToken] = useState("draft-a");
            window.__selectDraftB = () => {
              window.__afterSelection = true;
              setSelectionToken("draft-b");
              setConversation({ job_id: "job-1", messages: [{ id: "draft-b-message", sequence: 1, role: "user", content: "Draft B", citations: [], metadata: null, request_id: null, timestamp: "2026-09-22T00:00:00Z" }] });
            };
            const onConversationChanged = next => {
              if (window.__afterSelection) window.__staleEmissions += 1;
              setConversation(next);
            };
            return React.createElement(ChatPanel, { jobId: "job-1", conversation, selectionToken, mode: "baseline", onCopyToMnemos: () => {}, onRetry: () => {}, onConversationChanged });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-draft-selection", (_request, response) => {
          response.statusCode = 200; response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }], server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });
  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-draft-selection`);
    await page.getByPlaceholder("Ask about the findings...").fill("Question for draft A");
    await page.getByRole("button", { name: "Send" }).click();
    await page.waitForFunction(() => typeof window.__releaseDraftStream === "function");
    await page.evaluate(() => window.__selectDraftB());
    await page.evaluate(() => window.__releaseDraftStream());
    await page.getByText("Draft B").waitFor();
    assert.equal(await page.evaluate(() => window.__staleEmissions), 0);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});

test("changing MNEMOS selection hides an older retry ownership", async () => {
  const harnessId = "virtual:chat-panel-retry-selection-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root, configFile: false, envFile: false,
    define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`), "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false") },
    plugins: [{
      name: "chat-panel-retry-selection-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";
          window.__retryCalls = [];
          window.fetch = async (url, init = {}) => {
            const path = new URL(String(url)).pathname;
            if (path.endsWith("/chat/stream")) {
              const request = JSON.parse(init.body);
              window.__failedRequestId = request.request_id;
              return Response.json({ detail: { code: "MNEMOS_UNAVAILABLE", error: "MNEMOS unavailable" } }, { status: 503 });
            }
            if (path.endsWith("/conversations/mnemos-a")) return Response.json({ id: "mnemos-a", job_id: "job-1", messages: [] });
            throw new Error("Unexpected request: " + path);
          };
          function Harness() {
            const [conversation, setConversation] = useState({ id: "mnemos-a", job_id: "job-1", messages: [] });
            const [selectionToken, setSelectionToken] = useState("mnemos-a");
            window.__selectMnemosB = () => {
              setSelectionToken("mnemos-b");
              setConversation({ id: "mnemos-b", job_id: "job-1", messages: [{ id: "mnemos-b-user", sequence: 1, role: "user", content: "MNEMOS B", citations: [], metadata: null, request_id: null, timestamp: "2026-09-22T00:00:00Z" }] });
            };
            return React.createElement(ChatPanel, { jobId: "job-1", conversation, selectionToken, mode: "mnemos", onCopyToMnemos: () => {}, onRetry: requestId => window.__retryCalls.push(requestId), onConversationChanged: setConversation });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-retry-selection", (_request, response) => {
          response.statusCode = 200; response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }], server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });
  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-retry-selection`);
    await page.getByPlaceholder("Ask about the findings...").fill("Fail A");
    await page.getByRole("button", { name: "Send" }).click();
    await page.getByRole("button", { name: "Retry MNEMOS" }).waitFor();
    await page.evaluate(() => window.__selectMnemosB());
    await page.getByText("MNEMOS B").waitFor();
    assert.equal(await page.getByRole("button", { name: "Retry MNEMOS" }).count(), 0);
    assert.deepEqual(await page.evaluate(() => window.__retryCalls), []);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});

test("Retry MNEMOS carries the failed request id", async () => {
  const harnessId = "virtual:chat-panel-retry-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root, configFile: false, envFile: false,
    define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`), "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false") },
    plugins: [{
      name: "chat-panel-retry-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";
          window.__retryCalls = [];
          window.fetch = async (url, init = {}) => {
            const request = JSON.parse(init.body);
            window.__failedRequestId = request.request_id;
            return Response.json({ detail: { code: "MNEMOS_UNAVAILABLE", error: "MNEMOS unavailable" } }, { status: 503 });
          };
          function Harness() {
            const [conversation, setConversation] = useState({ id: "mnemos-1", job_id: "job-1", messages: [] });
            return React.createElement(ChatPanel, { jobId: "job-1", conversation, mode: "mnemos", onCopyToMnemos: () => {}, onRetry: requestId => window.__retryCalls.push(requestId), onConversationChanged: setConversation });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-retry", (_request, response) => {
          response.statusCode = 200; response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }], server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });
  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-retry`);
    await page.getByPlaceholder("Ask about the findings...").fill("Retry this");
    await page.getByRole("button", { name: "Send" }).click();
    await page.getByRole("button", { name: "Retry MNEMOS" }).click();
    assert.deepEqual(await page.evaluate(() => window.__retryCalls), [await page.evaluate(() => window.__failedRequestId)]);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
});

for (const pageOwned of [true, false]) test(`terminal replay callbacks retain persisted metadata request identity and one message pair (${pageOwned ? "page" : "panel"} owned)`, async () => {
  const harnessId = "virtual:chat-panel-terminal-replay-harness";
  const resolvedHarnessId = `\0${harnessId}`;
  const harnessServer = await createServer({
    root, configFile: false, envFile: false,
    define: { "import.meta.env.VITE_API_BASE_URL": JSON.stringify(`${apiBase}/`), "import.meta.env.VITE_AIPAM_DEMO_MODE": JSON.stringify("false") },
    plugins: [{
      name: "chat-panel-terminal-replay-harness",
      resolveId(id) { if (id === harnessId) return resolvedHarnessId; },
      load(id) {
        if (id !== resolvedHarnessId) return;
        return `
          import React, { useState } from "react";
          import { createRoot } from "react-dom/client";
          import { ChatPanel } from "/src/components/ChatPanel.tsx";
          window.__attemptChanges = []; window.__retryCalls = []; window.__streams = [];
          let persisted;
          window.fetch = async (url, init = {}) => {
            const path = new URL(String(url)).pathname;
            if (path.endsWith("/chat/stream")) {
              const request = JSON.parse(init.body);
              window.__streams.push(request);
              if (!persisted) persisted = {
                id: "mnemos-1", job_id: "job-1", created_at: "2026-09-22T00:00:00Z", updated_at: "2026-09-22T00:00:01Z",
                messages: [
                  { id: "persisted-user", sequence: 1, role: "user", content: request.message, citations: [], metadata: null, request_id: request.request_id, timestamp: "2026-09-22T00:00:00Z" },
                  { id: "persisted-error", sequence: 2, role: "assistant", content: "Error: Terminal failure", citations: [], metadata: { status: "error", request_id: request.request_id, user_message_id: "persisted-user", retrieval_status: "unavailable" }, request_id: null, timestamp: "2026-09-22T00:00:01Z" },
                ],
              };
              else await new Promise(resolve => { window.__releaseReplay = resolve; });
              if (window.__interruptReplay) return Response.json({ detail: "Replay temporarily unavailable" }, { status: 503 });
              const terminal = { type: "meta", conversation_id: "mnemos-1", request_id: request.request_id, status: "error", citations: [], retrieval_status: "unavailable" };
              const events = window.__streams.length > 1 ? [terminal, { type: "replace", content: "Error: Terminal failure" }]
                : [{ type: "error", content: "Terminal failure" }, terminal];
              return new Response(events.map(event => "data: " + JSON.stringify(event) + "\\n\\n").join("") + "data: [DONE]\\n\\n", { headers: { "Content-Type": "text/event-stream" } });
            }
            if (path.endsWith("/conversations/mnemos-1")) return Response.json(persisted);
            throw new Error("Unexpected request: " + path);
          };
          function Harness() {
            const [conversation, setConversation] = useState({ id: "mnemos-1", job_id: "job-1", messages: [] });
            const [attempt, setAttempt] = useState(null);
            window.__conversation = conversation;
            return React.createElement(ChatPanel, {
              jobId: "job-1", conversation, selectionToken: "branch-1", mode: "mnemos", attempt,
              onAttemptChange: ${pageOwned} ? next => { window.__attemptChanges.push(next); setAttempt(next); } : undefined,
              onRetry: requestId => window.__retryCalls.push(requestId), onCopyToMnemos: () => {}, onConversationChanged: setConversation,
            });
          }
          createRoot(document.getElementById("root")).render(React.createElement(Harness));
        `;
      },
      configureServer(server) {
        server.middlewares.use("/__chat-panel-terminal-replay", (_request, response) => {
          response.statusCode = 200; response.setHeader("Content-Type", "text/html");
          response.end(`<div id="root"></div><script type="module" src="/@id/__x00__${harnessId}"></script>`);
        });
      },
    }], server: { host: "127.0.0.1", port: 0 }, appType: "custom",
  });
  let browser;
  try {
    await harnessServer.listen();
    const address = harnessServer.httpServer.address();
    assert.ok(address && typeof address !== "string");
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}/__chat-panel-terminal-replay`);
    await page.getByPlaceholder("Ask about the findings...").fill("Replay this failure");
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await page.getByRole("button", { name: "Replay MNEMOS" }).waitFor();
    const requestId = await page.evaluate(() => window.__streams[0].request_id);
    if (pageOwned) {
      const failed = await page.evaluate(() => window.__attemptChanges.at(-1));
      assert.equal(failed.userMessageId, "persisted-user");
      assert.equal(failed.assistantMessageId, "persisted-error");
      assert.equal(failed.conversationId, "mnemos-1");
    }
    await page.getByRole("button", { name: "Replay MNEMOS" }).click();
    await page.waitForFunction(() => window.__streams.length === 2);
    assert.deepEqual(await page.evaluate(() => window.__conversation.messages.map(message => message.id)), ["persisted-user", "persisted-error"]);
    assert.deepEqual(await page.evaluate(() => window.__retryCalls), [requestId]);
    const streams = await page.evaluate(() => window.__streams);
    assert.deepEqual(streams[1], streams[0]);
    assert.deepEqual(streams[1], { message: "Replay this failure", conversation_id: "mnemos-1", mode: "mnemos", request_id: requestId });
    await page.evaluate(() => window.__releaseReplay());
    await page.getByRole("button", { name: "Replay MNEMOS" }).waitFor();
    assert.equal(await page.getByText("Error: Terminal failure", { exact: true }).count(), 1);
    assert.equal(await page.getByText("Replay this failure", { exact: true }).count(), 1);
    assert.equal(await page.getByPlaceholder("Ask about the findings...").isEnabled(), true);
    if (pageOwned) assert.equal(await page.evaluate(() => window.__attemptChanges.at(-1).assistantMessageId), "persisted-error");
    await page.evaluate(() => { window.__interruptReplay = true; });
    await page.getByRole("button", { name: "Replay MNEMOS" }).click();
    await page.waitForFunction(() => window.__streams.length === 3);
    await page.evaluate(() => window.__releaseReplay());
    await page.getByRole("button", { name: "Replay MNEMOS" }).waitFor();
    assert.equal(await page.evaluate(() => window.__conversation.messages[1].metadata.request_id), requestId);
    assert.deepEqual(await page.evaluate(() => window.__conversation.messages.map(message => message.id)), ["persisted-user", "persisted-error"]);
    assert.equal(await page.evaluate(() => window.__conversation.messages[1].metadata.status), "error");
    assert.deepEqual(await page.evaluate(() => window.__streams[2]), streams[0]);
  } finally {
    await browser?.close();
    await harnessServer.close();
  }
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
