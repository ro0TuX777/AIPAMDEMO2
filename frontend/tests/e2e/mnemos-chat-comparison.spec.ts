import { expect, test, type Page, type Route } from "@playwright/test";

const jobId = "mnemos-comparison-e2e";
const now = "2026-09-22T00:00:00Z";
const message = (id: string, sequence: number, role: string, content: string) => ({ id, sequence, role, content, citations: [] as any[], metadata: null as any, request_id: null as string | null, timestamp: now });
const rootMessages = [message("q1", 1, "user", "First baseline question"), message("a1", 2, "assistant", "Earlier baseline answer"), message("q2", 3, "user", "Was this C2 activity?"), message("a2", 4, "assistant", "Later baseline answer")];
const history = (id: string, messages: any[]) => ({ id, job_id: jobId, created_at: now, updated_at: now, messages });
const branch = (root: string, copy = false) => ({ id: `${root}-${copy ? "copy" : "snapshot"}`, conversation_id: `${root}-${copy ? "copy-chat" : "snapshot-chat"}`, label: copy ? "Copied question" : "MNEMOS snapshot", source_message_id: copy ? "q2" : null, request_id: null, history_cutoff_sequence: copy ? 2 : 4, inherited_root_conversation_id: root, inherited_cutoff_sequence: copy ? 2 : 4, inherited_messages: structuredClone(rootMessages.slice(0, copy ? 2 : 4)), messages: [] as any[], created_at: now, updated_at: now });
const group = (root: string) => ({ group_id: `${root}-group`, job_id: jobId, root_conversation_id: root, title: null, snapshot_branch_id: `${root}-snapshot`, active_branch_id: `${root}-snapshot`, conversation_id: `${root}-snapshot-chat`, branches: [branch(root)], created_at: now, updated_at: now });
function gate() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; }

// Only HTTP is replaced: rendering, selection, fetch/SSE parsing and attempt ownership are real.
async function fixture(page: Page, options: {
  fresh?: boolean; unavailable?: boolean; used?: boolean; terminalError?: boolean; lostBranchResponse?: boolean;
  withCopy?: boolean; longHistory?: boolean;
  hydration?: ReturnType<typeof gate>; preparation?: ReturnType<typeof gate>; selection?: ReturnType<typeof gate>;
  retryResponse?: ReturnType<typeof gate>; streamResponse?: ReturnType<typeof gate>; redundantHistory?: ReturnType<typeof gate>;
  selectionResponses?: Array<ReturnType<typeof gate> | undefined>;
} = {}) {
  const calls = { opens: [] as any[], branches: [] as any[], selections: [] as any[], streams: [] as any[], history: [] as string[], fallback: 0 };
  const groups = new Map(["root-1", "root-2"].map(root => [root, group(root)]));
  if (options.withCopy) groups.get("root-1")!.branches.push(branch("root-1", true));
  if (options.longHistory) groups.get("root-1")!.branches[0].inherited_messages = Array.from({ length: 40 }, (_, index) => message(`long-${index}`, index + 1, index % 2 ? "assistant" : "user", `History ${index + 1}: ` + "Investigate the observed outbound beacon traffic and correlate the network evidence. ".repeat(8)));
  const histories = new Map([history("root-1", structuredClone(rootMessages)), history("root-2", [message("other-q", 1, "user", "Other root question")])].map(item => [item.id, item]));
  const summaries = options.fresh ? [] : ["root-1", "root-2"];
  let unavailable = options.unavailable;
  const json = (route: Route, data: unknown) => route.fulfill({ contentType: "application/json", body: JSON.stringify(data) });
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(`/api/v1/jobs/${jobId}`, "");
    const body = request.postDataJSON();
    if (path.endsWith("/settings/setup_status")) return json(route, { model_configured: true });
    if (path === "") return json(route, { job: { job_id: jobId, status: "completed", created_at: now, stages: [], sensors: [], pcaps: [], metrics: { durations: {}, pcap_stats: {} } } });
    if (path === "/conversations") return json(route, summaries.map(id => ({ id, job_id: jobId, created_at: now, updated_at: now, title: id, message_count: histories.get(id)?.messages.length ?? 0 })));
    if (path.startsWith("/conversations/")) {
      const id = path.split("/").at(-1)!;
      calls.history.push(id);
      if (id === "root-1" && options.hydration) await options.hydration.promise;
      if (id === "saved-root" && calls.history.filter(item => item === id).length > 1 && options.redundantHistory) await options.redundantHistory.promise;
      const persisted = histories.get(id) ?? [...groups.values()].flatMap(g => g.branches).find(b => b.conversation_id === id);
      return json(route, persisted && "id" in persisted && histories.has(id) ? persisted : history(id, persisted?.messages ?? []));
    }
    if (path === "/chat/comparisons") {
      calls.opens.push(body);
      if (!groups.has(body.root_conversation_id)) groups.set(body.root_conversation_id, group(body.root_conversation_id));
      return json(route, groups.get(body.root_conversation_id));
    }
    if (path.endsWith("/branches")) {
      calls.branches.push(body);
      if (options.preparation) await options.preparation.promise;
      const owner = [...groups.values()].find(g => path.includes(g.group_id))!;
      const existing = owner.branches.find(item => item.request_id === body.request_id);
      const copied = existing ?? { ...branch(owner.root_conversation_id, true), request_id: body.request_id };
      if (!existing) owner.branches.push(copied);
      if (options.lostBranchResponse && calls.branches.length === 1) return route.abort("connectionreset");
      return json(route, copied);
    }
    if (path.startsWith("/chat/comparisons/") && request.method() === "PATCH") {
      calls.selections.push({ group: path.split("/").at(-1), ...body });
      const owner = [...groups.values()].find(g => path.endsWith(g.group_id))!;
      owner.active_branch_id = body.active_branch_id;
      const response = structuredClone(owner);
      const pending = options.selectionResponses?.[calls.selections.length - 1] ?? (path.endsWith("root-1-group") ? options.selection : undefined);
      if (pending) await pending.promise;
      return json(route, response);
    }
    if (path === "/chat/stream") {
      calls.streams.push(body);
      const streamNumber = calls.streams.length;
      if (options.streamResponse && streamNumber === 1) await options.streamResponse.promise;
      if (options.retryResponse && streamNumber === 2) await options.retryResponse.promise;
      if (unavailable) { unavailable = false; return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: { code: "MNEMOS_UNAVAILABLE", error: "Historical retrieval is unavailable" } }) }); }
      const id = body.conversation_id ?? "saved-root";
      const citations = options.used ? [{ type: "historical_finding", id: "finding-42", snippet: "Confirmed historical beacon", source_job_id: "prior-job", source_project_id: null, href: "/jobs/prior-job/findings/finding-42" }] : [];
      const user = { ...message("server-user", 1, "user", body.message), request_id: body.request_id };
      const failed = options.terminalError && streamNumber === 1;
      const assistant = { ...message("server-assistant", 2, "assistant", failed ? "Error: Historical retrieval is unavailable" : "Server answer"), request_id: body.request_id, metadata: { status: failed ? "error" : "completed", retrieval_status: failed ? "unavailable" : body.mode === "mnemos" ? options.used ? "used" : "no_matches" : null }, citations };
      histories.set(id, history(id, [user, assistant]));
      const owner = [...groups.values()].flatMap(g => g.branches).find(b => b.conversation_id === id);
      if (owner) owner.messages = [user, assistant];
      if (!body.conversation_id) summaries.push(id);
      const events = [{ type: failed ? "error" : "token", content: failed ? "Historical retrieval is unavailable" : "Server answer" }, { type: "meta", conversation_id: id, request_id: body.request_id, branch_id: owner?.id, status: failed ? "error" : "completed", retrieval_status: assistant.metadata.retrieval_status, citations }];
      return route.fulfill({ contentType: "text/event-stream", body: events.map(event => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n" });
    }
    if (path === "/chat") { calls.fallback++; return route.fulfill({ status: 500 }); }
    if (path.endsWith("/library/config")) return json(route, { admin_required: false });
    return json(route, { items: [] });
  });
  return { calls, groups };
}
const toggle = (page: Page) => page.getByRole("button", { name: "MNEMOS comparison", exact: true });
const pane = (page: Page) => page.getByRole("complementary", { name: "MNEMOS comparison" });
const settle = (page: Page) => page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
async function visit(page: Page) { await page.goto(`/jobs/${jobId}/chat`); await expect(toggle(page)).toBeEnabled(); }
async function copy(page: Page) { await page.getByRole("button", { name: "Copy to MNEMOS" }).nth(1).click(); }
async function submit(page: Page, text = "Check history") { await page.getByLabel("MNEMOS message").fill(text); await page.getByRole("button", { name: "Send to MNEMOS" }).click(); }

test("fresh baseline adopts server IDs and URL before its saved question can be copied", async ({ page }) => {
  const { calls } = await fixture(page, { fresh: true });
  await page.goto(`/jobs/${jobId}/chat`);
  await page.getByPlaceholder("Ask about the findings...").fill("Fresh question");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page).toHaveURL(/conversation=saved-root/);
  await expect(page.getByText("Server answer", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Copy to MNEMOS" }).click();
  await expect(page.getByText("Copied from baseline message server-user")).toBeVisible();
  expect(calls.streams).toHaveLength(1);
  expect(calls.streams[0]).toMatchObject({ mode: "baseline", message: "Fresh question" });
  expect(calls.streams[0].request_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(calls.streams[0].conversation_id).toBeUndefined();
  expect(calls.opens).toEqual([{ root_conversation_id: "saved-root" }]);
  expect(calls.history).toContain("saved-root");
});

test("first open shows the server inherited prefix in a desktop complementary pane", async ({ page }) => {
  const { calls } = await fixture(page);
  await visit(page); await toggle(page).click();
  await expect(pane(page)).toBeVisible();
  await expect(pane(page).getByRole("region", { name: "Baseline history" })).toContainText("Later baseline answer");
  await expect(pane(page).getByRole("region", { name: "Baseline history" }).locator("p")).toHaveCount(4);
  await expect(page.getByRole("dialog", { name: "MNEMOS comparison" })).toHaveCount(0);
  expect(await page.getByTestId("main-content").evaluate(el => (el as HTMLElement).inert)).toBe(false);
  expect(calls.opens).toEqual([{ root_conversation_id: "root-1" }]);
  expect(calls.streams).toHaveLength(0);
});

test("copy remains an editable pending draft without a branch or send", async ({ page }) => {
  const { calls } = await fixture(page);
  await visit(page); await copy(page);
  await expect(page.getByText("Copied from baseline message q2")).toBeVisible();
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Was this C2 activity?");
  await page.getByLabel("MNEMOS message").fill("Edited copied question");
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-snapshot");
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Edited copied question");
  expect(calls.branches).toHaveLength(0); expect(calls.streams).toHaveLength(0); expect(calls.selections).toHaveLength(0);
});

test("submitted copy selects its owner, excludes the source from inherited history, and preserves snapshot", async ({ page }) => {
  const { calls } = await fixture(page);
  await visit(page); await copy(page); await submit(page, "Edited copy");
  await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-copy");
  const prefix = pane(page).getByRole("region", { name: "Baseline history" });
  await expect(prefix.locator("p")).toHaveCount(2); await expect(prefix).not.toContainText("Was this C2 activity?"); await expect(prefix).not.toContainText("Later baseline answer");
  expect(calls.branches).toEqual([{ source_message_id: "q2", request_id: calls.streams[0].request_id }]);
  expect(calls.streams).toHaveLength(1);
  expect(calls.streams[0]).toMatchObject({ conversation_id: "root-1-copy-chat", mode: "mnemos", message: "Edited copy" });
  expect(calls.streams[0].request_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }]);
  await page.getByLabel("Comparison branch").selectOption("root-1-snapshot");
  await expect(prefix.locator("p")).toHaveCount(4); await expect(pane(page).getByText("Server answer", { exact: true })).toHaveCount(0);
});

test("reload restores selected baseline root and persisted active branch", async ({ page }) => {
  const { calls } = await fixture(page);
  await visit(page); await page.getByLabel("Baseline conversation").selectOption("root-2");
  await expect(page).toHaveURL(/conversation=root-2/); await toggle(page).click();
  await submit(page); await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  await page.reload(); await expect(page.getByLabel("Baseline conversation")).toHaveValue("root-2"); await toggle(page).click();
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  expect(calls.opens).toEqual([{ root_conversation_id: "root-2" }, { root_conversation_id: "root-2" }]);
  // A non-default branch is restored too, independently of the root-2 snapshot.
  await page.getByLabel("Baseline conversation").selectOption("root-1"); await copy(page); await submit(page);
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-copy");
  await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  await page.reload(); await expect(toggle(page)).toBeEnabled(); await toggle(page).click();
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-copy");
  expect(calls.branches).toHaveLength(1); expect(calls.streams).toHaveLength(2);
});

for (const used of [false, true]) test(`completed MNEMOS displays ${used ? "used historical source with nullable project" : "no_matches"}`, async ({ page }) => {
  const { calls } = await fixture(page, { used });
  await visit(page); await toggle(page).click(); await submit(page);
  await expect(pane(page).getByText(used ? "Historical confirmed findings used" : "No relevant historical confirmed findings found", { exact: true })).toBeVisible();
  if (used) {
    const sources = pane(page).getByRole("region", { name: "Historical confirmed findings" });
    await expect(sources.getByRole("link", { name: "Confirmed historical beacon" })).toHaveAttribute("href", "/jobs/prior-job/findings/finding-42");
    await expect(sources).toContainText("Job prior-job"); await expect(sources).not.toContainText("Project null");
  }
  expect(calls.streams).toHaveLength(1); expect(calls.fallback).toBe(0);
});

test("HTTP 503 retains retry across close/reopen with same request and one optimistic pair", async ({ page }) => {
  const retryResponse = gate();
  const { calls } = await fixture(page, { unavailable: true, retryResponse });
  await visit(page); await copy(page); await submit(page, "Retry this copied prompt");
  await expect(page.getByText("MNEMOS is unavailable. Try again.", { exact: true })).toBeVisible();
  await expect(pane(page).getByText("Retry this copied prompt", { exact: true })).toHaveCount(1);
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
  await page.getByRole("button", { name: "Retry MNEMOS" }).click();
  await expect.poll(() => calls.streams.length).toBe(2);
  expect(calls.streams[1]).toEqual(calls.streams[0]); expect(calls.branches).toHaveLength(1); expect(calls.fallback).toBe(0);
  // Inspect while retry is pending, before server history could hide a duplicate pair.
  await expect(pane(page).getByText("Retry this copied prompt", { exact: true })).toHaveCount(1);
  await expect(pane(page).getByText("Error: Historical retrieval is unavailable", { exact: true })).toHaveCount(1);
  retryResponse.release();
  await expect(pane(page).getByText("Retry this copied prompt", { exact: true })).toHaveCount(1);
  await expect(pane(page).getByText("Server answer", { exact: true })).toHaveCount(1);
});

test("navigation wins over delayed initial hydration", async ({ page }) => {
  const hydration = gate(); const { calls } = await fixture(page, { hydration });
  await page.goto(`/jobs/${jobId}/chat`); await expect.poll(() => calls.history.includes("root-1")).toBe(true);
  await page.getByLabel("Baseline conversation").selectOption("root-2");
  await expect(page).toHaveURL(/conversation=root-2/);
  const late = page.waitForResponse(response => response.url().endsWith("/conversations/root-1")); hydration.release(); await late;
  await expect(page.getByLabel("Baseline conversation")).toHaveValue("root-2");
  await toggle(page).click(); await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  expect(calls.opens).toEqual([{ root_conversation_id: "root-2" }]);
});

for (const stage of ["branch creation", "active selection"]) test(`navigation during delayed copy ${stage} cannot select the old group or stream its prompt`, async ({ page }) => {
  const pending = gate();
  const { calls } = await fixture(page, stage === "branch creation" ? { preparation: pending } : { selection: pending });
  await visit(page); await copy(page); await submit(page);
  await expect.poll(() => stage === "branch creation" ? calls.branches.length : calls.selections.length).toBe(1);
  await page.getByLabel("Baseline conversation").selectOption("root-2"); await expect(page).toHaveURL(/conversation=root-2/);
  await toggle(page).click(); await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  const late = page.waitForResponse(response => response.url().endsWith(stage === "branch creation" ? "/branches" : "/root-1-group"));
  pending.release(); await (await late).finished();
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  await expect(pane(page).getByText("Check history", { exact: true })).toHaveCount(0);
  expect(calls.selections).toHaveLength(stage === "branch creation" ? 0 : 1); expect(calls.streams).toHaveLength(0);
  expect(calls.branches).toHaveLength(1);
});

test("duplicate submission during preparation makes one branch and one stream", async ({ page }) => {
  const preparation = gate(); const { calls } = await fixture(page, { preparation });
  await visit(page); await copy(page);
  await page.getByLabel("MNEMOS message").press("Enter"); await expect.poll(() => calls.branches.length).toBe(1);
  await expect(page.getByRole("button", { name: "Send to MNEMOS" })).toBeDisabled();
  await page.getByLabel("MNEMOS message").dispatchEvent("keydown", { key: "Enter" });
  preparation.release(); await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  expect(calls.branches).toHaveLength(1); expect(calls.streams).toHaveLength(1);
  expect(calls.branches[0].request_id).toBe(calls.streams[0].request_id);
});

test("copy asks before replacing a non-empty draft and respects both choices", async ({ page }) => {
  const { calls } = await fixture(page); await visit(page); await toggle(page).click();
  await page.getByLabel("MNEMOS message").fill("Keep my draft");
  page.once("dialog", async dialog => { expect(dialog.type()).toBe("confirm"); await dialog.dismiss(); }); await copy(page);
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Keep my draft");
  page.once("dialog", async dialog => { await dialog.accept(); }); await copy(page);
  await expect(page.getByLabel("MNEMOS message")).toHaveValue("Was this C2 activity?");
  expect(calls.branches).toHaveLength(0); expect(calls.streams).toHaveLength(0);
});

test("narrow modal traps Tab in both directions, isolates background, and restores focus on Escape", async ({ page }) => {
  await fixture(page); await page.setViewportSize({ width: 390, height: 844 }); await visit(page); await toggle(page).click();
  const dialog = page.getByRole("dialog", { name: "MNEMOS comparison" });
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  const background = page.getByTestId("app-root"); await expect(background).toHaveAttribute("aria-hidden", "true");
  expect(await background.evaluate(el => (el as HTMLElement).inert)).toBe(true);
  expect(await dialog.evaluate(el => Boolean(el.closest("[inert]")))).toBe(false);
  const close = dialog.getByRole("button", { name: "Close MNEMOS comparison" });
  await expect(close).toBeFocused();
  // Send is disabled for the empty draft; Shift+Tab must use the last enabled control.
  await page.keyboard.press("Shift+Tab"); await expect(page.getByLabel("MNEMOS message")).toBeFocused();
  await page.keyboard.press("Tab"); await expect(close).toBeFocused();
  await page.getByLabel("MNEMOS message").fill("Enable send");
  await close.focus(); await page.keyboard.press("Shift+Tab"); await expect(dialog.getByRole("button", { name: "Send to MNEMOS" })).toBeFocused();
  await page.keyboard.press("Tab"); await expect(close).toBeFocused();
  await page.keyboard.press("Escape"); await expect(dialog).toHaveCount(0); await expect(toggle(page)).toBeFocused();
  expect(await background.evaluate(el => (el as HTMLElement).inert)).toBe(false); await expect(background).not.toHaveAttribute("aria-hidden", "true");
});

test("manual branch PATCH cannot replace a newly selected root", async ({ page }) => {
  const selection = gate(); const { calls } = await fixture(page, { withCopy: true, selection });
  await visit(page); await toggle(page).click();
  await page.getByLabel("Comparison branch").selectOption("root-1-copy");
  await expect.poll(() => calls.selections.length).toBe(1);
  await page.getByLabel("Baseline conversation").selectOption("root-2");
  await expect(page).toHaveURL(/conversation=root-2/); await toggle(page).click();
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  const late = page.waitForResponse(response => response.request().method() === "PATCH");
  selection.release(); await (await late).finished(); await settle(page);
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  await expect(page).toHaveURL(/conversation=root-2/);
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }]);
  expect(calls.streams).toHaveLength(0); expect(calls.branches).toHaveLength(0);
});

test("latest manual branch choice wins over an older PATCH response", async ({ page }) => {
  const first = gate(); const { calls } = await fixture(page, { withCopy: true, selectionResponses: [first] });
  await visit(page); await toggle(page).click();
  await page.getByLabel("Comparison branch").selectOption("root-1-copy");
  await expect.poll(() => calls.selections.length).toBe(1);
  await page.getByLabel("Comparison branch").selectOption("root-1-snapshot");
  await expect.poll(() => calls.selections.length).toBe(2);
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-snapshot");
  const late = page.waitForResponse(response => response.request().method() === "PATCH" && response.request().postDataJSON().active_branch_id === "root-1-copy");
  first.release(); await (await late).finished(); await settle(page);
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-1-snapshot");
  await expect(pane(page).getByRole("region", { name: "Baseline history" }).locator("p")).toHaveCount(4);
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }, { group: "root-1-group", active_branch_id: "root-1-snapshot" }]);
  expect(calls.streams).toHaveLength(0); expect(calls.branches).toHaveLength(0);
});

for (const stage of ["copy POST", "copy PATCH", "stream"]) test(`page attempt locks survive drawer remount during ${stage}`, async ({ page }) => {
  const pending = gate();
  const { calls } = await fixture(page, stage === "copy POST" ? { preparation: pending } : stage === "copy PATCH" ? { selection: pending } : { streamResponse: pending });
  await visit(page); await copy(page); await submit(page, "One owned attempt");
  await expect.poll(() => stage === "copy POST" ? calls.branches.length : stage === "copy PATCH" ? calls.selections.length : calls.streams.length).toBe(1);
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await expect(page.getByLabel("Comparison branch")).toBeDisabled();
  await expect(page.getByLabel("MNEMOS message")).toBeDisabled();
  await expect(page.getByRole("button", { name: "Send to MNEMOS" })).toBeDisabled();
  await expect(pane(page).getByText("Thinking...", { exact: true })).toBeVisible();
  // Even a queued event from the remounted panel must fail admission at the page.
  await page.getByLabel("MNEMOS message").dispatchEvent("keydown", { key: "Enter" });
  pending.release(); await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Comparison branch")).toBeEnabled();
  await expect(page.getByLabel("MNEMOS message")).toBeEnabled();
  expect(calls.branches).toEqual([{ source_message_id: "q2", request_id: calls.streams[0].request_id }]);
  expect(calls.streams).toHaveLength(1);
  expect(calls.streams[0]).toMatchObject({ conversation_id: "root-1-copy-chat", mode: "mnemos", message: "One owned attempt" });
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }]);
});

test("lost copy POST response retries the admitted request after drawer remount", async ({ page }) => {
  const { calls } = await fixture(page, { lostBranchResponse: true });
  await visit(page); await copy(page); await submit(page, "Recover the same branch");
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await page.getByRole("button", { name: "Retry MNEMOS" }).click();
  await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  expect(calls.branches).toHaveLength(2); expect(calls.branches[1]).toEqual(calls.branches[0]);
  expect(calls.branches[0]).toEqual({ source_message_id: "q2", request_id: calls.streams[0].request_id });
  expect(calls.streams).toHaveLength(1); expect(calls.streams[0]).toMatchObject({ message: "Recover the same branch", conversation_id: "root-1-copy-chat", mode: "mnemos" });
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }]);
  await expect(page.getByLabel("Comparison branch").locator("option")).toHaveCount(2);
  await expect(pane(page).getByText("Recover the same branch", { exact: true })).toHaveCount(1);
});

for (const next of ["new draft", "another root"]) test(`fresh baseline completion cannot overwrite ${next}`, async ({ page }) => {
  const redundantHistory = gate(); const { calls } = await fixture(page, { redundantHistory });
  await visit(page); await page.getByRole("button", { name: "+ New", exact: true }).click();
  await page.getByPlaceholder("Ask about the findings...").fill("Save this new baseline");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  await expect(page).toHaveURL(/conversation=saved-root/);
  await expect(page.getByRole("button", { name: "Copy to MNEMOS" })).toHaveCount(1);
  if (next === "new draft") await page.getByRole("button", { name: "+ New", exact: true }).click();
  else { await page.getByLabel("Baseline conversation").selectOption("root-2"); await expect(page).toHaveURL(/conversation=root-2/); }
  const late = calls.history.filter(id => id === "saved-root").length > 1
    ? page.waitForResponse(response => response.url().endsWith("/conversations/saved-root")) : null;
  redundantHistory.release(); if (late) await (await late).finished(); await settle(page);
  if (next === "new draft") { await expect(page).not.toHaveURL(/conversation=/); await expect(toggle(page)).toBeDisabled(); }
  else { await expect(page).toHaveURL(/conversation=root-2/); await expect(page.getByText("Other root question", { exact: true })).toBeVisible(); }
  await expect(page.getByText("Save this new baseline", { exact: true })).toHaveCount(0);
  expect(calls.history.filter(id => id === "saved-root")).toHaveLength(1);
  expect(calls.streams).toHaveLength(1); expect(calls.streams[0]).toMatchObject({ mode: "baseline", message: "Save this new baseline" });
  expect(calls.streams[0].conversation_id).toBeUndefined();
});

test("terminal SSE error retains persisted pair and retry identity across drawer remount", async ({ page }) => {
  const retryResponse = gate(); const { calls } = await fixture(page, { terminalError: true, retryResponse });
  await visit(page); await copy(page); await submit(page, "Retry the terminal failure");
  await expect(pane(page).getByText("Error: Historical retrieval is unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toBeVisible();
  await page.getByRole("button", { name: "Retry MNEMOS" }).click();
  await expect.poll(() => calls.streams.length).toBe(2);
  expect(calls.streams[1]).toEqual(calls.streams[0]); expect(calls.branches).toHaveLength(1); expect(calls.selections).toHaveLength(1); expect(calls.fallback).toBe(0);
  await expect(pane(page).getByText("Retry the terminal failure", { exact: true })).toHaveCount(1);
  await expect(pane(page).getByText("Error: Historical retrieval is unavailable", { exact: true })).toHaveCount(1);
  retryResponse.release(); await expect(pane(page).getByText("Server answer", { exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Retry MNEMOS" })).toHaveCount(0);
});

test("old stream completion cannot clear the current root attempt", async ({ page }) => {
  const streamResponse = gate(); const retryResponse = gate();
  const { calls } = await fixture(page, { streamResponse, retryResponse });
  await visit(page); await toggle(page).click(); await submit(page, "Old root attempt");
  await expect.poll(() => calls.streams.length).toBe(1);
  await page.getByLabel("Baseline conversation").selectOption("root-2"); await expect(page).toHaveURL(/conversation=root-2/);
  await toggle(page).click(); await submit(page, "Current root attempt"); await expect.poll(() => calls.streams.length).toBe(2);
  const late = page.waitForResponse(response => response.url().endsWith("/chat/stream") && response.request().postDataJSON().message === "Old root attempt");
  streamResponse.release(); await (await late).finished(); await settle(page);
  await page.getByRole("button", { name: "Close MNEMOS comparison" }).click(); await toggle(page).click();
  await expect(page.getByLabel("MNEMOS message")).toBeDisabled(); await expect(page.getByLabel("Comparison branch")).toBeDisabled();
  await expect(pane(page).getByText("Old root attempt", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Comparison branch")).toHaveValue("root-2-snapshot");
  retryResponse.release(); await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  await expect(page.getByLabel("MNEMOS message")).toBeEnabled();
  expect(calls.streams.map(body => body.conversation_id)).toEqual(["root-1-snapshot-chat", "root-2-snapshot-chat"]);
  expect(calls.streams[0].request_id).not.toBe(calls.streams[1].request_id); expect(calls.branches).toHaveLength(0);
});

test("long narrow inherited transcript scrolls while composer remains usable", async ({ page }) => {
  const { calls } = await fixture(page, { longHistory: true });
  await page.setViewportSize({ width: 390, height: 844 }); await visit(page); await toggle(page).click();
  const dialog = page.getByRole("dialog", { name: "MNEMOS comparison" });
  const inherited = dialog.getByRole("region", { name: "Baseline history" });
  await expect(inherited.locator("p")).toHaveCount(40);
  const input = page.getByLabel("MNEMOS message");
  const send = dialog.getByRole("button", { name: "Send to MNEMOS" });
  const bounds = await input.boundingBox(); const sendBounds = await send.boundingBox();
  expect(bounds!.y).toBeGreaterThan(0); expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(844);
  expect(sendBounds!.x + sendBounds!.width).toBeLessThanOrEqual(390);
  const scrolled = await inherited.evaluate(element => {
    let scrollArea: HTMLElement | null = element as HTMLElement;
    while (scrollArea && !/(auto|scroll)/.test(getComputedStyle(scrollArea).overflowY)) scrollArea = scrollArea.parentElement;
    if (!scrollArea) return false;
    scrollArea.scrollTop = scrollArea.scrollHeight; return scrollArea.scrollTop > 0 && scrollArea.clientHeight < 422;
  });
  expect(scrolled).toBe(true);
  await input.fill("Question after a long baseline"); await send.click();
  await expect(dialog.getByText("Server answer", { exact: true })).toBeVisible();
  expect(calls.streams).toHaveLength(1); expect(calls.streams[0]).toMatchObject({ conversation_id: "root-1-snapshot-chat", mode: "mnemos", message: "Question after a long baseline" });
});

test("manual PATCH started before a send cannot erase that attempt's messages", async ({ page }) => {
  const selection = gate(); const streamResponse = gate();
  const { calls } = await fixture(page, { withCopy: true, selection, streamResponse });
  await visit(page); await toggle(page).click();
  await page.getByLabel("Comparison branch").selectOption("root-1-copy"); await expect.poll(() => calls.selections.length).toBe(1);
  await submit(page, "Keep this admitted turn"); await expect.poll(() => calls.streams.length).toBe(1);
  await expect(pane(page).getByText("Keep this admitted turn", { exact: true })).toHaveCount(1);
  const late = page.waitForResponse(response => response.request().method() === "PATCH");
  selection.release(); await (await late).finished(); await settle(page);
  await expect(pane(page).getByText("Keep this admitted turn", { exact: true })).toHaveCount(1);
  await expect(page.getByLabel("MNEMOS message")).toBeDisabled();
  streamResponse.release(); await expect(pane(page).getByText("Server answer", { exact: true })).toBeVisible();
  expect(calls.selections).toEqual([{ group: "root-1-group", active_branch_id: "root-1-copy" }]);
  expect(calls.streams).toHaveLength(1); expect(calls.branches).toHaveLength(0);
  expect(calls.streams[0]).toMatchObject({ conversation_id: "root-1-copy-chat", message: "Keep this admitted turn", mode: "mnemos" });
});
