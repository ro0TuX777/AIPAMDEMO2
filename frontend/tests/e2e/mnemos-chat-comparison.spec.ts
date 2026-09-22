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
async function fixture(page: Page, options: { fresh?: boolean; unavailable?: boolean; used?: boolean; hydration?: ReturnType<typeof gate>; preparation?: ReturnType<typeof gate>; selection?: ReturnType<typeof gate>; retryResponse?: ReturnType<typeof gate> } = {}) {
  const calls = { opens: [] as any[], branches: [] as any[], selections: [] as any[], streams: [] as any[], history: [] as string[], fallback: 0 };
  const groups = new Map(["root-1", "root-2"].map(root => [root, group(root)]));
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
      const copied = { ...branch(owner.root_conversation_id, true), request_id: body.request_id };
      owner.branches.push(copied);
      return json(route, copied);
    }
    if (path.startsWith("/chat/comparisons/") && request.method() === "PATCH") {
      calls.selections.push({ group: path.split("/").at(-1), ...body });
      if (options.selection && path.endsWith("root-1-group")) await options.selection.promise;
      const owner = [...groups.values()].find(g => path.endsWith(g.group_id))!;
      owner.active_branch_id = body.active_branch_id;
      return json(route, owner);
    }
    if (path === "/chat/stream") {
      calls.streams.push(body);
      if (options.retryResponse && calls.streams.length === 2) await options.retryResponse.promise;
      if (unavailable) { unavailable = false; return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: { code: "MNEMOS_UNAVAILABLE", error: "Historical retrieval is unavailable" } }) }); }
      const id = body.conversation_id ?? "saved-root";
      const citations = options.used ? [{ type: "historical_finding", id: "finding-42", snippet: "Confirmed historical beacon", source_job_id: "prior-job", source_project_id: null, href: "/jobs/prior-job/findings/finding-42" }] : [];
      const user = { ...message("server-user", 1, "user", body.message), request_id: body.request_id };
      const assistant = { ...message("server-assistant", 2, "assistant", "Server answer"), request_id: body.request_id, metadata: { status: "completed", retrieval_status: body.mode === "mnemos" ? options.used ? "used" : "no_matches" : null }, citations };
      histories.set(id, history(id, [user, assistant]));
      const owner = [...groups.values()].flatMap(g => g.branches).find(b => b.conversation_id === id);
      if (owner) owner.messages = [user, assistant];
      if (!body.conversation_id) summaries.push(id);
      const events = [{ type: "token", content: "Server answer" }, { type: "meta", conversation_id: id, request_id: body.request_id, branch_id: owner?.id, status: "completed", retrieval_status: assistant.metadata.retrieval_status, citations }];
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
  await page.getByLabel("MNEMOS message").press("Enter"); await page.getByRole("button", { name: "Send to MNEMOS" }).click();
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
