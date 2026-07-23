import React from "react";

interface Props {
  /** Reset key — when it changes, a previously-caught error is cleared so a
   *  new route gets a fresh attempt rather than staying stuck on the error UI. */
  resetKey?: string;
  children: React.ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Catches render/lazy-load failures below it so one broken route cannot blank
 * the whole app.
 *
 * The case this specifically guards: routes are code-split with React.lazy, and
 * a dynamic import() rejects when a user on a stale index.html (an open tab from
 * before a redeploy) requests a chunk whose hashed filename no longer exists.
 * Suspense only handles the pending promise, not its rejection — without this,
 * the rejection unmounts the entire tree. A stale-chunk error is offered a
 * reload (which fetches the current index.html and chunk names); any other
 * error is shown contained so the shell and navigation survive.
 */
export class RouteErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidUpdate(prev: Props) {
    // Navigating away from the broken route clears the error so the next route
    // renders normally instead of inheriting the error screen.
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  /** A failed dynamic import — the signal that the loaded app is out of date. */
  private isChunkLoadError(err: Error): boolean {
    const msg = `${err?.name ?? ""} ${err?.message ?? ""}`;
    return (
      err?.name === "ChunkLoadError" ||
      /dynamically imported module|Importing a module script failed|Failed to fetch dynamically|error loading dynamically imported/i.test(msg)
    );
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const stale = this.isChunkLoadError(error);

    return (
      <div
        className="mx-auto max-w-lg rounded-lg border border-slate-800 bg-slate-900/50 p-6 text-center"
        data-testid="route-error"
        role="alert"
      >
        <h2 className="text-lg font-semibold text-slate-100">
          {stale ? "This page needs a refresh" : "Something went wrong on this page"}
        </h2>
        <p className="mt-2 text-sm text-slate-400">
          {stale
            ? "The app was updated since this tab was opened, so part of it could not be loaded. Reloading will pick up the latest version."
            : "This view failed to render. The rest of the app is unaffected — you can navigate elsewhere or reload."}
        </p>
        {!stale && (
          <pre className="mt-3 overflow-auto rounded bg-slate-950 p-2 text-left text-[11px] leading-4 text-slate-500">
            {error.message || String(error)}
          </pre>
        )}
        <button
          onClick={() => window.location.reload()}
          data-testid="route-error-reload"
          className="mt-4 rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
        >
          Reload
        </button>
      </div>
    );
  }
}
