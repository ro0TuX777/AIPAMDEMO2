import { useEffect, useRef } from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/**
 * Focus management for a modal overlay.
 *
 * While `active`, focus is trapped inside the returned container: Tab / Shift+Tab
 * cycle within it instead of escaping to the page behind, and focus is moved
 * into the dialog on open. When it deactivates (or unmounts), focus is restored
 * to whatever held it before — so a keyboard or screen-reader user lands back
 * where they were rather than at the top of the document.
 *
 * Attach the returned ref to the dialog element.
 */
export function useFocusTrap<T extends HTMLElement>(active: boolean) {
  const ref = useRef<T>(null);

  useEffect(() => {
    if (!active) return;
    const container = ref.current;
    if (!container) return;

    const restoreTo = document.activeElement as HTMLElement | null;

    const visibleFocusables = (): HTMLElement[] =>
      Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        // offsetParent is null for display:none; skip hidden controls.
        (el) => el.offsetParent !== null || el === document.activeElement,
      );

    // Move focus in. Prefer the first focusable; fall back to the container
    // (which needs a tabindex to receive focus — callers set tabIndex={-1}).
    const initial = visibleFocusables()[0] ?? container;
    initial.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const items = visibleFocusables();
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const activeEl = document.activeElement;
      if (e.shiftKey && (activeEl === first || activeEl === container)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && activeEl === last) {
        e.preventDefault();
        first.focus();
      }
    };

    container.addEventListener("keydown", onKeyDown);
    return () => {
      container.removeEventListener("keydown", onKeyDown);
      // Restore focus to the opener on close. Focus can't have escaped the trap,
      // so this never yanks it from elsewhere; guard only on the target still
      // being in the document (by close time the dialog is unmounted and the
      // browser has moved focus to <body>, so we can't check containment here).
      if (restoreTo?.isConnected) {
        restoreTo.focus?.();
      }
    };
  }, [active]);

  return ref;
}
