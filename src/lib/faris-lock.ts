"use client";

const FARIS_LOCK_KEY = "faris_recovery_in_progress";

/**
 * Checks if a FARIS physical recovery process is currently actively running.
 */
export function isFarisLocked(): boolean {
  if (typeof window === "undefined") return false;
  return window.sessionStorage.getItem(FARIS_LOCK_KEY) === "true";
}

/**
 * Updates the global FARIS recovery lock state and dispatches a notification event.
 */
export function setFarisLock(locked: boolean): void {
  if (typeof window === "undefined") return;
  if (locked) {
    window.sessionStorage.setItem(FARIS_LOCK_KEY, "true");
  } else {
    window.sessionStorage.removeItem(FARIS_LOCK_KEY);
  }
  window.dispatchEvent(new CustomEvent("faris-lock-change", { detail: { locked } }));
}

/**
 * Triggers the modal popup warning that navigation is disabled during active FARIS recovery.
 */
export function showNavigationLockedAlert(): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent("faris-show-lock-alert"));
}
