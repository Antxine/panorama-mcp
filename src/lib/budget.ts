import { AsyncLocalStorage } from "async_hooks";

/**
 * Time budget of the running tool call. MCP clients give up on a request after about 60 seconds
 * (GitHub Copilot CLI, SDK default): past that, the answer is lost and the work still running only
 * loads Panorama and delays the next calls. Long operations (log jobs, backward log search) check
 * the budget and return partial results instead.
 *
 * PANOS_TOOL_BUDGET_SECONDS (default 50) sets it; raise it for clients with a longer request timeout.
 */

interface Budget {
  deadline: number;
  signal?: AbortSignal;
}

const store = new AsyncLocalStorage<Budget>();

export function toolBudgetMs(env: NodeJS.ProcessEnv = process.env): number {
  const value = Number(env.PANOS_TOOL_BUDGET_SECONDS);
  return (Number.isFinite(value) && value > 0 ? value : 50) * 1000;
}

/** Runs a tool handler with a deadline; `signal` is the client's cancellation signal, if any. */
export function runWithBudget<T>(fn: () => Promise<T>, signal?: AbortSignal, budgetMs = toolBudgetMs()): Promise<T> {
  return store.run({ deadline: Date.now() + budgetMs, signal }, fn);
}

/** Milliseconds left for the current tool call (Infinity outside a tool call). */
export function remainingMs(): number {
  const budget = store.getStore();
  if (!budget) return Infinity;
  if (budget.signal?.aborted) return 0;
  return budget.deadline - Date.now();
}

/** Whether the client cancelled the current tool call. */
export function cancelled(): boolean {
  return Boolean(store.getStore()?.signal?.aborted);
}
