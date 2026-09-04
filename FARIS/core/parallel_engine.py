import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Dict, Any, Optional

class ParallelEngine:
    """
    Parallel Processing Engine for FARIS.
    Executes independent forensic recovery, hashing, and validation tasks concurrently
    with bounded worker limits, isolation, and deterministic aggregation.
    """

    def __init__(self, max_workers: Optional[int] = None):
        cpu_count = os.cpu_count() or 2
        # Bound default workers between 2 and 4 to prevent CPU/RAM starvation
        self.max_workers = max_workers or min(4, max(2, cpu_count))

    def execute_tasks(
        self,
        task_func: Callable[[Any], Any],
        items: List[Any],
        task_name: str = "Parallel Task"
    ) -> List[Dict[str, Any]]:
        """
        Executes task_func on each item across bounded thread pool.
        Isolates failures and returns deterministic ordered results.
        """
        if not items:
            return []

        results = [None] * len(items)
        print(f"[*] Executing '{task_name}' on {len(items)} items using {self.max_workers} parallel workers...")

        start_time = time.time()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_index = {
                executor.submit(task_func, item): idx
                for idx, item in enumerate(items)
            }

            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                item = items[idx]
                try:
                    res = future.result()
                    results[idx] = {
                        "index": idx,
                        "status": "SUCCESS",
                        "result": res,
                        "error": None
                    }
                except Exception as exc:
                    results[idx] = {
                        "index": idx,
                        "status": "ERROR",
                        "result": None,
                        "error": str(exc)
                    }

        elapsed = round(time.time() - start_time, 3)
        success_count = sum(1 for r in results if r["status"] == "SUCCESS")
        print(f"[+] '{task_name}' finished in {elapsed}s ({success_count}/{len(items)} succeeded).")
        return results

# Singleton instance
parallel_engine = ParallelEngine()
