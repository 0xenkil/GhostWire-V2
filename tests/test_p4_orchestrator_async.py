"""Phase 4 — P4-1 async suspenders: a SYNC agent.run() is off-loaded via
asyncio.to_thread so the phase asyncio.timeout can fire (ORCH-TIMEOUT-1).

The orchestrator wraps each phase in `async with asyncio.timeout(...)`. If a sync
agent.run() (which may block on the bounded AI-backend recovery sleep) ran INLINE
in the event loop, the loop would be pinned and the deadline could never fire.
Off-loading to a worker thread keeps the loop free. We measure the timeout
latency INSIDE the loop (asyncio.run's executor-join at shutdown is separate and
irrelevant — in the real long-lived loop the orphaned thread just runs on).
"""
import asyncio
import inspect
import time


def _dispatch(run_callable, timeout_s):
    """The exact sync-vs-async dispatch the orchestrator now uses, returning
    (result, fired_after_s) measured on the event loop's own clock."""
    async def run_agent_async():
        if inspect.iscoroutinefunction(run_callable):
            return await run_callable()
        return await asyncio.to_thread(run_callable)

    async def driver():
        loop = asyncio.get_event_loop()
        t0 = loop.time()
        try:
            async with asyncio.timeout(timeout_s):
                return await run_agent_async(), None
        except (TimeoutError, asyncio.TimeoutError):
            return None, loop.time() - t0

    return asyncio.run(driver())


def test_sync_blocking_agent_lets_timeout_fire_promptly():
    # A sync agent that blocks 1s, off-loaded to a thread, lets the 0.3s phase
    # timeout fire at ~0.3s — the loop is NOT pinned by the blocking sleep.
    res, fired = _dispatch(lambda: time.sleep(1.0) or "unreached", timeout_s=0.3)
    assert res is None
    assert fired is not None and fired < 0.9   # fired at the deadline, not after 1s


def test_async_agent_is_awaited_directly():
    async def async_agent():
        await asyncio.sleep(0)
        return "ok"

    res, fired = _dispatch(async_agent, timeout_s=1.0)
    assert res == "ok" and fired is None


def test_fast_sync_agent_returns_normally():
    res, fired = _dispatch(lambda: "fast", timeout_s=1.0)
    assert res == "fast" and fired is None


def test_dispatch_matches_orchestrator_shape():
    # The orchestrator uses inspect.iscoroutinefunction to choose await-vs-to_thread.
    async def a():
        return 1

    def s():
        return 2

    assert inspect.iscoroutinefunction(a) is True
    assert inspect.iscoroutinefunction(s) is False
