"""Bounded camera workers; source credentials never leave private subprocess IPC."""
from __future__ import annotations

import asyncio
import json
import secrets
import shutil
from pathlib import Path


class CameraMediaBusy(RuntimeError):
    pass


class CameraMedia:
    def __init__(self, runtime_path: Path | None = None) -> None:
        self._sessions: dict[str, tuple[asyncio.subprocess.Process, asyncio.Lock]] = {}
        self._lock = asyncio.Lock()
        self._watchers: set[asyncio.Task] = set()
        self._runtime_path = runtime_path
        self._stopping = False

    def is_active(self, session_id: str) -> bool:
        entry = self._sessions.get(session_id)
        return entry is not None and entry[0].returncode is None

    async def _exchange(self, process, message: dict) -> dict:
        try:
            async with asyncio.timeout(20):
                process.stdin.write(json.dumps(message).encode() + b"\n")
                await process.stdin.drain()
                response = json.loads(await process.stdout.readline())
            if not isinstance(response, dict) or response.get("ok") is not True:
                raise ValueError("Worker failed")
            return response
        except (OSError, ValueError, TimeoutError):
            raise RuntimeError("Camera media operation failed") from None

    async def create(self, source: dict[str, str | bool], sdp: str | None = None) -> dict[str, str]:
        if sdp is not None and (not isinstance(sdp, str) or not 1 <= len(sdp.encode()) <= 65536):
            raise ValueError("Invalid SDP offer")
        async with self._lock:
            if self._stopping:
                raise RuntimeError("Camera media service is stopping")
            if len(self._sessions) >= 2:
                raise CameraMediaBusy("At most two camera sessions are allowed")
            node = shutil.which("node")
            runtime = Path(__file__).resolve().parent.parent / "matter_node"
            if not (runtime / "node_modules" / "werift").is_dir() and self._runtime_path:
                runtime = self._runtime_path
            script = runtime / "camera-worker.mjs"
            if node is None:
                raise RuntimeError("Node.js is required for camera media")
            process = await asyncio.create_subprocess_exec(
                node, str(script), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                limit=256 * 1024,
            )
            session_id = secrets.token_urlsafe(24)
            lock = asyncio.Lock()
            self._sessions[session_id] = (process, lock)
            watcher = asyncio.create_task(self._watch(session_id, process))
            self._watchers.add(watcher)
            watcher.add_done_callback(self._watchers.discard)
        try:
            async with lock:
                response = await self._exchange(process, {
                    "command": "offer" if sdp is not None else "solicit", "source": source, "sdp": sdp,
                })
            answer = response.get("sdp")
            if not isinstance(answer, str) or len(answer.encode()) > 65536:
                raise RuntimeError("Invalid camera answer")
            return {"session_id": session_id, "sdp": answer,
                    "type": "answer" if sdp is not None else "offer"}
        except BaseException:
            await self.close(session_id)
            raise

    async def _watch(self, session_id, process) -> None:
        await process.wait()
        self._sessions.pop(session_id, None)

    async def ice(self, session_id: str, candidate) -> None:
        entry = self._sessions.get(session_id)
        if entry is None:
            raise KeyError(session_id)
        process, lock = entry
        async with lock:
            await self._exchange(process, {"command": "ice", "candidate": candidate})

    async def answer(self, session_id: str, sdp: str) -> None:
        if not isinstance(sdp, str) or not 1 <= len(sdp.encode()) <= 65536:
            raise ValueError("Invalid SDP answer")
        entry = self._sessions.get(session_id)
        if entry is None:
            raise KeyError(session_id)
        process, lock = entry
        async with lock:
            await self._exchange(process, {"command": "answer", "sdp": sdp})

    async def close(self, session_id: str) -> None:
        entry = self._sessions.pop(session_id, None)
        if entry is None:
            return
        process, _ = entry
        if process.returncode is None:
            try:
                process.terminate()
                async with asyncio.timeout(5):
                    await process.wait()
            except TimeoutError:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                pass

    async def stop(self) -> None:
        async with self._lock:
            self._stopping = True
            session_ids = list(self._sessions)
        await asyncio.gather(*(self.close(key) for key in session_ids))
        if self._watchers:
            await asyncio.gather(*self._watchers)
