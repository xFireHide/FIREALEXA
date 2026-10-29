"""Lifecycle manager for the matter.js dynamic endpoint bridge process."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)
STARTUP_TIMEOUT = 30.0


class MatterJsProvider:
    def __init__(
        self,
        api_url: str,
        node_id: str,
        port: int,
        passcode: int,
        discriminator: int,
        vendor_id: int = 0xFFF1,
        product_id: int = 0x8000,
        storage_path: Path | None = None,
    ) -> None:
        self.api_url = api_url
        self.storage_path = storage_path or Path.home() / ".matter" / node_id
        self.values = {
            "FIREALEXA_MATTER_NODE_ID": node_id,
            "FIREALEXA_MATTER_PORT": str(port),
            "FIREALEXA_MATTER_PASSCODE": str(passcode),
            "FIREALEXA_MATTER_DISCRIMINATOR": str(discriminator),
            "FIREALEXA_MATTER_VENDOR_ID": str(vendor_id),
            "FIREALEXA_MATTER_PRODUCT_ID": str(product_id),
        }
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._recent_output: list[str] = []
        self._ready = asyncio.Event()
        self._status = "starting"

    @property
    def status(self) -> str:
        return self._status

    def mark_unavailable(self) -> None:
        """Record a failed start attempt for health reporting and retry loops."""
        self._status = "unavailable"

    async def _read_output(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        while line := await process.stdout.readline():
            message = line.decode(errors="replace").rstrip()
            self._recent_output.append(message)
            del self._recent_output[:-100]
            logger.info("[matter.js] %s", message)
            if message.startswith("FIREALEXA Matter bridge started"):
                self._ready.set()

    def _prepare_runtime(self) -> Path:
        """Select an installed runtime or prepare a writable per-instance copy."""
        package_dir = Path(__file__).resolve().parents[1] / "matter_node"
        package_script = package_dir / "bridge.mjs"
        if not package_script.is_file():
            raise RuntimeError(f"Matter bridge runtime is missing: {package_script}")

        if (package_dir / "node_modules" / "@matter" / "main").is_dir():
            return package_script

        runtime_dir = self.storage_path / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(runtime_dir, 0o700)
        except OSError:
            logger.warning("Could not restrict Matter runtime permissions at %s", runtime_dir)

        runtime_files = [path.name for path in sorted(package_dir.glob("*.mjs"))]
        runtime_files.append("package.json")
        has_lockfile = (package_dir / "package-lock.json").is_file()
        if has_lockfile:
            runtime_files.append("package-lock.json")
        else:
            # Remove a lock copied by an older package if the project later
            # returns to an unlocked dependency manifest.
            stale_lockfile = runtime_dir / "package-lock.json"
            if stale_lockfile.exists() or stale_lockfile.is_symlink():
                stale_lockfile.unlink()

        for filename in runtime_files:
            source = package_dir / filename
            if not source.is_file():
                raise RuntimeError(f"Matter runtime file is missing: {source}")
            destination = runtime_dir / filename
            if destination.is_symlink() or (
                destination.exists() and not destination.is_file()
            ):
                raise RuntimeError(
                    f"Matter runtime destination is not a regular file: {destination}"
                )
            source_bytes = source.read_bytes()
            if not destination.is_file() or source_bytes != destination.read_bytes():
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{filename}.", suffix=".tmp", dir=runtime_dir
                )
                temporary_path = Path(temporary_name)
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        descriptor = -1
                        stream.write(source_bytes)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(temporary_path, 0o600)
                    os.replace(temporary_path, destination)
                except BaseException:
                    if descriptor >= 0:
                        os.close(descriptor)
                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass
                    raise
            try:
                os.chmod(destination, 0o600)
            except OSError:
                logger.warning("Could not restrict Matter runtime file permissions at %s",
                               destination)

        dependency = runtime_dir / "node_modules" / "@matter" / "main"
        if not dependency.is_dir():
            npm_command = "npm ci" if has_lockfile else "npm install"
            install_command = f"{npm_command} --prefix {shlex.quote(str(runtime_dir))}"
            raise RuntimeError(
                "Matter.js dependencies are not installed. Install them with "
                f"`{install_command}` and restart the bridge."
            )
        return runtime_dir / "bridge.mjs"

    async def _node_executable(self) -> str:
        """Find Node.js and enforce the runtime package's declared minimum."""
        executable = shutil.which("node")
        if executable is None:
            raise RuntimeError("Node.js >=22.13.0 is required to publish Matter endpoints")
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                executable, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
        except asyncio.TimeoutError as exc:
            if process is not None:
                await self._terminate_process(process)
            raise RuntimeError("Timed out while checking the Node.js version") from exc
        except OSError as exc:
            raise RuntimeError("Could not read the installed Node.js version") from exc
        version_output = (stdout or stderr).decode("utf-8", errors="replace").strip()
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version_output)
        if process.returncode != 0 or match is None:
            raise RuntimeError(f"Could not parse Node.js version: {version_output!r}")
        version = tuple(int(component) for component in match.groups())
        if version < (22, 13, 0):
            raise RuntimeError(
                f"Node.js >=22.13.0 is required for matter.js; found {version_output}"
            )
        return executable

    async def start(self) -> None:
        if self._process is not None and self._process.returncode is None:
            raise RuntimeError("Matter.js bridge process is already running")
        self._status = "starting"
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            self._status = "unavailable"
            raise RuntimeError(
                f"Could not create Matter storage directory {self.storage_path}: {exc}"
            ) from exc
        try:
            os.chmod(self.storage_path, 0o700)
        except OSError:
            logger.warning("Could not restrict Matter storage permissions at %s", self.storage_path)
        reader_task = self._reader_task
        if reader_task:
            try:
                await reader_task
            except Exception:
                logger.warning("Previous Matter.js output reader failed", exc_info=True)
            finally:
                if self._reader_task is reader_task:
                    self._reader_task = None
        self._process = None
        try:
            script = self._prepare_runtime()
        except Exception as exc:
            self._status = "unavailable"
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError(f"Could not prepare Matter.js runtime: {exc}") from exc
        try:
            node_executable = await self._node_executable()
        except RuntimeError:
            self._status = "unavailable"
            raise
        environment = {
            key: os.environ[key]
            for key in ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR",
                        "XDG_DATA_HOME")
            if key in os.environ
        }
        environment.update(self.values)
        environment["FIREALEXA_API_URL"] = self.api_url
        environment["MATTER_STORAGE_PATH"] = str(self.storage_path.resolve())
        self._ready.clear()
        try:
            self._process = await asyncio.create_subprocess_exec(
                node_executable, str(script),
                cwd=script.parent,
                env=environment,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as exc:
            self._status = "unavailable"
            raise RuntimeError(f"Could not launch Matter.js with Node.js: {exc}") from exc
        process = self._process
        self._reader_task = asyncio.create_task(self._read_output())
        ready_task = asyncio.create_task(self._ready.wait())
        exit_task = asyncio.create_task(process.wait())
        try:
            done, _ = await asyncio.wait(
                {ready_task, exit_task},
                timeout=STARTUP_TIMEOUT,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if ready_task in done and process.returncode is None:
                self._status = "ready"
                logger.info("Matter.js bridge is ready (pid=%d)", process.pid)
                return

            if not done:
                await self._terminate_process(process)
                reason = f"did not become ready within {STARTUP_TIMEOUT:.0f}s"
            else:
                reason = f"exited during startup with code {process.returncode}"

            if self._reader_task:
                await self._reader_task
                self._reader_task = None
            output = " | ".join(self._recent_output[-30:])
            npm_command = (
                "npm ci" if (script.parent / "package-lock.json").is_file()
                else "npm install"
            )
            if self._process is process:
                self._process = None
            self._status = "unavailable"
            raise RuntimeError(
                f"Matter.js bridge {reason}; verify Node.js and dependencies "
                f"with `cd {script.parent} && {npm_command}`. Output: {output}"
            )
        except asyncio.CancelledError:
            try:
                await self.stop()
            except Exception:
                logger.exception("Could not clean up Matter.js after startup cancellation")
            self._status = "stopped"
            raise
        except Exception:
            try:
                await self.stop()
            except Exception:
                logger.exception("Could not clean up Matter.js after startup failure")
            self.mark_unavailable()
            raise
        finally:
            for task in (ready_task, exit_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(ready_task, exit_task, return_exceptions=True)

    async def wait(self) -> int:
        process = self._process
        if process is None:
            return 0
        result = await process.wait()
        reader_task = self._reader_task
        try:
            if reader_task:
                await reader_task
        finally:
            if self._process is process:
                self._process = None
            if self._reader_task is reader_task:
                self._reader_task = None
            self._status = "unavailable" if result != 0 else "stopped"
        return result

    async def stop(self) -> None:
        process = self._process
        if process is None:
            self._status = "stopped"
            return
        self._status = "stopping"
        reader_task = self._reader_task
        try:
            await self._terminate_process(process)
        finally:
            if reader_task:
                try:
                    await reader_task
                except Exception:
                    logger.warning("Matter.js output reader failed during shutdown", exc_info=True)
            if self._process is process:
                self._process = None
            if self._reader_task is reader_task:
                self._reader_task = None
            self._status = "stopped"

    @staticmethod
    async def _terminate_process(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            # It exited between the returncode check and terminate(). Still
            # reap it so asyncio can release the child process resources.
            pass
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=10)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
