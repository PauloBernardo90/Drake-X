"""Android emulator sandbox backend — dynamic analysis via AVD.

Provides the ability to install and run APK samples in an isolated
Android emulator instance for behavioral observation. This backend:

- Starts a headless Android emulator (AVD)
- Installs the APK via ``adb install``
- Optionally launches the main activity
- Collects logcat output
- Shuts down the emulator after execution

Requires:
- Android SDK with emulator and platform-tools
- At least one AVD configured
- ``ANDROID_HOME`` or ``ANDROID_SDK_ROOT`` set

This is a **research-grade** dynamic analysis tool — not a full-featured
behavioral sandbox. For production dynamic analysis, use dedicated
solutions like CuckooDroid or similar.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from ..logging import get_logger
from .base import (
    NetworkPolicy,
    SandboxBackend,
    SandboxConfig,
    SandboxResult,
    SandboxStatus,
)
from .exceptions import IsolationError, SandboxUnavailableError

log = get_logger("sandbox.emulator")

_ADB = "adb"
_EMULATOR = "emulator"


def _find_sdk_tool(name: str) -> str | None:
    """Find an Android SDK tool, checking PATH and ANDROID_HOME."""
    found = shutil.which(name)
    if found:
        return found

    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        for subdir in ("platform-tools", "emulator", "tools"):
            candidate = Path(sdk_root) / subdir / name
            if candidate.is_file():
                return str(candidate)
            # Windows .exe
            candidate_exe = candidate.with_suffix(".exe")
            if candidate_exe.is_file():
                return str(candidate_exe)
    return None


class EmulatorBackend(SandboxBackend):
    """Android emulator sandbox backend.

    Uses the Android SDK emulator to run APKs in an isolated Android
    environment for behavioral observation and logcat capture.
    """

    def __init__(self, *, avd_name: str = "drake_sandbox") -> None:
        self._avd_name = avd_name
        self._adb = _find_sdk_tool(_ADB)
        self._emulator = _find_sdk_tool(_EMULATOR)
        self._serial: str | None = None

    @property
    def name(self) -> str:
        return "emulator"

    def is_available(self) -> bool:
        """Check if emulator and adb are accessible."""
        return self._emulator is not None and self._adb is not None

    def verify_isolation(self, config: SandboxConfig) -> bool:
        """Verify emulator environment is usable."""
        if not self.is_available():
            raise SandboxUnavailableError(
                "Android emulator or adb not found. Set ANDROID_HOME and "
                "ensure emulator + platform-tools are installed."
            )

        # Check AVD exists
        try:
            proc = subprocess.run(
                [self._emulator, "-list-avds"],
                capture_output=True,
                timeout=10,
            )
            avds = proc.stdout.decode("utf-8", errors="replace").strip().splitlines()
            if self._avd_name not in avds:
                raise IsolationError(
                    f"AVD '{self._avd_name}' not found. Available: {', '.join(avds) or 'none'}. "
                    f"Create with: avdmanager create avd -n {self._avd_name} -k 'system-images;...'"
                )
        except subprocess.TimeoutExpired:
            raise IsolationError("Emulator -list-avds timed out")
        except FileNotFoundError:
            raise SandboxUnavailableError("Emulator binary not found at exec time")

        log.info("Emulator isolation verified (AVD: %s)", self._avd_name)
        return True

    def execute(
        self,
        command: list[str],
        workspace: Path,
        config: SandboxConfig,
    ) -> SandboxResult:
        """Execute APK analysis in the Android emulator.

        The ``command`` list is interpreted specially:
        - First element: path to the APK (relative to workspace)
        - Remaining elements: optional arguments
          - ``--launch``: also launch the main activity
          - ``--logcat-time=N``: capture logcat for N seconds (default 30)

        If command is empty or doesn't point to an APK, falls back to
        raw command execution via adb shell.
        """
        sample_dir = workspace / "sample"
        output_dir = workspace / "output"

        # Parse command options
        apk_path: Path | None = None
        launch = False
        logcat_seconds = 30

        for arg in command:
            if arg == "--launch":
                launch = True
            elif arg.startswith("--logcat-time="):
                try:
                    logcat_seconds = int(arg.split("=", 1)[1])
                except ValueError:
                    pass
            elif arg.endswith(".apk") and not apk_path:
                candidate = sample_dir / Path(arg).name
                if candidate.exists():
                    apk_path = candidate
                elif (workspace / arg).exists():
                    apk_path = workspace / arg

        # Start emulator
        emu_proc = self._start_emulator(config)
        if emu_proc is None:
            return SandboxResult(
                status=SandboxStatus.ERROR,
                error="Failed to start emulator",
                backend=self.name,
                command=command,
            )

        try:
            # Wait for boot
            if not self._wait_for_boot(timeout=config.timeout_seconds // 2):
                return SandboxResult(
                    status=SandboxStatus.TIMEOUT,
                    timed_out=True,
                    error="Emulator boot timed out",
                    backend=self.name,
                    command=command,
                    isolation_verified=True,
                )

            stdout_parts: list[str] = []
            stderr_parts: list[str] = []

            # Disable network if policy requires
            if config.network == NetworkPolicy.DENY:
                self._adb_shell("svc wifi disable")
                self._adb_shell("svc data disable")
                stdout_parts.append("[sandbox] Network disabled")

            # Install APK if provided
            if apk_path and apk_path.exists():
                install_result = self._install_apk(apk_path)
                stdout_parts.append(f"[install] {install_result}")

                if launch:
                    launch_result = self._launch_app(apk_path)
                    stdout_parts.append(f"[launch] {launch_result}")

            elif command:
                # Raw adb shell command
                shell_cmd = " ".join(command)
                result = self._adb_shell(shell_cmd)
                stdout_parts.append(result)

            # Capture logcat
            logcat = self._capture_logcat(logcat_seconds)
            stdout_parts.append(f"[logcat] ({len(logcat)} chars captured)")

            # Save logcat to output
            logcat_path = output_dir / "logcat.txt"
            logcat_path.write_text(logcat, encoding="utf-8")

            return SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0,
                stdout="\n".join(stdout_parts),
                stderr="\n".join(stderr_parts),
                backend=self.name,
                command=command,
                isolation_verified=True,
            )

        finally:
            self._stop_emulator(emu_proc)

    def _start_emulator(self, config: SandboxConfig) -> subprocess.Popen | None:
        """Start the emulator in headless mode."""
        emu_cmd = [
            self._emulator,
            f"-avd", self._avd_name,
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-gpu", "swiftshader_indirect",
            "-no-snapshot-save",
            "-wipe-data",
        ]

        if config.network == NetworkPolicy.DENY:
            emu_cmd.append("-no-sim")

        try:
            proc = subprocess.Popen(
                emu_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            log.info("Emulator started (PID %d, AVD %s)", proc.pid, self._avd_name)
            return proc
        except (FileNotFoundError, OSError) as exc:
            log.error("Failed to start emulator: %s", exc)
            return None

    def _wait_for_boot(self, timeout: int = 120) -> bool:
        """Wait for emulator to finish booting."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                proc = subprocess.run(
                    [self._adb, "shell", "getprop", "sys.boot_completed"],
                    capture_output=True,
                    timeout=5,
                )
                if proc.stdout.decode().strip() == "1":
                    log.info("Emulator boot completed")
                    return True
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(2)
        return False

    def _install_apk(self, apk_path: Path) -> str:
        """Install APK on the emulator."""
        try:
            proc = subprocess.run(
                [self._adb, "install", "-r", str(apk_path)],
                capture_output=True,
                timeout=60,
            )
            output = proc.stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                return f"Installed: {apk_path.name}"
            return f"Install failed: {output[:200]}"
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"Install error: {exc}"

    def _launch_app(self, apk_path: Path) -> str:
        """Attempt to launch the APK's main activity."""
        # Get package name via aapt or from filename
        try:
            proc = subprocess.run(
                [self._adb, "shell", "pm", "list", "packages", "-3"],
                capture_output=True,
                timeout=10,
            )
            packages = proc.stdout.decode().strip().splitlines()
            if packages:
                pkg = packages[-1].replace("package:", "").strip()
                subprocess.run(
                    [self._adb, "shell", "monkey", "-p", pkg, "-c",
                     "android.intent.category.LAUNCHER", "1"],
                    capture_output=True,
                    timeout=10,
                )
                return f"Launched: {pkg}"
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"Launch error: {exc}"
        return "Launch: no package found"

    def _capture_logcat(self, seconds: int) -> str:
        """Capture logcat output for the specified duration."""
        try:
            proc = subprocess.run(
                [self._adb, "logcat", "-d", "-v", "threadtime"],
                capture_output=True,
                timeout=seconds + 5,
            )
            return proc.stdout.decode("utf-8", errors="replace")[:1_000_000]
        except (subprocess.TimeoutExpired, OSError):
            return ""

    def _adb_shell(self, cmd: str) -> str:
        """Run adb shell command."""
        try:
            proc = subprocess.run(
                [self._adb, "shell", cmd],
                capture_output=True,
                timeout=10,
            )
            return proc.stdout.decode("utf-8", errors="replace")[:10_000]
        except (subprocess.TimeoutExpired, OSError) as exc:
            return f"adb shell error: {exc}"

    def _stop_emulator(self, proc: subprocess.Popen) -> None:
        """Stop the emulator gracefully."""
        try:
            subprocess.run(
                [self._adb, "emu", "kill"],
                capture_output=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
        log.info("Emulator stopped")
