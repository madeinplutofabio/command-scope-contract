"""Tests for csc_runner.sandbox — Linux sandbox backend.

Most tests work cross-platform by monkeypatching platform/tool/network
checks. Tests that require real Linux tools are skipped on other platforms.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from csc_runner.sandbox import (
    SandboxConfig,
    SandboxError,
    _is_under_any,
    _resolve_writable_roots,
    _validate_bind_prefix,
    _verify_bwrap_capabilities,
    build_hardened_command,
    check_command_allowed,
    default_hardened_config,
    validate_config,
    verify_hardened_runtime,
    verify_network_disabled,
    verify_platform,
    verify_tools,
)


def _config(**overrides) -> SandboxConfig:
    return SandboxConfig(**overrides)


def _mock_bwrap_success(*args, **kwargs):
    """Monkeypatch target for subprocess.run that simulates bwrap success."""
    return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="", stderr="")


def _mock_bwrap_failure(*args, **kwargs):
    """Monkeypatch target for subprocess.run that simulates bwrap failure."""
    return subprocess.CompletedProcess(
        args=args[0],
        returncode=1,
        stdout="",
        stderr="bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted",
    )


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestValidateConfig:
    def test_default_config_valid(self):
        validate_config(default_hardened_config())

    def test_zero_cpu_time_rejected(self):
        with pytest.raises(SandboxError, match="cpu_time_sec must be positive"):
            validate_config(_config(cpu_time_sec=0))

    def test_negative_memory_rejected(self):
        with pytest.raises(SandboxError, match="memory_bytes must be positive"):
            validate_config(_config(memory_bytes=-1))

    def test_zero_max_processes_rejected(self):
        with pytest.raises(SandboxError, match="max_processes must be positive"):
            validate_config(_config(max_processes=0))

    def test_zero_max_file_size_rejected(self):
        with pytest.raises(SandboxError, match="max_file_size_bytes must be positive"):
            validate_config(_config(max_file_size_bytes=0))

    def test_negative_uid_rejected(self):
        with pytest.raises(SandboxError, match="run_as_uid must be non-negative"):
            validate_config(_config(run_as_uid=-1, run_as_gid=1000))

    def test_negative_gid_rejected(self):
        with pytest.raises(SandboxError, match="run_as_gid must be non-negative"):
            validate_config(_config(run_as_uid=1000, run_as_gid=-1))

    def test_uid_without_gid_rejected(self):
        with pytest.raises(SandboxError, match="both be set or both be None"):
            validate_config(_config(run_as_uid=1000))

    def test_gid_without_uid_rejected(self):
        with pytest.raises(SandboxError, match="both be set or both be None"):
            validate_config(_config(run_as_gid=1000))

    def test_uid_and_gid_both_set_valid(self):
        validate_config(_config(run_as_uid=1000, run_as_gid=1000))

    def test_uid_and_gid_both_none_valid(self):
        validate_config(_config(run_as_uid=None, run_as_gid=None))


# ---------------------------------------------------------------------------
# Bind prefix validation
# ---------------------------------------------------------------------------


class TestValidateBindPrefix:
    def test_valid_absolute_path(self):
        _validate_bind_prefix("/workspace", "test")

    def test_empty_rejected(self):
        with pytest.raises(SandboxError, match="must not be empty"):
            _validate_bind_prefix("", "test")

    def test_relative_rejected(self):
        with pytest.raises(SandboxError, match="must be absolute"):
            _validate_bind_prefix("relative/path", "test")

    def test_glob_star_rejected(self):
        with pytest.raises(SandboxError, match="glob metacharacters"):
            _validate_bind_prefix("/workspace/*", "test")

    def test_glob_question_rejected(self):
        with pytest.raises(SandboxError, match="glob metacharacters"):
            _validate_bind_prefix("/workspace/file?.txt", "test")

    def test_glob_bracket_rejected(self):
        with pytest.raises(SandboxError, match="glob metacharacters"):
            _validate_bind_prefix("/workspace/[abc]", "test")

    def test_label_in_error(self):
        with pytest.raises(SandboxError, match="write_bind_prefixes"):
            _validate_bind_prefix("relative", "write_bind_prefixes")


# ---------------------------------------------------------------------------
# _is_under_any
# ---------------------------------------------------------------------------


class TestIsUnderAny:
    def test_exact_match(self):
        assert _is_under_any("/workspace", {"/workspace"}) is True

    def test_child(self):
        assert _is_under_any("/workspace/src", {"/workspace"}) is True

    def test_not_under(self):
        assert _is_under_any("/other", {"/workspace"}) is False

    def test_partial_name_no_match(self):
        assert _is_under_any("/workspace-evil", {"/workspace"}) is False

    def test_trailing_slash(self):
        assert _is_under_any("/workspace/", {"/workspace"}) is True

    def test_empty_ancestors(self):
        assert _is_under_any("/workspace", set()) is False


# ---------------------------------------------------------------------------
# Writable root resolution
# ---------------------------------------------------------------------------


class TestResolveWritableRoots:
    def test_existing_prefix_included(self, tmp_path):
        d = tmp_path / "out"
        d.mkdir()
        result = _resolve_writable_roots([str(d)])
        assert str(d) in result

    def test_nonexistent_under_existing_skipped(self, tmp_path):
        parent = tmp_path / "workspace"
        parent.mkdir()
        child = str(parent / "out")  # does not exist
        result = _resolve_writable_roots([str(parent), child])
        assert str(parent) in result
        assert child not in result

    def test_nonexistent_without_ancestor_rejected(self, tmp_path):
        missing = str(tmp_path / "nowhere" / "deep")
        with pytest.raises(SandboxError, match="does not exist"):
            _resolve_writable_roots([missing])

    def test_nested_roots_collapsed_to_ancestor(self, tmp_path):
        parent = tmp_path / "workspace"
        child = parent / "out"
        parent.mkdir()
        child.mkdir()
        result = _resolve_writable_roots([str(parent), str(child)])
        assert result == [str(parent)]

    def test_empty_prefixes_returns_empty(self):
        assert _resolve_writable_roots([]) == []


# ---------------------------------------------------------------------------
# Pre-flight verification
# ---------------------------------------------------------------------------


class TestVerifyPlatform:
    def test_non_linux_rejected(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.platform.system", lambda: "Windows")
        with pytest.raises(SandboxError, match="requires Linux"):
            verify_platform()

    def test_linux_passes(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.platform.system", lambda: "Linux")
        verify_platform()


class TestVerifyTools:
    def test_missing_bwrap_rejected(self, monkeypatch):
        real_which = shutil.which

        def _fake_which(name):
            if name == "bwrap":
                return None
            return real_which(name)

        monkeypatch.setattr("csc_runner.sandbox.shutil.which", _fake_which)
        with pytest.raises(SandboxError, match="bwrap"):
            verify_tools()

    def test_all_tools_present(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.shutil.which", lambda name: f"/usr/bin/{name}")
        verify_tools()


class TestVerifyNetworkDisabled:
    def test_loopback_only_passes(self, monkeypatch):
        monkeypatch.setattr(
            "csc_runner.sandbox.socket.if_nameindex",
            lambda: [(1, "lo")],
        )
        verify_network_disabled()

    def test_extra_interface_rejected(self, monkeypatch):
        monkeypatch.setattr(
            "csc_runner.sandbox.socket.if_nameindex",
            lambda: [(1, "lo"), (2, "eth0")],
        )
        with pytest.raises(SandboxError, match="eth0"):
            verify_network_disabled()

    def test_os_error_rejected(self, monkeypatch):
        def _boom():
            raise OSError("no permissions")

        monkeypatch.setattr("csc_runner.sandbox.socket.if_nameindex", _boom)
        with pytest.raises(SandboxError, match="cannot enumerate"):
            verify_network_disabled()


# ---------------------------------------------------------------------------
# bwrap capability smoke test
# ---------------------------------------------------------------------------


class TestVerifyBwrapCapabilities:
    def test_bwrap_smoke_success(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_success)
        config = _config()
        _verify_bwrap_capabilities(config)

    def test_bwrap_smoke_failure_gives_clear_error(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_failure)
        config = _config()
        with pytest.raises(SandboxError, match="runtime check failed"):
            _verify_bwrap_capabilities(config)

    def test_bwrap_smoke_failure_mentions_docs(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_failure)
        config = _config()
        with pytest.raises(SandboxError, match="deployment-modes"):
            _verify_bwrap_capabilities(config)

    def test_bwrap_smoke_failure_includes_stderr(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_failure)
        config = _config()
        with pytest.raises(SandboxError, match="RTM_NEWADDR"):
            _verify_bwrap_capabilities(config)

    def test_bwrap_smoke_empty_stderr_handled(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)

        def _fail_no_stderr(*args, **kwargs):
            return subprocess.CompletedProcess(args=args[0], returncode=1, stdout="", stderr="")

        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _fail_no_stderr)
        config = _config()
        with pytest.raises(SandboxError, match="<no stderr>"):
            _verify_bwrap_capabilities(config)

    def test_bwrap_probe_uses_usr_bin_true_when_no_bin(self, monkeypatch):
        """Config with /usr but not /bin should select /usr/bin/true."""

        def _selective_exists(path):
            if path in ("/usr", "/usr/bin/true"):
                return True
            if path == "/bin":
                return False
            return True

        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", _selective_exists)

        captured_argv = []

        def _capture_run(argv, **kwargs):
            captured_argv.extend(argv)
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _capture_run)

        config = _config(readonly_bind_paths=("/usr",))
        _verify_bwrap_capabilities(config)

        assert "/usr/bin/true" in captured_argv
        assert "/bin/true" not in captured_argv

    def test_bwrap_probe_no_executable_found(self, monkeypatch):
        """Config with no usable readonly paths should fail clearly."""
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: False)

        config = _config(readonly_bind_paths=())
        with pytest.raises(SandboxError, match="cannot select a probe executable"):
            _verify_bwrap_capabilities(config)

    def test_bwrap_probe_timeout_handled(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)

        def _timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _timeout)

        config = _config()
        with pytest.raises(SandboxError, match="timed out"):
            _verify_bwrap_capabilities(config)


# ---------------------------------------------------------------------------
# verify_hardened_runtime (full preflight)
# ---------------------------------------------------------------------------


class TestVerifyHardenedRuntime:
    def test_full_preflight(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.platform.system", lambda: "Linux")
        monkeypatch.setattr("csc_runner.sandbox.shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_success)
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        monkeypatch.setattr(
            "csc_runner.sandbox.socket.if_nameindex",
            lambda: [(1, "lo")],
        )
        config = _config(require_network_disabled=True)
        verify_hardened_runtime(config)

    def test_network_check_skippable(self, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.platform.system", lambda: "Linux")
        monkeypatch.setattr("csc_runner.sandbox.shutil.which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr("csc_runner.sandbox.subprocess.run", _mock_bwrap_success)
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        config = _config(require_network_disabled=False)
        verify_hardened_runtime(config)


# ---------------------------------------------------------------------------
# Advisory command blocking
# ---------------------------------------------------------------------------


class TestCheckCommandAllowed:
    def test_allowed_command_passes(self):
        check_command_allowed(["git", "status"], _config())

    def test_empty_argv_rejected(self):
        with pytest.raises(SandboxError, match="empty argv"):
            check_command_allowed([], _config())

    def test_shell_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["bash", "-c", "echo hi"], _config())

    def test_dash_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["dash"], _config())

    def test_python_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["python", "-c", "pass"], _config())

    def test_python3_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["python3", "-c", "pass"], _config())

    def test_python3_12_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["python3.12", "-c", "pass"], _config())

    def test_pypy_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["pypy3", "-c", "pass"], _config())

    def test_env_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["/usr/bin/env", "bash"], _config())

    def test_sudo_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["sudo", "cat", "/etc/shadow"], _config())

    def test_perl_blocked(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["perl", "-e", "1"], _config())

    def test_custom_blocked_command(self):
        config = _config(blocked_commands=frozenset({"mycmd"}))
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["mycmd"], config)

    def test_absolute_path_checked_by_basename(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["/usr/bin/bash"], _config())

    def test_case_insensitive(self):
        with pytest.raises(SandboxError, match="blocked"):
            check_command_allowed(["BASH"], _config())


# ---------------------------------------------------------------------------
# Launcher construction
# ---------------------------------------------------------------------------


class TestBuildHardenedCommand:
    def _build(self, tmp_path, **overrides):
        cwd = str(tmp_path / "workspace")
        os.makedirs(cwd, exist_ok=True)
        defaults = {
            "user_argv": ["cat", "/workspace/file.txt"],
            "cwd": cwd,
            "read_bind_prefixes": [],
            "write_bind_prefixes": [],
            "config": _config(),
        }
        defaults.update(overrides)
        return build_hardened_command(**defaults)

    def test_basic_structure(self, tmp_path):
        argv = self._build(tmp_path)
        assert argv[0] == "bwrap"
        assert "--" in argv
        assert "setpriv" in argv
        assert "--no-new-privs" in argv
        assert "prlimit" in argv
        assert argv[-2:] == ["cat", "/workspace/file.txt"]

    def test_unshare_net_present(self, tmp_path):
        argv = self._build(tmp_path)
        assert "--unshare-net" in argv

    def test_unshare_pid_present(self, tmp_path):
        argv = self._build(tmp_path)
        assert "--unshare-pid" in argv

    def test_die_with_parent_present(self, tmp_path):
        argv = self._build(tmp_path)
        assert "--die-with-parent" in argv

    def test_new_session_present(self, tmp_path):
        argv = self._build(tmp_path)
        assert "--new-session" in argv

    def test_no_new_privs_always_present(self, tmp_path):
        argv = self._build(tmp_path)
        assert "--no-new-privs" in argv

    def test_no_new_privs_without_privilege_drop(self, tmp_path):
        argv = self._build(tmp_path, config=_config(run_as_uid=None, run_as_gid=None))
        assert "--no-new-privs" in argv
        argv_str = " ".join(argv)
        assert "--reuid=" not in argv_str
        assert "--clear-groups" not in argv_str

    def test_privilege_drop_included(self, tmp_path):
        config = _config(run_as_uid=1000, run_as_gid=1000)
        argv = self._build(tmp_path, config=config)
        argv_str = " ".join(argv)
        assert "--reuid=1000" in argv_str
        assert "--regid=1000" in argv_str
        assert "--clear-groups" in argv_str
        assert "--no-new-privs" in argv_str

    def test_prlimit_values(self, tmp_path):
        config = _config(
            cpu_time_sec=60,
            memory_bytes=500_000_000,
            max_processes=50,
            max_file_size_bytes=10_000_000,
        )
        argv = self._build(tmp_path, config=config)
        argv_str = " ".join(argv)
        assert "--cpu=60" in argv_str
        assert "--as=500000000" in argv_str
        assert "--nproc=50" in argv_str
        assert "--fsize=10000000" in argv_str

    def test_cwd_readonly_when_not_under_writable(self, tmp_path):
        cwd = tmp_path / "workspace"
        cwd.mkdir()
        argv = self._build(tmp_path, cwd=str(cwd), write_bind_prefixes=[])
        cwd_str = str(cwd)
        found = False
        for i in range(len(argv) - 2):
            if argv[i] in ("--ro-bind", "--bind") and argv[i + 1] == cwd_str:
                assert argv[i] == "--ro-bind"
                found = True
                break
        assert found, f"cwd {cwd_str} not found in bind entries"

    def test_cwd_writable_when_under_writable_root(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        cwd = workspace / "subdir"
        cwd.mkdir()
        argv = self._build(
            tmp_path,
            cwd=str(cwd),
            write_bind_prefixes=[str(workspace)],
        )
        argv_str = " ".join(argv)
        assert f"--bind {workspace} {workspace}" in argv_str
        cwd_str = str(cwd)
        for i in range(len(argv) - 2):
            if argv[i] == "--ro-bind" and argv[i + 1] == cwd_str:
                pytest.fail(f"cwd {cwd_str} should not have a separate --ro-bind")

    def test_writable_prefix_bound_writable(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        argv = self._build(tmp_path, write_bind_prefixes=[str(out)])
        argv_str = " ".join(argv)
        assert f"--bind {out} {out}" in argv_str

    def test_read_prefix_under_writable_skipped(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        src = workspace / "src"
        src.mkdir()
        argv = self._build(
            tmp_path,
            cwd=str(workspace),
            read_bind_prefixes=[str(src)],
            write_bind_prefixes=[str(workspace)],
        )
        src_str = str(src)
        for i in range(len(argv) - 2):
            if argv[i] == "--ro-bind" and argv[i + 1] == src_str:
                pytest.fail(f"read prefix {src_str} should be skipped under writable root")

    def test_read_prefix_outside_writable_bound_readonly(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        data = tmp_path / "data"
        data.mkdir()
        argv = self._build(
            tmp_path,
            cwd=str(workspace),
            read_bind_prefixes=[str(data)],
            write_bind_prefixes=[],
        )
        argv_str = " ".join(argv)
        assert f"--ro-bind {data} {data}" in argv_str

    def test_empty_user_argv_rejected(self, tmp_path):
        with pytest.raises(SandboxError, match="empty user argv"):
            self._build(tmp_path, user_argv=[])

    def test_nonexistent_cwd_rejected(self, tmp_path):
        missing = str(tmp_path / "nope")
        with pytest.raises(SandboxError, match="does not exist"):
            self._build(tmp_path, cwd=missing)

    def test_glob_in_write_prefix_rejected(self, tmp_path):
        with pytest.raises(SandboxError, match="glob metacharacters"):
            self._build(tmp_path, write_bind_prefixes=["/workspace/*"])

    def test_relative_read_prefix_rejected(self, tmp_path):
        with pytest.raises(SandboxError, match="must be absolute"):
            self._build(tmp_path, read_bind_prefixes=["relative/path"])

    def test_system_paths_readonly(self, tmp_path, monkeypatch):
        monkeypatch.setattr("csc_runner.sandbox.os.path.exists", lambda p: True)
        cwd = str(tmp_path / "workspace")
        os.makedirs(cwd, exist_ok=True)
        config = _config(readonly_bind_paths=("/usr", "/lib"))
        argv = build_hardened_command(
            ["ls"],
            cwd=cwd,
            read_bind_prefixes=[],
            write_bind_prefixes=[],
            config=config,
        )
        argv_str = " ".join(argv)
        assert "--ro-bind /usr /usr" in argv_str
        assert "--ro-bind /lib /lib" in argv_str

    def test_chdir_set(self, tmp_path):
        cwd = str(tmp_path / "workspace")
        os.makedirs(cwd, exist_ok=True)
        argv = self._build(tmp_path, cwd=cwd)
        idx = argv.index("--chdir")
        assert argv[idx + 1] == cwd
