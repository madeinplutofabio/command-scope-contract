"""Tests for csc_runner.pathutil — path resolution, flavour detection,
prefix matching, and filesystem boundary enforcement."""

from __future__ import annotations

import os
import sys

import pytest

from csc_runner.pathutil import (
    CwdNotFoundError,
    PathEscapeError,
    _glob_literal_prefix,
    check_cwd_exists,
    detect_path_flavour,
    normalize_and_check_scope,
    normalize_path,
    path_within_prefixes,
    resolve_and_check_cwd,
)

# ---------------------------------------------------------------------------
# detect_path_flavour
# ---------------------------------------------------------------------------


class TestDetectPathFlavour:
    def test_posix_absolute(self):
        assert detect_path_flavour("/workspace/app") == "posix"

    def test_posix_root(self):
        assert detect_path_flavour("/") == "posix"

    def test_windows_drive(self):
        assert detect_path_flavour("C:\\Work\\App") == "windows"

    def test_windows_drive_forward_slash(self):
        assert detect_path_flavour("C:/Work/App") == "windows"

    def test_unc_backslash(self):
        assert detect_path_flavour("\\\\server\\share") == "windows"

    def test_unc_forward_slash(self):
        assert detect_path_flavour("//server/share") == "windows"

    def test_relative_detected_as_posix(self):
        # Relative paths have no drive letter or UNC prefix, so detected as posix
        assert detect_path_flavour("relative/path") == "posix"


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------


class TestNormalizePath:
    def test_posix_absolute(self):
        flavour, norm = normalize_path("/workspace/app")
        assert flavour == "posix"
        assert norm == "/workspace/app"

    def test_posix_preserves_case(self):
        flavour, norm = normalize_path("/Workspace/App")
        assert flavour == "posix"
        assert norm == "/Workspace/App"

    def test_windows_lowercased(self):
        flavour, norm = normalize_path("C:\\Work\\App")
        assert flavour == "windows"
        assert norm == "c:/work/app"

    def test_windows_case_insensitive(self):
        _, norm1 = normalize_path("C:\\Work\\App")
        _, norm2 = normalize_path("c:\\work\\app")
        assert norm1 == norm2

    def test_posix_relative_raises(self):
        with pytest.raises(PathEscapeError, match="must be absolute"):
            normalize_path("relative/path")

    def test_windows_drive_relative_raises(self):
        # C:relative is a drive-relative path (no root separator) — not absolute
        with pytest.raises(PathEscapeError, match="must be absolute"):
            normalize_path("C:relative")

    def test_posix_root(self):
        flavour, norm = normalize_path("/")
        assert flavour == "posix"
        assert norm == "/"


# ---------------------------------------------------------------------------
# path_within_prefixes
# ---------------------------------------------------------------------------


class TestPathWithinPrefixes:
    def test_exact_match(self):
        assert path_within_prefixes("/workspace", ["/workspace"]) is True

    def test_child_path(self):
        assert path_within_prefixes("/workspace/app/src", ["/workspace"]) is True

    def test_no_match(self):
        assert path_within_prefixes("/other/path", ["/workspace"]) is False

    def test_partial_name_no_match(self):
        # /workspace-evil should NOT match prefix /workspace
        assert path_within_prefixes("/workspace-evil", ["/workspace"]) is False

    def test_multiple_prefixes(self):
        assert path_within_prefixes("/home/user/file", ["/workspace", "/home/user"]) is True

    def test_mixed_flavour_denied(self):
        # Windows path should not match POSIX prefix
        assert path_within_prefixes("C:\\workspace\\app", ["/workspace"]) is False

    def test_posix_root_prefix(self):
        # Root prefix "/" should match all POSIX absolute paths
        assert path_within_prefixes("/any/path", ["/"]) is True

    def test_posix_root_exact(self):
        assert path_within_prefixes("/", ["/"]) is True

    def test_posix_root_does_not_match_windows(self):
        # "/" as prefix should not match Windows paths
        assert path_within_prefixes("C:\\work", ["/"]) is False

    def test_windows_drive_root_exact_match(self):
        assert path_within_prefixes("C:\\", ["C:\\"]) is True

    def test_windows_drive_root_children(self):
        assert path_within_prefixes("C:\\Work\\App", ["C:\\"]) is True

    def test_windows_case_insensitive_match(self):
        assert path_within_prefixes("C:\\Work\\App", ["c:\\work"]) is True

    def test_trailing_slash_on_prefix(self):
        assert path_within_prefixes("/workspace/app", ["/workspace/"]) is True

    def test_empty_prefixes(self):
        assert path_within_prefixes("/workspace", []) is False


# ---------------------------------------------------------------------------
# _glob_literal_prefix
# ---------------------------------------------------------------------------


class TestGlobLiteralPrefix:
    def test_no_glob(self):
        assert _glob_literal_prefix("/workspace/out") == "/workspace/out"

    def test_star_star(self):
        assert _glob_literal_prefix("/workspace/out/**") == "/workspace/out"

    def test_star_log(self):
        assert _glob_literal_prefix("/workspace/out/*.log") == "/workspace/out"

    def test_question_mark(self):
        assert _glob_literal_prefix("/workspace/out/file?.txt") == "/workspace/out"

    def test_bracket(self):
        assert _glob_literal_prefix("/workspace/out/[abc].txt") == "/workspace/out"

    def test_glob_at_root(self):
        # Glob right after root separator — no literal directory prefix
        assert _glob_literal_prefix("/*") == ""

    def test_windows_backslash_separator(self):
        assert _glob_literal_prefix("C:\\work\\out\\**") == "C:\\work\\out"


# ---------------------------------------------------------------------------
# resolve_and_check_cwd
# ---------------------------------------------------------------------------


class TestResolveAndCheckCwd:
    def test_valid_cwd_resolves(self, tmp_path):
        allowed = [str(tmp_path)]
        result = resolve_and_check_cwd(str(tmp_path), allowed)
        assert os.path.isabs(result)

    def test_cwd_outside_scope_raises(self, tmp_path):
        allowed_dir = tmp_path / "allowed"
        outside_dir = tmp_path / "outside"
        allowed_dir.mkdir()
        outside_dir.mkdir()

        with pytest.raises(PathEscapeError, match="outside allowed scope"):
            resolve_and_check_cwd(str(outside_dir), [str(allowed_dir)])

    def test_relative_cwd_rejected(self):
        with pytest.raises(PathEscapeError, match="must be absolute"):
            resolve_and_check_cwd("relative/path", ["/workspace"])

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="os.symlink requires elevated privileges on Windows",
    )
    def test_symlink_escape_rejected(self, tmp_path):
        allowed = tmp_path / "allowed"
        outside = tmp_path / "outside"
        allowed.mkdir()
        outside.mkdir()

        # Create symlink inside allowed that points outside
        escape_link = allowed / "escape"
        escape_link.symlink_to(outside)

        with pytest.raises(PathEscapeError, match="outside allowed scope"):
            resolve_and_check_cwd(str(escape_link), [str(allowed)])

    def test_dotdot_resolved(self, tmp_path):
        child = tmp_path / "child"
        child.mkdir()

        # tmp_path/child/.. resolves to tmp_path
        cwd_with_dotdot = str(child) + "/.."
        result = resolve_and_check_cwd(cwd_with_dotdot, [str(tmp_path)])
        assert os.path.realpath(str(tmp_path)) == result

    def test_syntactic_validation_before_realpath(self):
        # A relative path should be rejected by normalize_path()
        # before os.path.realpath() is ever called.
        with pytest.raises(PathEscapeError, match="must be absolute"):
            resolve_and_check_cwd("not/absolute", ["/"])


# ---------------------------------------------------------------------------
# check_cwd_exists
# ---------------------------------------------------------------------------


class TestCheckCwdExists:
    def test_existing_directory_passes(self, tmp_path):
        check_cwd_exists(str(tmp_path))

    def test_nonexistent_raises(self, tmp_path):
        missing = str(tmp_path / "does_not_exist")
        with pytest.raises(CwdNotFoundError):
            check_cwd_exists(missing)

    def test_file_not_directory_raises(self, tmp_path):
        a_file = tmp_path / "a_file.txt"
        a_file.write_text("content")
        with pytest.raises(CwdNotFoundError):
            check_cwd_exists(str(a_file))


# ---------------------------------------------------------------------------
# normalize_and_check_scope
# ---------------------------------------------------------------------------


class TestNormalizeAndCheckScope:
    def test_valid_scope_passes(self):
        normalize_and_check_scope("/workspace/out/**", ["/workspace"])

    def test_scope_outside_prefixes_raises(self):
        with pytest.raises(PathEscapeError, match="scope outside allowed prefixes"):
            normalize_and_check_scope("/other/path/**", ["/workspace"])

    def test_dotdot_in_literal_rejected(self):
        with pytest.raises(PathEscapeError, match="'..' not allowed"):
            normalize_and_check_scope("/workspace/../etc/**", ["/workspace"])

    def test_no_literal_prefix_rejected(self):
        with pytest.raises(PathEscapeError, match="no literal prefix"):
            normalize_and_check_scope("*", ["/workspace"])

    def test_relative_scope_rejected(self):
        with pytest.raises(PathEscapeError, match="must be absolute"):
            normalize_and_check_scope("relative/path/**", ["/workspace"])

    def test_non_glob_path(self):
        # A concrete path without glob metacharacters should still work
        normalize_and_check_scope("/workspace/out/file.txt", ["/workspace"])

    def test_label_in_error(self):
        with pytest.raises(PathEscapeError, match="read_paths"):
            normalize_and_check_scope("/other/**", ["/workspace"], label="read_paths")

    def test_mixed_flavour_scope_rejected(self):
        # Windows-style scope against POSIX-only prefixes
        with pytest.raises(PathEscapeError):
            normalize_and_check_scope("C:\\workspace\\out\\**", ["/workspace"])
