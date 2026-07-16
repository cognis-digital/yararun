"""Filesystem target expansion for YARARUN — turn paths into scannable files.

The engine in :mod:`yararun.core` scans a ``bytes`` blob. This module bridges
the gap between a user-supplied list of paths (files *and* directories) and that
blob-level API, honouring the repository's original promise of running rules
"over a directory".

It provides a single generator, :func:`iter_targets`, that expands a mix of
files and directories into concrete file paths while applying:

  * recursion control (``recursive`` — walk sub-directories or stay flat),
  * ``fnmatch`` include / exclude glob filters (matched against both the
    basename and the path relative to the walked root),
  * a per-file size ceiling (``max_bytes`` — skip anything larger; ``0`` == no
    limit), so a recursive scan cannot be derailed by a multi-GB artifact,
  * optional symlink following (off by default, to avoid loops / escapes).

Everything here is pure standard library, deterministic (sorted walk order),
and side-effect free apart from reading directory entries.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field


@dataclass
class WalkStats:
    """Counters describing what :func:`iter_targets` did — for reporting."""
    files_yielded: int = 0
    dirs_visited: int = 0
    skipped_size: int = 0
    skipped_excluded: int = 0
    skipped_unreadable: int = 0
    skipped_paths: list[str] = field(default_factory=list)


def _matches_any(name: str, rel: str, patterns: list[str]) -> bool:
    """True if ``name`` (basename) or ``rel`` (relative path) matches a glob."""
    for pat in patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat):
            return True
    return False


def _keep(name: str, rel: str,
          include: list[str], exclude: list[str]) -> bool:
    """Apply include/exclude glob policy. Exclude wins over include."""
    if exclude and _matches_any(name, rel, exclude):
        return False
    if include and not _matches_any(name, rel, include):
        return False
    return True


def iter_targets(
    paths,
    *,
    recursive: bool = True,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_bytes: int = 0,
    follow_symlinks: bool = False,
    stats: WalkStats | None = None,
):
    """Yield scannable file paths expanded from ``paths`` (files + dirs).

    Args:
        paths: iterable of file or directory paths. ``"-"`` (stdin) is passed
            through untouched so the caller can special-case it.
        recursive: when a directory is given, descend into sub-directories.
            When ``False`` only its immediate children are considered.
        include: glob patterns; if non-empty, a file must match at least one.
        exclude: glob patterns; a matching file is skipped (takes precedence).
        max_bytes: skip files strictly larger than this many bytes (``0`` off).
        follow_symlinks: follow symlinked directories while walking.
        stats: optional :class:`WalkStats` populated with per-run counters.

    Yields:
        File paths (str), de-duplicated, in a stable sorted order per root.
    """
    include = list(include or [])
    exclude = list(exclude or [])
    st = stats if stats is not None else WalkStats()
    seen: set[str] = set()

    def _emit(path: str) -> bool:
        real = os.path.normpath(path)
        if real in seen:
            return False
        seen.add(real)
        return True

    for raw in paths:
        if raw == "-":
            if _emit(raw):
                st.files_yielded += 1
                yield raw
            continue

        if os.path.isfile(raw):
            base = os.path.basename(raw)
            if not _keep(base, base, include, exclude):
                st.skipped_excluded += 1
                st.skipped_paths.append(raw)
                continue
            if max_bytes and _too_big(raw, max_bytes, st):
                continue
            if _emit(raw):
                st.files_yielded += 1
                yield raw
            continue

        if os.path.isdir(raw):
            yield from _walk_dir(
                raw, recursive=recursive, include=include, exclude=exclude,
                max_bytes=max_bytes, follow_symlinks=follow_symlinks,
                stats=st, emit=_emit,
            )
            continue

        # Non-existent path: surface it as unreadable, let the caller report.
        st.skipped_unreadable += 1
        st.skipped_paths.append(raw)


def _too_big(path: str, max_bytes: int, st: WalkStats) -> bool:
    try:
        if os.path.getsize(path) > max_bytes:
            st.skipped_size += 1
            st.skipped_paths.append(path)
            return True
    except OSError:
        st.skipped_unreadable += 1
        st.skipped_paths.append(path)
        return True
    return False


def _walk_dir(root, *, recursive, include, exclude,
              max_bytes, follow_symlinks, stats, emit):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        stats.dirs_visited += 1
        dirnames.sort()
        if not recursive:
            dirnames[:] = []          # visit only the top level
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if not _keep(fn, rel, include, exclude):
                stats.skipped_excluded += 1
                stats.skipped_paths.append(full)
                continue
            if max_bytes and _too_big(full, max_bytes, stats):
                continue
            if emit(full):
                stats.files_yielded += 1
                yield full
