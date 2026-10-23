"""Cooperative lifecycle mutex shared with Bash and PowerShell installers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import uuid


def linked(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        return bool(getattr(path.lstat(), 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))
    except FileNotFoundError:
        return False


def pending_upgrades(root: Path) -> list[str]:
    """Validate local transaction history before another lifecycle mutation."""
    root = root.resolve()
    directory = root / '.dev-workflow/upgrades'
    if any(linked(path) for path in (directory.parent, directory)):
        raise ValueError('Upgrade history is linked or reparsed')
    if not directory.exists():
        return []
    result = []
    for item in directory.iterdir():
        if linked(item) or not item.is_dir() or not re.fullmatch(r'[0-9a-f]{32}', item.name):
            raise ValueError('Unknown entry in upgrade transaction history')
        journal = item / 'journal.json'
        if linked(journal) or not journal.is_file():
            raise ValueError('Incomplete upgrade history; inspect before continuing')
        record = json.loads(journal.read_text(encoding='utf-8'))
        if (not isinstance(record, dict) or type(record.get('schemaVersion')) is not int
                or record['schemaVersion'] != 1 or record.get('target') != str(root)
                or record.get('transaction') != item.name):
            raise ValueError('Upgrade journal identity mismatch')
        if record.get('status') not in ('committed', 'rolled-back'):
            result.append(item.name)
    return result


def process_alive(pid: int) -> bool | None:
    if type(pid) is not int or pid <= 0:
        return None
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False if ctypes.get_last_error() == 87 else None
        try:
            code = wintypes.DWORD()
            return code.value == 259 if kernel.GetExitCodeProcess(handle, ctypes.byref(code)) else None
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return None


class LifecycleLock:
    """Existence of owner.json (CreateNew/O_EXCL), not its directory, is the lock.

    Parent borrowing is a coordination convenience for installer-sync, never an
    execution permission. No timeout-based stealing or deletion of live owners.
    """
    def __init__(self, root: Path, operation: str, *, transaction: str | None = None,
                 borrow_parent: bool = False, recover: bool = False, expected_owner: dict | None = None):
        self.root = root.resolve()
        self.directory = self.root / '.dev-workflow/lifecycle.lock'
        self.path = self.directory / 'owner.json'
        self.operation, self.transaction = operation, transaction
        self.borrow_parent, self.recover = borrow_parent, recover
        self._expected_owner = None
        if expected_owner is not None:
            if (not recover or type(expected_owner) is not dict
                    or set(expected_owner) != {'pid', 'token', 'operation', 'transaction'}
                    or type(expected_owner['pid']) is not int or expected_owner['pid'] <= 0
                    or type(expected_owner['token']) is not str or not re.fullmatch(r'[0-9a-f]{32}', expected_owner['token'])
                    or type(expected_owner['operation']) is not str
                    or expected_owner['transaction'] != transaction):
                raise ValueError('Invalid attested owner for lifecycle recovery')
            self._expected_owner = json.dumps(expected_owner, sort_keys=True, separators=(',', ':'))
        self.token = uuid.uuid4().hex
        self.owned = False

    def __enter__(self):
        for path in (self.directory.parent, self.directory, self.path):
            if linked(path):
                raise ValueError('Lifecycle lock path is linked or a reparse point')
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.recover:
            return self._acquire()
        # Serialize recoverers before they read owner.json. Otherwise a second
        # recoverer can unlink a fresh live owner using a stale dead-owner read.
        guard = self.directory / 'recovery.lock'
        if linked(guard):
            raise ValueError('Lifecycle recovery guard is linked or a reparse point')
        try:
            descriptor = os.open(guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError('Lifecycle recovery is locked; unknown recovery guards are never stolen')
        try:
            return self._acquire()
        finally:
            os.close(descriptor)
            guard.unlink()

    def _acquire(self):
        if self._expected_owner is not None and not self.path.exists():
            raise ValueError('Lifecycle attested owner disappeared before recovery')
        if self.path.exists():
            try:
                previous = json.loads(self.path.read_text(encoding='utf-8'))
            except (ValueError, OSError):
                raise ValueError('Lifecycle lock owner is unreadable; do not remove an unknown lock')
            if not isinstance(previous, dict):
                raise ValueError('Invalid lifecycle lock owner')
            if type(previous.get('pid')) is not int or previous['pid'] <= 0:
                raise ValueError('Invalid lifecycle lock process identity')
            if self.borrow_parent and previous.get('operation') == 'install' and previous['pid'] == os.getppid():
                return self
            if (self.recover and self.transaction and previous.get('transaction') == self.transaction
                    and process_alive(previous.get('pid')) is False):
                # Runs while recovery.lock is held. Recompare the complete frozen
                # attestation here; a precheck outside this boundary is insufficient.
                if self._expected_owner is not None:
                    if linked(self.path) or self.path.stat().st_nlink != 1:
                        raise ValueError('Lifecycle attested owner is linked before recovery')
                    current = json.loads(self.path.read_text(encoding='utf-8'))
                    if (current != previous
                            or json.dumps(current, sort_keys=True, separators=(',', ':')) != self._expected_owner):
                        raise ValueError('Lifecycle attested owner changed before recovery')
                self.path.unlink()
            else:
                raise ValueError('Lifecycle operation is already locked; live or unknown owners are never stolen')
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise ValueError('Lifecycle operation acquired by another process')
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(dict(pid=os.getpid(), operation=self.operation, transaction=self.transaction, token=self.token), stream)
            stream.flush()
            os.fsync(stream.fileno())
        self.owned = True
        return self

    def __exit__(self, *_):
        if self.owned:
            try:
                owner = json.loads(self.path.read_text(encoding='utf-8'))
                if owner.get('token') == self.token:
                    self.path.unlink()
            except (OSError, ValueError, AttributeError):
                pass
            try:
                self.directory.rmdir()
            except OSError:
                pass
