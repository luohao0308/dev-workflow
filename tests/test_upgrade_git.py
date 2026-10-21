"""Git discovery distinguishes absent repositories from inspection failures."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('upgrade_git_subject', Path(__file__).resolve().parents[1] / 'scripts/upgrade.py')
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)


class UpgradeGitTests(unittest.TestCase):
    def test_only_definitive_non_repository_is_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for failure in (FileNotFoundError(), subprocess.CompletedProcess([], 128, '', 'fatal: not a git repository (or any parent)')):
                with self.subTest(failure=type(failure).__name__):
                    with patch.object(ENGINE.subprocess, 'run', side_effect=failure if isinstance(failure, Exception) else None,
                                      return_value=failure):
                        self.assertIsNone(ENGINE.git(root, 'rev-parse', '--show-toplevel'))
                        (root / '.git').mkdir()
                        try:
                            with self.assertRaises(ValueError):
                                ENGINE.git(root, 'rev-parse', '--show-toplevel')
                        finally:
                            (root / '.git').rmdir()

    def test_git_errors_and_timeouts_never_disable_protections(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for arguments in (('rev-parse', '--show-toplevel'), ('ls-files', '--', ':(top,literal).dev-workflow'), ('rev-parse', '--git-path', 'info/exclude')):
                for failure in (subprocess.TimeoutExpired('git', 20), OSError('permission denied'),
                                subprocess.CompletedProcess([], 128, '', 'fatal: detected dubious ownership')):
                    with self.subTest(arguments=arguments, failure=type(failure).__name__):
                        with patch.object(ENGINE.subprocess, 'run', side_effect=failure if isinstance(failure, Exception) else None,
                                          return_value=failure):
                            with self.assertRaises(ValueError):
                                ENGINE.git(root, *arguments)
