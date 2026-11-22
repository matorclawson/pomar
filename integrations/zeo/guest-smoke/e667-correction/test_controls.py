# sow: pomar-guest-SOW-01
"""Mocked task-body regressions against one hash-bound owner entry.

No owner module is imported. The unchanged preflight and native main/watchdog
are excluded: only execute's result/step/finalization AST is compiled, with all
process, observation, command and retention operations replaced by fixtures.
"""
import argparse
import ast
import copy
import datetime
import hashlib
import json
import pathlib
import tempfile
import types
import unittest


ENTRY = None


class Unknown(RuntimeError):
    pass


def task_body(source):
    tree = ast.parse(source)
    execute = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'execute')
    start = next(i for i, n in enumerate(execute.body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'result' for t in n.targets))
    node = copy.deepcopy(execute)
    node.name = 'fixture_task_body'
    node.body = node.body[start:]
    return compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                   '<hash-bound-e667-task-body>', 'exec')


class Fixture:
    def __init__(self, home, fault=None):
        self.home = pathlib.Path(home)
        (self.home / 'logs').mkdir()
        self.fault = fault
        self.launches = []
        self.cleanups = 0
        self.retains = []
        self.saved = None
        self.cleaned = False

    def run(self):
        fixture = self

        class Input:
            closed = False

            def write(self, data):
                assert data == b'x'

            def close(self):
                if fixture.fault == 'stdin_close':
                    raise OSError('fixture close failure')
                self.closed = True

        class Child:
            pid = 12345
            returncode = None

            def __init__(self):
                self.stdin = Input()
                self.polls = 0

            def poll(self):
                if fixture.fault in ('log_digest', 'log_stat') and self.returncode is None:
                    return None  # Evidence failure is injected with a live child.
                self.polls += 1
                if self.polls >= 2:
                    self.returncode = 0
                return self.returncode

            def wait(self, timeout):
                assert timeout > 0
                self.returncode = 0
                return 0

        def launch(argv, **kwargs):
            self.launches.append(argv)
            self.cleaned = False
            assert kwargs['start_new_session'] is True
            assert kwargs['env'] == {'FIXTURE': 'no-claim-context'}
            assert kwargs['stdin'] is pipe
            if '-o' in argv:
                pathlib.Path(argv[argv.index('-o') + 1]).write_bytes(b'INERT FIXTURE OUTPUT')
            return Child()

        class Scope:
            gap = None
            known = {12345: {'pid': 12345, 'birth': 'FIXTURE'}}

            def __init__(self, kernel, pid):
                assert pid == 12345
                if fixture.fault == 'identity_unknown':
                    raise Unknown('fixture root identity unavailable')

            def scan(self, deadline):
                return [] if fixture.cleaned else [self.known[12345]]

            def cleanup(self, deadline):
                fixture.cleanups += 1
                if fixture.fault == 'cleanup_raises':
                    raise Unknown('fixture cleanup observation unavailable')
                fixture.cleaned = True
                return fixture.fault != 'cleanup_false', []

        def budget(*args):
            if self.fault in ('rss_unknown', 'retain_unack_result_open', 'retain_unack_result_write'):
                raise Unknown('fixture RSS unknown')
            if self.fault == 'rss_oserror':
                raise OSError('fixture observation failure')
            if self.fault == 'known_ceiling':
                raise RuntimeError('whole-job RSS ceiling exceeded')
            return {'rss_bytes': 1, 'scratch_allocated_bytes': 0}

        def digest(path):
            path = pathlib.Path(path)
            if self.fault == 'log_digest' and path.suffix == '.log':
                # Proves the correction performs cleanup before log hashing.
                self.assert_cleanup_before_evidence = self.cleaned
                raise OSError('fixture log read unavailable')
            return hashlib.sha256(path.read_bytes()).hexdigest()

        def command(argv):
            return {'/usr/bin/top': b'CPU usage: 0% user, 0% sys, 100% idle',
                    '/usr/sbin/sysctl': b'2' if argv[-1] == 'hw.logicalcpu' else b'90'}[argv[0]]

        def require(ok, message):
            if not ok:
                raise RuntimeError(message)

        def retain(deadline, original):
            self.retains.append(original)
            return {'state': 'UNKNOWN_ACK', 'acknowledged': False}

        class LogPath:
            def __init__(self, name):
                self.path = fixture.home / 'logs' / name

            def __fspath__(self):
                return str(self.path)

            def open(self, mode):
                return self.path.open(mode)

            def stat(self):
                if fixture.fault == 'log_stat':
                    fixture.assert_cleanup_before_evidence = fixture.cleaned
                    raise OSError('fixture log stat failure')
                return self.path.stat()

        class Logs:
            def __truediv__(self, name):
                return LogPath(name)

        class ResultPath:
            def open(self, mode):
                if fixture.fault == 'retain_unack_result_open':
                    raise OSError(28, 'fixture result open ENOSPC')
                return (fixture.home / 'result.json').open(mode)

        class Output:
            def __truediv__(self, name):
                if name == 'logs':
                    return Logs()
                return ResultPath() if name == 'result.json' else fixture.home / name

        def dump(value, stream, **kwargs):
            self.saved = copy.deepcopy(value)
            if self.fault in ('retain_unack_result_write', 'known_result_write'):
                raise OSError(28, 'fixture result write ENOSPC')
            return json.dump(value, stream, **kwargs)

        def sleep(seconds):
            if self.fault == 'log_digest':
                raise OSError('fixture monitor abort with child still live')

        pipe = object()
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        env = {'utc': lambda: now, 'ORIGINAL': 'FIXTURE_ONLY', '__file__': str(ENTRY),
               'digest': digest, 'before': {'fixture': 'source'}, 'source_binding': lambda: {'fixture': 'source'},
               'OUT': Output(), 'SOURCE': self.home, 'HERE': self.home, 'ENV': {'FIXTURE': 'no-claim-context'},
               'PYTHON': 'FIXTURE_PYTHON_NEVER_EXECUTED', 'SWIFTC': 'FIXTURE_SWIFTC_NEVER_EXECUTED',
               'ENTERED': 0, 'DEADLINE': 100, 'ABORT': False, 'cleanup_end': 200, 'margin_end': 300,
               'RESOURCES': {'memory_bytes': 1024, 'scratch_bytes': 1024},
               'time': types.SimpleNamespace(monotonic=lambda: 1, sleep=sleep),
               'subprocess': types.SimpleNamespace(Popen=launch, PIPE=pipe, TimeoutExpired=TimeoutError),
               'guard': types.SimpleNamespace(Unknown=Unknown, Scope=Scope, budget=budget,
                                              disk_usage=lambda *args: 0, remaining=lambda *args: 1),
               'kernel': object(), 'supervisors': [], 'require': require, 'command': command,
               'retain': retain, 're': __import__('re'), 'json': types.SimpleNamespace(dump=dump)}
        exec(task_body(ENTRY.read_text()), env)
        return env['fixture_task_body']()


class Controls(unittest.TestCase):
    def check_case(self, fault, expected_exit, cleanup_count, retain_count, launches=1):
        with tempfile.TemporaryDirectory() as home:
            fixture = Fixture(home, fault)
            self.assertEqual(fixture.run(), expected_exit)
            self.assertEqual(fixture.cleanups, cleanup_count)
            self.assertEqual(len(fixture.retains), retain_count)
            self.assertEqual(len(fixture.launches), launches, 'no next source step after failure/UNKNOWN')
            if fault in ('log_digest', 'log_stat'):
                self.assertTrue(fixture.assert_cleanup_before_evidence)
            return fixture

    def test_rss_unknown_stays_unknown_after_empty_cleanup(self):
        fixture = self.check_case('rss_unknown', 3, 1, 1)
        self.assertTrue(fixture.saved['observation_unknown'])
        self.assertTrue(fixture.saved['steps'][0]['quiescent'])

    def test_rss_oserror_is_observation_unknown(self):
        self.check_case('rss_oserror', 3, 1, 1)

    def test_log_read_error_cannot_skip_cleanup(self):
        self.check_case('log_digest', 2, 1, 0)

    def test_log_stat_error_with_live_child_cannot_skip_cleanup(self):
        self.check_case('log_stat', 2, 1, 0)

    def test_stdin_close_error_cannot_skip_cleanup(self):
        self.check_case('stdin_close', 2, 1, 0)

    def test_failed_cleanup_is_unknown(self):
        self.check_case('cleanup_false', 3, 1, 1)

    def test_cleanup_exception_is_unknown(self):
        self.check_case('cleanup_raises', 3, 1, 1)

    def test_unknown_identity_never_enters_signal_cleanup(self):
        self.check_case('identity_unknown', 3, 0, 1)

    def test_unacknowledged_retain_and_result_open_failure_preserve_three(self):
        self.check_case('retain_unack_result_open', 3, 1, 1)

    def test_unacknowledged_retain_and_result_write_failure_preserve_three(self):
        self.check_case('retain_unack_result_write', 3, 1, 1)

    def test_known_resource_ceiling_after_cleanup_is_known_failure(self):
        self.check_case('known_ceiling', 2, 1, 0)

    def test_positive_steps_can_complete_without_retention(self):
        self.check_case(None, 0, 2, 0, launches=2)

    def test_result_failure_after_known_quiescence_is_not_success(self):
        self.check_case('known_result_write', 2, 2, 0, launches=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--entry', type=pathlib.Path, required=True)
    args, remaining = parser.parse_known_args()
    bindings = json.loads(pathlib.Path(__file__).with_name('bindings.json').read_text())
    actual = hashlib.sha256(args.entry.read_bytes()).hexdigest()
    if actual not in (bindings['input_entry_sha256'], bindings['corrected_entry_sha256']):
        parser.error('entry bytes do not match reviewed input or corrected binding')
    ENTRY = args.entry
    unittest.main(argv=['test_controls.py', *remaining], verbosity=2)
