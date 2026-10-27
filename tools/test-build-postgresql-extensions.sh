#!/bin/sh
# sow: pomar-SOW-87 rev29. Existing independently adopted runtime only.
set -eu
invocation_epoch=$(/bin/date +%s)
: "${POMAR_RECIPE_PYTHON:?explicit adopted direct Python required}"
: "${POMAR_RECIPE_PYTHON_SHA256:?independent executable hash required}"
: "${POMAR_RECIPE_PYTHON_BYTES:?independent executable length required}"
: "${POMAR_RECIPE_RUNTIME_ROOT:?independently adopted complete runtime root required}"
: "${POMAR_RECIPE_RUNTIME_SUMS:?complete independently adopted runtime SHA256SUMS required}"
: "${POMAR_RECIPE_RUNTIME_SUMS_SHA256:?independent runtime inventory hash required}"
: "${POMAR_RECIPE_RUNTIME_SUMS_BYTES:?independent runtime inventory length required}"
: "${POMAR_RECIPE_WHOLE_SECONDS:?explicit admitted invocation bound required}"
case "$POMAR_RECIPE_WHOLE_SECONDS" in ''|*[!0-9]*) exit 2;; esac
[ "$POMAR_RECIPE_WHOLE_SECONDS" -ge 1 ] && [ "$POMAR_RECIPE_WHOLE_SECONDS" -le 7200 ] || exit 2
pin_file() {
 case "$1" in /*) ;; *) exit 2;; esac
 [ -f "$1" ] && [ ! -L "$1" ] || exit 2
 actual=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/shasum -a 256 "$1")
 [ "${actual%% *}" = "$2" ] || { echo 'bootstrap file hash differs' >&2; exit 1; }
 actual=$(/usr/bin/wc -c < "$1" | /usr/bin/tr -d ' ')
 [ "$actual" = "$3" ] || { echo 'bootstrap file length differs' >&2; exit 1; }
}
pin_file "$POMAR_RECIPE_PYTHON" "$POMAR_RECIPE_PYTHON_SHA256" "$POMAR_RECIPE_PYTHON_BYTES"
pin_file "$POMAR_RECIPE_RUNTIME_SUMS" "$POMAR_RECIPE_RUNTIME_SUMS_SHA256" "$POMAR_RECIPE_RUNTIME_SUMS_BYTES"
case "$POMAR_RECIPE_RUNTIME_ROOT" in /*) ;; *) exit 2;; esac
[ "$POMAR_RECIPE_RUNTIME_ROOT" != / ] && [ "$(cd "$POMAR_RECIPE_RUNTIME_ROOT" && /bin/pwd -P)" = "$POMAR_RECIPE_RUNTIME_ROOT" ] || exit 2
# The independently adopted inventory must be complete. This check does not
# manufacture its approval or prove completeness by hashing its own contents.
/usr/bin/awk -v prefix="$POMAR_RECIPE_RUNTIME_ROOT/" -v python="$POMAR_RECIPE_PYTHON" '
 NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || index($2,prefix) != 1 || $2 ~ /(^|\/)\.\.?($|\/)/ || $2 ~ /[\\:]/ {bad=1; exit}
 $2 == python {seen=1}
 END {if (bad || !seen) exit 1}
' "$POMAR_RECIPE_RUNTIME_SUMS" || { echo 'runtime inventory path/identity refused' >&2; exit 1; }
/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/shasum -a 256 -c "$POMAR_RECIPE_RUNTIME_SUMS" >/dev/null
source_pin=$(/usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/shasum -a 256 "$0")
: "${POMAR_RECIPE_TEST_ROOT:?explicit owned0700 test parent required}"
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C POMAR_RECIPE_PYTHON="$POMAR_RECIPE_PYTHON" POMAR_RECIPE_PYTHON_SHA256="$POMAR_RECIPE_PYTHON_SHA256" POMAR_RECIPE_PYTHON_BYTES="$POMAR_RECIPE_PYTHON_BYTES" POMAR_RECIPE_RUNTIME_ROOT="$POMAR_RECIPE_RUNTIME_ROOT" POMAR_RECIPE_RUNTIME_SUMS="$POMAR_RECIPE_RUNTIME_SUMS" POMAR_RECIPE_RUNTIME_SUMS_SHA256="$POMAR_RECIPE_RUNTIME_SUMS_SHA256" POMAR_RECIPE_RUNTIME_SUMS_BYTES="$POMAR_RECIPE_RUNTIME_SUMS_BYTES" POMAR_RECIPE_SOURCE_SHA256="${source_pin%% *}" POMAR_RECIPE_STARTED_EPOCH="$invocation_epoch" POMAR_RECIPE_WHOLE_SECONDS="$POMAR_RECIPE_WHOLE_SECONDS" "$POMAR_RECIPE_PYTHON" -I -S -B - "$0" "$POMAR_RECIPE_TEST_ROOT" "$@" <<'POMAR_TEST_PYTHON'
import copy
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
import venv
import subprocess

source = Path(sys.argv[1]).resolve().with_name('build-postgresql-extensions.sh').read_text()
code = source.split("<<'POMAR_PYTHON'\n", 1)[1].rsplit('\nPOMAR_PYTHON', 1)[0]
ns = {'__name__': 'offline_recipe_test', '__file__': '<fixture>'}
exec(compile(code, '<embedded-recipe>', 'exec'), ns)
test_parent = ns['custody'](ns['canonical'](sys.argv[2]), private=True)
suite_root = Path(tempfile.mkdtemp(prefix='recipe-test-', dir=test_parent))


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=suite_root))
        self.p = self.root / 'public-synthetic-input'
        self.p.write_bytes(b'synthetic fixture, not native code\n')
        self.p.chmod(0o600)
        self.pin = {'path': str(self.p), 'bytes': self.p.stat().st_size,
                    'sha256': ns['sha'](self.p.read_bytes())}

    def refused(self, fn, *args):
        with self.assertRaises((ValueError, OSError, tarfile.TarError)):
            fn(*args)

    def test_pin_reads_exact_bytes(self):
        self.assertEqual(ns['read_pin'](self.pin), self.p.read_bytes())

    def test_missing_pin(self):
        p = dict(self.pin); del p['sha256']
        self.refused(ns['read_pin'], p)

    def test_wrong_hash(self):
        p = dict(self.pin, sha256='0' * 64)
        self.refused(ns['read_pin'], p)

    def test_wrong_length(self):
        self.refused(ns['read_pin'], dict(self.pin, bytes=self.pin['bytes'] + 1))

    def test_missing_file(self):
        self.p.unlink()
        self.refused(ns['read_pin'], self.pin)

    def test_boolean_length(self):
        self.refused(ns['read_pin'], dict(self.pin, bytes=True))

    def test_fifo_refuses_without_blocking(self):
        self.p.unlink(); os.mkfifo(self.p, 0o600)
        self.refused(ns['read_pin'], self.pin)

    def test_hardlinked_pin(self):
        os.link(self.p, self.root / 'alias')
        self.refused(ns['read_pin'], self.pin)

    def test_symlinked_pin(self):
        link = self.root / 'link'; link.symlink_to(self.p)
        self.refused(ns['read_pin'], dict(self.pin, path=str(link)))

    def test_writable_input(self):
        self.p.chmod(0o622)
        self.refused(ns['read_pin'], self.pin)

    def test_writable_parent(self):
        self.root.chmod(0o722)
        try:
            self.refused(ns['read_pin'], self.pin)
        finally:
            self.root.chmod(0o700)

    def test_noncanonical_path(self):
        self.refused(ns['canonical'], str(self.root) + '/../elsewhere')

    def test_duplicate_json(self):
        self.refused(ns['decode'], b'{"sha":1,"sha":2}')

    def test_trailing_json(self):
        self.refused(ns['decode'], b'{} {}')

    def test_nonfinite_json(self):
        self.refused(ns['decode'], b'{"value":NaN}')

    def test_unknown_field(self):
        self.refused(ns['fields'], {'known': 1, 'unknown': 2}, 'known')

    def tar(self, entries):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as t:
            root = tarfile.TarInfo('source'); root.type = tarfile.DIRTYPE
            t.addfile(root)
            for name, kind in entries:
                m = tarfile.TarInfo(name); m.type = kind
                if kind == tarfile.REGTYPE:
                    m.size = 7; t.addfile(m, io.BytesIO(b'fixture'))
                else:
                    m.linkname = '../outside'; t.addfile(m)
        return raw.getvalue()

    def test_safe_archive_extracts_only_new_target(self):
        members = ns['archive'](self.tar([('source/a', tarfile.REGTYPE)]), 'source', 100)
        out = self.root / 'extract'
        ns['extract'](members, out)
        self.assertEqual((out / 'source/a').read_bytes(), b'fixture')
        self.refused(ns['extract'], members, out)

    def test_archive_absolute(self):
        self.refused(ns['archive'], self.tar([('/outside', tarfile.REGTYPE)]), 'source', 100)

    def test_archive_traversal(self):
        self.refused(ns['archive'], self.tar([('source/../outside', tarfile.REGTYPE)]), 'source', 100)

    def test_archive_duplicate(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.REGTYPE)] * 2), 'source', 100)

    def test_archive_symlink(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.SYMTYPE)]), 'source', 100)

    def test_archive_hardlink(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.LNKTYPE)]), 'source', 100)

    def test_archive_device(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.CHRTYPE)]), 'source', 100)

    def test_archive_parent_file(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.REGTYPE), ('source/a/b', tarfile.REGTYPE)]), 'source', 100)

    def test_archive_unpack_limit(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.REGTYPE)]), 'source', 6)

    def test_archive_wrong_root(self):
        self.refused(ns['archive'], self.tar([('source/a', tarfile.REGTYPE)]), 'other', 100)

    def test_complete_closure_and_missing_entry(self):
        files = ns['inventory'](self.root)
        manifest = suite_root / (self.root.name + '.json')
        manifest.write_text(json.dumps({'root': str(self.root), 'files': files})); manifest.chmod(0o600)
        pin = {'path': str(manifest), 'bytes': manifest.stat().st_size, 'sha256': ns['sha'](manifest.read_bytes())}
        self.assertEqual(ns['closure'](pin), self.root)
        (self.root / 'unlisted').write_bytes(b'extra')
        self.refused(ns['closure'], pin)

    def test_changed_closure_file(self):
        files = ns['inventory'](self.root)
        self.p.write_bytes(b'changed!')
        self.assertNotEqual(ns['inventory'](self.root), files)

    def test_external_closure_hardlink(self):
        os.link(self.p, suite_root / (self.root.name + '-external'))
        self.refused(ns['inventory'], self.root)

    def test_internal_closure_hardlink(self):
        os.link(self.p, self.root / 'alias')
        self.assertEqual(len(ns['inventory'](self.root)), 2)

    def test_escaping_closure_link(self):
        (self.root / 'link').symlink_to('../outside')
        self.refused(ns['inventory'], self.root)

    def test_closed_environment_no_inherited_credentials_or_tools(self):
        os.environ.update(PGPASSWORD='synthetic', PYTHONPATH='synthetic', CARGO_HOME='synthetic',
                          MAKEFLAGS='synthetic', DYLD_INSERT_LIBRARIES='synthetic', TOKEN='synthetic')
        tools = {'rustc': '/adopted/bin/rustc', 'cargo': '/adopted/bin/cargo', 'clang': '/adopted/bin/clang', 'perl': '/adopted/bin/perl'}
        env = ns['closed_environment'](self.root, tools, {'sdk': Path('/adopted/sdk')}, '/adopted/clang')
        self.assertTrue({'PGPASSWORD', 'PYTHONPATH', 'MAKEFLAGS', 'DYLD_INSERT_LIBRARIES', 'TOKEN'}.isdisjoint(env))
        self.assertEqual(env['CARGO_HOME'], str(self.root / 'cargo'))
        self.assertEqual(env['PGRX_BUILD_FLAGS'], '--frozen')
        self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
        self.assertNotIn('synthetic', ':'.join(env.values()))

    def test_pgrx_direct_pin_ignores_shadow_and_rejects_changed_identical_version_fake(self):
        shadow = self.root / 'bin'; shadow.mkdir(mode=0o700)
        (shadow / 'cargo-pgrx').write_bytes(b'version-identical shadow')
        os.environ['PATH'] = str(shadow)
        args = ns['pgrx_argv'](self.pin, ['init', '--pg17', '/reviewed/pg_config', '--no-run'])
        self.assertEqual(args[0], str(self.p))
        self.assertEqual(args[1], 'pgrx')
        changed = dict(self.pin, path=str(shadow / 'cargo-pgrx'))
        self.refused(ns['pgrx_argv'], changed, ['--version'])

    def test_runtime_inventory_mismatch_refuses_in_launcher_before_input_or_output(self):
        env = dict(os.environ)
        env['POMAR_RECIPE_RUNTIME_SUMS_SHA256'] = '0' * 64
        output = self.root / 'no-output-on-runtime-mismatch'
        script = Path(sys.argv[1]).resolve().with_name('build-postgresql-extensions.sh')
        r = subprocess.run(['/bin/sh', str(script), '--check', '--input', str(self.root / 'missing'),
                            '--input-sha256', 'a' * 64, '--output', str(output), '--output-parent', str(self.root)],
                           env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b'bootstrap file hash differs', r.stderr)
        self.assertFalse(output.exists())

    def test_isolated_no_site_runtime(self):
        self.assertEqual(sys.flags.no_site, 1)
        self.assertEqual(sys.flags.isolated, 1)

    def test_unbound_native_build_refuses_before_input_output_or_child(self):
        original = list(sys.argv)
        output = self.root / 'no-native-output'
        try:
            sys.argv = ['recipe', '--build', '--input', str(self.root / 'missing-input'),
                        '--input-sha256', 'a' * 64, '--output', str(output), '--output-parent', str(self.root)]
            with self.assertRaisesRegex(ValueError, 'NO_CURRENT_BINDING_VERIFIED'):
                ns['main']()
            self.assertFalse(output.exists())
            self.assertEqual(self.p.read_bytes(), b'synthetic fixture, not native code\n')
        finally:
            sys.argv = original

    def test_one_clock_counts_preflight_and_has_no_phase_reset(self):
        now = [10.0]
        clock = ns['InvocationClock'](100, 120, monotonic=lambda: now[0], wall=lambda: 130)
        self.assertEqual(clock.deadline, 100.0)  # Bootstrap already consumed30s.
        now[0] = 90; clock.check()
        now[0] = 101
        with self.assertRaisesRegex(ValueError, 'original invocation deadline'):
            clock.check()
        self.assertEqual(clock.deadline, 100.0)

    def test_exhausted_preflight_refuses_read_and_extraction_without_effect(self):
        original = ns['CLOCK']
        now = [0.0]
        ns['CLOCK'] = ns['InvocationClock'](100, 1, monotonic=lambda: now[0], wall=lambda: 100)
        now[0] = 2
        try:
            self.refused(ns['read_pin'], self.pin)
            target = self.root / 'not-extracted'
            self.refused(ns['extract'], {}, target)
            self.assertFalse(target.exists())
        finally:
            ns['CLOCK'] = original

    def test_owned_venv_global_site_sentinel_is_disabled_by_no_site(self):
        envroot = self.root / 'inert-test-runtime'
        venv.EnvBuilder(with_pip=False, symlinks=False).create(envroot)
        sites = list(envroot.glob('lib/python*/site-packages'))
        self.assertEqual(len(sites), 1)
        sentinel = self.root / 'site-started'
        (sites[0] / 'sitecustomize.py').write_text('from pathlib import Path; Path(' + repr(str(sentinel)) + ').write_text("synthetic")\n')
        python = envroot / 'bin/python3'
        # Installed Darwin framework site.py uses this exact launch path to find
        # the owned pyvenv.cfg. A copied framework executable alone is not proof
        # that this fixture became the active virtual environment.
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', '__PYVENV_LAUNCHER__': str(python)}
        probe = 'import sys,json; print(json.dumps({"prefix":sys.prefix,"site_loaded":"site" in sys.modules,"no_site":sys.flags.no_site}))'
        isolated = subprocess.run([str(python), '-I', '-S', '-B', '-c', probe],
                                  env=env, check=True, timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        isolated_observation = json.loads(isolated.stdout)
        print('site-fixture-no-site ' + json.dumps(isolated_observation), flush=True)
        self.assertEqual(isolated_observation['prefix'], str(envroot))
        self.assertEqual(isolated_observation['no_site'], 1)
        self.assertFalse(isolated_observation['site_loaded'])
        self.assertFalse(sentinel.exists())
        control = subprocess.run([str(python), '-I', '-B', '-c', probe], env=env, check=True, timeout=10,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        control_observation = json.loads(control.stdout)
        print('site-fixture-positive-control ' + json.dumps(control_observation) + ' stderr=' + repr(control.stderr), flush=True)
        self.assertEqual(control_observation['prefix'], str(envroot))
        self.assertEqual(control_observation['no_site'], 0)
        self.assertTrue(control_observation['site_loaded'])
        self.assertTrue(sentinel.exists())  # Positive control uses only our inert owned venv.

    def test_fixed_version_source_pins_are_not_placeholders(self):
        self.assertEqual(ns['PG_SHA'], 'dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979')
        self.assertEqual(ns['GRAPH_COMMIT'], '66d4c551db213000506fd858676269ba8f801a44')
        self.refused(ns['validate'], {'schema': 'pomar.postgres-extension-build/v1'})

    def test_wrong_version_owner_bounds_and_unavailable_pin_refuse_at_boundary(self):
        base = dict.fromkeys('schema platform owner recipe_sha256 runtime_sums output output_parent frozen_recipe archives graphql_commit graphql_toml_sha256 graphql_lock_sha256 closures tools os_identity_sha256 libclang_dir jobs whole_seconds log_bytes disk_bytes bootstrap_role smoke_sql'.split())
        base.update(schema='pomar.postgres-extension-build/v1', platform='darwin/arm64', owner=os.geteuid(),
                    recipe_sha256='a' * 64, graphql_commit=ns['GRAPH_COMMIT'], graphql_toml_sha256='b' * 64,
                    graphql_lock_sha256='c' * 64, bootstrap_role='fixture', jobs=1, whole_seconds=ns['WHOLE_SECONDS'],
                    log_bytes=1024, disk_bytes=1 << 20, frozen_recipe={'sha256': ns['RECIPE_SHA'], 'bytes': 16126})
        os.environ['POMAR_RECIPE_SOURCE_SHA256'] = 'a' * 64
        for key, bad, expected in [('platform', 'linux/arm64', 'platform/owner/version'),
                                   ('owner', 0, 'platform/owner/version'), ('jobs', True, 'resource bound'),
                                   ('graphql_commit', 'latest', 'GraphQL source/lock'),
                                   ('graphql_lock_sha256', None, 'GraphQL source/lock'),
                                   ('frozen_recipe', {'sha256': '0' * 64, 'bytes': 16126}, 'frozen recipe differs')]:
            with self.subTest(key=key):
                doc = copy.deepcopy(base); doc[key] = bad
                with self.assertRaisesRegex(ValueError, expected):
                    ns['validate'](doc)


try:
    if sys.argv[3:] == ['--only-site-startup']:
        suite = unittest.TestSuite([BoundaryTests('test_owned_venv_global_site_sentinel_is_disabled_by_no_site')])
    elif not sys.argv[3:]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests)
    else:
        raise ValueError('only the fixed --only-site-startup focused selector is supported')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
finally:
    # Only this exact newly allocated synthetic fixture tree, never a build/prefix.
    shutil.rmtree(suite_root)
print('OFFLINE SYNTHETIC SOURCE BOUNDARIES ONLY; no archive fetch, native build, SQL, signing or adoption.')
sys.exit(0 if result.wasSuccessful() else 1)
POMAR_TEST_PYTHON
