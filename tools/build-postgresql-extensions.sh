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
[ "$#" -eq 9 ] || { echo "usage: --check|--plan|--build --input ABS --input-sha256 SHA --output ABS --output-parent ABS" >&2; exit 2; }
exec /usr/bin/env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C POMAR_RECIPE_PYTHON="$POMAR_RECIPE_PYTHON" POMAR_RECIPE_PYTHON_SHA256="$POMAR_RECIPE_PYTHON_SHA256" POMAR_RECIPE_PYTHON_BYTES="$POMAR_RECIPE_PYTHON_BYTES" POMAR_RECIPE_RUNTIME_ROOT="$POMAR_RECIPE_RUNTIME_ROOT" POMAR_RECIPE_RUNTIME_SUMS="$POMAR_RECIPE_RUNTIME_SUMS" POMAR_RECIPE_RUNTIME_SUMS_SHA256="$POMAR_RECIPE_RUNTIME_SUMS_SHA256" POMAR_RECIPE_RUNTIME_SUMS_BYTES="$POMAR_RECIPE_RUNTIME_SUMS_BYTES" POMAR_RECIPE_SOURCE_SHA256="${source_pin%% *}" POMAR_RECIPE_STARTED_EPOCH="$invocation_epoch" POMAR_RECIPE_WHOLE_SECONDS="$POMAR_RECIPE_WHOLE_SECONDS" "$POMAR_RECIPE_PYTHON" -I -S -B - "$@" <<'POMAR_PYTHON'
# Embedded standard-library implementation; no imported package or network API.
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import sys
import tarfile
import time

PG_SHA = 'dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979'
SSL_SHA = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
GRAPH_COMMIT = '66d4c551db213000506fd858676269ba8f801a44'
RECIPE_SHA = '0466d82e8a2d8c85c204b757758b4a4c5d38b07fe2f8f0540df109c83b852321'
TOOLS = {'rustc', 'cargo', 'cargo-pgrx', 'clang', 'make', 'perl', 'xcrun', 'otool', 'pomar'}


class InvocationClock:
    def __init__(self, epoch, whole, monotonic=time.monotonic, wall=time.time):
        elapsed = wall() - epoch
        if elapsed < 0:
            raise ValueError('bootstrap wall clock moved backwards; original held')
        self.monotonic = monotonic
        self.deadline = monotonic() + whole - elapsed

    def check(self):
        if self.monotonic() >= self.deadline:
            raise ValueError('original invocation deadline exhausted; no phase reset')


# The shell captured entry before bootstrap reads. Bridge once to monotonic time;
# thereafter every phase shares this same deadline, including check/plan. Blocking
# OS calls and bootstrap clock discontinuities still require the adopted outer cap.
WHOLE_SECONDS = int(os.environ['POMAR_RECIPE_WHOLE_SECONDS'])
CLOCK = InvocationClock(float(os.environ['POMAR_RECIPE_STARTED_EPOCH']), WHOLE_SECONDS)
CLOCK.check()


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def fields(obj, names):
    require(type(obj) is dict and set(obj) == set(names.split()), 'missing/unknown fields')


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def terminate(signum, frame):
    raise InterruptedError('recipe interrupted; preserve original output and child disposition')


def canonical(value):
    require(type(value) is str and value.startswith('/') and str(Path(value)) == value,
            'canonical absolute path required')
    require(not any(c.isspace() or c in ':,\\\"\'\x00' for c in value), 'ambiguous path character')
    p = Path(value)
    require('..' not in p.parts and p.resolve() == p, 'symlink/parent path refused')
    return p


def custody(path, private=False):
    path = canonical(str(path))
    for p in [path, *path.parents]:
        s = p.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.geteuid())
                and not s.st_mode & 0o022, 'directory custody refused')
    if private:
        s = path.lstat()
        require(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700,
                'private owned0700 directory required')
    return path


def read_pin(pin, max_bytes=128 << 20):
    CLOCK.check()
    fields(pin, 'path sha256 bytes')
    require(digest(pin['sha256']) and type(pin['bytes']) is int
            and 0 < pin['bytes'] <= max_bytes, 'missing/invalid file pin')
    path = canonical(pin['path'])
    custody(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        a = os.fstat(f.fileno())
        require(stat.S_ISREG(a.st_mode) and a.st_uid in (0, os.geteuid())
                and a.st_nlink == 1 and not a.st_mode & 0o022
                and a.st_size == pin['bytes'], 'file custody/length differs')
        raw = f.read(max_bytes + 1)
        b = os.fstat(f.fileno())
        c = path.lstat()
        require((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns)
                == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns)
                and (a.st_dev, a.st_ino) == (c.st_dev, c.st_ino), 'file changed while reading')
        require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'file digest differs')
        CLOCK.check()
        return raw


def relative(value):
    require(type(value) is str and value and '\\' not in value
            and not any(c in value for c in '\x00\n\r'), 'invalid relative path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and '..' not in p.parts and str(p) == value
            and value != '.', 'escaping/noncanonical relative path')
    return p


def inventory(root, allow_empty=False):
    custody(root)
    pins = []
    aliases = {}
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            CLOCK.check()
            p = Path(parent) / name
            s = p.lstat()
            require(s.st_uid in (0, os.geteuid()) and
                    (stat.S_ISLNK(s.st_mode) or not s.st_mode & 0o022), 'closure custody differs')
            if stat.S_ISDIR(s.st_mode):
                continue
            item = {'path': str(p.relative_to(root)), 'mode': stat.S_IMODE(s.st_mode)}
            if stat.S_ISLNK(s.st_mode):
                link = os.readlink(p)
                require(not os.path.isabs(link) and p.resolve().is_relative_to(root)
                        and p.resolve().exists(), 'escaping/dangling closure link')
                item['link'] = link
            else:
                require(stat.S_ISREG(s.st_mode) and (s.st_size > 0 or allow_empty) and s.st_size <= 128 << 20,
                        'special/empty/oversize closure file')
                raw = p.read_bytes()
                after = p.lstat()
                require((s.st_ino, s.st_dev, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                        == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        'closure file changed')
                item.update(sha256=sha(raw), bytes=len(raw), links=s.st_nlink)
                aliases.setdefault((s.st_dev, s.st_ino), []).append(s.st_nlink)
            pins.append(item)
    require(all(len(v) == v[0] for v in aliases.values()), 'external hardlink alias')
    return sorted(pins, key=lambda p: p['path'])


def closure(pin):
    doc = decode(read_pin(pin, 64 << 20))
    fields(doc, 'root files')
    root = custody(canonical(doc['root']))
    require(type(doc['files']) is list and 0 < len(doc['files']) <= 300000,
            'incomplete closure inventory')
    for item in doc['files']:
        fields(item, 'path mode link' if 'link' in item else 'path mode sha256 bytes links')
        relative(item['path'])
        require(type(item['mode']) is int and 0 <= item['mode'] <= 0o777, 'invalid closure mode')
        if 'link' not in item:
            require(digest(item['sha256']) and type(item['bytes']) is int and item['bytes'] >= 0
                    and type(item['links']) is int and item['links'] > 0, 'invalid closure file pin')
    require(inventory(root, allow_empty=True) == doc['files'], 'closure inventory differs')
    return root


def archive(raw, root, limit):
    relative(root)
    require('/' not in root, 'single archive root required')
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as t:
        for m in t:
            CLOCK.check()
            name = m.name.rstrip('/') if m.isdir() else m.name
            p = relative(name)
            require(p.parts[0] == root and name not in result, 'archive root/duplicate differs')
            # Refuse links and special members rather than delegate extraction to tar.
            require(m.isdir() or m.isfile(), 'archive links/special members refused')
            require(not m.mode & 0o7000 and 0 <= m.size <= 128 << 20, 'archive mode/length refused')
            total += m.size
            require(total <= limit and len(result) < 100000, 'archive unpacked limit')
            result[name] = (m.mode, None if m.isdir() else t.extractfile(m).read())
            if not m.isdir():
                require(len(result[name][1]) == m.size, 'archive member truncated')
            CLOCK.check()
    require(result and root in result and result[root][1] is None, 'archive root missing')
    for name in result:
        for parent in PurePosixPath(name).parents:
            if str(parent) == '.':
                break
            require(str(parent) not in result or result[str(parent)][1] is None,
                    'archive parent is not directory')
    return result


def extract(members, target):
    CLOCK.check()
    target.mkdir(mode=0o700)
    for name, (mode, raw) in sorted(members.items(), key=lambda x: (len(PurePosixPath(x[0]).parts), x[0])):
        CLOCK.check()
        p = target / name
        if raw is None:
            p.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with p.open('xb') as f:
                f.write(raw)
            p.chmod(0o700 if mode & 0o111 else 0o600)
        CLOCK.check()


def validate(doc):
    CLOCK.check()
    fields(doc, 'schema platform owner recipe_sha256 runtime_sums output output_parent frozen_recipe archives graphql_commit graphql_toml_sha256 graphql_lock_sha256 closures tools os_identity_sha256 libclang_dir jobs whole_seconds log_bytes disk_bytes bootstrap_role smoke_sql')
    require(digest(doc['recipe_sha256']) and doc['recipe_sha256'] == os.environ.get('POMAR_RECIPE_SOURCE_SHA256'),
            'reviewed recipe source digest differs')
    require(doc['schema'] == 'pomar.postgres-extension-build/v1' and doc['platform'] == 'darwin/arm64'
            and platform.system() == 'Darwin' and platform.machine() == 'arm64'
            and os.geteuid() != 0 and doc['owner'] == os.geteuid(), 'platform/owner/version differs')
    for name, low, high in [('jobs', 1, 32), ('whole_seconds', 1, 7200),
                            ('log_bytes', 1024, 64 << 20), ('disk_bytes', 1 << 20, 64 << 30)]:
        require(type(doc[name]) is int and low <= doc[name] <= high, 'invalid explicit resource bound')
    require(doc['whole_seconds'] == WHOLE_SECONDS, 'input/launcher original budget differs')
    require(re.fullmatch('[a-zA-Z_][a-zA-Z0-9_]{0,62}', doc['bootstrap_role']) is not None,
            'invalid bootstrap role')
    require(doc['graphql_commit'] == GRAPH_COMMIT and digest(doc['graphql_toml_sha256'])
            and digest(doc['graphql_lock_sha256']), 'GraphQL source/lock pin missing')
    require(doc['frozen_recipe']['sha256'] == RECIPE_SHA and doc['frozen_recipe']['bytes'] == 16126,
            'frozen recipe differs')
    frozen = decode(read_pin(doc['frozen_recipe']))
    fields(doc['archives'], 'postgres openssl graphql')
    for name, expected, size in [('postgres', PG_SHA, 21787224), ('openssl', SSL_SHA, 53279637)]:
        require(doc['archives'][name]['sha256'] == expected
                and doc['archives'][name]['bytes'] == size, 'fixed source version/hash/length differs')
    smoke = read_pin(doc['smoke_sql'])
    expected_smoke = next(p for p in frozen['inputManifest']['files'] if p['file'] == 'artifact-smoke.sql')
    require(sha(smoke) == expected_smoke['sha256'] and len(smoke) == expected_smoke['bytes'], 'smoke differs')
    roots = {'postgres': 'postgresql-17.11', 'openssl': 'openssl-3.5.9', 'graphql': 'pg_graphql-' + GRAPH_COMMIT}
    members = {k: archive(read_pin(doc['archives'][k]), roots[k], min(doc['disk_bytes'], 512 << 20)) for k in roots}
    require(sum(len(raw) for group in members.values() for _, raw in group.values() if raw is not None)
            <= 512 << 20, 'aggregate unpacked source exceeds512MiB')
    graph = members['graphql']
    for name, key in [('Cargo.toml', 'graphql_toml_sha256'), ('Cargo.lock', 'graphql_lock_sha256')]:
        raw = graph.get(roots['graphql'] + '/' + name, (0, None))[1]
        require(raw is not None and sha(raw) == doc[key], 'GraphQL archive descriptor differs')
    require(re.search(rb'(?m)^version\s*=\s*"1\.6\.1"\s*$', graph[roots['graphql'] + '/Cargo.toml'][1]),
            'GraphQL package version differs')
    fields(doc['closures'], 'tools cargo sdk uuid python')
    closures = {k: closure(v) for k, v in doc['closures'].items()}
    require(len(set(closures.values())) == len(closures), 'closure roots collide')
    require(not any((closures['cargo'] / name).exists()
                    for name in ['credentials', 'credentials.toml', 'config', 'config.toml']),
            'Cargo credentials/config overrides refused')
    require(closures['python'] == canonical(os.environ['POMAR_RECIPE_RUNTIME_ROOT']) and canonical(sys.executable).is_relative_to(closures['python']), 'interpreter outside prebound runtime closure')
    require(doc['runtime_sums'] == {'path': os.environ['POMAR_RECIPE_RUNTIME_SUMS'], 'sha256': os.environ['POMAR_RECIPE_RUNTIME_SUMS_SHA256'], 'bytes': int(os.environ['POMAR_RECIPE_RUNTIME_SUMS_BYTES'])}, 'bootstrap/runtime inventory pin differs')
    read_pin(doc['runtime_sums'], 64 << 20)
    initial_bytes = sum(len(raw) for group in members.values() for _, raw in group.values() if raw is not None)
    initial_bytes += sum(x.get('bytes', 0) for x in inventory(closures['cargo'], allow_empty=True))
    require(initial_bytes < doc['disk_bytes'], 'initial unpack/cache exceeds disk budget')
    require(set(doc['tools']) == TOOLS, 'tool closure incomplete')
    for name, pin in doc['tools'].items():
        read_pin(pin)
        require(canonical(pin['path']).is_relative_to(closures['tools'])
                and os.access(pin['path'], os.X_OK), 'tool outside adopted closure/non-executable')
    require(canonical(doc['libclang_dir']).is_relative_to(closures['tools'])
            and (Path(doc['libclang_dir']) / 'libclang.dylib').is_file(), 'explicit libclang closure missing')
    osraw = Path('/System/Library/CoreServices/SystemVersion.plist').read_bytes()
    require(digest(doc['os_identity_sha256']) and sha(osraw) == doc['os_identity_sha256'], 'host identity differs')
    CLOCK.check()
    return members, roots, closures, smoke


def closed_environment(out, tools, closures, libclang_dir):
    path = [str(out / 'postgres' / 'bin')] + sorted({str(Path(p).parent) for p in tools.values()}) + ['/usr/bin', '/bin']
    return {'PATH': ':'.join(path), 'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'),
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'CARGO_NET_OFFLINE': 'true',
            'PGRX_BUILD_FLAGS': '--frozen', 'CARGO_HOME': str(out / 'cargo'),
            'PGRX_HOME': str(out / 'pgrx'), 'RUSTC': tools['rustc'], 'CARGO': tools['cargo'], 'CC': tools['clang'],
            'PERL': tools['perl'], 'SDKROOT': str(closures['sdk']), 'LIBCLANG_PATH': libclang_dir}


def pgrx_argv(pin, args):
    # Cargo's documented custom-subcommand argv: cargo-pgrx pgrx ARGS.
    # Use the pinned direct executable, never Cargo's CARGO_HOME/bin/PATH search.
    read_pin(pin)
    return [pin['path'], 'pgrx', *args]


def fixed_plan(doc, out, roots, closures):
    # DATA ONLY. No admitted controller/lease/start/cleanup contract exists yet.
    tools = {k: v['path'] for k, v in doc['tools'].items()}
    ssl, pg = out / 'openssl', out / 'postgres'
    pgsrc = out / 'src/postgres' / roots['postgres']
    sslsrc = out / 'src/openssl' / roots['openssl']
    graph = out / 'src/graphql' / roots['graphql']
    steps = []
    def step(cwd, argv, required):
        CLOCK.check()
        steps.append({'cwd': str(cwd), 'argv': [str(x) for x in argv], 'required_observation': required})
    for name, expected in [('rustc', '1.88.0'), ('cargo', '1.88.0')]:
        step(out, [tools[name], '--version'], 'Actual exact version ' + expected)
    step(out, pgrx_argv(doc['tools']['cargo-pgrx'], ['--version']), 'Actual pgrx0.16.1, pinned direct executable')
    step(out, [tools['xcrun'], '--show-sdk-path'], 'Resolve exactly to selected SDK closure')
    step(sslsrc, [tools['perl'], sslsrc / 'Configure', 'darwin64-arm64-cc', '--prefix=' + str(ssl),
                 '--openssldir=' + str(ssl / 'ssl'), '--libdir=lib', 'no-shared', '-fPIC'], 'New owned OpenSSL configure only')
    for args in [['-j', str(doc['jobs'])], ['test'], ['install_sw']]:
        step(sslsrc, [tools['make'], *args], 'Zero original exit, complete logs and whole descendant/stream quiescence')
    step(out, [ssl / 'bin/openssl', 'version', '-a'], 'Actual OpenSSL3.5.9')
    step(out / 'build', [pgsrc / 'configure', '--prefix=' + str(pg), '--without-readline', '--without-icu',
                        '--with-ssl=openssl', '--with-uuid=e2fs'], 'New coherent prefix; use selected OpenSSL/UUID/SDK flags')
    for args in [['-j', str(doc['jobs'])], ['check'], ['install']]:
        step(out / 'build', [tools['make'], *args], 'Zero original exit and original controller quiescence')
    for ext in ['pgcrypto', 'uuid-ossp']:
        for args in [['-j', str(doc['jobs'])], ['install']]:
            step(out / 'build', [tools['make'], '-C', 'contrib/' + ext, *args], 'Actual native module/control/SQL installed')
    pgconfig = pg / 'bin/pg_config'
    for arg in ['--version', '--configure', '--bindir', '--sharedir', '--pkglibdir']:
        step(out, [pgconfig, arg], 'Version17.11 and actual directories inside new prefix; preserve readback')
    step(graph, [tools['cargo'], 'metadata', '--frozen', '--format-version', '1', '--manifest-path', graph / 'Cargo.toml',
                 '--no-default-features', '--features', 'pg17'], 'Cargo.toml/lock unchanged before/after, including failure')
    for args in [['init', '--pg17', str(pgconfig), '--no-run'],
                 ['install', '--release', '--pg-config', str(pgconfig), '--manifest-path', str(graph / 'Cargo.toml'),
                  '--no-default-features', '--features', 'pg17']]:
        step(graph, pgrx_argv(doc['tools']['cargo-pgrx'], args), 'Exact pinned direct plugin; frozen offline closure; unchanged Cargo preimages')
    return {'kind': 'FIXED_SOURCE_BUILD_PLAN_NOT_EXECUTABLE', 'controller_binding': 'NO_CURRENT_BINDING_VERIFIED',
            'native_execution_supported': False, 'artifact_ready': False, 'steps': steps,
            'environment': closed_environment(out, tools, closures, doc['libclang_dir']),
            'pending_execution_integration': ['Runtime owner actual controller identity/lease/start/custody/cleanup receipt',
                'One invocation deadline including preflight, safe extraction and cache-copy, with finite cleanup reserve',
                'Actual linkage readbacks, complete existing postgres-tools/v1 inventory and independent manifest hash',
                'Existing pomar postgres run actual pinned original smoke, complete logs and positive cleanup receipt',
                'Unchanged source/lock/input/prefix inventories and separate unsigned build provenance'],
            'not_a_receipt': True}


def require_build_binding():
    # No fabricated interface/token or caller-supplied command can bypass this.
    raise ValueError('NO_CURRENT_BINDING_VERIFIED: Runtime controller/lease/start/cleanup contract absent; build refused before output or native child')


def main():
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--build', action='store_true')
    mode.add_argument('--plan', action='store_true')
    p.add_argument('--input', required=True)
    p.add_argument('--input-sha256', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--output-parent', required=True)
    a = p.parse_args()
    CLOCK.check()
    if a.build:
        require_build_binding()
    # No output/prefix effects in either check or plan mode.
    input_path = canonical(a.input)
    require(digest(a.input_sha256), 'independent input digest required')
    raw = read_pin({'path': str(input_path), 'sha256': a.input_sha256, 'bytes': input_path.stat().st_size}, 4 << 20)
    doc = decode(raw)
    members, roots, closures, smoke = validate(doc)
    parent = custody(canonical(a.output_parent), private=True)
    out = canonical(a.output)
    require(doc['output'] == str(out) and doc['output_parent'] == str(parent), 'reviewed output binding differs')
    require(out.parent == parent and not out.exists() and not out.is_symlink(), 'unadopted/colliding output')
    for root in [*closures.values(), input_path.parent]:
        require(not out.is_relative_to(root) and not root.is_relative_to(out), 'output/input paths overlap')
    if a.check:
        print(json.dumps({'kind': 'OFFLINE_INPUT_CHECK_ONLY', 'input_sha256': a.input_sha256,
                          'build_executed': False, 'artifact_ready': False}))
        return
    print(json.dumps(fixed_plan(doc, out, roots, closures), sort_keys=True))


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, terminate)
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, tarfile.TarError) as e:
        print('extension recipe refused: ' + str(e), file=sys.stderr)
        sys.exit(1)
POMAR_PYTHON
