#!/bin/sh
# sow: pomar-guest-SOW-01 rev4
# Read-only metadata, never a guest launcher or an acceptance/reset test.
exec /usr/bin/python3 -I -S - "$0" "$@" <<'PY'
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time

LIMIT = 16384
HASH_LIMIT = 64 * 1024 * 1024
REFS = ("source_head", "engine_ref", "profile_ref", "original_job_ref",
        "guest_instance_ref", "image_ref_sha256", "kernel_ref_sha256",
        "init_ref_sha256", "baseline_generation", "reset_generation",
        "owned_overlay_ref")
LATER = ("systemd_pid1_unit_mainpid_settlement", "timeout_term_kill_reap",
         "proc_identity_so_peercred_pidfd", "root_fixed_fixture_custody_admission",
         "fresh_baseline_reset_overlay_identity",
         "owned_stop_drain_reap_cleanup_evidence_survival_base_unchanged")


def cell(state, value=None, reason=None, **details):
    out = {"state": state, **details}
    if state == "OBSERVED":
        out["value"] = value
    if reason:
        out["reason"] = reason
    return out


def unknown(reason):
    return cell("UNKNOWN", reason=reason)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def regular_bytes(path, limit):
    # No FIFO/device blocking and no symlink substitution for JSON inputs.
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not a regular file")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input limit exceeded")
    return data


def load_json(path):
    data = regular_bytes(path, 65536)
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out
    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value, hashlib.sha256(data).hexdigest()


def safe_claim(value):
    # Only the reference allowlist is retained, never the supplied object/env.
    if value is None:
        return unknown("UNBOUND")
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9:._/+@=-]{1,256}", value):
        return cell("REFUSED", reason="INVALID_REFERENCE")
    return cell("OBSERVED", value, provenance="UNVERIFIED_OWNER_INPUT_CLAIM")


class Probe:
    def __init__(self, fixture):
        self.root = pathlib.Path(fixture).resolve() if fixture else None
        self.scope = "SYNTHETIC_FIXTURE_NOT_GUEST" if fixture else "LOCAL_NAMESPACE_NOT_AUTHENTICATED_GUEST"

    def path(self, name):
        if self.root is None:
            return pathlib.Path(name)
        path = self.root / name.lstrip("/")
        # Fixture symlinks must never cause a read outside the synthetic tree.
        path.resolve().relative_to(self.root)
        return path

    def read(self, name):
        try:
            fd = os.open(str(self.path(name).resolve()), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    return cell("REFUSED", reason="NON_REGULAR_READ_TARGET")
                data = stream.read(LIMIT + 1)
            return cell("OBSERVED", data[:LIMIT].decode("utf-8", "replace"),
                        scope=self.scope, truncated=len(data) > LIMIT,
                        captured_sha256=hashlib.sha256(data[:LIMIT]).hexdigest(),
                        capture_limit_bytes=LIMIT)
        except PermissionError:
            return cell("PERMISSION_DENIED", reason="READ_DENIED", scope=self.scope)
        except FileNotFoundError:
            return unknown("PATH_UNAVAILABLE")
        except (OSError, ValueError):
            return unknown("READ_OR_FIXTURE_BOUNDARY_FAILED")

    def link(self, name):
        try:
            return cell("OBSERVED", os.readlink(str(self.path(name)))[:4096], scope=self.scope)
        except PermissionError:
            return cell("PERMISSION_DENIED", reason="READLINK_DENIED")
        except (OSError, ValueError):
            return unknown("LINK_UNAVAILABLE")

    def digest(self, name):
        try:
            path = self.path(name)
            fd = os.open(str(path.resolve()), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    return cell("REFUSED", reason="NON_REGULAR_HASH_TARGET")
                h = hashlib.sha256()
                count = 0
                while True:
                    data = stream.read(min(65536, HASH_LIMIT + 1 - count))
                    if not data:
                        break
                    count += len(data)
                    if count > HASH_LIMIT:
                        return unknown("HASH_LIMIT_EXCEEDED")
                    h.update(data)
                after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return unknown("HASH_TARGET_CHANGED")
            return cell("OBSERVED", h.hexdigest(), bytes=count, scope=self.scope)
        except PermissionError:
            return cell("PERMISSION_DENIED", reason="HASH_DENIED")
        except (OSError, ValueError):
            return unknown("HASH_TARGET_UNAVAILABLE")


def filtered_lines(observation, prefixes):
    if observation["state"] != "OBSERVED" or not prefixes:
        return observation
    return {**observation, "value": "\n".join(line for line in observation["value"].splitlines()
                                              if line.startswith(prefixes))}


def version_command(path, args):
    # Fixed, version-only commands. Never execute paths supplied by owner JSON.
    env = {"PATH": "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/",
           "LANG": "C", "GOTOOLCHAIN": "local", "PYTHONNOUSERSITE": "1"}
    start = time.monotonic()
    child = subprocess.Popen([path] + args, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    reason = None
    selector = selectors.DefaultSelector()
    try:
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() - start > 2:
                reason = "VERSION_TIMEOUT"
                break
            for key, _ in selector.select(0.05):
                part = os.read(key.fd, min(4096, LIMIT + 1 - len(data)))
                if not part:
                    selector.unregister(key.fileobj)
                else:
                    data.extend(part)
                    if len(data) > LIMIT:
                        reason = "VERSION_OUTPUT_LIMIT"
                        break
            if reason:
                break
        if reason:
            child.kill()  # Only this version-probe child; never a guest/reset act.
        try:
            code = child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            code = child.wait(timeout=2)
            reason = "VERSION_TIMEOUT"
    finally:
        selector.close()
        child.stdout.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
    if reason or code != 0:
        return cell("UNKNOWN", reason=reason or "VERSION_NONZERO", exit=code,
                    truncated=len(data) > LIMIT,
                    captured_sha256=hashlib.sha256(data[:LIMIT]).hexdigest())
    return cell("OBSERVED", bytes(data).decode("utf-8", "replace"), exit=code,
                truncated=False, captured_sha256=hashlib.sha256(data).hexdigest())


def tool(probe, name, expected, args, pattern):
    if probe.root is not None:
        # No fixture executable is run. Its data remains explicitly synthetic.
        version = probe.read("/tools/" + name + ".version")
        return {"version": version,
                "binary_sha256": probe.digest("/tools/" + name + ".binary"),
                "closure": unknown("NO_ADOPTED_OWNER_VERIFICATION"),
                "expected": expected,
                "version_matches": bool(re.search(pattern, version["value"])) if version["state"] == "OBSERVED" else None,
                "qualification": "NOT_AUTHENTICATED"}
    path = shutil.which(name, path="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin")
    if not path:
        return {"version": unknown("TOOL_UNAVAILABLE"), "expected": expected,
                "closure": unknown("NO_ADOPTED_OWNER_VERIFICATION")}
    digest = probe.digest(path)
    try:
        version = version_command(path, args)
    except (OSError, subprocess.SubprocessError):
        version = unknown("VERSION_PROBE_FAILED")
    after = probe.digest(path)
    if digest != after:
        digest = unknown("BINARY_CHANGED_DURING_VERSION_PROBE")
    match = (bool(re.search(pattern, version["value"]))
             if version["state"] == "OBSERVED" else None)
    return {"path": path, "binary_sha256": digest, "version": version,
            "expected": expected, "version_matches": match,
            "closure": unknown("NO_ADOPTED_OWNER_VERIFICATION"),
            "qualification": "NOT_AUTHENTICATED"}


def collect(probe):
    status = filtered_lines(probe.read("/proc/1/status"), ("Name:", "Pid:", "NSpid:"))
    nspid = filtered_lines(status, ("NSpid:",))
    if nspid["state"] == "OBSERVED" and not nspid["value"]:
        nspid = cell("UNSUPPORTED", reason="NSPID_FIELD_UNAVAILABLE")
    cgroup = {"filesystem_type": unknown("MOUNT_NOT_IDENTIFIED"),
              "version": unknown("CGROUP_VERSION_UNAVAILABLE"),
              "self_membership": probe.read("/proc/self/cgroup"),
              "pid1_membership": probe.read("/proc/1/cgroup"),
              "mountinfo": filtered_lines(probe.read("/proc/self/mountinfo"), ())}
    mountinfo = cgroup["mountinfo"]
    # Mountinfo is public kernel metadata, not an environment/private buffer.
    if mountinfo["state"] == "OBSERVED":
        lines = [line for line in mountinfo["value"].splitlines()
                 if " - cgroup2 " in line or " - cgroup " in line]
        mountinfo["value"] = "\n".join(lines)
        types = sorted({line.split(" - ", 1)[1].split()[0] for line in lines})
        if types:
            cgroup["filesystem_type"] = cell("OBSERVED", types, scope=probe.scope)
            cgroup["version"] = cell("OBSERVED", "v2" if types == ["cgroup2"] else "v1_or_hybrid", scope=probe.scope)
    # Never mistake the hierarchy root for this process's delegated cgroup.
    membership = cgroup["self_membership"]
    group = None
    if membership["state"] == "OBSERVED" and not membership.get("truncated"):
        rows = [line[3:] for line in membership["value"].splitlines() if line.startswith("0::")]
        if len(rows) == 1 and rows[0].startswith("/") and ".." not in pathlib.PurePosixPath(rows[0]).parts:
            group = rows[0]
    root_is_standard = False
    if mountinfo["state"] == "OBSERVED" and not mountinfo.get("truncated"):
        root_is_standard = any(len(line.split()) > 6 and line.split()[3:5] == ["/", "/sys/fs/cgroup"]
                               and " - cgroup2 " in line for line in mountinfo["value"].splitlines())
    for name in ("cgroup.controllers", "cpu.max", "memory.max", "pids.max", "memory.current", "pids.current"):
        cgroup[name] = probe.read("/sys/fs/cgroup" + group.rstrip("/") + "/" + name) if group is not None and root_is_standard else cell("UNSUPPORTED", reason="NO_UNAMBIGUOUS_STANDARD_V2_MOUNT_AND_MEMBERSHIP")
    return {"platform": {"os_release": probe.read("/etc/os-release"),
                         "arch": probe.read("/platform/arch") if probe.root else cell("OBSERVED", os.uname().machine, scope=probe.scope),
                         "kernel": probe.read("/proc/sys/kernel/osrelease")},
            "pid1": {"proc1_comm": probe.read("/proc/1/comm"), "proc1_status_nspid": status,
                     "nspid": nspid,
                     "proc1_exe_link": probe.link("/proc/1/exe"),
                     "proc1_exe_target_sha256": probe.digest("/proc/1/exe"),
                     "self_pid_namespace_link": probe.link("/proc/self/ns/pid"),
                     "pid1_pid_namespace_link": probe.link("/proc/1/ns/pid")},
            "cgroup": cgroup,
            "tools": {"go": tool(probe, "go", "1.27.x", ["version"], r"\bgo1\.27(?:\.|\s)"),
                      "python": tool(probe, "python3", "3.12.12", ["-I", "-S", "--version"], r"\bPython 3\.12\.12(?:\s|$)"),
                      "make": tool(probe, "make", "4.4.1", ["--version"], r"\bGNU Make 4\.4\.1(?:\s|$)")}}


def main():
    parser = argparse.ArgumentParser(description="Read-only metadata PRECHECK; not guest admission or acceptance")
    def argument_error(_):
        raise ValueError("invalid arguments")
    parser.error = argument_error
    parser.add_argument("--owner-input", help="bounded per-original JSON claims; verification remains external")
    parser.add_argument("--fixture-root", help="synthetic offline data only; never guest evidence")
    args = parser.parse_args(sys.argv[2:])
    started = now()
    probe = Probe(args.fixture_root)
    payload = pathlib.Path(sys.argv[1]).resolve()
    manifest, manifest_sha = load_json(payload.with_name("manifest.json"))
    payload_sha = hashlib.sha256(regular_bytes(payload, 65536)).hexdigest()
    if manifest.get("schema") != "pomar.ubuntu26-input/v1" or manifest.get("role") != "TEMPLATE_NOT_OWNER_ORIGINAL" or manifest.get("payload_sha256") != payload_sha:
        raise ValueError("template or payload mismatch")
    owner, owner_sha = load_json(args.owner_input) if args.owner_input else ({}, None)
    if owner and owner.get("schema") != "pomar.ubuntu26-owner-claims/v1":
        raise ValueError("owner claims schema mismatch")
    bindings = {key: safe_claim(owner.get(key)) for key in REFS}
    bindings["toolchain_closure_refs"] = {name: safe_claim(owner.get("toolchain_closure_refs", {}).get(name))
                                           for name in ("go", "python", "make")}
    times = {key: safe_claim(owner.get(key)) for key in ("T0", "absolute_expiry_E", "clock_origin", "clock_units")}
    report = {"schema": "pomar.ubuntu26-observation/v1", "stage": "METADATA_PRECHECK_ONLY",
              "qualification": "NOT_AUTHENTICATED_NOT_ACCEPTANCE", "scope": probe.scope,
              "identity": {"payload_sha256_observed": payload_sha, "manifest_sha256_observed": manifest_sha,
                           "owner_input_sha256_observed": owner_sha, "template_role": manifest["role"],
                           "owner_verification_state": "UNAVAILABLE_NO_ADOPTED_RECEIVER_IN_PAYLOAD",
                           "binding_claims": bindings, "verified_owner_refs": {}},
              "observations": collect(probe),
              "execution": {"argv": [str(payload)] + sys.argv[2:], "collector_start_utc": started,
                            "collector_end_utc": now(), "collector_clock": "UTC ISO8601; not owner deadline",
                            "owner_original_time_claims": times, "owner_original_time_binding_state": "UNVERIFIED",
                            "clock_comparison": "NOT_PERFORMED", "budget_reset": False,
                            "exit": 0, "refusal_state": None, "cleanup_or_reset_proven": False},
              "later_acceptance": {key: {"state": "NOT_RUN"} for key in LATER}}
    raw = json.dumps(report["observations"], sort_keys=True, separators=(",", ":")).encode()
    def truncated(value):
        if isinstance(value, dict):
            return value.get("truncated") is True or any(truncated(x) for x in value.values())
        if isinstance(value, list):
            return any(truncated(x) for x in value)
        return False
    report["execution"]["truncation"] = truncated(report["observations"])
    report["execution"]["captured_observations_sha256"] = hashlib.sha256(raw).hexdigest()
    report["execution"]["raw_output_sha256"] = {"state": "UNKNOWN", "reason": "WHOLE_STDOUT_DIGEST_MUST_BE_RETAINED_BY_OUTER_RECEIVER"}
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode()) > 262144:
        raise ValueError("report limit exceeded")
    print(encoded)


try:
    main()
except (OSError, ValueError, TypeError, AttributeError, KeyError, json.JSONDecodeError):
    # Never echo an input object, exception message, credential or private data.
    print(json.dumps({"schema": "pomar.ubuntu26-observation/v1", "stage": "METADATA_PRECHECK_ONLY",
                      "qualification": "REFUSED", "refusal_state": "INPUT_OR_PROBE_REFUSED",
                      "later_acceptance": {key: {"state": "NOT_RUN"} for key in LATER}}))
    sys.exit(2)
PY
