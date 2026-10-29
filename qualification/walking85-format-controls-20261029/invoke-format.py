"""One-off monotonic-budget caller; standard 83a9/b899 remain unchanged."""
# Minimal timer/runtime prerequisites only. argv[3] is the existing
# ENG monotonic lease end in BOTH modes, never a Mat clock or fresh duration.
import os, sys, time, signal, threading
M_END = float(sys.argv[3])
_WORK = sys.argv[1] == '--work'
_EARLY_STOP = M_END - (30 if _WORK else 5)
if time.monotonic() >= _EARLY_STOP: os._exit(124)
if os.getpgrp() != os.getpid(): os.setpgid(0, 0)
assert os.getpgrp() == os.getpid()
def _expire_owned_group(): os.killpg(os.getpgrp(), signal.SIGKILL)
_early = threading.Timer(_EARLY_STOP-time.monotonic(), _expire_owned_group)
_early.daemon = True; _early.start()
# Extra imports, argument paths, lease/manifest reads and every child start are
# AFTER the monotonic fence. A blocked json/Path/bootstrap cannot lose it.
import json, hashlib, subprocess, tarfile
from pathlib import Path

# The launcher gives this fixed work guard its own group. Keep the guard alive
# until the fixed phase and its group drain; its timer never uses wall time.
if sys.argv[1] == '--work':
    D=Path(sys.argv[2]); M_END=float(sys.argv[3]); PAIR_E=float(sys.argv[4])
    STOP=M_END-30
    assert os.getuid()==503 and os.getpgrp()==os.getpid() and time.monotonic()<STOP
    def stop_work(): os.killpg(os.getpgrp(),signal.SIGKILL)
    try:
        launcher=int((D/'launcher.pid').read_text())
        assert os.getppid()==launcher
        (D/'work-identity.json').write_text(json.dumps({'pid':os.getpid(),'ppid':launcher,'pgid':os.getpgrp(),'mono_end':M_END})+'\n')
        child=subprocess.Popen(['/usr/bin/python3','-I',str(D/'format-phase.py'),str(D),str(M_END),str(PAIR_E)],cwd=D)
        rc=child.wait(timeout=max(.1,STOP-time.monotonic()))
        probe=subprocess.Popen(['/bin/ps','-ax','-o','pid=,pgid='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        out,err=probe.communicate(timeout=max(.1,min(5,STOP-time.monotonic())))
        rows=[tuple(map(int,l.split()))for l in out.splitlines()if len(l.split())==2 and all(p.isdigit()for p in l.split())]
        assert probe.returncode==0 and any(pid==os.getpid() and pg==os.getpgrp()for pid,pg in rows)
        assert not[pid for pid,pg in rows if pg==os.getpgrp() and pid not in (os.getpid(),probe.pid)],'work group not drained'
        assert time.monotonic()<STOP
        os._exit(rc if 0<=rc<=255 else 1)
    except BaseException:
        # Never let a failed guard exit while its children outlive its timer.
        stop_work()
        raise

D=Path(sys.argv[1]); OUTSIDE_T0=float(sys.argv[2])
assert os.getuid()==503 and D==D.resolve()
# Own this controller group, including both unchanged standard controllers.
# The standard launcher separately owns the work guard's group.
if os.getpgrp()!=os.getpid():os.setpgid(0,0)
assert os.getpgrp()==os.getpid()
lease=json.loads((D/'native-budget.json').read_text());assert float(lease['mono_end'])==M_END
assert time.monotonic()<M_END-35
# This epoch exists only inside ENG for legacy pair compatibility. It is not
# the caller's epoch and is never used to compute/rearm our elapsed budget.
PAIR_E=time.time()+max(0,M_END-time.monotonic())
assert D.stat().st_uid==503 and D.stat().st_mode&0o777==0o700
packet=json.loads((D/'packet.json').read_text())
assert packet['outside_t0']==OUTSIDE_T0 and packet['native_budget']==lease
for name,pin in packet['files'].items():
    b=(D/name).read_bytes();assert len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256']
for name in ['launcher.pid','launcher.pgid','launcher.done','launcher-receipt.json','watchdog.fired','watchdog.ready']:
    assert not(D/name).exists()
assert os.getloadavg()[0]<12 and os.statvfs(D).f_bavail*os.statvfs(D).f_frsize>=20*1024**3
assert time.monotonic()<M_END-35
for name in ['home','tmp']:(D/name).mkdir(mode=0o700)
env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(D/'home'),'USER':'rodbot','LOGNAME':'rodbot','TMPDIR':str(D/'tmp'),'TASK_EXEC_ROOT':str(D),'LC_ALL':'C','TZ':'UTC','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOMAXPROCS':'2','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/bin/false','GIT_SSH_COMMAND':'/usr/bin/false','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.allow','GIT_CONFIG_VALUE_0':'never','GIT_CONFIG_KEY_1':'credential.helper','GIT_CONFIG_VALUE_1':''}
PYTHON='/usr/bin/python3';pair=Path('/Users/rodbot/zeo/seat-gates/zeo-rt/app-composed-c44c49a5-Q1-20261027')
for name,expected in [('gate-bounded.py','83a9b8340ee3714e3786dc17d85e6e44e0767ddd91649d11879733c2d86c6a2d'),('gate-watchdog.py','b8992a54f633d7245356129562d2be0ef01e67ca6d1c725ad3b79cdcab837d8e')]:
    assert hashlib.sha256((pair/name).read_bytes()).hexdigest()==expected
assert hashlib.sha256(Path(PYTHON).read_bytes()).hexdigest()=='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
watchArgv=[PYTHON,'-I',str(pair/'gate-watchdog.py'),str(D),str(PAIR_E)]
launchArgv=[PYTHON,'-I',str(pair/'gate-bounded.py'),str(D),'--deadline-epoch',str(PAIR_E),'--grace','10','--reserve','20','--rss-mib','1024','--disk-mib','256','--log-bytes','4194304','--poll','.25','--watchdog-ready-timeout','5','--cmd',PYTHON,'-I',str(D/'invoke-format.py'),'--work',str(D),str(M_END),str(PAIR_E)]
try:
    (D/'original.json').write_text(json.dumps({'outside_t0':OUTSIDE_T0,'native_budget':lease,'pair_local_epoch':PAIR_E,'watchdogArgv':watchArgv,'launcherArgv':launchArgv,'environment':env,'selection':packet['selection'],'scope':'One-off source format only','setsidLimit':'Standard process-group control does not cover escaped setsid descendants'},indent=2)+'\n')
    # Both controllers inherit this owned group. The monotonic hard fence
    # bounds them even if ENG wall time rolls back and their wall timer slips.
    watch=subprocess.Popen(watchArgv,env=env,cwd=D,stdout=(D/'watchdog.out').open('xb'),stderr=subprocess.STDOUT)
    launch=subprocess.Popen(launchArgv,env=env,cwd=D,stdout=(D/'launcher-control.out').open('xb'),stderr=subprocess.STDOUT)
    (D/'controller-binding.json').write_text(json.dumps({'watchdogPid':watch.pid,'launcherPid':launch.pid,'controllerPgid':os.getpgrp(),'mono_end':M_END,'pair_local_epoch':PAIR_E})+'\n')
    rc=launch.wait(timeout=max(.1,M_END-5-time.monotonic()));wr=watch.wait(timeout=max(.1,M_END-5-time.monotonic()))
    assert time.monotonic()<M_END-5
    receipt=json.loads((D/'launcher-receipt.json').read_text())
    success=rc==0 and wr==0 and receipt['final_exit']==0 and receipt['drain']=='clean' and receipt['cleanup']=='tmp removed' and receipt['archive']=='written' and not receipt['past_deadline'] and(D/'launcher.done').read_text().strip()=='0' and not(D/'watchdog.fired').exists()
    names=['original.json','native-budget.json','entry-owner-receiving.json','entry-native-facts.json','controller-binding.json','work-identity.json','format-result.json','launcher-receipt.json','launcher.done','watchdog.ready','watchdog.out','launcher-control.out','gate.log','evidence.tgz']
    rows=[]
    for name in names:
        if(D/name).is_file():
            b=(D/name).read_bytes();rows.append({'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    record={'schema':'dtac-source-format-return-v2','success':success,'launcherExit':rc,'watchdogExit':wr,'receipt':receipt,'outside_t0':OUTSIDE_T0,'native_budget':lease,'finishedMonotonic':time.monotonic(),'files':rows,'nativeExecuted':False}
    (D/'return-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    assert time.monotonic()<M_END-5
    with tarfile.open(D/'format-return.tar','w')as t:
        for name in ['return-manifest.json',*[r['name']for r in rows]]:t.add(D/name,arcname=name)
    assert time.monotonic()<M_END-5
    print(json.dumps({'success':success,'returnBytes':(D/'format-return.tar').stat().st_size,'returnSHA256':hashlib.sha256((D/'format-return.tar').read_bytes()).hexdigest(),'finishedMonotonic':time.monotonic(),'native_budget':lease}),flush=True)
    os._exit(0 if success else rc or wr or 1)
except BaseException:
    # Controller uncertainty cannot outlive the caller while a daemon timer
    # disappears. Work retains its separate fixed monotonic group fence.
    os.killpg(os.getpgrp(),signal.SIGKILL)
    raise
