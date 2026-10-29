"""Fixed ordinary source caller; qualified 83a9/b899 controls unchanged."""
import os, sys, time, json, hashlib, subprocess, signal, threading, tarfile
from pathlib import Path

D=Path(sys.argv[1]);T0=float(sys.argv[2]);E=T0+300
assert time.time()<E and os.getuid()==503 and D==D.resolve()
timer=threading.Timer(E-time.time(),lambda:os._exit(124));timer.daemon=True;timer.start()
assert D.stat().st_uid==503 and D.stat().st_mode&0o777==0o700
packet=json.loads((D/'packet.json').read_text())
assert packet['T0']==T0 and packet['E']==E
for name,pin in packet['files'].items():
    b=(D/name).read_bytes();assert len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256']
for name in ['launcher.pid','launcher.pgid','launcher.done','launcher-receipt.json','watchdog.fired','watchdog.ready']:
    assert not (D/name).exists()
assert os.getloadavg()[0]<12 and os.statvfs(D).f_bavail*os.statvfs(D).f_frsize>=20*1024**3
assert time.time()<E-30
for name in ['home','tmp']: (D/name).mkdir(mode=0o700)
env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(D/'home'),'USER':'rodbot','LOGNAME':'rodbot','TMPDIR':str(D/'tmp'),'TASK_EXEC_ROOT':str(D),'LC_ALL':'C','TZ':'UTC','GOTOOLCHAIN':'local','GOPROXY':'off','GOSUMDB':'off','GOMAXPROCS':'2','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_NOSYSTEM':'1','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/bin/false','GIT_SSH_COMMAND':'/usr/bin/false','GIT_CONFIG_COUNT':'2','GIT_CONFIG_KEY_0':'protocol.allow','GIT_CONFIG_VALUE_0':'never','GIT_CONFIG_KEY_1':'credential.helper','GIT_CONFIG_VALUE_1':''}
PY='/usr/bin/python3'
pair=Path('/Users/rodbot/zeo/seat-gates/zeo-rt/app-composed-c44c49a5-Q1-20261027')
for name,expected in [('gate-bounded.py','83a9b8340ee3714e3786dc17d85e6e44e0767ddd91649d11879733c2d86c6a2d'),('gate-watchdog.py','b8992a54f633d7245356129562d2be0ef01e67ca6d1c725ad3b79cdcab837d8e')]:
    assert hashlib.sha256((pair/name).read_bytes()).hexdigest()==expected
assert hashlib.sha256(Path(PY).read_bytes()).hexdigest()=='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
watchArgv=[PY,'-I',str(pair/'gate-watchdog.py'),str(D),str(E)]
launchArgv=[PY,'-I',str(pair/'gate-bounded.py'),str(D),'--deadline-epoch',str(E),'--grace','10','--reserve','20','--rss-mib','1024','--disk-mib','256','--log-bytes','4194304','--poll','.25','--watchdog-ready-timeout','5','--cmd',PY,'-I',str(D/'format-phase.py'),str(D),str(E)]
(D/'original.json').write_text(json.dumps({'T0':T0,'E':E,'watchdogArgv':watchArgv,'launcherArgv':launchArgv,'environment':env,'selection':packet['selection'],'scope':'Source format only, no native driver or source test','setsidLimit':'Standard owned process-group monitor does not cover escaped setsid descendants'},indent=2)+'\n')
watch=subprocess.Popen(watchArgv,env=env,cwd=D,stdout=(D/'watchdog.out').open('xb'),stderr=subprocess.STDOUT,start_new_session=True)
launch=subprocess.Popen(launchArgv,env=env,cwd=D,stdout=(D/'launcher-control.out').open('xb'),stderr=subprocess.STDOUT,start_new_session=True)
(D/'controller-binding.json').write_text(json.dumps({'watchdogPid':watch.pid,'launcherPid':launch.pid,'T0':T0,'E':E})+'\n')
rc=launch.wait(timeout=max(.1,E-time.time()));wr=watch.wait(timeout=max(.1,E-time.time()))
assert time.time()<E
receipt=json.loads((D/'launcher-receipt.json').read_text())
success=rc==0 and wr==0 and receipt['final_exit']==0 and receipt['drain']=='clean' and receipt['cleanup']=='tmp removed' and receipt['archive']=='written' and not receipt['past_deadline'] and (D/'launcher.done').read_text().strip()=='0' and not(D/'watchdog.fired').exists()
names=['original.json','controller-binding.json','format-result.json','launcher-receipt.json','launcher.done','watchdog.ready','watchdog.out','launcher-control.out','gate.log','evidence.tgz']
rows=[]
for name in names:
    if(D/name).is_file():
        b=(D/name).read_bytes();rows.append({'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
record={'schema':'dtac-source-format-return-v1','success':success,'launcherExit':rc,'watchdogExit':wr,'receipt':receipt,'T0':T0,'E':E,'finished':time.time(),'files':rows,'nativeExecuted':False}
(D/'return-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
assert time.time()<E
with tarfile.open(D/'format-return.tar','w')as t:
    for name in ['return-manifest.json',*[r['name']for r in rows]]:t.add(D/name,arcname=name)
assert time.time()<E
print(json.dumps({'success':success,'returnBytes':(D/'format-return.tar').stat().st_size,'returnSHA256':hashlib.sha256((D/'format-return.tar').read_bytes()).hexdigest(),'finished':time.time(),'E':E}),flush=True)
raise SystemExit(0 if success else rc or wr or 1)
