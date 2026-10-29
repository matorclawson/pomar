"""Fixed source-only operator ingress/return, following App dispatch-original.
Candidate formatting stays on ENG UID503 under unchanged standard83a9/b899.
"""
import os,sys,time,threading,signal
T0=float(sys.argv[2]);E=T0+300
if time.time()>=E:os._exit(124)
if os.getpgrp()!=os.getpid():os.setpgid(0,0)
assert os.getpgrp()==os.getpid()
expiry=threading.Timer(E-time.time(),lambda:os.killpg(os.getpid(),signal.SIGKILL));expiry.daemon=True;expiry.start()
import json,hashlib,subprocess,shlex,re,base64,tarfile
from pathlib import Path
HERE=Path(__file__).parent
selection=json.loads(Path(sys.argv[1]).read_text())
key=selection['id'];assert re.fullmatch(r'[A-Za-z0-9_-]{1,180}',key)
assert selection['whole_seconds']==300
assert float(selection['entry_from_epoch'])<=T0<float(selection['entry_until_epoch']) and E<=float(selection['max_end'])
assert selection['case']=='DTAC-Pomar87rev43-pure2-source-qualification'
assert selection['source_head']=='fd20fb2f18ea4d04ea035c2a16641b8ff1838d8e'
assert selection['repository']=='zeroemployeeorg/pomar' and selection['repository_exclusion_ref']
manifestRaw=(HERE/'format-packet.json').read_bytes()
assert hashlib.sha256(manifestRaw).hexdigest()==selection['packet_sha256']
manifest=json.loads(manifestRaw)
assert manifest['head']==selection['source_head']
G='/Users/rodbot/zeo/seat-gates/dt-animated-comics-maintainer/'+key
DEST=HERE/'format-originals'/key;DEST.parent.mkdir(exist_ok=True);DEST.mkdir(mode=0o700)
state={'selection':selection,'T0':T0,'E':E,'G':G,'state':'UNKNOWN_NOT_STARTED','head':selection['source_head'],'nativeExecuted':False}
def save():
    assert time.time()<E
    p=DEST/'dispatch-receipt.json';raw=(json.dumps(state,indent=2)+'\n').encode()
    with (DEST/'dispatch.pending').open('wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert time.time()<E;os.replace(DEST/'dispatch.pending',p)
    directory=os.open(DEST,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)
    assert p.read_bytes()==raw and time.time()<E
def run(argv,label,cap=60,allow=False):
    assert time.time()<E
    with (DEST/(label+'.out')).open('xb')as out,(DEST/(label+'.err')).open('xb')as err:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=max(.1,min(cap,E-time.time())))
    state[label+'_exit']=p.returncode;save()
    if p.returncode and not allow:raise RuntimeError(label+' exit '+str(p.returncode))
    return p
SSH=['ssh','-oBatchMode=yes','-oConnectTimeout=10','-oServerAliveInterval=5','-oServerAliveCountMax=2','-oForwardAgent=no','-oForwardX11=no','-oClearAllForwardings=yes','-oRequestTTY=no','rodbot@100.125.183.112']
SCP=['scp','-q','-oBatchMode=yes','-oConnectTimeout=10','-oServerAliveInterval=5','-oServerAliveCountMax=2','-oForwardAgent=no','-oClearAllForwardings=yes']
def remote(code,label,cap=30):
    fixed='import os,time,threading\nE='+repr(E)+'\nif time.time()>=E:os._exit(124)\nt=threading.Timer(E-time.time(),lambda:os._exit(124));t.daemon=True;t.start()\nimport base64;exec(base64.b64decode('+repr(base64.b64encode(code.encode()).decode())+'))'
    return run(SSH+[shlex.join(['/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','/usr/bin/python3','-I','-S','-c',fixed])],label,cap)
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
save()
try:
    for name,pin in manifest['files'].items():
        p=HERE/pin['local_name'];assert p.stat().st_size==pin['bytes'] and digest(p)==pin['sha256']
    code='G='+repr(G)+'\n'+'''import os,hashlib
from pathlib import Path
p=Path(G);parent=p.parent
assert os.getuid()==503 and parent==parent.resolve() and parent.stat().st_uid==503
assert not p.exists() and not p.is_symlink()
assert os.getloadavg()[0]<12 and os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize>=20*1024**3
assert hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest()=='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
assert time.time()<E-30
p.mkdir(mode=0o700)
print('FRESH_PRIVATE_SOURCE_INPUT_DIRECTORY')
'''
    remote(code,'fresh-source-guard')
    packet={'selection':selection,'T0':T0,'E':E,'files':{name:{'bytes':r['bytes'],'sha256':r['sha256']}for name,r in manifest['files'].items()}}
    packetRaw=(json.dumps(packet,indent=2)+'\n').encode();(DEST/'packet.json').write_bytes(packetRaw)
    for name,pin in manifest['files'].items():run(SCP+[str(HERE/pin['local_name']),'rodbot@100.125.183.112:'+G+'/'+name],'ingress-'+name,60)
    run(SCP+[str(DEST/'packet.json'),'rodbot@100.125.183.112:'+G+'/packet.json'],'ingress-packet',30)
    rows=packet['files'];rows['packet.json']={'bytes':len(packetRaw),'sha256':hashlib.sha256(packetRaw).hexdigest()}
    code='G='+repr(G)+'\nROWS='+repr(rows)+'\n'+'''import os,hashlib,stat
from pathlib import Path
assert os.getuid()==503 and time.time()<E-30
for name,pin in ROWS.items():
 p=Path(G)/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==503 and s.st_nlink==1
 b=p.read_bytes();assert len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256'];p.chmod(0o600)
print('ALL_EXACT_SOURCE_AND_PHASE_BYTES_RECEIVED')
'''
    remote(code,'sealed-input-readback')
    state['state']='STANDARD_SOURCE_FORMAT_ATTEMPT';save();print(json.dumps(state),flush=True)
    argv=['/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','/usr/bin/nice','-n','10','/usr/bin/python3','-I',G+'/invoke-format.py',G,str(T0)]
    original=run(SSH+[shlex.join(argv)],'standard-format',max(.1,E-time.time()),True)
    # Fixed return artifact is constructed by the source caller after pair drain.
    code='G='+repr(G)+'\n'+'''import hashlib,json
from pathlib import Path
p=Path(G)/'format-return.tar';b=p.read_bytes();assert len(b)<=8*1024**2
print(json.dumps({'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
'''
    remote(code,'return-original-pin',20)
    returned=json.loads((DEST/'return-original-pin.out').read_text())
    run(SCP+['rodbot@100.125.183.112:'+G+'/format-return.tar',str(DEST/'format-return.tar')],'return-source-evidence',30)
    archive=DEST/'format-return.tar';assert archive.stat().st_size==returned['bytes'] and digest(archive)==returned['sha256']
    allowed={'return-manifest.json','original.json','controller-binding.json','format-result.json','launcher-receipt.json','launcher.done','watchdog.ready','watchdog.out','launcher-control.out','gate.log','evidence.tgz'}
    with tarfile.open(archive,'r')as t:
        members=t.getmembers();assert len(members)<=len(allowed) and len({m.name for m in members})==len(members)
        assert sum(m.size for m in members)<=8*1024**2
        for m in members:
            assert m.isfile() and m.name in allowed and time.time()<E
            (DEST/m.name).write_bytes(t.extractfile(m).read())
    receipt=json.loads((DEST/'return-manifest.json').read_text())
    assert receipt['T0']==T0 and receipt['E']==E
    for row in receipt['files']:
        p=DEST/row['name'];assert row['name'] in allowed and p.stat().st_size==row['bytes'] and digest(p)==row['sha256']
    success=original.returncode==0 and receipt['success'] and (DEST/'launcher.done').read_text().strip()=='0'
    if success:
        result=json.loads((DEST/'format-result.json').read_text());assert result['head']==state['head'] and len(result['files'])==2
        for row in result['files']:
            b=row['full_utf8'].encode();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
    state.update(state='SOURCE_FORMAT_RETURNED_VERIFIED'if success else'SOURCE_FORMAT_FAILED_OR_UNKNOWN_RETAIN_ORIGINAL',success=success,returned=returned,finished=time.time())
    save();print(json.dumps(state),flush=True);os._exit(0 if success and time.time()<E else 1)
except BaseException as error:
    state.update(state='FAILED_OR_UNKNOWN_RETAIN_ORIGINAL_NO_RETRY',reason=repr(error),finished=time.time())
    if time.time()<E:save();print(json.dumps(state),flush=True)
    raise
