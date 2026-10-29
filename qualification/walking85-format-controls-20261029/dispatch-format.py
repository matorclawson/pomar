"""Fixed source-only operator ingress/return, following App dispatch-original.
Candidate formatting stays on ENG UID503 under unchanged standard83a9/b899.
"""
import os,sys,time,threading,signal
M0=time.monotonic();T0=time.time();M_END=M0+300;E=T0+300
TRANSPORT_MARGIN=10.0;RETURN_RESERVE=20.0
def remaining():return M_END-time.monotonic()
if os.getpgrp()!=os.getpid():os.setpgid(0,0)
assert os.getpgrp()==os.getpid()
expiry=threading.Timer(remaining(),lambda:os.killpg(os.getpid(),signal.SIGKILL));expiry.daemon=True;expiry.start()
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
assert set(manifest['files'])=={'invoke-format.py','format-phase.py','sealed-source-data.json','source.bundle'}
assert manifest['head']==selection['source_head']
G='/Users/rodbot/zeo/seat-gates/dt-animated-comics-maintainer/'+key
DEST=HERE/'format-originals'/key;DEST.parent.mkdir(exist_ok=True);DEST.mkdir(mode=0o700)
state={'selection':selection,'T0':T0,'E_display_only':E,'monotonic_origin':M0,'monotonic_end':M_END,'G':G,'state':'UNKNOWN_NOT_STARTED','head':selection['source_head'],'nativeExecuted':False}
def save():
    assert remaining()>0
    p=DEST/'dispatch-receipt.json';raw=(json.dumps(state,indent=2)+'\n').encode()
    with (DEST/'dispatch.pending').open('wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    assert remaining()>0;os.replace(DEST/'dispatch.pending',p)
    directory=os.open(DEST,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)
    assert p.read_bytes()==raw and remaining()>0
def run(argv,label,cap=60,allow=False,input_path=None):
    assert remaining()>0
    with (DEST/(label+'.out')).open('xb')as out,(DEST/(label+'.err')).open('xb')as err:
        stream=Path(input_path).open('rb') if input_path is not None else subprocess.DEVNULL
        try:p=subprocess.run(argv,stdin=stream,stdout=out,stderr=err,timeout=max(.1,min(cap,remaining())))
        finally:
            if input_path is not None:stream.close()
    state[label+'_exit']=p.returncode;save()
    if p.returncode and not allow:raise RuntimeError(label+' exit '+str(p.returncode))
    return p
SSH=['ssh','-oBatchMode=yes','-oConnectTimeout=10','-oServerAliveInterval=5','-oServerAliveCountMax=2','-oForwardAgent=no','-oForwardX11=no','-oClearAllForwardings=yes','-oRequestTTY=no','rodbot@100.125.183.112']
def remote(code,label,cap=30,bootstrap_duration=None,input_path=None):
    # Only durations cross hosts. After the first acknowledged lease, every
    # remote helper consumes the SAME persisted ENG monotonic end, never a
    # newly calculated wall-derived duration.
    if bootstrap_duration is not None:
        budget='M_ORIGIN=time.monotonic();M_END=M_ORIGIN+'+repr(bootstrap_duration)+'\n'
    else:
        budget='M_ORIGIN='+repr(lease['mono_origin'])+';M_END='+repr(lease['mono_end'])+'\nassert time.monotonic()>=M_ORIGIN\n'
    fixed='import os,time,threading,signal\n'+budget+'if time.monotonic()>=M_END:os._exit(124)\nif os.getpgrp()!=os.getpid():os.setpgid(0,0)\nt=threading.Timer(M_END-time.monotonic(),lambda:os.killpg(os.getpgrp(),signal.SIGKILL));t.daemon=True;t.start()\nimport base64;exec(base64.b64decode('+repr(base64.b64encode(code.encode()).decode())+'))'
    return run(SSH+[shlex.join(['/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','/usr/bin/python3','-I','-S','-c',fixed])],label,cap,input_path=input_path)
def receive_file(name,local,pin):
    # Fixed data-only stdin receiver. No SFTP/SSHD file writer is treated as
    # being covered by our lease: this actual receiver owns a monotonic fence.
    assert name in {'invoke-format.py','format-phase.py','sealed-source-data.json','source.bundle','packet.json'}
    code='G='+repr(G)+'\nNAME='+repr(name)+'\nPIN='+repr(pin)+'\n'+'''import os,sys,hashlib,stat
from pathlib import Path
assert os.getuid()==503 and time.monotonic()<M_END-35
p=Path(G)/NAME;assert not p.exists() and not p.is_symlink()
assert 0<PIN['bytes']<=2*1024**2
raw=sys.stdin.buffer.read(PIN['bytes']+1)
assert len(raw)==PIN['bytes'] and hashlib.sha256(raw).hexdigest()==PIN['sha256']
with p.open('xb')as stream:
 stream.write(raw);stream.flush();os.fsync(stream.fileno())
p.chmod(0o600);st=p.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid==503 and st.st_nlink==1
assert time.monotonic()<M_END-35
print('EXACT_FIXED_INPUT_RECEIVED',flush=True)
'''
    remote(code,'ingress-'+name,60,input_path=local)
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
save()
try:
    state['entry_fit']='UNAVAILABLE_MAINTAINED_OPERATION_NOT_SUPPLIED'
    state['state']='NO_START_ENTRY_FIT_BINDING_MISSING';save()
    print(json.dumps(state),flush=True)
    os._exit(119)
    # Entry-FIT remains OPEN. The following exact fixed receiver/workflow is
    # not reachable until its maintained resource/exclusion operation is
    # actually supplied, implemented and independently reviewed. No bool/ref
    # in a selection can bypass this missing-input fence.
    for name,pin in manifest['files'].items():
        p=HERE/pin['local_name'];assert p.stat().st_size==pin['bytes'] and digest(p)==pin['sha256']
    # First lease starts on ENG before its acknowledgement. Accept it only
    # when the complete handshake RTT is <= the deducted transport margin.
    # Therefore startENG <= sendOutside+margin and endENG <= outsideEnd-20.
    sent_mono=time.monotonic();duration=remaining()-TRANSPORT_MARGIN-RETURN_RESERVE
    assert duration>60
    code='G='+repr(G)+'\nDURATION='+repr(duration)+'\n'+'''import os,hashlib,json
from pathlib import Path
p=Path(G);parent=p.parent
assert os.getuid()==503 and parent==parent.resolve() and parent.stat().st_uid==503
assert not p.exists() and not p.is_symlink()
assert os.getloadavg()[0]<12 and os.statvfs(parent).f_bavail*os.statvfs(parent).f_frsize>=20*1024**3
assert hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest()=='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
assert time.monotonic()<M_END-35
p.mkdir(mode=0o700)
lease={'mono_origin':M_ORIGIN,'mono_end':M_END,'duration_seconds':DURATION,'clock':'time.monotonic','transport_margin_seconds':10.0,'outside_return_reserve_seconds':20.0}
assert time.get_clock_info('monotonic').monotonic and not time.get_clock_info('monotonic').adjustable
(p/'native-budget.json').write_text(json.dumps(lease,indent=2)+'\\n')
print(json.dumps(lease),flush=True)
'''
    remote(code,'fresh-source-guard',TRANSPORT_MARGIN,bootstrap_duration=duration)
    handshake_rtt=time.monotonic()-sent_mono
    assert handshake_rtt<=TRANSPORT_MARGIN, 'uncertain transport; no candidate admission'
    lease=json.loads((DEST/'fresh-source-guard.out').read_text())
    assert lease['duration_seconds']==duration and abs(lease['mono_end']-lease['mono_origin']-duration)<.001
    state['native_budget']=lease;state['lease_handshake_rtt']=handshake_rtt;state['deducted_transport_margin']=TRANSPORT_MARGIN;save()
    packet={'selection':selection,'outside_t0':T0,'native_budget':lease,'files':{name:{'bytes':r['bytes'],'sha256':r['sha256']}for name,r in manifest['files'].items()}}
    packetRaw=(json.dumps(packet,indent=2)+'\n').encode();(DEST/'packet.json').write_bytes(packetRaw)
    for name,pin in manifest['files'].items():receive_file(name,HERE/pin['local_name'],{'bytes':pin['bytes'],'sha256':pin['sha256']})
    receive_file('packet.json',DEST/'packet.json',{'bytes':len(packetRaw),'sha256':hashlib.sha256(packetRaw).hexdigest()})
    rows=packet['files'];rows['packet.json']={'bytes':len(packetRaw),'sha256':hashlib.sha256(packetRaw).hexdigest()}
    code='G='+repr(G)+'\nROWS='+repr(rows)+'\n'+'''import os,hashlib,stat
from pathlib import Path
assert os.getuid()==503 and time.monotonic()<M_END-35
for name,pin in ROWS.items():
 p=Path(G)/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==503 and s.st_nlink==1
 b=p.read_bytes();assert len(b)==pin['bytes'] and hashlib.sha256(b).hexdigest()==pin['sha256'];p.chmod(0o600)
print('ALL_EXACT_SOURCE_AND_PHASE_BYTES_RECEIVED')
'''
    remote(code,'sealed-input-readback')
    assert remaining()>RETURN_RESERVE+5
    state['state']='STANDARD_SOURCE_FORMAT_ATTEMPT';save();print(json.dumps(state),flush=True)
    argv=['/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin','/usr/bin/nice','-n','10','/usr/bin/python3','-I',G+'/invoke-format.py',G,str(T0),str(lease['mono_end'])]
    original=run(SSH+[shlex.join(argv)],'standard-format',max(.1,remaining()-RETURN_RESERVE),True)
    # Fixed return artifact is constructed by the source caller after pair drain.
    code='G='+repr(G)+'\n'+'''import hashlib,json
from pathlib import Path
p=Path(G)/'format-return.tar';b=p.read_bytes();assert len(b)<=8*1024**2
print(json.dumps({'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}))
'''
    remote(code,'return-original-pin',20)
    returned=json.loads((DEST/'return-original-pin.out').read_text())
    code='G='+repr(G)+'\n'+'''import sys
from pathlib import Path
b=(Path(G)/'format-return.tar').read_bytes();assert len(b)<=8*1024**2
assert time.monotonic()<M_END
sys.stdout.buffer.write(b);sys.stdout.buffer.flush()
'''
    remote(code,'return-source-evidence',30)
    archive=DEST/'return-source-evidence.out';assert archive.stat().st_size==returned['bytes'] and digest(archive)==returned['sha256']
    allowed={'return-manifest.json','original.json','native-budget.json','controller-binding.json','work-identity.json','format-result.json','launcher-receipt.json','launcher.done','watchdog.ready','watchdog.out','launcher-control.out','gate.log','evidence.tgz'}
    with tarfile.open(archive,'r')as t:
        members=t.getmembers();assert len(members)<=len(allowed) and len({m.name for m in members})==len(members)
        assert sum(m.size for m in members)<=8*1024**2
        for m in members:
            assert m.isfile() and m.name in allowed and remaining()>0
            (DEST/m.name).write_bytes(t.extractfile(m).read())
    receipt=json.loads((DEST/'return-manifest.json').read_text())
    assert receipt['outside_t0']==T0 and receipt['native_budget']==lease
    assert receipt['finishedMonotonic']<lease['mono_end']-5
    for row in receipt['files']:
        p=DEST/row['name'];assert row['name'] in allowed and p.stat().st_size==row['bytes'] and digest(p)==row['sha256']
    success=original.returncode==0 and receipt['success'] and (DEST/'launcher.done').read_text().strip()=='0'
    if success:
        result=json.loads((DEST/'format-result.json').read_text());assert result['head']==state['head'] and len(result['files'])==2
        for row in result['files']:
            b=row['full_utf8'].encode();assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
    state.update(state='SOURCE_FORMAT_RETURNED_VERIFIED'if success else'SOURCE_FORMAT_FAILED_OR_UNKNOWN_RETAIN_ORIGINAL',success=success,returned=returned,finished=time.time(),finishedMonotonic=time.monotonic())
    save();print(json.dumps(state),flush=True);os._exit(0 if success and remaining()>0 else 1)
except BaseException as error:
    state.update(state='FAILED_OR_UNKNOWN_RETAIN_ORIGINAL_NO_RETRY',reason=repr(error),finished=time.time(),finishedMonotonic=time.monotonic())
    if remaining()>0:save();print(json.dumps(state),flush=True)
    raise
