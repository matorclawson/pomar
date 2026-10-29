"""Fixed source-only operator ingress/return, following App dispatch-original.
Candidate formatting stays on ENG UID503 under unchanged standard83a9/b899.
Entry receiving below is a SOURCE DRAFT, not an adopted owner protocol.
The explicit draft refusal is retained pending exact-head owner review.
"""
import os,sys,time,threading,signal
M0=time.monotonic();T0=time.time();M_END=M0+300;E=T0+300
TRANSPORT_MARGIN=10.0;RETURN_RESERVE=20.0
def remaining():return M_END-time.monotonic()
if os.getpgrp()!=os.getpid():os.setpgid(0,0)
assert os.getpgrp()==os.getpid()
expiry=threading.Timer(remaining(),lambda:os.killpg(os.getpid(),signal.SIGKILL));expiry.daemon=True;expiry.start()
import json,hashlib,subprocess,shlex,re,base64,tarfile,selectors
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
        out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
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
    assert name in {'invoke-format.py','format-phase.py','sealed-source-data.json','source.bundle','packet.json','entry-owner-receiving.json'}
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

def strict_json(raw):
    # Limit nesting, structural items and bytes BEFORE the recursive decoder
    # allocates containers. JSON validity and duplicate keys are checked below.
    assert isinstance(raw,(str,bytes)) and len(raw)<=2*1024**2
    text=raw.decode('utf-8','strict')if isinstance(raw,bytes)else raw
    depth=0;items=0;quoted=False;escaped=False
    for ch in text:
        if quoted:
            if escaped:escaped=False
            elif ch=='\\':escaped=True
            elif ch=='"':quoted=False
        elif ch=='"':quoted=True
        elif ch in '[{':
            depth+=1;items+=1;assert depth<=24 and items<=32768
        elif ch in ']}':
            depth-=1;assert depth>=0
        elif ch in ',:':
            items+=1;assert items<=32768
    assert depth==0 and not quoted and not escaped
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise ValueError('duplicate owner-data key')
            result[k]=v
        return result
    def constant(value):raise ValueError('nonfinite owner data')
    def integer(token):
        assert len(token)<=20,'oversized integer token'
        return int(token)
    def floating(token):
        assert len(token)<=64,'oversized float token'
        value=float(token);assert -1.7976931348623157e308<=value<=1.7976931348623157e308,'nonfinite float'
        return value
    return json.loads(text,object_pairs_hook=pairs,parse_constant=constant,parse_int=integer,parse_float=floating)

def durable_owner(name,raw):
    assert name in('entry-owner-receiving.json','entry-native-facts.json') and len(raw)<=256*1024
    assert remaining()>0
    tmp=DEST/(name+'.pending');final=DEST/name
    with tmp.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,final)
    directory=os.open(DEST,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)
    assert final.read_bytes()==raw and remaining()>0
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def bounded_child(argv,env,out_cap,err_cap,stop):
    # Child stays in this already-fenced owned group. On any uncertainty the
    # original's exception path kills that SAME group, including descendants.
    assert time.monotonic()<stop<M_END
    child=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    buffers=[bytearray(),bytearray()];caps=[out_cap,err_cap];total=0
    try:
        with selectors.DefaultSelector()as poll:
            for index,pipe in enumerate((child.stdout,child.stderr)):
                os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,index)
            while poll.get_map():
                left=stop-time.monotonic()
                if left<=0:raise TimeoutError('bounded child/pipe drain expired')
                for event,_ in poll.select(min(.1,left)):
                    index=event.data;room=caps[index]-len(buffers[index])
                    try:chunk=os.read(event.fd,min(65536,room+1))
                    except BlockingIOError:continue
                    if not chunk:poll.unregister(event.fileobj);event.fileobj.close();continue
                    if len(chunk)>room or total+len(chunk)>out_cap+err_cap:raise ValueError('output overflow; no truncated document accepted')
                    buffers[index].extend(chunk);total+=len(chunk)
        rc=child.wait(timeout=max(.001,stop-time.monotonic()))
        assert time.monotonic()<stop
        return rc,bytes(buffers[0]),bytes(buffers[1])
    except BaseException:
        # Retain direct-child reap result; descendants are NOT declared drained
        # from this PID alone. The original exception path terminates its group.
        if child.poll()is None:child.kill()
        try:child.wait(timeout=max(.001,min(1,stop-time.monotonic())))
        except subprocess.TimeoutExpired:pass
        raise
    finally:
        for pipe in(child.stdout,child.stderr):
            if not pipe.closed:pipe.close()

def mail_json(args):
    # Existing operator-side Messenger, NOT an ENG service or candidate API.
    # No inbox/other-seat bodies are archived or sent to ENG. Only the actual
    # bound owning reply is retained as this original's accounting input.
    pins={
        '/Users/rodbot/.local/bin/zmsg':'7f67a5b51b68032ab8d009d033ea85e0fa64d9ff2f143ae6ab261f4c4c98e782',
        '/Users/rodbot/.local/libexec/zeo-cutover/6b88b35d605787c7f98f268cabc25a85eb3d85458f2dbeb4f39580f948a6f7f6/zmsg-remote':'6b88b35d605787c7f98f268cabc25a85eb3d85458f2dbeb4f39580f948a6f7f6',
        '/bin/bash':'16303dedab719ddb63efd9dd68092a0da37b397bfd4fcb856d5f1c86c5ee414b',
        '/usr/bin/curl':'b636262803922ee1dd0fbf614818473ffa53c811e44fd3278c2270d3af4759d3',
        '/usr/bin/jq':'b16bc93b2f3c69ce3134f20b796bb72aa3410b10166566ac2ca1bee5e4153ed5',
    }
    for name,want in pins.items():assert digest(name)==want,'operator Messenger tool changed'
    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/Users/rodbot','USER':'rodbot','LOGNAME':'rodbot','ZMAIL_INSTANCE':'dt-animated-comics-maintainer'}
    argv=['/Users/rodbot/.local/bin/zmsg',*args]
    for attempt in range(2):
        assert remaining()>35,'insufficient original budget for owner receiving'
        rc,out,err=bounded_child(argv,env,2*1024**2,65536,min(time.monotonic()+60,M_END-20))
        if rc==0:return strict_json(out)
        # Match the pinned client's curl -f HTTP status diagnostic, not a
        # substring in an arbitrary error or owner body. Unknown shape refuses.
        http503=rc in(5,22) and not out and re.fullmatch(rb'curl: \(22\) The requested URL returned error: 503\r?\n?',err)is not None
        if attempt==0 and http503:
            delay=10+int.from_bytes(os.urandom(2),'big')%31
            assert remaining()>delay+40,'503 cannot consume return reserve'
            time.sleep(delay)
            continue
        raise RuntimeError('NO_START: owner receiving command failed; no alternate identity/port')

def owner_document(message,who,schema):
    # These draft body fields are proposed for this case only. The server
    # envelope above is maintained; this body is NOT an existing owner DTO.
    assert message.get('schema')=='zeomessenger.message/v1' and message.get('from')==who,'not canonical owner receiving'
    body=message.get('body','');assert isinstance(body,str) and len(body.encode())<=65536
    blocks=re.findall(r'```json\n(.*?)\n```',body,re.S)
    assert len(blocks)==1,'one actual owner JSON document required'
    value=strict_json(blocks[0]);assert isinstance(value,dict) and value.get('schema')==schema
    for name,want in [('source_head',selection['source_head']),('source_tree','235b139cf97027715e1a68b84adbbcff4764097f'),('source_base','d115cca68238cef853bb524ba3ae57d3cb1f59a3'),('packet_sha256',selection['packet_sha256']),('code_commit',manifest['codeCommit']),('repository','zeroemployeeorg/pomar'),('host','eng-uk-0006'),('uid',503),('seat','dt-animated-comics-maintainer'),('generation',1),('case',selection['case']),('actor_session','01a15758-8bc9-7d22-a419-267f254eb8b1')]:
        assert type(value.get(name))is type(want) and value[name]==want,'owner document original/source/principal mismatch'
    if who=='zeo-rt-sched':
        for name,want in [('selection_id',key),('outside_original_t0',T0),('entry_from_epoch',selection['entry_from_epoch']),('entry_until_epoch',selection['entry_until_epoch']),('max_end',selection['max_end'])]:
            assert type(value.get(name))is type(want) and value[name]==want,'fresh owner window/original mismatch'
    return value

def entry_owner_receiving():
    # Root policy/adoption is real owning message data, not a caller boolean.
    # The Root message is supplied with the actual new selection AFTER static
    # review; absence is NO_START, not a request for a generic profile family.
    policy_id=selection.get('root_entry_policy_message_id')
    assert isinstance(policy_id,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,240}',policy_id),'NO_START: Root operating policy absent'
    policy_message=mail_json(['show',policy_id,'--json'])
    policy=owner_document(policy_message,'zeo-rt','walking85-entry-native-policy/v1')
    assert policy.get('adoption')=='ADOPTED_FOR_ONE_OFF_SOURCE_FORMAT'
    assert policy.get('memory_recipe')=='vm_stat.free+inactive' and type(policy.get('headroom_bytes'))is int and policy['headroom_bytes']==4*1024**3
    assert policy.get('seat_root')==str(Path(G).parent) and policy.get('native_hostname')=='ENG-UK-0006'
    assert type(policy.get('seat_ceiling_bytes'))is int and 256*1024**2<=policy['seat_ceiling_bytes']<=2**50
    nonce=os.urandom(16).hex();rid='w85-entry-'+nonce
    request={'schema':'walking85-entry-owner-request/v1','nonce':nonce,'selection_id':key,'case':selection['case'],'source_head':selection['source_head'],'packet_sha256':selection['packet_sha256'],'code_commit':manifest['codeCommit'],'repository':'zeroemployeeorg/pomar','host':'eng-uk-0006','uid':503,'this_cap_bytes':1024**3,'headroom_bytes':4*1024**3,'outside_original_t0':T0,'scope':'CURRENT canonical named reservations and held no-wait Pomar exclusion for THIS live entry, not a new allocation or a preexisting snapshot'}
    request.update(source_tree='235b139cf97027715e1a68b84adbbcff4764097f',source_base='d115cca68238cef853bb524ba3ae57d3cb1f59a3',seat='dt-animated-comics-maintainer',generation=1,actor_session='01a15758-8bc9-7d22-a419-267f254eb8b1',entry_from_epoch=selection['entry_from_epoch'],entry_until_epoch=selection['entry_until_epoch'],max_end=selection['max_end'])
    body='sow: pomar-SOW-87 rev43 / DTAC01rev3\nActual bounded entry receiving request; reply once with current canonical input, or UNKNOWN/NO_START. No reservation/slot change requested.\n```json\n'+json.dumps(request,sort_keys=True)+'\n```'
    sent=mail_json(['send','zeo-rt-sched','--id',rid,'--subject','W85 live entry receiving '+nonce,'--body',body,'--json'])
    assert sent.get('schema')=='zeomessenger.send/v1' and not sent.get('error')
    request_id=sent.get('message_id');assert isinstance(request_id,str) and request_id.endswith(rid)
    state['entry_request']={'message_id':request_id,'nonce':nonce,'policy_message':policy_id};save()
    # A single bounded same-original receiving exchange. No re-send, job retry,
    # background poller, timer wake or unrelated mail acknowledgement is made.
    until=min(time.monotonic()+45,M_END-80)
    while time.monotonic()<until:
        box=mail_json(['inbox','--all','--limit','200','--json'])
        assert box.get('schema')=='zeomessenger.inbox/v1' and box.get('seat')=='dt-animated-comics-maintainer'
        matches=[m for m in box.get('messages',[])if m.get('from')=='zeo-rt-sched' and m.get('in_reply_to')==request_id]
        assert len(matches)<=1,'ambiguous canonical reply'
        if matches:
            message=mail_json(['show',matches[0]['id'],'--json'])
            assert message.get('in_reply_to')==request_id
            value=owner_document(message,'zeo-rt-sched','walking85-entry-accounting/v1')
            assert value.get('nonce')==nonce and value.get('selection_id')==key and value.get('status')=='CURRENT_ENTRY_INPUT'
            assert value.get('current_named_reservations_complete')is True and value.get('entry_accounting_held_until_receiving')is True
            generation=value.get('ledger_generation');assert isinstance(generation,str) and 0<len(generation)<=200
            assert isinstance(value.get('owning_ledger_ref'),str) and value['owning_ledger_ref']
            exclusion=value.get('repository_exclusion',{})
            assert exclusion.get('repository')=='zeroemployeeorg/pomar' and exclusion.get('holder_id')==key and exclusion.get('state')=='HELD' and exclusion.get('held_until_terminal')is True
            claims=value.get('named_reservations');assert isinstance(claims,list) and 1<=len(claims)<=256
            ids=set();own=0;total=0
            for row in claims:
                assert isinstance(row,dict) and isinstance(row.get('id'),str) and row['id'] not in ids
                ids.add(row['id']);assert row.get('host')=='eng-uk-0006' and row.get('state')in('PENDING','HELD','RUNNING')
                cap=row.get('cap_bytes');assert type(cap)is int and 0<cap<=2**40
                assert isinstance(row.get('repository'),str) and row['repository']
                if row['id']==key:
                    own+=1;assert cap==1024**3 and row['repository']=='zeroemployeeorg/pomar'
                elif row['repository']=='zeroemployeeorg/pomar':raise RuntimeError('NO_START: another canonical Pomar holder')
                gate=row.get('gate_directory')
                assert gate is None or isinstance(gate,str) and re.fullmatch(r'/Users/(rodbot|zeobuild)/[A-Za-z0-9_./-]{1,600}',gate) and '/..' not in gate
                total+=cap
            assert own==1,'this1GiB must occur exactly once, never double counted'
            # Preserve exact body UTF-8 digests and normalized full server
            # envelopes; never call reserialized envelope bytes raw transport.
            bound={'root_policy':policy,'root_policy_message':policy_id,'scheduler_input':value,'scheduler_message':message['id'],'request_id':request_id,'received_monotonic':time.monotonic(),'required_bytes':total+4*1024**3,'owner_envelopes':{'root':policy_message,'scheduler':message},'body_sha256':{'root':hashlib.sha256(policy_message['body'].encode()).hexdigest(),'scheduler':hashlib.sha256(message['body'].encode()).hexdigest()}}
            raw=(json.dumps(bound,indent=2)+'\n').encode()
            state['entry_owner_pin']=durable_owner('entry-owner-receiving.json',raw);save()
            return bound
        time.sleep(min(2,max(.01,until-time.monotonic())))
    raise RuntimeError('NO_START: bounded canonical owner receiving unavailable')

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
save()
try:
    # Never exercise this proposed exchange merely to qualify its own source.
    # Removing this refusal requires exact-source Root/Scheduler receiving and
    # independent review, followed by a new current selection; no CLI override.
    state.update(state='NO_START_ENTRY_RECEIVING_DRAFT_NOT_ADOPTED',reason='source-only receiving/native-fit implementation awaits owning compatibility and independent review');save()
    print(json.dumps(state),flush=True);os._exit(119)
    owner=entry_owner_receiving()
    assert digest(__file__)==manifest['outside']['sha256'] and Path(__file__).stat().st_size==manifest['outside']['bytes']
    for name,pin in manifest['files'].items():
        p=HERE/pin['local_name'];assert p.stat().st_size==pin['bytes'] and digest(p)==pin['sha256']
    # First lease starts on ENG before its acknowledgement. Accept it only
    # when the complete handshake RTT is <= the deducted transport margin.
    # Therefore startENG <= sendOutside+margin and endENG <= outsideEnd-20.
    sent_mono=time.monotonic();duration=remaining()-TRANSPORT_MARGIN-RETURN_RESERVE
    assert duration>60
    assert time.monotonic()-owner['received_monotonic']<10,'NO_START: owner input aged before native sampling'
    code='G='+repr(G)+'\nDURATION='+repr(duration)+'\nOWNER='+repr(owner)+'\n'+'''import os,hashlib,json,re,subprocess,socket,selectors
from pathlib import Path
p=Path(G);parent=p.parent
assert os.getuid()==503 and parent==parent.resolve() and parent.stat().st_uid==503
assert not p.exists() and not p.is_symlink()
policy=OWNER['root_policy'];account=OWNER['scheduler_input']
assert socket.gethostname()==policy['native_hostname']
assert hashlib.sha256(Path('/usr/bin/python3').read_bytes()).hexdigest()=='34129c71a01a74f7f3b2443521519b2e5447553fa187f5fcafaaf8c42cc192e2'
# Native read-only probes run inside the already armed original ENG guard.
# No candidate command, owner-supplied argv, raw process arguments or files
# from another seat are read. Probe output is bounded before interpretation.
pins={'/usr/bin/vm_stat':'1947d48441639dc229b56ccc26792105a54a34a66c984e921d42c9a37b85b520',
      '/usr/sbin/sysctl':'6622f616b0c573eeede54165af8642df5d755d7e1423543de3ee648203725a3a',
      '/bin/ps':'a06fe087161557f1f8c030672eaedcd90bc6a8e92b8f2d44e07cffedc3349205',
      '/usr/bin/du':'8032033d0795ec38b575b7a9069e495f2584c444fb5e2bc22b6777088456036f'}
for tool,want in pins.items():assert hashlib.sha256(Path(tool).read_bytes()).hexdigest()==want
def probe(argv,limit):
 assert argv[0]in pins and time.monotonic()<M_END-40
 stop=min(time.monotonic()+3,M_END-35)
 child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 data=[bytearray(),bytearray()];caps=[limit,4096];total=0
 try:
  with selectors.DefaultSelector()as poll:
   for index,pipe in enumerate((child.stdout,child.stderr)):
    os.set_blocking(pipe.fileno(),False);poll.register(pipe,selectors.EVENT_READ,index)
   while poll.get_map():
    left=stop-time.monotonic()
    if left<=0:raise TimeoutError('native probe or pipe drain expired')
    for event,_ in poll.select(min(.1,left)):
     index=event.data;room=caps[index]-len(data[index])
     try:chunk=os.read(event.fd,min(65536,room+1))
     except BlockingIOError:continue
     if not chunk:poll.unregister(event.fileobj);event.fileobj.close();continue
     if len(chunk)>room or total+len(chunk)>limit+4096:raise ValueError('native output overflow')
     data[index].extend(chunk);total+=len(chunk)
  assert child.wait(timeout=max(.001,stop-time.monotonic()))==0 and time.monotonic()<stop
  return bytes(data[0]).decode('utf-8','strict')
 except BaseException:
  # This helper's already-owned group includes the probe and descendants.
  # Never leave them behind while an exception destroys the daemon timer.
  if child.poll()is None:child.kill()
  try:child.wait(timeout=max(.001,min(1,M_END-time.monotonic())))
  finally:os.killpg(os.getpgrp(),signal.SIGKILL)
  raise
 finally:
  for pipe in(child.stdout,child.stderr):
   if not pipe.closed:pipe.close()
sample_start=time.monotonic()
vm=probe(['/usr/bin/vm_stat'],65536)
page=re.search(r'page size of ([0-9]+) bytes',vm);assert page
page_size=int(page.group(1));assert page_size in(4096,16384)
def pages(name):
 rows=re.findall(r'^'+re.escape(name)+r':\\s+([0-9]+)\\.\\s*$',vm,re.M);assert len(rows)==1
 return int(rows[0])
reclaimable=(pages('Pages free')+pages('Pages inactive'))*page_size
physical_text=probe(['/usr/sbin/sysctl','-n','hw.memsize'],128).strip();assert physical_text.isdigit()
physical=int(physical_text);assert 0<reclaimable<=physical
required=OWNER['required_bytes'];assert type(required)is int and reclaimable>=required
load=os.getloadavg()[0];assert load<12
fs=os.statvfs(parent);free_bytes=fs.f_bavail*fs.f_frsize;assert free_bytes>=20*1024**3
# Only this seat's existing gate root is measured. No whole-volume walk.
used_text=probe(['/usr/bin/du','-sk',str(parent)],4096).strip()
size,path=used_text.split('\\t',1);assert size.isdigit() and path==str(parent)
seat_bytes=int(size)*1024
assert seat_bytes+256*1024**2<=policy['seat_ceiling_bytes']
# Actual canonical exclusion must cover other principals' repository views;
# its owning implementation is still absent. This census implements ONLY a
# conservative same-UID compiler executable-name refusal, even for accounted
# peer compilers. It does not identify Python gate scripts or prove gate/view
# absence. Never inspect arbitrary peer argv or signal a peer process.
for claim in account['named_reservations']:
 gate=claim.get('gate_directory')
 if claim['id']!=account['selection_id'] and claim['repository']=='zeroemployeeorg/pomar':raise RuntimeError('NO_START: another Pomar claim')
 if gate==G:assert not Path(gate).exists() and not Path(gate).is_symlink()
processes=probe(['/bin/ps','-axo','uid=,pid=,ppid=,pgid=,comm='],1024**2)
conflicts=[]
for line in processes.splitlines():
 fields=line.strip().split(None,4);assert len(fields)==5 and all(x.isdigit()for x in fields[:4])
 uid,pid,ppid,pgid=map(int,fields[:4]);name=Path(fields[4]).name
 if uid==503 and pgid!=os.getpgrp() and name in('go','gofmt','compile','link'):
  conflicts.append({'pid':pid,'ppid':ppid,'pgid':pgid,'name':name})
assert not conflicts,'NO_START: conservative same-UID compiler-name refusal (accounted peers may also refuse)'
sample_end=time.monotonic();assert sample_end-sample_start<=8 and sample_end<M_END-35
facts={'schema':'walking85-entry-native-facts/draft','sample_start':sample_start,'sample_end':sample_end,'uid':os.getuid(),'hostname':socket.gethostname(),'page_size':page_size,'free_inactive_bytes':reclaimable,'physical_bytes':physical,'required_bytes':required,'load1':load,'filesystem_free_bytes':free_bytes,'seat_bytes':seat_bytes,'seat_ceiling_bytes':policy['seat_ceiling_bytes'],'same_uid_compiler_name_conflicts':conflicts,'process_check_scope':'conservative compiler-name refusal only; no gate/private-view exclusion proof','scheduler_message':OWNER['scheduler_message'],'root_policy_message':OWNER['root_policy_message'],'request_id':OWNER['request_id'],'source_head':account['source_head'],'packet_sha256':account['packet_sha256'],'code_commit':account['code_commit'],'selection_id':account['selection_id'],'repository_exclusion':account['repository_exclusion'],'ledger_generation':account['ledger_generation']}
assert time.monotonic()<M_END-35
p.mkdir(mode=0o700)
lease={'mono_origin':M_ORIGIN,'mono_end':M_END,'duration_seconds':DURATION,'clock':'time.monotonic','transport_margin_seconds':10.0,'outside_return_reserve_seconds':20.0}
assert time.get_clock_info('monotonic').monotonic and not time.get_clock_info('monotonic').adjustable
facts_raw=(json.dumps(facts,indent=2)+'\\n').encode()
for name,raw in [('native-budget.json',(json.dumps(lease,indent=2)+'\\n').encode()),('entry-native-facts.json',facts_raw)]:
 with(p/(name+'.pending')).open('xb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 os.replace(p/(name+'.pending'),p/name)
directory=os.open(p,os.O_RDONLY)
try:os.fsync(directory)
finally:os.close(directory)
print(json.dumps({'lease':lease,'entry_native_facts':facts,'entry_native_facts_pin':{'bytes':len(facts_raw),'sha256':hashlib.sha256(facts_raw).hexdigest()}}),flush=True)
'''
    remote(code,'fresh-source-guard',TRANSPORT_MARGIN,bootstrap_duration=duration)
    handshake_rtt=time.monotonic()-sent_mono
    assert handshake_rtt<=TRANSPORT_MARGIN, 'uncertain transport; no candidate admission'
    receiving=strict_json((DEST/'fresh-source-guard.out').read_text());lease=receiving['lease']
    facts=receiving['entry_native_facts']
    assert facts['request_id']==owner['request_id'] and facts['selection_id']==key
    assert facts['source_head']==selection['source_head'] and facts['packet_sha256']==selection['packet_sha256']
    facts_raw=(json.dumps(facts,indent=2)+'\n').encode()
    assert durable_owner('entry-native-facts.json',facts_raw)==receiving['entry_native_facts_pin']
    state['entry_native_facts_pin']=receiving['entry_native_facts_pin']
    state['entry_native_facts']=facts;save()
    assert lease['duration_seconds']==duration and abs(lease['mono_end']-lease['mono_origin']-duration)<.001
    state['native_budget']=lease;state['lease_handshake_rtt']=handshake_rtt;state['deducted_transport_margin']=TRANSPORT_MARGIN;save()
    packet={'selection':selection,'outside_t0':T0,'native_budget':lease,'files':{name:{'bytes':r['bytes'],'sha256':r['sha256']}for name,r in manifest['files'].items()}}
    packet['files']['entry-owner-receiving.json']=state['entry_owner_pin']
    packet['files']['entry-native-facts.json']=state['entry_native_facts_pin']
    packetRaw=(json.dumps(packet,indent=2)+'\n').encode();(DEST/'packet.json').write_bytes(packetRaw)
    for name,pin in manifest['files'].items():receive_file(name,HERE/pin['local_name'],{'bytes':pin['bytes'],'sha256':pin['sha256']})
    receive_file('entry-owner-receiving.json',DEST/'entry-owner-receiving.json',state['entry_owner_pin'])
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
    # Staging can stale the earlier sample. Keep this explicit second refusal
    # until actual Scheduler generation/held-view/charge and fresh native facts
    # are rejoined HERE immediately before candidate admission. A new snapshot
    # or a candidate held bool cannot supply the missing owning operation.
    raise RuntimeError('NO_START: actual admission freshness/owner terminal receiving not implemented; preserve same original and charge')
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
    allowed={'return-manifest.json','original.json','native-budget.json','entry-owner-receiving.json','entry-native-facts.json','controller-binding.json','work-identity.json','format-result.json','launcher-receipt.json','launcher.done','watchdog.ready','watchdog.out','launcher-control.out','gate.log','evidence.tgz'}
    with tarfile.open(archive,'r')as t:
        members=t.getmembers();assert len(members)<=len(allowed) and len({m.name for m in members})==len(members)
        assert sum(m.size for m in members)<=8*1024**2
        for m in members:
            assert m.isfile() and m.name in allowed and remaining()>0
            raw=t.extractfile(m).read()
            if m.name in('entry-owner-receiving.json','entry-native-facts.json'):
                assert raw==(DEST/m.name).read_bytes(),'returned owning chain differs from durable original'
            else:(DEST/m.name).write_bytes(raw)
    receipt=json.loads((DEST/'return-manifest.json').read_text())
    returned_pins={row['name']:{'bytes':row['bytes'],'sha256':row['sha256']}for row in receipt['files']}
    assert returned_pins['entry-owner-receiving.json']==state['entry_owner_pin']
    assert returned_pins['entry-native-facts.json']==state['entry_native_facts_pin']
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
    if 'entry_request'in state:state['owner_terminal_receiving']='UNIMPLEMENTED_UNKNOWN_RETAIN_SAME_HOLDER_CHARGE_NO_SELF_RELEASE'
    # No uncertain mail/probe/SSH child may outlive the original's disappearing
    # daemon timer. Save the typed uncertainty, then terminate only this group.
    try:
        if remaining()>0:save();print(json.dumps(state),flush=True)
    finally:os.killpg(os.getpgrp(),signal.SIGKILL)
