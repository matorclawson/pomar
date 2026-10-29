"""Fixed Pomar rev43 source formatting phase; not a native driver or controller."""
import os, sys, time, json, hashlib, subprocess, difflib
from pathlib import Path

D = Path(sys.argv[1]); E = float(sys.argv[2]); STOP = E - 30
assert D == D.resolve() and os.getuid() == 503
raw = (D / 'gate.log').open('xb'); os.dup2(raw.fileno(), 1); os.dup2(raw.fileno(), 2)
HEAD = 'fd20fb2f18ea4d04ea035c2a16641b8ff1838d8e'
TREE = '235b139cf97027715e1a68b84adbbcff4764097f'
BASE = 'd115cca68238cef853bb524ba3ae57d3cb1f59a3'
NAMES = ['internal/nativeworkload/walking85_qualification.go', 'internal/nativeworkload/walking85_qualification_test.go']
PINS = [(23592, '76ff7a9175c62111f66ae21de042c9aab92c5995e9084a53088d1a70774a82ad'), (27025, 'bff22e79445acaf62379c85531225dbc4630044cf4f20c2a841987f389eb3f6e')]
GIT = '/usr/bin/git'; FMT = '/opt/homebrew/Cellar/go/1.27.0/libexec/bin/gofmt'
def sha(b): return hashlib.sha256(b).hexdigest()
def live():
    assert time.time() < STOP, 'original work deadline'
    ready = (D / 'watchdog.ready').read_text().split()
    assert abs(float(ready[1])-E) < .001
    os.kill(int(ready[0]), 0)
    launcher = int((D / 'launcher.pid').read_text())
    assert os.getppid() == launcher, 'not child of selected launcher'
    os.kill(launcher, 0)
def run(argv, cwd=None, cap=30):
    live()
    p = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=max(.1,min(cap,STOP-time.time())))
    assert p.returncode == 0, (argv, p.returncode, p.stderr.decode(errors='replace'))
    return p.stdout
code = 1
try:
    live()
    assert sha(Path(FMT).read_bytes()) == '0bcfa961e5c2a8ef2cac1e8a03e3267d615196ee59248eab3ab152495a397185'
    sealed = (D/'sealed-source-data.json').read_bytes()
    assert len(sealed)==55943 and sha(sealed)=='11f896c1b4f74d259089f0a26d2785a0e6cc831264e39be3b560236380a6a9c2'
    data = json.loads(sealed)
    assert (data['head'],data['tree'],data['base']) == (HEAD,TREE,BASE)
    assert [row['path'] for row in data['files']] == NAMES
    bundle = D/'source.bundle'; b=bundle.read_bytes()
    assert len(b)==1085765 and sha(b)=='ab084d2c302c972b4728b0d1053015fee6fef5bb6d68b5016d3c44da64fbd479'
    repo=D/'tmp/source'
    run([GIT,'-c','core.hooksPath=/dev/null','-c','protocol.file.allow=always','clone','--no-checkout',str(bundle),str(repo)])
    run([GIT,'-c','core.hooksPath=/dev/null','checkout','--detach',HEAD],repo)
    run([GIT,'remote','remove','origin'],repo)
    assert run([GIT,'rev-parse','HEAD','HEAD^{tree}'],repo).decode().split()==[HEAD,TREE]
    assert run([GIT,'status','--porcelain'],repo)==b''
    assert run([GIT,'remote'],repo)==b''
    assert run([GIT,'diff','--name-status',BASE+'..HEAD'],repo).decode().splitlines()==['A\t'+n for n in NAMES]
    assert run([GIT,'ls-tree',BASE,'--',*NAMES],repo)==b''
    mapper = run([GIT,'rev-parse',HEAD+':internal/nativeworkload/walking85.go',HEAD+':internal/nativeworkload/walking85_test.go'],repo).decode().split()
    assert mapper==['fa9e88038313f891718ac2b24723186c89f40e62','fd025ceeb5139a42b2d4f9d3aee88d25d35ad66a']
    print('HEAD '+HEAD+'\nDIRTY 0\nHOST eng-uk-0006',flush=True)
    before=[]
    for name,pin,row in zip(NAMES,PINS,data['files']):
        v=(repo/name).read_bytes(); assert (len(v),sha(v))==pin
        assert row['preimage'] is None and row['full_utf8'].encode()==v
        before.append(v)
    argv=[FMT,'-w',*NAMES]
    run(argv,repo,60)
    changed=run([GIT,'diff','--name-only','HEAD'],repo).decode().splitlines()
    assert set(changed)<=set(NAMES)
    result={'schema':'walking85-source-format-only-v1','head':HEAD,'tree':TREE,'base':BASE,'argv':argv,'qualifiedSourceGate':False,'nativeExecuted':False,'files':[]}
    out=D/'output';out.mkdir(mode=0o700)
    for name,original in zip(NAMES,before):
        value=(repo/name).read_bytes(); live()
        target=out/Path(name).name;target.write_bytes(value)
        delta=''.join(difflib.unified_diff(original.decode().splitlines(True),value.decode().splitlines(True),fromfile=name+' (original)',tofile=name+' (formatted)'))
        result['files'].append({'path':name,'beforeBytes':len(original),'beforeSHA256':sha(original),'bytes':len(value),'sha256':sha(value),'full_utf8':value.decode(),'diff':delta})
    result['finishedEpoch']=time.time(); live()
    (D/'format-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'formatExit':0,'postimages':[{k:r[k]for k in ('path','bytes','sha256')}for r in result['files']]}),flush=True)
    code=0
finally:
    print('EXIT '+str(code),flush=True)
