#!/usr/bin/env python3
"""Gate 3: compare all host-C tensors with Python and run UBSan guards."""
import argparse
import ctypes as C
import hashlib
import itertools
import json
from pathlib import Path
import random
import shlex
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from validation.reference import read_npy_rows,STAGES
from quantization.host import Native
from quantization.reference import LayerModel,ArithmeticFailure,shift,I32_MIN,I32_MAX,I64_MIN,I64_MAX,normalize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--tag',default='');args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    build=out/'.output';build.mkdir(exist_ok=True)
    def command(argv,name,**kwargs):
        name=(args.tag+'-' if args.tag else '')+name
        result=subprocess.run(argv,cwd=ROOT,capture_output=True,**kwargs)
        (out/(name+'.log')).write_bytes(result.stdout+result.stderr)
        with (out/'commands.jsonl').open('a') as f:f.write(json.dumps(dict(argv=list(map(str,argv)),exit_code=result.returncode,log=name+'.log'))+'\n')
        if result.returncode:raise RuntimeError(f'{name} failed: {result.stderr.decode()}')
        return result
    common=['clang-12','-O2','-g','-Wall','-Wextra']
    command(common+['-shared','-fPIC',str(ROOT/'quantization/native.c'),'-o',str(build/'native.so')],'build-host')
    command(common+['-fsanitize=undefined','-fno-sanitize-recover=all',str(ROOT/'quantization/native.c'),'-o',str(build/'sanitizer')],'build-ubsan')
    model=LayerModel.load();native=Native(build/'native.so')
    packed=(C.c_ubyte*5304)();assert native.lib.ls_native_packed(packed)==5304
    assert bytes(packed)==model.packed()
    boundary_checks=0
    for value in (I64_MIN,I64_MIN+1,-(1<<32),-7,-5,-3,-1,0,1,3,5,7,(1<<32),I64_MAX):
        for bits in (0,1,2,16,32,62,63):
            output=C.c_int32();actual=native.lib.ls_native_shift(value,bits,C.byref(output))
            try: expected=shift(value,bits)
            except ArithmeticFailure as error:assert actual=={'configuration':1,'overflow':3}[error.code]
            else:assert actual==0 and output.value==expected
            boundary_checks+=1
    for a,b in ((I64_MAX,1),(I64_MIN,-1),(I64_MIN,I64_MIN),(I64_MAX,I64_MAX),(I64_MIN,I64_MAX),(I64_MAX,-1),(0,0)):
        actual=C.c_int64();code=native.lib.ls_native_add(a,b,C.byref(actual))
        if I64_MIN<=a+b<=I64_MAX:assert code==0 and actual.value==a+b
        else:assert code==3
        boundary_checks+=1
    for q in (0,1,16,22,24,25):
        x=[1,-1,3,-3,0,I64_MIN];mu=[0,0,0,0,0,I64_MIN];scale=[2]*6;limits=[4]*6
        value=(C.c_int32*6)();code=native.lib.ls_native_normalize((C.c_int64*6)(*x),(C.c_int64*6)(*mu),
            (C.c_int64*6)(*scale),q,(C.c_uint64*6)(*limits),value)
        try: expected=normalize(x,mu,scale,q,limits)
        except ArithmeticFailure:assert code==1
        else:assert code==0 and list(value)==expected
        boundary_checks+=1
    for kind in range(1,5):
        native.lib.ls_native_invalid_metadata(kind)
        try:native.infer(model.mean)
        except ArithmeticFailure as error:assert error.code=='configuration'
        else:raise AssertionError('Invalid metadata produced success')
        boundary_checks+=1
    native.lib.ls_native_reset()
    for j in range(6):
        raw=list(model.mean);raw[j]+=model.config['delta_limits'][j]+1
        try:native.infer(raw)
        except ArithmeticFailure as error:assert error.code=='range'
        else:raise AssertionError('Unsupported raw input produced success')
        boundary_checks+=1
    rows=read_npy_rows(ROOT/'dataset/reproduction-xdp-data.npy')
    fixtures=[list(row) for row in rows]
    for signs in itertools.product((-1,1),repeat=6):
        fixtures.append([mu+sign*bound for mu,sign,bound in zip(model.mean,signs,model.config['delta_limits'])])
    fixtures += [list(model.mean),[0]*6,[20,0,20,5001,20,1],[124,5000,20,5001,64,3]]
    rng=random.Random(20261107)
    for _ in range(96):fixtures.append([mu+rng.randint(-bound,bound) for mu,bound in zip(model.mean,model.config['delta_limits'])])
    digest=hashlib.sha256();records=0
    for raw in fixtures:
        actual,label=native.infer(raw);expected,reference=model.infer(raw)
        assert actual==expected and label==reference
        for stage in STAGES:digest.update(struct.pack('<'+'i'*len(actual[stage]),*actual[stage]))
        records+=1
    sanitizer=command([str(build/'sanitizer')],'ubsan',input=b''.join(struct.pack('<6q',*raw) for raw in fixtures))
    result=dict(status='PASS',gate=3,execution='Host compiled C only; not kernel',records=records,
                dataset_rows=len(rows),stage_tensors=records*6,integers=records*136,
                boundary_checks=boundary_checks,parameter_bytes=5304,parameter_sha256=hashlib.sha256(bytes(packed)).hexdigest(),
                tensor_sha256=digest.hexdigest(),mismatches=0,ubsan='PASS',ubsan_output=sanitizer.stdout.decode().strip())
    (out/'host_results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))


if __name__=='__main__':main()
