"""Run new-model test rows through actual C stages under undefined-behavior sanitizer."""
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pipeline import HERE,load_numeric,write,preservation
from integer import command,MODES

import argparse
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=HERE/'run')
out=parser.parse_args().output;tree=out/'.output/tree';test=load_numeric(out/'test.npz')
driver=out/'.output/sanitizer.c'
driver.write_text('''#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#ifdef FRESH_XDP
#define main original_validation_main
#include "tree/validation/native.c"
#undef main
#else
#include "tree/evaluation/tc_vectors.c"
#endif
int main(void){int64_t raw[6];int32_t output[192],label;unsigned count=0;size_t got;
#ifdef FRESH_XDP
native_reset();
#endif
while((got=fread(raw,sizeof(*raw),6,stdin))==6){
#ifdef FRESH_XDP
label=native_mlp(raw,output);assert(label==0||label==1);
#else
assert(!vector_infer(raw,output,&label));
#endif
count++;}
assert(!got&&!ferror(stdin));printf("UBSan: %u fresh-model held-out rows completed\\n",count);return 0;}
''')
results={}
for mode in MODES:
    argv=['clang-12','-O1','-g','-pthread','-fsanitize=undefined','-fno-sanitize-recover=all',
          '-I'+str(tree/('validation/include' if mode=='xdp_q16' else 'tc/tests/include')),'-I'+str(tree/'validation/include')]
    if mode=='xdp_q16':argv+=['-DFRESH_XDP']
    if mode=='tc_layer_specific':argv+=['-DIDS_LAYER_SPECIFIC']
    target=out/'.output'/('sanitizer-'+mode)
    command(out,argv+[driver,'-o',target],mode+'-ubsan-build')
    p=subprocess.run([target],input=test['features'].astype('<i8').tobytes(),capture_output=True)
    (out/(mode+'-ubsan.log')).write_bytes(p.stdout+p.stderr)
    assert p.returncode==0,(mode,p.stderr.decode())
    assert p.stdout.decode()==f"UBSan: {len(test['indices'])} fresh-model held-out rows completed\n"
    results[mode]=dict(status='PASS',records=len(test['indices']),returncode=p.returncode,diagnostics=p.stderr.decode())
write(out/'sanitizer.json',dict(status='PASS',execution='Host C under UBSan; not kernel execution',modes=results,preservation=preservation()))
print(results)
