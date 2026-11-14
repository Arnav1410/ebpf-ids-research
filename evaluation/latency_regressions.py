#!/usr/bin/env python3
"""Run existing TC host regressions in both modes; never invokes BPF/networking."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tc'))
from tc import demo


def run(output):
    output = output.resolve();output.mkdir(parents=True, exist_ok=False)
    (output/'.output').mkdir()
    results = dict(scope='Host-compiled TC tests only; no kernel or network execution', modes={})
    for mode in ('static_q16', 'layer_specific'):
        target = output/'.output'/(mode+'.so')
        argv=['clang-12','-O3','-shared','-fPIC','-pthread']
        if mode=='layer_specific':argv.append('-DIDS_LAYER_SPECIFIC')
        argv+=['-I'+str(ROOT/'tc/tests/include'),'-I'+str(ROOT/'validation/include'),str(ROOT/'tc/tests/native.c'),'-o',str(target)]
        p=subprocess.run(argv,capture_output=True,text=True)
        (output/(mode+'-build.log')).write_text(p.stdout+p.stderr)
        with (output/'commands.jsonl').open('a') as dest:dest.write(json.dumps(dict(argv=argv,exit_code=p.returncode))+'\n')
        if p.returncode:raise RuntimeError('Existing TC host build failed')
        demo.test_tc.CONTEXT=target,ROOT,mode
        # Legacy TC tests import `demo` as a sibling script. Temporarily bind
        # that name to tc.demo, rather than the newer root demo/ package.
        # Restore sys.modules after the test run; change no existing sources.
        with patch.dict(sys.modules, {'demo': demo}), (output/(mode+'-tests.log')).open('w') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(demo.test_tc))
        results['modes'][mode]=dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
                                   failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped))
    results['status']='PASS' if all(r['status']=='PASS' for r in results['modes'].values()) else 'FAIL'
    (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))
    return int(results['status']!='PASS')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    raise SystemExit(run(p.parse_args().output))
