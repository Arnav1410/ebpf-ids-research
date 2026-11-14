"""Stage-gated offline study. Run from the isolated worktree root with -m."""
import argparse
from pathlib import Path
import subprocess
import platform

from .common import HERE, ROOT, sha, write, read


def implementation_manifest():
    paths=[HERE/name for name in ('PROTOCOL.json','dataset.py','split.py','train.py','metrics.py','evaluate.py','common.py')]+[ROOT/'src/mlp.py']
    return {str(p.relative_to(ROOT)):sha(p) for p in paths}


def check_implementation(out):
    if read(out/'implementation.json')!=implementation_manifest():raise ValueError('Audited implementation changed since preparation')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=['prepare','split','train','evaluate','audit','report','summary'])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source',type=Path)
    a=p.parse_args();out=a.output.resolve()
    if a.stage=='prepare':
        if a.source is None:p.error('--source is required for prepare')
        from .dataset import prepare
        prepare(a.source,out)
        write(out/'implementation.json',implementation_manifest())
        import numpy,torch,sklearn,matplotlib
        write(out/'environment.json',dict(python=platform.python_version(),kernel=platform.release(),machine=platform.machine(),
            git_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            branch=subprocess.check_output(['git','branch','--show-current'],cwd=ROOT,text=True).strip(),
            packages=dict(numpy=numpy.__version__,torch=torch.__version__,sklearn=sklearn.__version__,matplotlib=matplotlib.__version__)))
    elif a.stage in ('split','train','evaluate'):
        check_implementation(out)
        if a.stage=='split':
            from .split import make_split
            make_split(out)
        elif a.stage=='train':
            from .train import train_both
            train_both(out)
        else:
            from .evaluate import evaluate
            evaluate(out)
    else:
        from .report import audit,report,summary
        {'audit':audit,'report':report,'summary':summary}[a.stage](out)


if __name__=='__main__':main()
