import datetime
import json
from pathlib import Path
import shlex
import subprocess
import sys
from zoneinfo import ZoneInfo

log_dir = Path(sys.argv[1])
label = sys.argv[2]
argv = sys.argv[3:]
command = shlex.join(argv)
started = datetime.datetime.now(ZoneInfo('Asia/Kolkata')).isoformat()
with (log_dir / 'commands.txt').open('a') as f:
    f.write(f'[{started}] cwd={Path.cwd()}\n{command}\n')
with (log_dir / (label + '.log')).open('wb') as output:
    try:
        result = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=False)
        status = result.returncode
    except FileNotFoundError as exc:
        output.write((str(exc) + '\n').encode())
        status = 127
ended = datetime.datetime.now(ZoneInfo('Asia/Kolkata')).isoformat()
with (log_dir / 'commands.jsonl').open('a') as f:
    f.write(json.dumps(dict(label=label, argv=argv, cwd=str(Path.cwd()), started=started, ended=ended, exit_code=status)) + '\n')
print(f'{label}: exit={status}; log={log_dir / (label + ".log")}', flush=True)
sys.exit(status)
