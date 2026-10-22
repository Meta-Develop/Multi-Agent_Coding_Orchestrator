#!/usr/bin/env bash
# Run on the parent host: OUT=/existing/private/dir MACO_GROK_BIN=/absolute/grok ./scripts/diagnose-grok-launch.sh
# Up to 15 sequential 180-second probes. No credentials are read/copied by this script;
# only systemd read-only mounts expose auth.json to Grok. Do not run with bash -x.
set -euo pipefail
set +x
umask 077
: "${OUT:?Set OUT to an existing output directory}"
: "${MACO_GROK_BIN:?Set MACO_GROK_BIN to the absolute Grok executable}"
test -d "$OUT"
exec python3 - <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

out = Path(os.environ['OUT']).resolve(strict=True)
grok = Path(os.environ['MACO_GROK_BIN'])
if not grok.is_absolute() or grok.is_symlink() or not grok.is_file() or not os.access(grok, os.X_OK):
    raise SystemExit('MACO_GROK_BIN must be an absolute, regular, non-symlink executable path')
grok = grok.resolve(strict=True)
cam = Path.home() / '.local/share/coding-agent-manager/accounts/grok-cli/work2'
if not (cam / 'auth.json').is_file() or (cam / 'auth.json').is_symlink():
    raise SystemExit('Expected a regular, non-symlink CAM work2 auth.json (not read)')
runtime_root = Path(os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}'))
summary_path = Path(os.environ.get('R38_SUMMARY', str(Path.home() /
    'agent-work/maco-e2e-20261015/runs/e2e-mixed-r37r2/repo/.maco/o2/runs/'
    'e2e-mixed-r37r2/logs/readme-worker.summary.json')))
recorded = json.loads(summary_path.read_text())['command']
assert recorded[1] == '--no-auto-update'
assert recorded[recorded.index('--output-format') + 1] == 'streaming-json'
assert recorded[recorded.index('--sandbox') + 1] == 'strict'
schema = recorded[recorded.index('--json-schema') + 1]
json.loads(schema)
trusted_path = '/run/current-system/sw/bin:/usr/bin:/bin'

def executable(name):
    found = shutil.which(name, path=trusted_path) or shutil.which(name)
    if not found:
        raise SystemExit(f'Required host executable missing: {name}')
    return str(Path(found).resolve(strict=True))

timeout, systemd, systemctl, env_bin, git, python = map(executable,
    ['timeout', 'systemd-run', 'systemctl', 'env', 'git', 'python3'])
bwrap = shutil.which('bwrap', path=trusted_path)
bwrap = str(Path(bwrap).resolve()) if bwrap else None
# Never dump the ambient environment. Redact secret-looking values if a runtime
# happens to echo them; auth.json is NEVER opened, parsed, copied, or logged here.
secret_name = re.compile(r'token|secret|password|passwd|api.?key|credential|authorization|cookie|(?:^|[_-])key(?:$|[_-])', re.I)
secret_values = [v for k, v in os.environ.items() if secret_name.search(k) and len(v) >= 4]

def redact(value):
    text = value.decode('utf-8', 'replace') if isinstance(value, bytes) else str(value)
    for secret in sorted(secret_values, key=len, reverse=True):
        text = text.replace(secret, '<redacted>')
    text = re.sub(r'(?i)((?:https?|socks[45]h?)://)[^/@\s]+@', r'\1<redacted>@', text)
    text = re.sub(r'(?i)(bearer\s+)[^\s"\x27,}]+', r'\1<redacted>', text)
    text = re.sub(r'(?i)(?<![\w.-])((?:[\w.-]*(?:token|secret|password|passwd|api[_-]?key|credential|authorization|cookie)[\w.-]*|(?:[\w.-]*[_-])?key(?:[_-][\w.-]+)?)["\x27]?\s*[:=]\s*)("[^"\n]*"|\x27[^\x27\n]*\x27|[^\s,}]+)',
                  r'\1"<redacted>"', text)
    # Also catch unlabeled JWTs / long opaque keys without reading credential files.
    return re.sub(r'(?<![\w/])(?:eyJ[A-Za-z0-9_.=-]{32,}|(?:xai-|sk-)[A-Za-z0-9_-]{16,}|[A-Za-z0-9_+=]{48,})(?![\w/])',
                  '<redacted-opaque>', text)

def save(name, value):
    (out / name).write_text(redact(value), encoding='utf-8')

def save_json(name, value):
    # Redact values before encoding: substitutions in encoded JSON can insert
    # unescaped quotes and destroy launch/status evidence.
    def clean(value):
        if isinstance(value, str):
            try:
                nested = json.loads(value)
            except ValueError:
                return redact(value)
            if isinstance(nested, (dict, list)):
                # In particular, schema properties named claim_token describe
                # types, not credentials. Preserve the structure of JSON argv.
                return json.dumps(clean(nested), separators=(',', ':'), ensure_ascii=False)
            return redact(value)
        if isinstance(value, list): return [clean(item) for item in value]
        if isinstance(value, dict):
            return {key: '<redacted>' if isinstance(item, str) and secret_name.search(key)
                    and not re.fullmatch(r'GIT_CONFIG_KEY_\d+', key) else clean(item)
                    for key, item in value.items()}
        return value
    (out / name).write_text(json.dumps(clean(value), indent=2) + '\n', encoding='utf-8')

def save_native_log(name, path):
    # Read only these named native diagnostic outputs, never credential inputs.
    # No symlink following or unbounded reads from runtime-controlled files.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        save(name, 'UNOBSERVED: native log was not created\n')
        return None
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimeError('Native log is not a regular file')
        limit = 8 * 1024 * 1024
        data = stream.read(limit + 1)
    save(name, data[:limit])
    if len(data) > limit:
        with (out / name).open('a') as stream:
            stream.write('\nTRUNCATED: native log exceeded 8 MiB\n')
    return data[:limit].decode('utf-8', 'replace')

def native_stage_markers(*logs):
    # Emit only constant labels, never native log lines, prompts or RPC payloads.
    # Absence of a marker is unobserved, not proof the operation did not happen.
    markers = [
        ('initialize_complete', 'headless: spawn + initialize complete'),
        ('authenticate_complete', 'headless: authenticate complete'),
        ('session_open_complete', 'headless: open_session complete'),
        ('model_switch_requested', 'sending "session/set_model" request'),
        ('model_effort_applied', 'headless: model/effort set'),
        ('prompt_requested', 'sending "session/prompt" request'),
        ('first_chunk', 'headless: time-to-first-chunk'),
        ('prompt_response', 'received "session/prompt" response'),
    ]
    return [label for label, marker in markers
            if any(marker in log for log in logs if log is not None)]

def note(message):
    with (out / 'summary.txt').open('a') as stream:
        stream.write(redact(message) + '\n')
    print(redact(message), flush=True)

if (out / 'summary.txt').exists():
    raise SystemExit('Use a fresh OUT: summary.txt already exists')
note('R38 diagnostic; exit 124=timeout; other nonzero may be launch/protocol failure.')
note('A reproduces Grok argv/environment/stdin and outer policy, with a trivial prompt/fresh git repo.')
note('Standalone diagnostic omits MACO guardian/FD sealing, CAM lease, journal and live IPC tokens; private Git uses fresh local objects.')
note('No production launch code or sandbox policy is changed. Each probe has timeout 180; units have RuntimeMaxSec=180s.')
note('J tests native bwrap/tool network; inference requests may run in the Grok parent outside that inner namespace.')
note('C uses --prompt-file /dev/stdin; D uses --single. Bare stdin/positional prompts select the interactive UI and are not headless comparisons.')
note('Optional CAM leaves present: config.toml=' + str((cam / 'config.toml').is_file()) +
     ' models_cache.json=' + str((cam / 'models_cache.json').is_file()))

deny = ('@clock @debug @module @obsolete @raw-io @reboot @swap bpf fanotify_init '
        'fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive '
        'mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink '
        'msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise '
        'process_vm_readv process_vm_writev quotactl quotactl_fd semctl '
        'semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget '
        'link linkat mknod mknodat')
fixed = [
    'ProtectSystem=strict', 'ProtectHome=tmpfs', 'NoNewPrivileges=yes',
    'CapabilityBoundingSet=', 'AmbientCapabilities=', 'RestrictSUIDSGID=yes',
    'LockPersonality=yes', 'PrivateTmp=yes', 'PrivateDevices=yes', 'PrivateUsers=yes',
    'PrivateIPC=yes', 'ProtectKernelTunables=yes', 'ProtectKernelModules=yes',
    'ProtectKernelLogs=yes', 'ProtectClock=yes', 'ProtectControlGroups=yes',
    'ProtectProc=invisible', 'ProcSubset=pid', 'SystemCallArchitectures=native',
    'SystemCallErrorNumber=EPERM', 'RestrictRealtime=yes', 'KeyringMode=private',
    'UMask=0077', 'MemorySwapMax=0', 'LimitCORE=0', 'OOMPolicy=kill',
    'RestrictNamespaces=no', 'PrivateNetwork=no', 'MemoryMax=4294967296',
    'TasksMax=256', 'CPUQuota=400%', 'LimitNOFILE=8192', 'LimitFSIZE=2147483648',
]
sockets = [runtime_root / x for x in ('bus', 'systemd', 'gnupg', 'keyring',
    'wayland-0', 'pipewire-0', 'pulse', 'ssh-agent', 'docker.sock', 'podman', 'libvirt')]
sockets += list(map(Path, ['/run/dbus/system_bus_socket', '/var/run/dbus/system_bus_socket',
    '/run/docker.sock', '/var/run/docker.sock', '/run/podman', '/run/libvirt',
    '/var/run/libvirt', '/run/credentials', '/run/secrets', '/run/keys',
    '/nix/var/nix/daemon-socket']))

# Instrumentation only: replace the actual bwrap executable at its canonical path
# and replay its EXACT namespace/mount prefix with a harmless DNS/TLS payload.
# If Grok never calls bwrap, or uses opaque FD arguments, say so rather than
# pretending a hand-built sandbox was Grok's sandbox. No network payload/token logs.
shim_source = r'''#!PYTHON
import json, os, subprocess, sys
from pathlib import Path
root = Path(R38_ROOT)
args = sys.argv[1:]
print('R38_BWRAP_CALLED', file=sys.stderr, flush=True)
zero = {'--unshare-all','--unshare-user','--unshare-user-try','--unshare-ipc',
        '--unshare-pid','--unshare-net','--unshare-uts','--unshare-cgroup',
        '--unshare-cgroup-try','--share-net','--die-with-parent','--new-session',
        '--as-pid-1','--clearenv','--disable-userns','--assert-userns','--perms-ignored'}
one = {'--uid','--gid','--hostname','--chdir','--unsetenv','--lock-file',
       '--sync-fd','--block-fd','--userns','--userns2','--pidns','--seccomp',
       '--add-seccomp-fd','--args','--info-fd','--json-status-fd','--cap-add',
       '--cap-drop','--perms','--size','--proc','--dev','--tmpfs','--mqueue','--remount-ro'}
two = {'--bind','--bind-try','--ro-bind','--ro-bind-try','--dev-bind','--dev-bind-try',
       '--ro-bind-data','--bind-data','--file','--symlink','--setenv'}
i = 0
reason = None
while i < len(args):
    a = args[i]
    if a == '--':
        break
    if not a.startswith('-'):
        break
    if a in {'--seccomp','--add-seccomp-fd','--args','--block-fd','--sync-fd',
             '--ro-bind-data','--bind-data','--file','--info-fd','--json-status-fd'}:
        reason = 'opaque/consumable FD argument ' + a
        break
    if a in zero: i += 1
    elif a in one: i += 2
    elif a in two: i += 3
    elif a == '--dir': i += 2
    else:
        reason = 'unknown bwrap option ' + a
        break
if i >= len(args): reason = 'no command boundary'
if any('/proc/self/fd/' in a or '/dev/fd/' in a for a in args[:i]):
    reason = 'prefix refers to inherited file descriptors'
if reason:
    print('R38_NETWORK_PROBE_SKIPPED: ' + reason, file=sys.stderr, flush=True)
else:
    prefix = args[:i]
    # Flags only: avoid logging original argv, --setenv values or command payloads.
    print('R38_BWRAP_NETWORK_FLAGS ' + json.dumps([a for a in prefix if a in
          {'--unshare-all','--unshare-net','--share-net'}]), file=sys.stderr, flush=True)
    probe = """import socket, ssl
for host in ('api.x.ai', 'grok.com', 'cli-chat-proxy.grok.com'):
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        print('R38_DNS', host, 'ok', len(addresses), flush=True)
        with socket.create_connection((host,443), timeout=10) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                print('R38_TLS', host, 'ok', flush=True)
    except Exception as e:
        print('R38_NET_FAIL', host, type(e).__name__, 'errno', getattr(e,'errno',None), flush=True)
"""
    try:
        result = subprocess.run([str(root/'real-bwrap'), *prefix, '--',
            'PYTHON', '-c', probe], stdin=subprocess.DEVNULL,
            stdout=sys.stderr, stderr=sys.stderr, timeout=30)
        print('R38_NETWORK_PROBE_EXIT', result.returncode, file=sys.stderr, flush=True)
    except subprocess.TimeoutExpired:
        print('R38_NETWORK_PROBE_TIMEOUT', file=sys.stderr, flush=True)
os.execv(str(root/'real-bwrap'), [str(root/'real-bwrap'), *args])
'''.replace('PYTHON', python)

def property_path(path):
    # systemd splits path lists on whitespace, interprets ':' and expands '%'.
    value = str(path)
    if any(c.isspace() for c in value) or any(c in value for c in ':\\"\x27'):
        raise RuntimeError('Diagnostic paths must not contain whitespace, quotes, backslashes or colons')
    return value.replace('%', '%%')

def run(name, change='baseline'):
    with tempfile.TemporaryDirectory(prefix='r38-repo-') as repo_tmp, \
         tempfile.TemporaryDirectory(prefix='r38-home-', dir=runtime_root) as home_tmp:
        repo, home = Path(repo_tmp), Path(home_tmp)
        (repo / 'README.md').write_text('R38 diagnostic repository\n')
        git_env = {'PATH': trusted_path, 'HOME': str(home),
                   'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        for args in ([git, 'init', '-q', str(repo)],
                     [git, '-C', str(repo), 'add', 'README.md'],
                     [git, '-C', str(repo), '-c', 'user.name=R38', '-c',
                      'user.email=r38@example.invalid', '-c', 'commit.gpgsign=false',
                      'commit', '-qm', 'diagnostic baseline']):
            subprocess.run(args, check=True, stdout=subprocess.DEVNULL,
                           env=git_env)
        base = subprocess.run([git, '-C', str(repo), 'rev-parse', 'HEAD'], check=True,
                              stdout=subprocess.PIPE, env=git_env).stdout.decode().strip()
        # Recreate managed_git_environment's private index/object indirection,
        # using ONLY this new repository. Never touch the checkout or real run.
        private_git = home / 'maco-private-git-v1'
        shared_objects = home / 'shared-objects'
        (private_git / 'objects').mkdir(parents=True)
        (private_git / 'refs/heads').mkdir(parents=True)
        shutil.copyfile(repo / '.git/index', private_git / 'index')
        shutil.move(str(repo / '.git/objects'), shared_objects)
        shutil.rmtree(repo / '.git')
        (private_git / 'HEAD').write_text('ref: refs/heads/maco-worker\n')
        (private_git / 'refs/heads/maco-worker').write_text(base + '\n')
        (private_git / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n')
        (repo / '.git').write_text('gitdir: ' + str(private_git) + '\n')
        managed_git_env = {'GIT_DIR': str(private_git),
            'GIT_OBJECT_DIRECTORY': str(private_git / 'objects'),
            'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(shared_objects),
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '2',
            'GIT_CONFIG_KEY_0': 'gc.auto', 'GIT_CONFIG_VALUE_0': '0',
            'GIT_CONFIG_KEY_1': 'maintenance.auto', 'GIT_CONFIG_VALUE_1': 'false',
            'GIT_WORK_TREE': str(repo)}
        git_env.update(managed_git_env)
        prompt = ('Append exactly one final line "Hello from MACO" to README.md. '
                  'Do not change any other file. Do not stage, commit, push, delegate or inspect credentials. '
                  'Return a result matching the supplied JSON schema if present.\n')
        prompt_path = home / 'worker-effective-prompt.md'
        prompt_path.write_text(prompt)
        # Replace whole argv values only; preserve recorded order, flags and schema.
        argv = list(recorded[1:])
        argv[argv.index('--prompt-file') + 1] = str(prompt_path)
        argv[argv.index('--cwd') + 1] = str(repo)
        if change in ('stdin', 'argument'):
            index = argv.index('--prompt-file')
            argv[index:index + 2] = (['--prompt-file', '/dev/stdin'] if change == 'stdin'
                                   else ['--single', prompt])
        if change == 'no-schema':
            index = argv.index('--json-schema')
            del argv[index:index + 2]
        if change == 'verbose':
            argv.append(verbose_flag)
            if re.search(r'(?<![\w-])--debug-file(?![\w-])', help_text):
                argv += ['--debug-file', str(home / 'native-debug.log')]
        if change in ('help', 'version', 'models'):
            argv = ['--no-auto-update', '--' + change] if change != 'models' else ['--no-auto-update', 'models']
        child_env = {'PATH': trusted_path, 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                     'TERM': 'dumb', 'HOME': str(home), 'TMPDIR': str(home), 'GROK_HOME': str(home)}
        child_env.update(managed_git_env)
        child_env.update(MACO_RUN_ID='r38-diag', MACO_TASK_ID='readme-worker')
        if Path('/etc/ssl/certs/ca-bundle.crt').is_file():
            child_env.update(SSL_CERT_FILE='/etc/ssl/certs/ca-bundle.crt',
                             NIX_SSL_CERT_FILE='/etc/ssl/certs/ca-bundle.crt')
        if change == 'network-env':
            child_env.update(network_env)
        props = list(fixed)
        # Match production's exact executable-file visibility. ProtectHome=tmpfs
        # otherwise hides home-installed Grok even though host preflight found it.
        # Do not expose its parent directory or any sibling in ~/.grok.
        props += ['BindReadOnlyPaths=' + property_path(grok),
                  'ReadOnlyPaths=' + property_path(grok)]
        props.append('RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' +
                     (' AF_NETLINK' if change == 'netlink' else ''))
        if change != 'no-syscall-filter': props.append('SystemCallFilter=~' + deny)
        for path in sockets + [cam]: props.append('InaccessiblePaths=-' + property_path(path))
        for path in (repo, home):
            props.extend(['BindPaths=' + property_path(path), 'ReadWritePaths=' + property_path(path)])
        # Same three read-only leaf projections as GrokCredentialSource. No cp/cat/read.
        for leaf, omit in [('auth.json', None), ('config.toml', 'no-config'),
                           ('models_cache.json', 'no-cache')]:
            source = cam / leaf
            if source.is_symlink(): raise RuntimeError('Refusing symlink CAM projection')
            if source.is_file() and change != omit:
                props.extend(['BindReadOnlyPaths=' + property_path(source) + ':' + property_path(home / leaf),
                              'ReadOnlyPaths=' + property_path(home / leaf)])
        # Preserve read-only prompt/.git input and shared-object access. Production
        # additionally seals private Git metadata leaves and exact journal files.
        for path in (prompt_path, repo / '.git', shared_objects):
            props += ['BindReadOnlyPaths=' + property_path(path),
                      'ReadOnlyPaths=' + property_path(path)]
        if change == 'bwrap-probe':
            if not bwrap:
                note(f'{name} SKIP: no bwrap on MACO trusted PATH')
                save(name + '.out', '')
                save(name + '.err', 'SKIP: bwrap missing from trusted PATH\n')
                return '', None
            # Copy ONLY the non-secret bwrap executable so the shim cannot recurse.
            shutil.copyfile(bwrap, home / 'real-bwrap')
            (home / 'real-bwrap').chmod(0o700)
            shim = home / 'bwrap-shim'
            shim.write_text(shim_source.replace('R38_ROOT', repr(str(home))))
            shim.chmod(0o700)
            props += ['BindReadOnlyPaths=' + property_path(shim) + ':' + property_path(bwrap)]
        unit = f'r38-{os.getpid()}-{name.lower()}'
        command = [systemd, '--user', '--quiet', '--pipe', '--wait', '--collect',
                   '--service-type=exec', '--slice=app.slice', '--expand-environment=no',
                   '--unit=' + unit, '--working-directory=' + str(repo),
                   '--property=KillMode=control-group', '--property=KillSignal=SIGKILL',
                   '--property=FinalKillSignal=SIGKILL', '--property=TimeoutStopSec=100ms',
                   '--property=RuntimeMaxSec=180s']
        command += ['--property=' + p for p in props]
        command += ['--', env_bin, '-i', *[f'{k}={v}' for k, v in sorted(child_env.items())], str(grok), *argv]
        save_json(name + '.launch.json', {'argv': [str(grok), *argv],
             'cwd': str(repo), 'env': child_env, 'stdin':
             {'open': 'empty pipe kept open', 'stdin': 'prompt bytes then EOF'}.get(change, '/dev/null'),
             'outer_properties': props})
        note(f'{name} START change={change}')
        started = time.monotonic()
        held_writer = None
        try:
            process = subprocess.Popen([timeout, '--signal=TERM', '--kill-after=5', '180', *command],
                stdin=subprocess.PIPE if change in ('open', 'stdin') else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'XDG_RUNTIME_DIR': str(runtime_root)})
            if change == 'open':
                held_writer = os.dup(process.stdin.fileno())
            try:
                stdout, stderr = process.communicate(prompt.encode() if change == 'stdin' else None, timeout=190)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            code = process.returncode
        finally:
            if held_writer is not None: os.close(held_writer)
            # RuntimeMaxSec and KillMode bound descendants even if timeout kills
            # the waiting client. Do not remove mount sources while a unit is alive.
            stopped = subprocess.run([systemctl, '--user', 'stop', unit + '.service'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={'XDG_RUNTIME_DIR': str(runtime_root)}, timeout=15)
            if stopped.returncode:
                state = subprocess.run([systemctl, '--user', 'is-active', unit + '.service'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env={'XDG_RUNTIME_DIR': str(runtime_root)}, timeout=10)
                if state.returncode not in (3, 4):
                    raise RuntimeError('Could not confirm diagnostic unit stopped')
        save(name + '.out', stdout)
        save(name + '.err', stderr)
        native_log = save_native_log(name + '.native.jsonl', home / 'logs/unified.jsonl')
        debug_log = None
        if change == 'verbose':
            debug_log = save_native_log(name + '.native-debug.log', home / 'native-debug.log')
        stages = native_stage_markers(native_log, debug_log)
        diff = subprocess.run([git, '-C', str(repo), 'diff', '--no-ext-diff', '--no-textconv', '--', 'README.md'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=git_env)
        save(name + '.diff', diff.stdout)
        edited = (repo / 'README.md').read_text() == 'R38 diagnostic repository\nHello from MACO\n'
        seconds = time.monotonic() - started
        save_json(name + '.status.json', {'exit_code': code, 'seconds': seconds,
             'exact_readme_edit': edited, 'observed_native_stage_markers': stages})
        note(f'{name} exit={code} seconds={seconds:.1f} exact_readme_edit={edited}')
        note(f'{name} observed_native_stage_markers={json.dumps(stages)} (missing markers remain unobserved)')
        return redact(stdout + b'\n' + stderr), code

# Help/version/catalog are bounded too. Catalog success is separated from actual
# generation; it can work even when the inference endpoint or tool sandbox fails.
help_text, help_status = run('help', 'help')
if help_status != 0:
    note('ABORT: contained help did not succeed; no native protocol or advertised-flag conclusion is possible. Inspect help.err and help.launch.json.')
    raise SystemExit(1)
run('version', 'version')
run('models', 'models')
run('A')
run('B-open-stdin', 'open')
run('C-stdin-prompt', 'stdin')
run('D-argument-prompt', 'argument')
run('E-no-config', 'no-config')
run('F-no-cache', 'no-cache')
run('G-no-schema', 'no-schema')
run('H-allow-netlink', 'netlink')
run('I-no-syscall-filter', 'no-syscall-filter')
j_capture, _ = run('J-bwrap-network', 'bwrap-probe')
if 'R38_BWRAP_CALLED' not in j_capture:
    note('J-bwrap-network UNVERIFIED: no bwrap invocation intercepted; startup may stall earlier or Grok may resolve another bwrap path')
verbose_flag = next((flag for flag in ('--verbose', '--debug')
                     if re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', help_text)), None)
if verbose_flag:
    run('K-verbose', 'verbose')
else:
    save('K-verbose.out', '')
    save('K-verbose.err', 'SKIP: installed help advertises neither --verbose nor --debug\n')
    note('K-verbose SKIP: no advertised flag; no invented debug environment variable')
network_env = {key: os.environ[key] for key in (
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy',
    'all_proxy', 'no_proxy', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NIX_SSL_CERT_FILE',
    'NODE_EXTRA_CA_CERTS') if key in os.environ}
if network_env:
    run('L-network-env', 'network-env')
else:
    save('L-network-env.out', '')
    save('L-network-env.err', 'SKIP: no ambient proxy/CA variables to compare\n')
    note('L-network-env SKIP: no ambient proxy/CA variables')
note('Finished. Review .out/.err, .launch.json and .diff alongside exit codes; no MACO acceptance is implied.')
PY
