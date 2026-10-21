"""Hermetic diagnostic orchestration regression; no systemd/provider launch."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

source = Path(sys.argv[1]).read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
real_run, real_popen, real_which = subprocess.run, subprocess.Popen, shutil.which

for help_exit in (0, 127):
    with tempfile.TemporaryDirectory(prefix='r38-regression-') as directory:
        root = Path(directory)
        home, out, runtime = [root / name for name in ('home', 'out', 'runtime')]
        for path in (home, out, runtime):
            path.mkdir()
        program = home / 'downloads/grok'
        program.parent.mkdir()
        program.write_text('#!/bin/sh\nexit 99\n')
        program.chmod(0o700)
        cam = home / '.local/share/coding-agent-manager/accounts/grok-cli/work2'
        cam.mkdir(parents=True)
        auth = cam / 'auth.json'
        for name in ('auth.json', 'config.toml', 'models_cache.json'):
            (cam / name).write_text('credential-input-must-never-be-read')
        summary = root / 'summary.json'
        summary.write_text(json.dumps({'command': ['<program>', '--no-auto-update',
            '--prompt-file', '<prompt>', '--model', 'grok-4.6', '--reasoning-effort',
            'xhigh', '--cwd', '<worktree>', '--json-schema',
            '{"type":"object","properties":{"claim_token":{"type":["integer","null"]}}}',
            '--output-format', 'streaming-json', '--sandbox', 'strict',
            '--always-approve', '--disable-web-search', '--no-memory', '--no-subagents']}))
        seen = []

        class FakeProcess:
            def __init__(self, args, **kwargs):
                seen.append(args)
                self.args = args
                self.returncode = help_exit if '--help' in args else 0
                self.stdin = None
                self.read_fd = None
                if kwargs['stdin'] == subprocess.PIPE:
                    self.read_fd, writer = os.pipe()
                    self.stdin = os.fdopen(writer, 'wb')
                # This is the regression: the exact home executable must survive
                # ProtectHome; neither its directory nor siblings may be exposed.
                assert '--property=ProtectHome=tmpfs' in args
                for prop in ('BindReadOnlyPaths=', 'ReadOnlyPaths='):
                    assert '--property=' + prop + str(program) in args
                    assert '--property=' + prop + str(program.parent) not in args
                assert '--property=ReadWritePaths=' + str(program) not in args
                child_home = Path(next(a.removeprefix('HOME=') for a in args if a.startswith('HOME=')))
                logs = child_home / 'logs'
                logs.mkdir()
                (logs / 'unified.jsonl').write_text(
                    '{"msg":"startup fixture","ctx":{"pre_key":"synthetic-private-key"}}\n'
                    'Bearer synthetic-bearer-credential\nambient-secret-fixture\n')
                if '--debug-file' in args:
                    Path(args[args.index('--debug-file') + 1]).write_text(
                        'headless: spawn + initialize complete\n'
                        'headless: authenticate complete\n'
                        'headless: open_session complete\n'
                        'sending "session/set_model" request: api_key="synthetic-private-key"\n')
                if any(a.endswith('-a') and a.startswith('--unit=') for a in args):
                    repo = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--working-directory=')))
                    with (repo / 'README.md').open('a') as stream:
                        stream.write('Hello from MACO\n')

            def communicate(self, input=None, timeout=None):
                if self.stdin:
                    self.stdin.close()
                    os.close(self.read_fd)
                if '--help' in self.args:
                    if self.returncode:
                        return b'', b'/usr/bin/env: grok: No such file or directory\n'
                    return b'--debug\n--debug-file <FILE>\n', b''
                return b'{"type":"available_commands"}\n', b''

            def kill(self):
                self.returncode = -9

        def fake_run(args, **kwargs):
            if '--user' in args:
                return subprocess.CompletedProcess(args, 0, b'', b'')
            with mock.patch('subprocess.Popen', real_popen):
                return real_run(args, **kwargs)

        def which(name, path=None):
            if name in ('systemd-run', 'systemctl', 'bwrap'):
                return real_which('true')
            return real_which(name, path=path) or real_which(name)

        original_open = os.open
        original_path_open = Path.open

        def guarded_open(path, *args, **kwargs):
            assert Path(path) != auth, 'diagnostic tried to open the credential input'
            return original_open(path, *args, **kwargs)

        def guarded_path_open(path, *args, **kwargs):
            assert path != auth, 'diagnostic tried to read or copy the credential input'
            return original_path_open(path, *args, **kwargs)

        namespace = {'__name__': '__main__'}
        with mock.patch.dict(os.environ, {'OUT': str(out), 'MACO_GROK_BIN': str(program),
                'R38_SUMMARY': str(summary), 'XDG_RUNTIME_DIR': str(runtime),
                'HTTPS_PROXY': 'http://fixture.invalid:8080',
                'R38_SECRET': 'ambient-secret-fixture'}, clear=True), \
                mock.patch.object(Path, 'home', return_value=home), \
                mock.patch('shutil.which', side_effect=which), \
                mock.patch('subprocess.Popen', side_effect=FakeProcess), \
                mock.patch('subprocess.run', side_effect=fake_run), \
                mock.patch.object(Path, 'open', guarded_path_open), \
                mock.patch('os.open', side_effect=guarded_open):
            try:
                exec(compile(source, 'R38-diag embedded Python', 'exec'), namespace)
            except SystemExit as error:
                assert help_exit != 0 and error.code == 1
            else:
                assert help_exit == 0
            # Neither native output links nor FIFO/device files may make log
            # capture read a credential or block after the unit has stopped.
            linked_log = root / 'linked-log'
            linked_log.symlink_to(auth)
            try:
                namespace['save_native_log']('unsafe.log', linked_log)
            except OSError:
                pass
            else:
                raise AssertionError('native log capture followed a symlink')
            fifo = root / 'fifo-log'
            os.mkfifo(fifo)
            try:
                namespace['save_native_log']('unsafe.log', fifo)
            except RuntimeError:
                pass
            else:
                raise AssertionError('native log capture accepted a FIFO')
            namespace['save_native_log']('absent.log', root / 'missing-log')
            assert (out / 'absent.log').read_text().startswith('UNOBSERVED:')
            large = root / 'large-log'
            large.write_bytes(b'x' * (8 * 1024 * 1024 + 1))
            namespace['save_native_log']('bounded.log', large)
            assert (out / 'bounded.log').stat().st_size < 8 * 1024 * 1024 + 100
            assert (out / 'bounded.log').read_text().endswith('TRUNCATED: native log exceeded 8 MiB\n')
            namespace['save_json']('redaction.json', {
                'argv': ['api_key=synthetic-private-key'],
                'outer_properties': ['KeyringMode=private'],
            })
            redacted = json.loads((out / 'redaction.json').read_text())
            assert redacted['outer_properties'] == ['KeyringMode=private']
            assert 'synthetic-private-key' not in redacted['argv'][0]

        log = (out / 'summary.txt').read_text()
        status = json.loads((out / 'help.status.json').read_text())
        assert status['exit_code'] == help_exit
        assert status['exact_readme_edit'] is False
        if help_exit:
            assert len(seen) == 1
            assert 'ABORT: contained help did not succeed' in log
            assert 'no advertised flag' not in log
            assert not (out / 'A.launch.json').exists()
        else:
            assert len(seen) == 15
            assert json.loads((out / 'A.status.json').read_text())['exact_readme_edit'] is True
            assert '--debug' in json.loads((out / 'K-verbose.launch.json').read_text())['argv']
            assert json.loads((out / 'A.launch.json').read_text())['env']['GIT_CONFIG_KEY_0'] == 'gc.auto'
            argv = json.loads((out / 'A.launch.json').read_text())['argv']
            schema = json.loads(argv[argv.index('--json-schema') + 1])
            assert schema['properties']['claim_token']['type'] == ['integer', 'null']
            assert 'UNOBSERVED' not in (out / 'A.native.jsonl').read_text()
            assert (out / 'K-verbose.native-debug.log').is_file()
            stages = json.loads((out / 'K-verbose.status.json').read_text())['observed_native_stage_markers']
            assert stages == ['initialize_complete', 'authenticate_complete',
                              'session_open_complete', 'model_switch_requested']
            assert json.loads((out / 'A.status.json').read_text())['observed_native_stage_markers'] == []
            assert 'model_switch_requested' in log
            assert 'missing markers remain unobserved' in log
            stdin_argv = json.loads((out / 'C-stdin-prompt.launch.json').read_text())['argv']
            assert stdin_argv[stdin_argv.index('--prompt-file') + 1] == '/dev/stdin'
            single_argv = json.loads((out / 'D-argument-prompt.launch.json').read_text())['argv']
            assert '--single' in single_argv and '--prompt-file' not in single_argv
            assert 'cli-chat-proxy.grok.com' in namespace['shim_source']
        for path in out.iterdir():
            text = path.read_text()
            for secret in ('credential-input-must-never-be-read', 'synthetic-private-key',
                    'synthetic-bearer-credential', 'ambient-secret-fixture'):
                assert secret not in text, (path.name, 'unredacted fixture secret')

print('PASS: exact executable binds, help failure, native log capture/redaction, and no credential reads')
