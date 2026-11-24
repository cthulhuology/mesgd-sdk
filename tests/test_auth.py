#!/usr/bin/env python3
"""Run auth contract tests with available local toolchains, without downloads."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def lua_value(v):
    if v is None: return 'nil'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, str): return json.dumps(v)
    if isinstance(v, list): return '{'+','.join(map(lua_value, v))+'}'
    if isinstance(v, dict): return '{'+','.join('['+lua_value(k)+']='+lua_value(x) for k,x in v.items())+'}'
    return str(v)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', action='append', help='run a selected language (repeatable)')
    args = parser.parse_args()
    results = {}
    with tempfile.TemporaryDirectory(prefix='mesgd-sdk-auth-tests-') as temporary:
        temp = Path(temporary)
        env = os.environ.copy()
        env.update(GOCACHE=str(temp/'go-cache'), GOTELEMETRY='off', CARGO_TARGET_DIR=str(temp/'rust-target'))
        # Optional reusable build cache; no SDK source/build directories are modified.
        if os.environ.get('MESGD_AUTH_TEST_CACHE'):
            cache = Path(os.environ['MESGD_AUTH_TEST_CACHE']); cache.mkdir(parents=True, exist_ok=True)
            env.update(GOCACHE=str(cache/'go'), CARGO_TARGET_DIR=str(cache/'rust'))
        fixture = temp/'contract.lua'
        fixture.write_text('return '+lua_value(json.loads((ROOT/'fixtures/auth_contract.json').read_text())))
        jobs = {
          'python': ('python3', [['python3','test_auth.py']], ROOT/'python'),
          'javascript': ('node', [['node','test_auth.mjs']], ROOT/'javascript'),
          'ruby': ('ruby', [['ruby','test_auth.rb']], ROOT/'ruby'),
          'php': ('php', [['php','test_auth.php']], ROOT/'php'),
          'perl': ('perl', [['perl','test_auth.pl']], ROOT/'perl'),
          'lua': ('lua', [['lua','test_auth.lua',str(fixture)]], ROOT/'lua'),
          'go': ('go', [['go','test','-run','TestAuth','-v','.']], ROOT/'go'),
          'rust': ('cargo', [['cargo','test','--offline','--test','test_auth']], ROOT/'rust'),
          'erlang': ('erlc', [
              ['erlc','-Werror','-o',str(temp),'mesgd_auth_client.erl','test_auth.erl'],
              ['erl','-noshell','-pa',str(Path.home()/'.beamer'),'-eval',
               f'code:add_patha("{temp}"), case eunit:test(test_auth,[verbose]) of ok -> halt(0); _ -> halt(1) end.']], ROOT/'erlang'),
          'c': ('gcc', [
              ['gcc','-Wall','-Wextra','-Werror','-std=c11','-I../3rd-party/cJSON','auth.c','test_auth.c','../3rd-party/cJSON/cJSON.c','-o',str(temp/'test-c')],
              [str(temp/'test-c')]], ROOT/'c'),
          'dart': ('dart', [
              ['dart', 'pub', 'get', '--offline'],
              ['dart', 'test', 'test/auth_test.dart']], ROOT/'dart'),
          'cpp': ('g++', [
              ['gcc','-Wall','-Wextra','-Werror','-std=c11','-I../3rd-party/cJSON','-c','../c/auth.c','-o',str(temp/'auth.o')],
              ['gcc','-std=c11','-I../3rd-party/cJSON','-c','../3rd-party/cJSON/cJSON.c','-o',str(temp/'cJSON.o')],
              ['g++','-Wall','-Wextra','-Werror','-std=c++17','-I../3rd-party/cJSON','test_auth.cc',str(temp/'auth.o'),str(temp/'cJSON.o'),'-o',str(temp/'test-cpp')],
              [str(temp/'test-cpp')]], ROOT/'cpp'),
        }
        selected = args.language or list(jobs)
        for name in selected:
            if name not in jobs: parser.error('no runnable contract suite for '+name)
            tool, commands, cwd = jobs[name]
            if not shutil.which(tool):
                print('SKIP '+name+': toolchain unavailable', flush=True); results[name] = 'skip'; continue
            print('Testing '+name, flush=True)
            try:
                for command in commands: subprocess.run(command, cwd=cwd, env=env, check=True, timeout=180)
                results[name] = 'pass'
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                results[name] = 'fail'
        print('Auth contracts: '+', '.join(name+'='+result for name,result in results.items()), flush=True)
        print('Source adapters needing external toolchain validation: Java, C#, Kotlin, Swift, OCaml, Haskell, Forth.')
        return 1 if 'fail' in results.values() else 0

if __name__ == '__main__': raise SystemExit(main())
