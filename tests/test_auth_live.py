#!/usr/bin/env python3
"""Test native HTTPS auth clients against an isolated local mesgd fixture.
Requires installed mesgd server beams in ~/.beamer, Erlang, OpenSSL and libcurl.
No deployed server, account, key or database is touched.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def otp(secret, offset=0):
    raw = base64.b32decode(secret+'='*((8-len(secret)%8)%8))
    counter = int(time.time())//30+offset
    digest = hmac.new(raw, struct.pack('>Q',counter), hashlib.sha1).digest()
    start = digest[-1]&15
    return f'{(struct.unpack(">I",digest[start:start+4])[0]&0x7fffffff)%1000000:06d}'


def main():
    with tempfile.TemporaryDirectory(prefix='mesgd-sdk-auth-live-') as directory:
        temp = Path(directory)
        env = os.environ.copy()
        env.update(MESGD_AUTH_TEST_DIR=str(temp),MESGD_AUTH_CA_FILE=str(temp/'ca.pem'),
                   NODE_EXTRA_CA_CERTS=str(temp/'ca.pem'), SSL_CERT_FILE=str(temp/'ca.pem'),
                   GOCACHE=os.environ.get('GOCACHE',str(temp/'go-cache')),GOTELEMETRY='off')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=mesgd SDK test CA','-addext','subjectAltName=DNS:localhost',
                        '-keyout',str(temp/'ca-key.pem'),'-out',str(temp/'ca.pem')],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN=localhost',
                        '-keyout',str(temp/'key.pem'),'-out',str(temp/'server.csr')],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (temp/'extensions').write_text('subjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n')
        subprocess.run(['openssl','x509','-req','-in',str(temp/'server.csr'),'-CA',str(temp/'ca.pem'),
                        '-CAkey',str(temp/'ca-key.pem'),'-CAcreateserial','-days','1','-extfile',str(temp/'extensions'),
                        '-out',str(temp/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (temp/'mesgd.config').write_text('{keystore, '+json.dumps(str(temp/'keys'))+'}.\n{auth_issuer, "SDK integration"}.\n')
        subprocess.run(['erlc','-o',str(temp),str(ROOT/'tests/fixtures/auth_server.erl'),
                        str(ROOT/'tests/drivers/auth_test_client.erl'),str(ROOT/'erlang/mesgd_auth_client.erl')],check=True)
        commands = {
          'python':['python3',str(ROOT/'tests/drivers/python_client.py')],
          'javascript':['node',str(ROOT/'tests/drivers/javascript_client.mjs')],
          'ruby':['ruby',str(ROOT/'tests/drivers/ruby_client.rb')],
          'php':['php','-d','openssl.cafile='+str(temp/'ca.pem'),str(ROOT/'tests/drivers/php_client.php')],
          'erlang':['erl','-noshell','-pa',str(Path.home()/'.beamer'),'-eval',f'code:add_patha("{temp}"), auth_test_client:main().'],
        }
        if shutil.which('go'):
            subprocess.run(['go','build','-o',str(temp/'go-client'),'./cmd/auth_test_client'],cwd=ROOT/'go',env=env,check=True,timeout=180)
            commands['go']=[str(temp/'go-client')]
        if shutil.which('gcc') and shutil.which('pkg-config') and subprocess.run(['pkg-config','--exists','libcurl']).returncode==0:
            import shlex
            flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','libcurl'],text=True))
            subprocess.run(['gcc','-Wall','-Wextra','-Werror','-std=c11','-I'+str(ROOT/'c'),'-I'+str(ROOT/'3rd-party/cJSON'),
                            str(ROOT/'c/auth.c'),str(ROOT/'c/auth_curl.c'),str(ROOT/'3rd-party/cJSON/cJSON.c'),
                            str(ROOT/'tests/drivers/c_client.c'),'-o',str(temp/'c-client')]+flags,check=True)
            commands['c']=[str(temp/'c-client')]
        server_log = open(temp/'server.log','wb')
        server = subprocess.Popen(['erl','-noshell','-pa',str(Path.home()/'.beamer'),'-eval',
                f'code:add_patha("{temp}"), auth_server:start().'],cwd=temp,env=env,stdout=server_log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+15
            while not (temp/'ready').exists():
                if server.poll() is not None: raise RuntimeError('isolated mesgd fixture failed to start')
                if time.monotonic()>deadline: raise RuntimeError('isolated mesgd fixture startup timed out')
                time.sleep(.05)
            env['MESGD_AUTH_URL']='https://localhost:'+(temp/'ready').read_text()
            keys=[k for k in json.loads((ROOT/'fixtures/jwks.json').read_text()) if 'd' not in k]
            assert len(keys)==2
            for language,command in commands.items():
                if os.environ.get('MESGD_AUTH_LIVE_LANGUAGE') and language!=os.environ['MESGD_AUTH_LIVE_LANGUAGE']: continue
                if not shutil.which(command[0]): print('SKIP '+language+': toolchain unavailable',flush=True);continue
                def call(op,args,status=None):
                    proc=subprocess.run(command,input=json.dumps({'op':op,'args':args})+'\n',text=True,
                                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,cwd=ROOT,timeout=25)
                    if proc.returncode: raise AssertionError(language+' '+op+' transport failed (details suppressed to avoid logging secrets)')
                    try: result=json.loads(proc.stdout)
                    except ValueError: raise AssertionError(language+' '+op+' returned invalid JSON') from None
                    if status is not None:
                        assert result.get('status')==status,language+' '+op+' wrong HTTP status'
                        return
                    assert 'result' in result,language+' '+op+' failed'
                    return result['result']
                user='sdk_'+language+'_'+temp.name.rsplit('-',1)[-1]
                password='SDK test unique password';replacement='SDK test replacement password'
                enrollment=call('signup',[user,user+'@example.com',password,keys])
                assert enrollment['otpauth_uri'].startswith('otpauth://totp/')
                if 'qr_png_base64' in enrollment: assert base64.b64decode(enrollment['qr_png_base64']).startswith(b'\x89PNG\r\n\x1a\n')
                # Confirm the previous counter, leaving the current counter for login.
                confirmed=call('confirm',[user,enrollment['enrollment_token'],otp(enrollment['secret'],-1)])
                current=otp(enrollment['secret'])
                call('login',[user,'wrong password',current],401)
                session=call('login',[user,password,current])
                call('login',[user,password,current],401)
                got=call('keys',[session['access_token']])
                assert len(got['public_keys'])==2
                call('set_keys',[session['access_token'],password,current,keys],401)
                call('logout',[confirmed['access_token']])
                call('keys',[confirmed['access_token']],401)
                future=otp(enrollment['secret'],1)
                call('reset_password',[user,'wrong recovery',replacement,future],401)
                reset=call('reset_password',[user,confirmed['recovery_codes'][0],replacement,future])
                assert reset['password_reset'] and reset['recovery_codes']!=confirmed['recovery_codes']
                call('keys',[session['access_token']],401)
                call('reset_password',[user,confirmed['recovery_codes'][0],replacement,future],401)
                key_user=user+'_keys'
                key_enrollment=call('signup',[key_user,key_user+'@example.com',password,[]])
                key_confirm=call('confirm',[key_user,key_enrollment['enrollment_token'],otp(key_enrollment['secret'],-1)])
                changed=call('set_keys',[key_confirm['access_token'],password,otp(key_enrollment['secret']),keys])
                assert len(changed['public_keys'])==2
                assert len(call('keys',[key_confirm['access_token']])['public_keys'])==2
                print('PASS '+language+': verified HTTPS enrollment, OTP login, replay rejection, key updates, logout and password reset',flush=True)
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill();server.wait()
            server_log.close()

if __name__=='__main__': main()
