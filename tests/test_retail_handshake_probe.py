import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import retail_handshake_probe as probe
spec=importlib.util.spec_from_file_location('inspect_handshake',ROOT/'tools/inspect-retail-handshake.py')
inspect_handshake=importlib.util.module_from_spec(spec); spec.loader.exec_module(inspect_handshake)


class HandshakeProbeTests(unittest.TestCase):
    def test_direct_exec_and_environment_isolation(self):
        with patch.object(sys,'argv',['probe','--','/steam wrapper','a b']), \
             patch.dict(os.environ,{'STEAM_COMPAT_INSTALL_PATH':'/game','ISAC_SDK_ADAPTER':'1','ISAC_RETAIL_PROFILE':'1'},clear=True), \
             patch.object(probe.forward,'verify') as verify, \
             patch.object(probe,'prepare_capture',return_value=Path('/private')), \
             patch.object(probe.os,'execvpe') as execute:
            probe.main()
            verify.assert_called_once_with(Path('/game'),probe=probe.PROBE)
            command,argv,env=execute.call_args.args
            self.assertEqual((command,argv),('/steam wrapper',['/steam wrapper','a b']))
            self.assertEqual({k for k in env if k.startswith('ISAC_')},{'ISAC_RETAIL_HANDSHAKE','ISAC_RETAIL_CAPTURE_DIR'})
            self.assertEqual(env['ISAC_RETAIL_CAPTURE_DIR'],'Z:\\private\\handshake-private')

    def test_private_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'evidence').mkdir()
            old=os.umask(0o077)
            try:
                with patch.object(probe.forward,'ROOT',root),patch.object(probe.forward,'digest',return_value='fixture'):
                    capture=probe.prepare_capture()
                self.assertEqual(capture.stat().st_mode&0o777,0o700)
                self.assertEqual((capture/'handshake-private').stat().st_mode&0o777,0o700)
                self.assertEqual((capture/'metadata.json').stat().st_mode&0o777,0o600)
                self.assertFalse(json.loads((capture/'metadata.json').read_text())['raw_bearers_saved'])
            finally:
                os.umask(old)

    def test_core_bounds_lineage_and_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=str(Path(directory)/'core')
            subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(ROOT/'tests/retail_handshake_core.c'),'-o',binary],check=True,capture_output=True)
            result=subprocess.run([binary],check=True,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.stdout.splitlines(),[hashlib.sha256(v).hexdigest() for v in
                (b'',b'abc',b'a'*55,b'a'*56,b'a'*64,b'a'*1024)])

    def test_runtime_signatures_and_forward_only_build(self):
        snapshot=ROOT/'private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin'
        if not snapshot.exists():
            self.skipTest('private static text unavailable')
        self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),'dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74')
        code=snapshot.read_bytes()
        source=(ROOT/'src/uplay_probe/retail_type5_win.c').read_text()
        selected=source.split('#elif defined(ISAC_RETAIL_HANDSHAKE)\nstatic const Site sites[] = {',1)[1].split('#elif defined(ISAC_RETAIL_PROFILE)',1)[0]
        sites=re.findall(r'SITE\((0x[0-9a-f]+),"([^"]+)"\)',selected)
        self.assertEqual(len(sites),12)
        for rva,signature in sites:
            expected=bytes.fromhex(signature.replace('\\x','')); offset=int(rva,16)-0x1000
            self.assertEqual(code[offset:offset+len(expected)],expected,rva)
        source=(ROOT/'tools/build-uplay-probe.sh').read_text()
        self.assertIn('stack_source="$source_dir/retail_handshake_win.c"',source)
        self.assertIn('probe_defines=(-DISAC_RETAIL_ONLY=1)',source)

    def test_redacted_summary_correlations_and_partial_capture(self):
        def token(slot,value):
            return {'slot':slot,'length':len(value),'sha256':hashlib.sha256(value).hexdigest(),
                    'remaining_seconds_estimate':900}
        def row(event,tokens,**kwargs):
            return {'event':event,'encoding':'handshake-metadata-v1','complete':True,'tokens':tokens,**kwargs}
        records=[row('auth_reply',[token(1,b'PRIVATE-AUTH')]),
                 row('join_reply',[token(1,b'PRIVATE-JOIN')],flag=1,uint32_c=42),
                 row('instance_connect',[token(1,b'PRIVATE-AUTH'),token(2,b'PRIVATE-JOIN'),token(3,b'')]),
                 row('game_connect_reply',[],flag=1)]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.jsonl'
            path.write_text('\n'.join(json.dumps(r) for r in records)+'\n{"truncated":')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                inspect_handshake.summarize(path)
            text=output.getvalue()
            self.assertIn('instance_slot=1 auth_slot_matches=[1] join_token_match=False',text)
            self.assertIn('instance_slot=2 auth_slot_matches=[] join_token_match=True',text)
            self.assertIn('instance_slot=3 auth_slot_matches=[] join_token_match=False',text)
            self.assertIn('parsed_bool=True',text)
            self.assertIn('No end record',text)
            self.assertNotIn('PRIVATE',text)
            self.assertNotIn(hashlib.sha256(b'PRIVATE-JOIN').hexdigest(),text)

    @unittest.skipUnless(os.environ.get('ISAC_TEST_HANDSHAKE_PROTON')=='1','Opt-in actual Proton fixture')
    def test_actual_proton(self):
        from test_retail_type5_proton import COMMON, STEAM_CLIENT
        with tempfile.TemporaryDirectory(prefix='isac-handshake-proton-') as directory:
            work=Path(directory); (work/'compat').mkdir()
            binary=work/'handshake.exe'; events=work/'handshake.jsonl'
            subprocess.run(['x86_64-w64-mingw32-gcc','-O2','-Wall','-Wextra','-Werror',
                str(ROOT/'tests/retail_handshake_wine.c'),str(ROOT/'tests/retail_handshake_fixture.S'),
                '-o',str(binary)],check=True,capture_output=True)
            env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','PYTHON','WINE','ISAC_','STEAM_COMPAT_'))}
            env.update(STEAM_COMPAT_DATA_PATH=str(work/'compat'),STEAM_COMPAT_CLIENT_INSTALL_PATH=STEAM_CLIENT,
                       SteamAppId='0',SteamGameId='0',PROTON_LOG='1',PROTON_LOG_DIR=str(work),
                       WINEDEBUG='-all,+seh',WINEDLLOVERRIDES='mscoree,mshtml=')
            result=subprocess.run([str(COMMON/'SteamLinuxRuntime_4/_v2-entry-point'),'--verb=waitforexitandrun','--',
                str(COMMON/'Proton - Experimental/proton'),'waitforexitandrun',str(binary),
                'Z:'+str(events).replace('/','\\')],env=env,capture_output=True,text=True,timeout=60,umask=0o077)
            self.assertEqual(result.returncode,0,result.stdout[-2000:]+result.stderr[-2000:])
            records=[json.loads(line) for line in events.read_text().splitlines()]
            captured=[r for r in records if r.get('encoding')=='handshake-metadata-v1']
            self.assertEqual(len(captured),5)
            self.assertTrue(all(r['complete'] for r in captured))
            auth,join,connect,reply=captured[:4]
            self.assertEqual(auth['tokens'][0]['sha256'],connect['tokens'][0]['sha256'])
            self.assertEqual(join['tokens'][0]['sha256'],connect['tokens'][1]['sha256'])
            self.assertEqual(auth['tokens'][2]['sha256'],connect['tokens'][2]['sha256'])
            self.assertEqual(reply['flag'],1)
            self.assertEqual(records[-1]['event'],'end')
            self.assertEqual(records[-1]['resume_failures'],0)
            self.assertGreaterEqual(records[-1]['debug_context_refreshes'],2)
            self.assertNotIn('data_hex',events.read_text())
            self.assertNotIn('Unhandled exception',(work/'steam-0.log').read_text(errors='replace'))


if __name__=='__main__':
    unittest.main()
