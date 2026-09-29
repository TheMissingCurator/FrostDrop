import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import retail_tutorial_probe as probe
import retail_presentation_probe as presentation_probe
spec=importlib.util.spec_from_file_location('inspect_tutorial',ROOT/'tools/inspect-retail-tutorial.py')
inspector=importlib.util.module_from_spec(spec); spec.loader.exec_module(inspector)


class TutorialProbeTests(unittest.TestCase):
    def test_presentation_capture_is_redacted_and_not_misclassified(self):
        header = inspector.HEADER.pack(b'ISACTUT1', 1, 16)
        fixture = header + inspector.RECORD.pack(1, 1100, 7, 1, 0, 0x12345)
        fixture += inspector.RECORD.pack(2, 1200, 8, 1, 0, 0x67890)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'presentation-1.bin'
            path.write_bytes(fixture)
            path.with_suffix('.jsonl').write_text('\n'.join(json.dumps(row) for row in
                ({'event': 'tutorial_ready', 'tick_ms': 1000},
                 {'event': 'marker', 'key': 7, 'tick_ms': 1150},
                 {'event': 'tutorial_end', 'gaps': 0, 'core_failed': 0},
                 {'event': 'end', 'resume_failures': 0})))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                messages, markers, issues = inspector.summary(path)
            self.assertEqual(messages, [])
            self.assertEqual(markers, [(1150, 7)])
            self.assertEqual(issues, [])
            self.assertIn('client_node=mission_objective_notification_node relative_ms=100',
                          output.getvalue())
            self.assertIn('poll_dialogue_rtpc_node:1', output.getvalue())
            self.assertNotIn('selected stream not correlated', output.getvalue())

    def test_new_presentation_metadata_names_the_two_execute_sites(self):
        header = inspector.HEADER.pack(b'ISACTUT1', 1, 16)
        fixture = header + inspector.RECORD.pack(1, 1100, 7, 1, 0, 0x12345)
        fixture += inspector.RECORD.pack(2, 1200, 8, 1, 0, 0x67890)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / 'presentation-private'
            private.mkdir()
            path = private / 'presentation-1.bin'
            path.write_bytes(fixture)
            (root / 'metadata.json').write_text(json.dumps({'node_sites': {
                '7': 'execute-dialogue-event-evaluation',
                '8': 'execute-agent-dialogue-event-evaluation'}}))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                inspector.summary(path)
            self.assertIn('execute_dialogue_event_node:1', output.getvalue())
            self.assertIn('execute_agent_dialogue_event_node:1', output.getvalue())

    def test_presentation_launcher_uses_opt_in_retail_variant(self):
        with patch.object(sys, 'argv', ['probe', '--', '/steam wrapper']), \
             patch.dict(os.environ, {'STEAM_COMPAT_INSTALL_PATH': '/game'}, clear=True), \
             patch.object(presentation_probe.forward, 'verify') as verify, \
             patch.object(presentation_probe, 'prepare_capture', return_value=Path('/private')), \
             patch.object(presentation_probe.os, 'execvpe') as execute:
            self.assertIsNone(presentation_probe.main())
            verify.assert_called_once_with(Path('/game'), probe=presentation_probe.PROBE)
            environment = execute.call_args.args[2]
            self.assertEqual(environment['ISAC_RETAIL_PRESENTATION'], '1')
            self.assertNotIn('ISAC_RETAIL_TUTORIAL', environment)

    def test_launcher_environment_and_direct_exec(self):
        with patch.object(sys,'argv',['probe','--','/steam wrapper','a b']), \
             patch.dict(os.environ,{'STEAM_COMPAT_INSTALL_PATH':'/game','ISAC_SDK_ADAPTER':'1','ISAC_RETAIL_HANDSHAKE':'1'},clear=True), \
             patch.object(probe.forward,'verify') as verify, \
             patch.object(probe,'prepare_capture',return_value=Path('/private')), \
             patch.object(probe.os,'execvpe') as execute:
            self.assertIsNone(probe.main())
            verify.assert_called_once_with(Path('/game'),probe=probe.PROBE)
            command,argv,env=execute.call_args.args
            self.assertEqual((command,argv),('/steam wrapper',['/steam wrapper','a b']))
            self.assertEqual({k for k in env if k.startswith('ISAC_')},{'ISAC_RETAIL_TUTORIAL','ISAC_RETAIL_CAPTURE_DIR'})
            self.assertEqual(env['ISAC_RETAIL_CAPTURE_DIR'],'Z:\\private\\tutorial-private')

    def test_private_permissions_and_marker_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'evidence').mkdir(); previous=os.umask(0o077)
            try:
                with patch.object(probe.forward,'ROOT',root),patch.object(probe.forward,'digest',return_value='fixture'):
                    capture=probe.prepare_capture()
                self.assertEqual(capture.stat().st_mode&0o777,0o700)
                self.assertEqual((capture/'tutorial-private').stat().st_mode&0o777,0o700)
                self.assertEqual((capture/'metadata.json').stat().st_mode&0o777,0o600)
                data=json.loads((capture/'metadata.json').read_text())
                self.assertFalse(data['replay_enabled']); self.assertFalse(data['responses_changed'])
                self.assertEqual(data['markers']['4'],'ai_spawned')
                self.assertEqual(data['markers']['5'],'safe_house_entered')
                self.assertEqual(data['markers']['6'],'merchant_accessed')
                self.assertEqual(data['markers']['7'],'coordinator_voice_onset')
                self.assertEqual(data['markers']['8'],'vault_attempt')
                self.assertEqual(data['markers']['9'],'combat_started')
                self.assertEqual(data['markers']['0'],'notable_enemy_action')
                self.assertEqual(data['markers']['10'],'combat_ended')
            finally:
                os.umask(previous)

    def test_portable_core_and_key_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'core'
            subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror',str(ROOT/'tests/retail_tutorial_core.c'),'-o',str(binary)],check=True,capture_output=True)
            result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=5)
            self.assertIn('fragmentation, filtering, markers, bounds passed',result.stdout)

    def test_verified_sites_and_forward_only_build(self):
        snapshot=ROOT/'private/tctd-runtime-text-dc921cc2dc6eeb2010544af75cdcc9a7f6fc15ae6ece47841a37866c03eefb74.bin'
        if not snapshot.exists():
            self.skipTest('private analyzed text unavailable')
        code=snapshot.read_bytes()
        source=(ROOT/'src/uplay_probe/retail_type5_win.c').read_text()
        selected=source.split('static const Site sites[] = {',1)[1].split('#elif defined(ISAC_RETAIL_HANDSHAKE)',1)[0]
        sites=re.findall(r'SITE\((0x[0-9a-f]+),"([^"]+)"\)',selected)
        # Tutorial/presentation sites plus the isolated vault-state variant.
        self.assertEqual(len(sites),14)
        for rva,signature in sites:
            expected=bytes.fromhex(signature.replace('\\x','')); offset=int(rva,16)-0x1000
            self.assertEqual(code[offset:offset+len(expected)],expected,rva)
        source=(ROOT/'tools/build-uplay-probe.sh').read_text()
        self.assertIn('stack_source="$source_dir/retail_tutorial_win.c"',source)
        self.assertIn('probe_defines=(-DISAC_RETAIL_ONLY=1)',source)

    def test_dialogue_node_vtable_slots_are_not_poll_rtpc(self):
        rdata_file=ROOT/'private/startup-leads-jcoCPbG7/static-rdata.bin'
        if not rdata_file.exists():
            self.skipTest('private analyzed rdata unavailable')
        data=rdata_file.read_bytes()
        self.assertEqual(data[:8],b'ISACRD01')
        rdata_rva=0x2901000
        image_base=0x140000000
        for name,vtable,method in (
            (b'audio:ExecuteDialogueEvent',0x2a34c28,0x6316d0),
            (b'audio:PostDialogueEvent',0x2a36a78,0x632dc0),
            (b'audio:ExecuteAgentDialogueEvent',0x31689f8,0x15c00a0),
            (b'audio:PollDialogueRTPC',0x2a36778,0x632b20)):
            self.assertIn(name+b'\0',data)
            self.assertEqual(struct.unpack_from('<Q',data,16+vtable+0xc0-rdata_rva)[0],
                             image_base+method)

    def test_redaction_fragmentation_markers_and_truncation(self):
        from isac_protocol.framing import MessageFrame,OutboundEnvelope,encode_length_prefixed_frame,encode_outbound_envelope
        connect=bytes(range(1,17))+b'\0'
        world=encode_length_prefixed_frame(MessageFrame(2,connect))+encode_length_prefixed_frame(MessageFrame(7,b'PRIVATE-PLAYER-DATA'))
        out=encode_outbound_envelope(OutboundEnvelope(3,0,(MessageFrame(0x88,b'PRIVATE-ITEM'),)))
        header=inspector.HEADER.pack(b'ISACTUT1',1,16)
        fixture=header
        for sequence,(kind,data) in enumerate(((1,world[:3]),(1,world[3:]),(3,connect),(2,out)),1):
            fixture+=inspector.RECORD.pack(sequence,1000+sequence*100,kind,1,len(data),int(sequence==1))+data
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'tutorial-1.bin'; path.write_bytes(fixture)
            path.with_suffix('.jsonl').write_text('\n'.join(json.dumps(row) for row in
                ({'event':'tutorial_ready','tick_ms':1000},
                 {'event':'marker','key':9,'tick_ms':1200},
                 {'event':'marker','key':4,'tick_ms':1250},
                 {'event':'marker','key':0,'tick_ms':1250},
                 {'event':'marker','key':10,'tick_ms':1400},
                 {'event':'tutorial_end','gaps':0,'core_failed':0}, {'event':'end','resume_failures':0})))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                messages,markers,issues=inspector.summary(path)
            self.assertEqual(len(messages),3)
            self.assertEqual(markers,[(1200,9),(1250,4),(1250,0),(1400,10)])
            self.assertFalse(issues)
            self.assertIn('ai_spawned',output.getvalue())
            self.assertIn('combat_segment=1 duration_ms=200',output.getvalue())
            self.assertIn('numpad=decimal',output.getvalue())
            self.assertNotIn('PRIVATE',output.getvalue())
            path.write_bytes(fixture[:-1])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertIn('truncated record payload',inspector.summary(path)[2])

    @unittest.skipUnless(os.environ.get('ISAC_TEST_TUTORIAL_PROTON')=='1','Opt-in actual Proton fixture')
    def test_actual_proton_lifecycle_and_ring_reuse(self):
        from test_retail_type5_proton import COMMON, STEAM_CLIENT
        with tempfile.TemporaryDirectory(prefix='isac-tutorial-proton-') as directory:
            work=Path(directory); (work/'compat').mkdir()
            binary=work/'tutorial.exe'; events=work/'tutorial-1.jsonl'; payload=events.with_suffix('.bin')
            subprocess.run(['x86_64-w64-mingw32-gcc','-O2','-Wall','-Wextra','-Werror',
                str(ROOT/'tests/retail_tutorial_wine.c'),str(ROOT/'tests/retail_handshake_fixture.S'),
                '-o',str(binary)],check=True,capture_output=True)
            env={k:v for k,v in os.environ.items() if not k.startswith(('LD_','PYTHON','WINE','ISAC_','STEAM_COMPAT_'))}
            env.update(STEAM_COMPAT_DATA_PATH=str(work/'compat'),STEAM_COMPAT_CLIENT_INSTALL_PATH=STEAM_CLIENT,
                       SteamAppId='0',SteamGameId='0',PROTON_LOG='1',PROTON_LOG_DIR=str(work),
                       WINEDEBUG='-all,+seh',WINEDLLOVERRIDES='mscoree,mshtml=')
            result=subprocess.run([str(COMMON/'SteamLinuxRuntime_4/_v2-entry-point'),'--verb=waitforexitandrun','--',
                str(COMMON/'Proton - Experimental/proton'),'waitforexitandrun',str(binary),
                'Z:'+str(events).replace('/','\\'),'Z:'+str(payload).replace('/','\\')],
                env=env,capture_output=True,text=True,timeout=60,umask=0o077)
            self.assertEqual(result.returncode,0,result.stdout[-2000:]+result.stderr[-2000:])
            rows=[json.loads(line) for line in events.read_text().splitlines()]
            self.assertEqual(rows[-1]['event'],'end'); self.assertEqual(rows[-1]['resume_failures'],0)
            self.assertEqual([r['key'] for r in rows if r['event']=='marker'],
                             list(range(1,10))+[0,10])
            self.assertEqual(len(list(inspector.records(payload))),605)
            self.assertNotIn(bytes([0xa5])*128,payload.read_bytes())
            with contextlib.redirect_stdout(io.StringIO()):
                messages,markers,issues=inspector.summary(payload)
            self.assertEqual(len(messages),602); self.assertEqual(len(markers),11); self.assertFalse(issues)
            self.assertNotIn('Unhandled exception',(work/'steam-0.log').read_text(errors='replace'))


if __name__=='__main__':
    unittest.main()
