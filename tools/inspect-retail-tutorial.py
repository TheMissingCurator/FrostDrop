#!/usr/bin/env python3
"""Redacted tutorial timelines and marker windows; never print payloads or IDs."""
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from isac_protocol.codec import DecodeError
from isac_protocol.framing import InboundFrameStreamDecoder, decode_outbound_envelope

HEADER=struct.Struct('<8sII')
RECORD=struct.Struct('<QQIIII')
LABELS={1:'world_loaded',2:'objective_started',3:'objective_completed',
        4:'ai_spawned',5:'safe_house_entered',6:'merchant_accessed',
        7:'coordinator_voice_onset',8:'vault_attempt',9:'combat_started',
        0:'notable_enemy_action',10:'combat_ended'}


def records(path):
    if path.stat().st_size>67108864+16:
        raise ValueError('oversized tutorial capture')
    with path.open('rb') as stream:
        header=stream.read(HEADER.size)
        if len(header)!=HEADER.size or HEADER.unpack(header)!=(b'ISACTUT1',1,16):
            raise ValueError('invalid tutorial header')
        expected=1
        while raw:=stream.read(RECORD.size):
            if len(raw)!=RECORD.size:
                raise ValueError('truncated record header')
            sequence,tick,kind,source,length,aux=RECORD.unpack(raw)
            if sequence!=expected or expected>500000 or kind not in range(1,9) or length>16384 or source>64:
                raise ValueError('invalid tutorial record')
            payload=stream.read(length)
            if len(payload)!=length:
                raise ValueError('truncated record payload')
            expected+=1
            yield tick,kind,source,aux,payload


def summary(path):
    presentation = path.stem.startswith('presentation-')
    node_names={7:'mission_objective_notification_node',8:'poll_dialogue_rtpc_node'}
    if presentation:
        capture_metadata=path.parent.parent/'metadata.json'
        if capture_metadata.exists():
            settings=json.loads(capture_metadata.read_text())
            sites=settings.get('node_sites',{})
            if sites=={'7':'execute-dialogue-event-evaluation',
                       '8':'execute-agent-dialogue-event-evaluation'}:
                node_names={7:'execute_dialogue_event_node',
                            8:'execute_agent_dialogue_event_node'}
    metadata=path.with_suffix('.jsonl')
    markers=[]; ended=False; issues=[]; origin=None; end_row=None
    if metadata.exists():
        if metadata.stat().st_size>1048576:
            raise ValueError('oversized tutorial metadata')
        for line in metadata.read_text().splitlines():
            try:
                row=json.loads(line)
            except json.JSONDecodeError:
                issues.append('partial metadata record'); continue
            if row.get('event')=='tutorial_ready':
                origin=row.get('tick_ms')
            elif row.get('event')=='marker':
                key,tick=row.get('key'),row.get('tick_ms')
                if type(key) is not int or key not in LABELS or type(tick) is not int or tick<0:
                    raise ValueError('invalid marker')
                markers.append((tick,key))
            elif row.get('event')=='tutorial_end':
                end_row=row
                if row.get('gaps') or row.get('core_failed'):
                    issues.append('observer gap/limit/read failure')
            elif row.get('event')=='refused':
                issues.append('observer refused')
            elif row.get('event')=='end':
                ended=True
                if row.get('resume_failures'):
                    issues.append('thread resume failure')
    messages=[]; counts=Counter(); decoders={}; sync=[]; connect=[]; creation=[]; sync_bodies=[]; connect_bodies=[]; node_events=[]
    try:
        for tick,kind,source,aux,payload in records(path):
            if origin is None:
                origin=tick
            counts[kind]+=1
            if kind==1:
                if not source:
                    raise ValueError('world record missing source')
                decoder=decoders.setdefault(source,InboundFrameStreamDecoder(maximum_frame_length=16777216))
                if aux&1:
                    sync.append(source)
                for frame in decoder.feed(payload):
                    if not messages and frame.type_id==2 and len(frame.body)==17:
                        sync_bodies.append(frame.body)
                    messages.append((tick,'in',frame.type_id,len(frame.body)))
            elif kind==2:
                envelope=decode_outbound_envelope(payload)
                if envelope.channel!=0 or any(f.type_id in (0,2) for f in envelope.frames):
                    raise ValueError('credential/nonworld outbound record')
                messages.extend((tick,'out',f.type_id,len(f.body)) for f in envelope.frames)
            elif kind==3:
                if len(payload)!=17 or payload[16]>1:
                    raise ValueError('invalid reconstructed connect reply')
                connect.append((tick,bool(payload[16]),not any(payload[:16])))
                connect_bodies.append(payload)
            elif kind==4:
                if len(payload)!=(0 if aux else 16):
                    raise ValueError('invalid reconstructed create reply')
                creation.append(aux)
            elif kind==6:
                issues.append('observer field error code='+str(aux))
            elif kind in (7,8):
                if payload:
                    raise ValueError('presentation event must have no payload')
                node_events.append((tick,kind,aux))
            if len(messages)>200000:
                raise ValueError('message analysis limit')
    except (ValueError,DecodeError) as error:
        issues.append(str(error))
    pending=sum(d.buffered_bytes for d in decoders.values())
    correlated=bool(sync_bodies and connect_bodies and sync_bodies[0] in connect_bodies)
    if decoders and not correlated and not presentation:
        issues.append('selected stream not correlated with parsed connect reply')
    if pending:
        issues.append('incomplete world frame tail')
    if not ended:
        issues.append('no end record; process exit or capture still running')
    print('world_streams='+str(len(decoders))+' sync_records='+str(len(sync))
          +' parsed_messages='+str(len(messages))+' pending_bytes='+str(pending))
    print('connect_replies='+str(len(connect))+' create_reply_statuses='+str(creation))
    print('connect_reply_correlated='+str(correlated))
    if end_row:
        print('observer_records='+str(end_row.get('records'))+' markers='+str(end_row.get('markers')))
    for tick,flag,zero in connect:
        print('connect_reply parsed_bool='+str(flag)+' prefix_zero='+str(zero))
    if presentation:
        for tick,kind,caller in node_events[:256]:
            print(f'client_node={node_names[kind]} relative_ms={tick-(origin or tick)} '
                  f'caller_rva={caller:#x} execution_result=unobserved')
        if len(node_events)>256:
            print(f'client_node_events_omitted={len(node_events)-256}')
        print('client_node_counts='+','.join(f'{node_names[k]}:{counts[k]}' for k in (7,8)))
    for direction in ('in','out'):
        counter=Counter(type_id for _,d,type_id,_ in messages if d==direction)
        print(direction+'_type_counts='+','.join(f'0x{k:04x}:{v}' for k,v in sorted(counter.items())))
    for index,(tick,key) in enumerate(markers,1):
        before=Counter((d,t) for when,d,t,_ in messages if tick-3000<=when<tick)
        after=Counter((d,t) for when,d,t,_ in messages if tick<=when<=tick+5000)
        fmt=lambda values: ','.join(f'{d}/0x{t:04x}:{n}' for (d,t),n in values.most_common(12)) or 'none'
        pad='decimal' if key==10 else str(key)
        print(f'marker={index} numpad={pad} label={LABELS[key]} relative_ms={tick-(origin or tick)}')
        print('  before_3s='+fmt(before)); print('  after_5s='+fmt(after))
    combat_start=None
    combat_number=0
    for tick,key in markers:
        if key==9:
            combat_start=tick
        elif key==10 and combat_start is not None:
            combat_number+=1
            during=Counter((direction,type_id) for when,direction,type_id,_ in messages
                           if combat_start<=when<=tick)
            kinds=','.join(f'{direction}/0x{type_id:04x}:{count}'
                           for (direction,type_id),count in during.most_common(20)) or 'none'
            print(f'combat_segment={combat_number} duration_ms={tick-combat_start} '
                  f'message_types={kinds}')
            combat_start=None
    if combat_start is not None:
        print('combat_segment_unclosed=1')
    print('capture_notes='+'; '.join(dict.fromkeys(issues)) if issues else 'capture_notes=no detected gaps')
    if not messages:
        print('No selected world messages; do not treat this as a usable gameplay capture.')
    return messages,markers,issues


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    args=parser.parse_args()
    files=(sorted((args.capture/'tutorial-private').glob('tutorial-*.bin'))+
           sorted((args.capture/'presentation-private').glob('presentation-*.bin'))
           if args.capture.is_dir() else [args.capture])
    if not files:
        parser.error('no tutorial payload files')
    for path in files:
        print(path.name); summary(path)


if __name__=='__main__':
    main()
