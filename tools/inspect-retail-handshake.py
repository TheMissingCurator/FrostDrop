#!/usr/bin/env python3
"""Summarize fingerprint correlations, never print private values or hashes."""
import argparse
import json
from pathlib import Path
import re

EVENTS={'auth_reply','join_reply','instance_connect','game_connect_reply'}


def summarize(path):
    if path.stat().st_size>1024*1024:
        raise ValueError('oversized handshake capture')
    auth=[]; joins=[]; ended=False
    for line in path.read_text().splitlines():
        try:
            row=json.loads(line)
        except json.JSONDecodeError:
            print('incomplete JSON record; ignored')
            continue
        event=row.get('event')
        if event in ('starting','ready','refused','end'):
            print('observer='+event)
            ended |= event=='end'
            continue
        if event not in EVENTS:
            continue
        if row.get('encoding')!='handshake-metadata-v1' or row.get('complete') is not True:
            print('event='+event+' incomplete-field-capture; ignored')
            continue
        tokens=row.get('tokens',[])
        if not isinstance(tokens,list) or len(tokens)>4:
            raise ValueError('invalid token metadata')
        for index,t in enumerate(tokens):
            if (t.get('slot')!=index+1 or not isinstance(t.get('length'),int)
                    or not 0<=t['length']<=1024 or not re.fullmatch('[0-9a-f]{64}',t.get('sha256',''))
                    or not isinstance(t.get('remaining_seconds_estimate'),int)
                    or not 0<=t['remaining_seconds_estimate']<1<<64):
                raise ValueError('invalid token fingerprint record')
        print('event='+event+' token_lengths='+str([t['length'] for t in tokens])
              +' remaining_seconds_estimates='+str([t['remaining_seconds_estimate'] for t in tokens]))
        if event=='auth_reply':
            auth.extend(tokens)
        elif event=='join_reply':
            if type(row.get('flag')) is not int or row['flag'] not in (0,1):
                raise ValueError('invalid join flag')
            print('join_success='+str(bool(row['flag'])))
            if row['flag']:
                if type(row.get('uint32_c')) is not int or not 0<=row['uint32_c']<1<<32:
                    raise ValueError('invalid join scalar')
                print('join_uint32_c='+str(row['uint32_c']))
                joins.extend(tokens)
        elif event=='instance_connect':
            for t in tokens:
                # Empty-token hashes are not evidence of credential lineage.
                matches=lambda group:[g['slot'] for g in group if t['length'] and g['length']==t['length'] and g['sha256']==t['sha256']]
                print(f"instance_slot={t['slot']} auth_slot_matches={matches(auth)} join_token_match={bool(matches(joins))}")
        elif event=='game_connect_reply':
            if type(row.get('flag')) is not int or row['flag'] not in (0,1):
                raise ValueError('invalid connect flag')
            print('game_connect_reply_delimiter=0x0002 parsed_bool='+str(bool(row['flag']))
                  +' prefix_field_bytes=16')
    if not ended:
        print('No end record: observations may still be usable; absence of an event is not conclusive.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    args=parser.parse_args()
    files=sorted((args.capture/'handshake-private').glob('handshake-*.jsonl')) if args.capture.is_dir() else [args.capture]
    for file in files:
        print(file.name); summarize(file)


if __name__=='__main__':
    main()
