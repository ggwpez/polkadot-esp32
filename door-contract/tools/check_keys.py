#!/usr/bin/env python3
"""Verify live key-policy proofs, then exercise the firmware's RFID admission code."""
from pathlib import Path
import subprocess
import sys
import time
import door

door.CONTRACT = 'door-keys'
door.DEPLOYMENT = door.PROJECT / 'keys-deployment.json'
names = ('Alice', 'Bob', 'Charlie')
expected = ('Alice', 'Bob') if sys.argv[1] == 'Both' else () if sys.argv[1] == 'None' else (sys.argv[1],)
if any(name not in names[:2] for name in expected):
    sys.exit('Expected Alice, Bob, or Both')
# The signing WebSocket and proof HTTP endpoint can briefly expose different
# finalized heads. Retry a valid older policy; never suppress proof failures.
for attempt in range(12):
    _, policy = door.policy_at_finalized()
    digests = [door.commitment(name, policy[8:40]) for name in names]
    active = [policy[i:i+32] for i in range(40, len(policy), 32) if any(policy[i:i+32])]
    if active == [digests[names.index(name)] for name in expected]:
        break
    if attempt < 11:
        time.sleep(3)
else:
    sys.exit('Live policy is not the expected assignment')

def array(data): return '{' + ','.join(str(b) for b in data) + '}'

source = '#include "door_policy.h"\n#include <assert.h>\nint main(void) {\n'
source += f'unsigned char policy[392] = {array(policy)};\n'
source += 'unsigned char digests[3][32] = {' + ','.join(array(d) for d in digests) + '};\n'
source += 'door_policy_state state = {0};\n'
source += 'assert(door_policy_accept(&state,policy,sizeof policy,100,1788800000000ULL,1788800000000ULL,1000));\n'
for index, name in enumerate(names):
    source += f'assert(door_policy_scan(&state,digests[{index}],1001)=={int(name in expected)});\n'
    source += f'assert(door_policy_unlocked(&state,1002)=={int(name in expected)});\n'
if expected:
    source += f'assert(door_policy_scan(&state,digests[{names.index(expected[0])}],2000));\n'
    source += 'assert(door_policy_unlocked(&state,6999)); assert(!door_policy_unlocked(&state,7000));\n'
source += 'return 0; }\n'
tmp = door.LOCAL / 'tmp'
tmp.mkdir(parents=True, exist_ok=True)
path = tmp / 'check-live-keys.c'
path.write_text(source)
executable = tmp / 'check-live-keys'
subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-I' + str(door.ROOT / 'polkadot-lightclient/src'),
    str(path), str(door.ROOT / 'polkadot-lightclient/src/door_policy.c'), '-o', str(executable)], check=True)
subprocess.run([str(executable)], check=True)
summary = f'{sys.argv[1]} admitted, unauthorized named keys denied, five-second relock passed' if expected else 'all named keys denied; door stays closed'
print(f'Live proofs verified: {summary} (revision {int.from_bytes(policy[4:8], "little")}).')
