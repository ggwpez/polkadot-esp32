#!/usr/bin/env python3
"""Devnet contract administration; run from the door-sensor directory as
.venv/bin/python door-contract/tools/door.py ... ."""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "door-contract"
LOCAL = ROOT / ".local-backups/door"
RPC = "https://asset-hub-paseo-rpc.n.dwellir.com"
WS = "wss://asset-hub-paseo-rpc.n.dwellir.com"
GENESIS = "0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2"
PACKAGE = "@example/door-policy"
# Synthetic examples; replace with your tag UIDs before deploying.
NAMED = {"alice": "04:00:00:00:00:00:01", "bob": "00:00:00:02", "charlie": "04:00:00:00:00:00:03"}
RAW_KEY = b"door.policy.v1"
STORAGE_KEY = hashlib.blake2b(RAW_KEY, digest_size=16).digest() + RAW_KEY
CDM = str(PROJECT / "node_modules/.bin/cdm")
DEPLOYMENT = PROJECT / "deployment.json"
CONTRACT = "door-policy"
POLICY_LEN = 392
MAGIC = b"DOR1"

def secret(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing {name}; export it in your environment (see README.md)")
    return value

def salt_bytes():
    return int(secret("DOOR_SALT_HEX"), 16).to_bytes(32, "big")

def commitment(uid, salt=None):
    uid = NAMED.get(uid.lower(), uid)
    if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){3,9}", uid):
        raise ValueError("UID must be Alice/Bob/Charlie or colon-separated hexadecimal bytes")
    raw = bytes.fromhex(uid.replace(":", ""))
    if len(raw) not in (4, 7, 10):
        raise ValueError("UID must contain 4, 7 or 10 bytes")
    pepper = bytes.fromhex(secret("DOOR_PEPPER_HEX"))
    if len(pepper) != 32:
        raise ValueError("Pepper must be 32 bytes")
    return hmac.digest(pepper, b"door-key:" + (salt if salt is not None else salt_bytes()) + bytes([len(raw)]) + raw, "sha256")

def run(args, log=None):
    result = subprocess.run(args, cwd=PROJECT, capture_output=True, text=True)
    # CLI arguments can include a signing secret; never echo commands/errors containing it.
    output = result.stdout + result.stderr
    mnemonic = os.environ.get("DOOR_MNEMONIC", "")
    if mnemonic:
        output = output.replace(mnemonic, "[REDACTED]")
    if log:
        LOCAL.mkdir(parents=True, exist_ok=True)
        (LOCAL / log).write_text(output)
    if result.returncode:
        raise RuntimeError(output)
    return output

def chain():
    from substrateinterface import SubstrateInterface
    api = SubstrateInterface(url=RPC)
    if api.get_block_hash(0) != GENESIS:
        raise RuntimeError("Wrong Asset Hub genesis")
    return api

def signer():
    from substrateinterface import Keypair
    key = Keypair.create_from_mnemonic(secret("DOOR_MNEMONIC"))
    if key.ss58_address != secret("DOOR_ADMIN_ADDRESS"):
        raise RuntimeError("Mnemonic does not match configured admin")
    return key

def restore_account():
    key = signer()
    path = Path.home() / ".cdm/accounts.json"
    records = json.loads(path.read_text()) if path.exists() else {}
    if "devnet" in records and records["devnet"]["address"] != key.ss58_address:
        raise RuntimeError("CDM devnet account differs; refusing to overwrite it")
    records["devnet"] = {"address": key.ss58_address, "mnemonic": secret("DOOR_MNEMONIC")}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(records, f)
    path.chmod(0o600)

def address():
    path = DEPLOYMENT
    if not path.exists():
        raise RuntimeError("No deployment.json; deploy or resolve first")
    value = json.loads(path.read_text())["address"]
    if value == "0x" + "0" * 40:
        raise RuntimeError("Placeholder contract address; deploy your own contract first")
    return value

def call(function, *args):
    data = run(["cargo", "pvm-contract", "encode", "--abi", str(PROJECT / f"target/release/{CONTRACT}.abi.json"),
                "--function", function, *map(str, args)]).strip()
    # Encode prints only calldata in the current pinned tooling.
    match = re.search(r"0x[0-9a-fA-F]+", data)
    if not match:
        raise RuntimeError("Encoder did not return calldata")
    signer()
    output = run(["node", "tools/submit.mjs", "call", address(), match[0]], log=f"call-{function}.log")
    print(output)

def resolve():
    print(run([CDM, "install", PACKAGE, "-n", "devnet"], "resolve.log"))
    cdm = json.loads((PROJECT / "cdm.json").read_text())
    entry = cdm["contracts"][PACKAGE]
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", entry["address"]):
        raise RuntimeError("Registry returned malformed address")
    (PROJECT / "deployment.json").write_text(json.dumps({"network": "devnet", "genesis": GENESIS,
        "package": PACKAGE, **entry}, indent=2) + "\n")

def verify(root, key, nodes):
    """Use the firmware's C verifier, not a second implementation."""
    libpath = LOCAL / "tmp/libdoorproof.so"
    libpath.parent.mkdir(parents=True, exist_ok=True)
    sources = [PROJECT / "tools/proof_verify.c"] + [ROOT / "polkadot-lightclient/src" / n
               for n in ("trie.c", "lc_crypto.c", "scale.c", "lc_reader.c")]
    if not libpath.exists() or any(p.stat().st_mtime > libpath.stat().st_mtime for p in sources):
        run(["gcc", "-shared", "-fPIC", "-O2", "-I" + str(ROOT / "polkadot-lightclient/src"),
             *map(str, sources), "-l:libsodium.so.23", "-o", str(libpath)])
    lib = ctypes.CDLL(str(libpath))
    ptr = ctypes.POINTER(ctypes.c_ubyte)
    lib.door_verify.argtypes = [ptr, ptr, ctypes.c_size_t, ctypes.POINTER(ptr),
                               ctypes.POINTER(ctypes.c_size_t), ctypes.c_size_t, ptr, ctypes.c_size_t]
    lib.door_verify.restype = ctypes.c_int
    array = lambda b: (ctypes.c_ubyte * len(b)).from_buffer_copy(b)
    buffers = [array(bytes.fromhex(n.removeprefix("0x"))) for n in nodes]
    refs = (ptr * len(buffers))(*[ctypes.cast(b, ptr) for b in buffers])
    lengths = (ctypes.c_size_t * len(buffers))(*map(len, buffers))
    out = (ctypes.c_ubyte * 4096)()
    n = lib.door_verify(array(root), array(key), len(key), refs, lengths, len(buffers), out, len(out))
    if n < 0:
        raise RuntimeError(f"Firmware trie verifier rejected proof ({n})")
    return bytes(out[:n])

def rpc(api, method, params):
    result = api.rpc_request(method, params)
    if "error" in result:
        raise RuntimeError(str(result["error"]))
    return result["result"]

def unhex(value):
    return bytes.fromhex(value.removeprefix("0x")) if isinstance(value, str) else bytes(value)

def policy_at_finalized():
    api = chain()
    at = api.get_chain_finalised_head()
    account = api.query("Revive", "AccountInfoOf", [address()], block_hash=at)
    info = account.value
    if not info:
        raise RuntimeError("No contract at configured address")
    # Runtime metadata decodes the account variant; fail instead of guessing layout.
    def find_trie(value):
        if isinstance(value, dict):
            if "trie_id" in value:
                return value["trie_id"]
            for sub in value.values():
                found = find_trie(sub)
                if found is not None:
                    return found
        return None
    trie = find_trie(info)
    if trie is None:
        raise RuntimeError("AccountInfoOf has no contract trie_id")
    child = b":child_storage:default:" + unhex(trie)
    top_key = "0x" + child.hex()
    root = unhex(rpc(api, "chain_getHeader", [at])["stateRoot"])
    account_key = api.create_storage_key("Revive", "AccountInfoOf", [address()]).to_hex()
    top = rpc(api, "state_getReadProof", [[top_key, account_key], at])
    if verify(root, unhex(account_key), top["proof"]) != bytes(account.data.data):
        raise RuntimeError("Contract account metadata did not match its state proof")
    from Crypto.Hash import keccak
    expected_code = keccak.new(digest_bits=256, data=(PROJECT/f"target/release/{CONTRACT}.polkavm").read_bytes()).digest()
    contract_info = info["account_type"]["Contract"]
    if unhex(contract_info["code_hash"]) != expected_code:
        raise RuntimeError("Deployed code does not match the local Rust contract artifact")
    child_root = verify(root, child, top["proof"])
    if len(child_root) != 32:
        raise RuntimeError("Invalid child root length")
    proof = rpc(api, "state_getChildReadProof", [top_key, ["0x"+STORAGE_KEY.hex()], at])
    value = verify(child_root, STORAGE_KEY, proof["proof"])
    if len(value) != POLICY_LEN or value[:4] != MAGIC or (MAGIC == b"DOR2" and value[8] > 1):
        raise RuntimeError("Unknown policy format")
    evidence = {"at": at, "address": address(), "stateRoot": "0x"+root.hex(),
                "childKey": top_key, "storageKey": "0x"+STORAGE_KEY.hex(), "accountInfo": info,
                "accountKey": account_key,
                "topProof": top, "childProof": proof, "policy": "0x"+value.hex()}
    LOCAL.mkdir(parents=True, exist_ok=True)
    (LOCAL / f"{CONTRACT}-proof.json").write_text(json.dumps(evidence, indent=2)+"\n")
    return child, value

def main():
    global DEPLOYMENT, CONTRACT, POLICY_LEN, MAGIC, RAW_KEY, STORAGE_KEY
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group()
    modes.add_argument("--toggle", action="store_true", help="Use the legacy public door-toggle contract")
    modes.add_argument("--keys", action="store_true", help="Use the public Alice/Bob key-assignment contract")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("status", "resolve", "configure-salt", "provision", "inspect", "toggle"):
        sub.add_parser(name)
    a = sub.add_parser("deploy")
    a.add_argument("--register", action="store_true", help="Publish through CDM; requires Bulletin authorization")
    a = sub.add_parser("allow"); a.add_argument("slot", type=int, choices=range(11)); a.add_argument("uid")
    a = sub.add_parser("revoke"); a.add_argument("slot", type=int, choices=range(11))
    a = sub.add_parser("hash"); a.add_argument("uid")
    a = sub.add_parser("assign"); a.add_argument("key", choices=("Alice", "Bob", "Both", "None"))
    for command in ("enable", "disable"):
        a = sub.add_parser(command); a.add_argument("key", choices=("Alice", "Bob"))
    args = p.parse_args()
    if args.toggle:
        DEPLOYMENT = PROJECT / "toggle-deployment.json"
        CONTRACT, POLICY_LEN, MAGIC = "door-toggle", 9, b"DOR2"
        RAW_KEY = b"door.toggle.v1"
        STORAGE_KEY = hashlib.blake2b(RAW_KEY, digest_size=16).digest() + RAW_KEY
        if args.command not in ("status", "deploy", "provision", "inspect", "toggle") or getattr(args, "register", False):
            raise RuntimeError("Public toggle supports direct deploy, status, provision, inspect and toggle")
    elif args.keys:
        DEPLOYMENT = PROJECT / "keys-deployment.json"
        CONTRACT = "door-keys"
        if args.command not in ("status", "deploy", "provision", "inspect", "assign", "enable", "disable") or getattr(args, "register", False):
            raise RuntimeError("Key assignment supports direct deploy, status, provision, inspect and assign")
    elif args.command in ("toggle", "assign", "enable", "disable"):
        raise RuntimeError("Use --keys assign Alice/Bob/Both, or --toggle toggle for the legacy toggle contract")
    if args.command == "hash":
        print("0x"+commitment(args.uid).hex()); return
    if args.command == "status":
        restore_account(); print(run([CDM,"account","bal","-n","devnet"])); return
    if args.command == "deploy":
        if DEPLOYMENT.exists():
            raise RuntimeError("deployment.json already exists; refusing an accidental second deployment")
        restore_account(); api = chain()
        account = api.query("System", "Account", [secret("DOOR_ADMIN_ADDRESS")]).value
        if int(account["data"]["free"]) == 0:
            raise RuntimeError("Fund " + secret("DOOR_ADMIN_ADDRESS") + " at https://faucet.polkadot.io/paseo?parachain=1000")
        from Crypto.Hash import keccak
        h160 = "0x" + keccak.new(digest_bits=256, data=signer().public_key).digest()[12:].hex()
        if not api.query("Revive", "OriginalAccount", [h160]).value:
            print(run(["node", "tools/submit.mjs", "map"], "map.log"))
        print(run([CDM,"build","--contracts",CONTRACT,"-n","devnet"],f"{CONTRACT}-build.log"))
        abi = json.loads((PROJECT/f"target/release/{CONTRACT}.abi.json").read_text())
        if not any(x.get("name")==("toggle" if args.toggle else "assignKey" if args.keys else "setKey") for x in abi):
            raise RuntimeError("Missing expected ABI")
        if args.register:
            print(run([CDM,"deploy","-n","devnet"],"deploy.log")); resolve(); return
        # Constructor ABI: three fixed-width uint256 words, without a selector.
        constructor_data = "0x" + (salt_bytes() + commitment("Alice") + commitment("Bob")).hex() if args.keys else "0x"
        output = run(["node", "tools/submit.mjs", "deploy", str(PROJECT/f"target/release/{CONTRACT}.polkavm"), constructor_data],f"{CONTRACT}-deploy.log")
        print(output)
        match=re.search(r"Contract address:\s*(0x[0-9a-fA-F]{40})",output)
        if not match: raise RuntimeError("Inspect deploy.log: transaction returned no recognizable address")
        DEPLOYMENT.write_text(json.dumps({"network":"devnet","genesis":GENESIS,
            "address":match[1],("deployer" if args.toggle or args.keys else "admin"):secret("DOOR_ADMIN_ADDRESS"),
            "transaction":re.search(r"Finalized transaction:\s*(0x[0-9a-fA-F]{64})",output)[1],
            "registered":False},indent=2)+"\n")
        return
    if args.command == "toggle": call("toggle"); return
    if args.command in ("enable", "disable"):
        call("setKeyEnabled", ("Alice", "Bob").index(args.key), "true" if args.command == "enable" else "false"); return
    if args.command == "assign": call("assignKey", ("Alice", "Bob", "Both", "None").index(args.key)); return
    if args.command == "resolve": resolve(); return
    if args.command == "configure-salt": call("configureSalt",int.from_bytes(salt_bytes(),"big")); return
    if args.command == "revoke": call("setKey",args.slot,0); return
    child, policy = policy_at_finalized()
    if args.command == "allow":
        if policy[8:40] == bytes(32): raise RuntimeError("Run configure-salt first")
        call("setKey",args.slot,int.from_bytes(commitment(args.uid,policy[8:40]),"big")); return
    if args.command == "inspect":
        if args.keys:
            alice, bob = (commitment(name, policy[8:40]) for name in ("Alice", "Bob"))
            active = [policy[i:i+32] for i in range(40, POLICY_LEN, 32) if any(policy[i:i+32])]
            selected = "Alice" if active == [alice] else "Bob" if active == [bob] else "Both" if active == [alice, bob] else "None" if not active else None
            if selected is None: raise RuntimeError("Policy is not a valid named-key assignment")
            print(json.dumps({"address":address(), "revision":int.from_bytes(policy[4:8],"little"),
                              "assignedKey":selected},indent=2)); return
        if args.toggle:
            print(json.dumps({"address":address(), "revision":int.from_bytes(policy[4:8],"little"),
                              "open":bool(policy[8])},indent=2)); return
        print(json.dumps({"address":address(), "revision":int.from_bytes(policy[4:8],"little"),
              "activeSlots":[i for i in range(11) if any(policy[40+32*i:72+32*i])]},indent=2)); return
    if args.command == "provision":
        pepper = bytes(32) if args.toggle else bytes.fromhex(secret("DOOR_PEPPER_HEX"))
        if len(pepper)!=32: raise RuntimeError("Pepper must be 32 bytes")
        text = '#pragma once\n#include <stdint.h>\n#define DOOR_CONFIGURED 1\n'
        for name, data in (("DOOR_CHILD_KEY",child),("DOOR_STORAGE_KEY",STORAGE_KEY),("DOOR_PEPPER",pepper)):
            text += f'static const uint8_t {name}[{len(data)}] = {{'+','.join(f'0x{b:02x}' for b in data)+'};\n'
        path=ROOT/"polkadot-lightclient/src/door.local.h"
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,"w") as f: f.write(text)
        path.chmod(0o600)
        print("Provisioned contract child trie" + (" for public toggle" if args.toggle else " and pepper") + "; rebuild and flash firmware.")

if __name__ == "__main__":
    try: main()
    except Exception as e:
        message = str(e)
        for name in ("DOOR_MNEMONIC","DOOR_PEPPER_HEX"):
            if os.environ.get(name): message=message.replace(os.environ[name],"[REDACTED]")
        sys.exit(message)
