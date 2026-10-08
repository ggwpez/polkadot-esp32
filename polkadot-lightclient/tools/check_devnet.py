#!/usr/bin/env python3
"""Read-only Products Devnet preflight; RPC consistency is not proof verification.

Run with a Python environment containing xxhash and websocket-client.
Endpoint source: https://docs.polkadotcommunity.foundation/reference/networks/
"""
import concurrent.futures
import datetime
import json
import ssl
import urllib.request

import websocket
from gen_checkpoint import twox128, twox64_concat, Dec, h2b

RELAY = ["https://paseo-rpc.n.dwellir.com",
         "https://paseo-v2.rpc.turboflakes.io"]
HUB = ["https://asset-hub-paseo-rpc.n.dwellir.com",
       "https://sys.turboflakes.io/asset-hub-paseo"]
GENESIS = {
    "relay": "0x374057be67b355151f271ff70c3db98308c62c8adc48dc6724b6a009a1a014fd",
    "hub": "0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2",
}


def rpc(url, method, params=None):
    # Match the controller's TLS version before attempting a flash.
    ctx = ssl.create_default_context()
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    body = dict(jsonrpc="2.0", id=1, method=method, params=params or [])
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=25) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method}: {result['error']}")
    return result["result"]


def check(role, url):
    result = dict(role=role, endpoint=url)
    try:
        result["chain"] = rpc(url, "system_chain")
        result["genesis"] = rpc(url, "chain_getBlockHash", [0])
        if result["genesis"] != GENESIS[role]:
            raise ValueError("wrong genesis")
        head = rpc(url, "chain_getFinalizedHead")
        header = rpc(url, "chain_getHeader", [head])
        number = int(header["number"], 16)
        result.update(finalized_hash=head, finalized_number=number)
        version = rpc(url, "state_getRuntimeVersion", [head])
        result["runtime"] = {k: version[k] for k in ("specName", "specVersion", "stateVersion")}
        key = "0x" + (twox128("System") + twox128("Number")).hex()
        value = rpc(url, "state_getStorage", [key, head])
        result["system_number"] = int.from_bytes(h2b(value), "little")
        if result["system_number"] != number:
            raise ValueError("System::Number differs from header")
        proof = rpc(url, "state_getReadProof", [[key], head])
        if proof["at"] != head or not proof["proof"]:
            raise ValueError("missing proof or wrong proof block")
        result["storage_proof_bytes"] = sum(len(h2b(n)) for n in proof["proof"])
        if role == "relay":
            auth = rpc(url, "state_call", ["GrandpaApi_grandpa_authorities", "0x", head])
            result["authorities"] = Dec(h2b(auth)).compact()
            result["set_id"] = int.from_bytes(h2b(rpc(url, "state_call",
                ["GrandpaApi_current_set_id", "0x", head])), "little")
            finality = rpc(url, "grandpa_proveFinality", [number])
            if not finality:
                raise ValueError("no finality proof available at head")
            result["finality_proof_bytes"] = len(h2b(finality))
            key = "0x" + (twox128("Paras") + twox128("Heads") +
                           twox64_concat((1000).to_bytes(4, "little"))).hex()
            if not rpc(url, "state_getStorage", [key, head]):
                raise ValueError("no para 1000 head")
            ws = websocket.create_connection(url.replace("https:", "wss:"), timeout=25,
                                             sslopt={"ssl_version": ssl.PROTOCOL_TLSv1_2})
            try:
                ws.send(json.dumps(dict(jsonrpc="2.0", id=1,
                    method="chain_subscribeFinalizedHeads", params=[])))
                reply = json.loads(ws.recv())
                if "result" not in reply:
                    raise ValueError(f"subscription failed: {reply}")
                notification = json.loads(ws.recv())
                if notification.get("method") != "chain_finalizedHead":
                    raise ValueError("missing finalized-head notification")
                result["websocket_tls12"] = True
            finally:
                ws.close()
        else:
            key = "0x" + (twox128("ParachainInfo") + twox128("ParachainId")).hex()
            result["para_id"] = int.from_bytes(h2b(rpc(url, "state_getStorage", [key, head])), "little")
            if result["para_id"] != 1000:
                raise ValueError("wrong para ID")
        result["ok"] = True
    except Exception as error:
        result.update(ok=False, error=str(error))
    return result


if __name__ == "__main__":
    jobs = [("relay", u) for u in RELAY] + [("hub", u) for u in HUB]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        results = list(pool.map(lambda job: check(*job), jobs))
    print(json.dumps(dict(checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          note="RPC sanity only; verify signatures and Merkle proofs separately",
                          results=results), indent=2))
    raise SystemExit(0 if all(r["ok"] for r in results) else 1)
