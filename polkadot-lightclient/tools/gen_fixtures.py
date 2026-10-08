#!/usr/bin/env python3
"""Capture live mainnet data into test/fixtures/ so the C verification core can
be tested on a host, with real signatures and real proofs, without a board.

Everything captured is internally consistent: the justification, the header it
commits to, and both storage proofs all come from the same relay block.

  python3 tools/gen_fixtures.py
"""
import argparse, json, urllib.request, hashlib, struct, os, sys, xxhash

REL = "https://polkadot.api.onfinality.io/public"
AHUB = "https://statemint.api.onfinality.io/public"
OUT = os.path.join(os.path.dirname(__file__), "..", "test", "fixtures")


def rpc(method, params=None, endpoint=None):
    req = urllib.request.Request(
        endpoint or REL,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params or []}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.0"})
    r = json.load(urllib.request.urlopen(req, timeout=60))
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def h2b(h): return bytes.fromhex(h[2:] if h.startswith("0x") else h)
def blake256(b): return hashlib.blake2b(b, digest_size=32).digest()
def twox128(s):
    b = s.encode() if isinstance(s, str) else s
    return b"".join(xxhash.xxh64(b, seed=i).intdigest().to_bytes(8, "little") for i in (0, 1))
def twox64_concat(b): return xxhash.xxh64(b, seed=0).intdigest().to_bytes(8, "little") + b


def enc_compact(v):
    if v < 64: return bytes([v << 2])
    if v < 2**14: return (v << 2 | 1).to_bytes(2, "little")
    if v < 2**30: return (v << 2 | 2).to_bytes(4, "little")
    n = (v.bit_length() + 7) // 8
    return bytes([(n - 4) << 2 | 3]) + v.to_bytes(n, "little")


class Dec:
    def __init__(self, b): self.b, self.i = b, 0
    def take(self, n):
        if self.i + n > len(self.b): raise ValueError("truncated")
        v = self.b[self.i:self.i + n]; self.i += n; return v
    def u32(self): return int.from_bytes(self.take(4), "little")
    def u64(self): return int.from_bytes(self.take(8), "little")
    def compact(self):
        b0 = self.b[self.i]; m = b0 & 3
        if m == 0: self.i += 1; return b0 >> 2
        if m == 1: return int.from_bytes(self.take(2), "little") >> 2
        if m == 2: return int.from_bytes(self.take(4), "little") >> 2
        n = (b0 >> 2) + 4; self.i += 1
        return int.from_bytes(self.take(n), "little")


def pack_nodes(nodes):
    """u32 count, then per node u32 len + bytes."""
    out = struct.pack("<I", len(nodes))
    for n in nodes:
        out += struct.pack("<I", len(n)) + n
    return out


def carray(name, data, per_line=16):
    out = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), per_line):
        out.append("    " + " ".join(f"0x{b:02x}," for b in data[i:i + per_line]))
    out.append("};")
    return "\n".join(out)


def main():
    global REL, AHUB, OUT
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--relay', default=REL)
    ap.add_argument('--hub', default=AHUB)
    ap.add_argument('--out', default=OUT)
    args = ap.parse_args()
    REL, AHUB, OUT = args.relay, args.hub, args.out
    os.makedirs(OUT, exist_ok=True)

    print("capturing authority set ...")
    head0 = rpc("chain_getFinalizedHead")
    d = Dec(h2b(rpc("state_call", ["GrandpaApi_grandpa_authorities", "0x", head0])))
    n = d.compact()
    auth = [(d.take(32), d.u64()) for _ in range(n)]
    set_id = Dec(h2b(rpc("state_call", ["GrandpaApi_current_set_id", "0x", head0]))).u64()
    total = sum(w for _, w in auth)
    threshold = total - (total - 1) // 3
    auth.sort(key=lambda x: x[0])
    print(f"  {len(auth)} authorities, set_id={set_id}, threshold >{threshold-1}")

    print("capturing finality proof ...")
    bnum = int(rpc("chain_getHeader", [head0])["number"], 16)
    proof_bytes = h2b(rpc("grandpa_proveFinality", [bnum]))
    p = Dec(proof_bytes)
    p.take(32)
    just_len = p.compact()          # read the length first: slice bounds are
    just = p.b[p.i:p.i + just_len]  # evaluated left to right, so p.i must be settled
    j = Dec(just)
    rnd = j.u64(); c_hash = j.take(32); c_num = j.u32(); npre = j.compact()
    print(f"  {len(proof_bytes)} bytes, round={rnd}, target=#{c_num}, {npre} precommits")

    print("capturing relay header ...")
    hj = rpc("chain_getHeader", ["0x" + c_hash.hex()])
    digest = b"".join(h2b(x) for x in hj["digest"]["logs"])
    header = (h2b(hj["parentHash"]) + enc_compact(int(hj["number"], 16))
              + h2b(hj["stateRoot"]) + h2b(hj["extrinsicsRoot"])
              + enc_compact(len(hj["digest"]["logs"])) + digest)
    if blake256(header) != c_hash:
        sys.exit("re-encoded relay header does not hash to the commit target")
    relay_state_root = h2b(hj["stateRoot"])
    print(f"  {len(header)} bytes, binds to the commit target")

    print("capturing Paras::Heads(1000) proof ...")
    pkey = twox128("Paras") + twox128("Heads") + twox64_concat((1000).to_bytes(4, "little"))
    paras_nodes = [h2b(x) for x in
                   rpc("state_getReadProof", [["0x" + pkey.hex()], "0x" + c_hash.hex()])["proof"]]
    print(f"  {len(paras_nodes)} nodes, {sum(map(len, paras_nodes))} bytes")

    # Decode locally so the fixture header can carry the expected answers.
    def nibbles(k):
        o = []
        for c in k: o += [c >> 4, c & 0xf]
        return o

    def rcompact(b, i):
        b0 = b[i]; m = b0 & 3
        if m == 0: return b0 >> 2, i + 1
        if m == 1: return int.from_bytes(b[i:i+2], "little") >> 2, i + 2
        if m == 2: return int.from_bytes(b[i:i+4], "little") >> 2, i + 4
        nn = (b0 >> 2) + 4
        return int.from_bytes(b[i+1:i+1+nn], "little"), i + 1 + nn

    def decode_node(b):
        i = 0; b0 = b[i]; i += 1
        if b0 == 0: return ("empty",)
        if   b0 & 0xC0 == 0x40: kind, mx = "leaf", 63
        elif b0 & 0xC0 == 0x80: kind, mx = "bnv", 63
        elif b0 & 0xC0 == 0xC0: kind, mx = "bv", 63
        elif b0 & 0xE0 == 0x20: kind, mx = "hleaf", 31
        elif b0 & 0xF0 == 0x10: kind, mx = "hbranch", 15
        else: raise ValueError("bad node header")
        nk = b0 & mx
        if nk == mx:
            while True:
                a = b[i]; i += 1; nk += a
                if a != 255: break
        nb = (nk + 1) // 2; part = nibbles(b[i:i+nb]); i += nb
        if nk % 2 == 1: part = part[1:]
        part = part[:nk]
        if kind in ("leaf", "hleaf"):
            if kind == "leaf":
                ln, i = rcompact(b, i); return ("leaf", part, ("inline", b[i:i+ln]))
            return ("leaf", part, ("hashed", b[i:i+32]))
        bm = int.from_bytes(b[i:i+2], "little"); i += 2
        val = None
        if kind == "bv":
            ln, i = rcompact(b, i); val = ("inline", b[i:i+ln]); i += ln
        elif kind == "hbranch":
            val = ("hashed", b[i:i+32]); i += 32
        ch = [None] * 16
        for c in range(16):
            if bm >> c & 1:
                ln, i = rcompact(b, i); ch[c] = b[i:i+ln]; i += ln
        return ("branch", part, val, ch)

    def walk(root, key, nodes):
        db = {blake256(x): x for x in nodes}
        path = nibbles(key); pos = 0; cur = root; inl = None
        while True:
            raw = inl if inl is not None else db.get(cur)
            inl = None
            if raw is None: raise KeyError("missing node")
            nd = decode_node(raw)
            if nd[0] == "empty": return None
            part = nd[1]
            if path[pos:pos+len(part)] != part: return None
            pos += len(part)
            if nd[0] == "leaf":
                if pos != len(path): return None
                v = nd[2]
                return v[1] if v[0] == "inline" else db[v[1]]
            _, _, val, ch = nd
            if pos == len(path):
                if not val: return None
                return val[1] if val[0] == "inline" else db[val[1]]
            c = ch[path[pos]]; pos += 1
            if c is None: return None
            if len(c) == 32: cur = c
            else: inl = c

    headdata = walk(relay_state_root, pkey, paras_nodes)
    ln, i = rcompact(headdata, 0)
    ah_header = headdata[i:i+ln]
    ah_hash = blake256(ah_header)
    ah_num, k = rcompact(ah_header, 32)
    ah_state_root = ah_header[k:k+32]
    print(f"  -> Asset Hub #{ah_num} 0x{ah_hash.hex()[:16]}...")

    print("capturing Asset Hub storage proof ...")
    targets = {
        "AH_SYSTEM_NUMBER":   twox128("System") + twox128("Number"),
        "AH_TIMESTAMP_NOW":   twox128("Timestamp") + twox128("Now"),
        "AH_TOTAL_ISSUANCE":  twox128("Balances") + twox128("TotalIssuance"),
    }
    ah_nodes = [h2b(x) for x in rpc("state_getReadProof",
                                    [["0x" + k2.hex() for k2 in targets.values()],
                                     "0x" + ah_hash.hex()], endpoint=AHUB)["proof"]]
    print(f"  {len(ah_nodes)} nodes, {sum(map(len, ah_nodes))} bytes")
    values = {name: walk(ah_state_root, k2, ah_nodes) for name, k2 in targets.items()}
    for name, v in values.items():
        print(f"    {name:20s} = {int.from_bytes(v,'little')}")
    if int.from_bytes(values["AH_SYSTEM_NUMBER"], "little") != ah_num:
        sys.exit("AH System::Number disagrees with the proven header number")

    open(os.path.join(OUT, "finality_proof.bin"), "wb").write(proof_bytes)
    open(os.path.join(OUT, "relay_header.bin"), "wb").write(header)
    open(os.path.join(OUT, "paras_proof.bin"), "wb").write(pack_nodes(paras_nodes))
    open(os.path.join(OUT, "ah_proof.bin"), "wb").write(pack_nodes(ah_nodes))
    open(os.path.join(OUT, "authorities.bin"), "wb").write(
        struct.pack("<I", len(auth)) + b"".join(pk for pk, _ in auth)
        + b"".join(struct.pack("<Q", w) for _, w in auth))

    L = [f"/* GENERATED by tools/gen_fixtures.py - relay {REL}, hub {AHUB}. */",
         "#ifndef FIXTURES_H", "#define FIXTURES_H", "", "#include <stdint.h>", ""]
    L.append(f"#define FX_SET_ID          {set_id}ull")
    L.append(f"#define FX_TOTAL_WEIGHT    {total}ull")
    L.append(f"#define FX_THRESHOLD       {threshold}ull")
    L.append(f"#define FX_ROUND           {rnd}ull")
    L.append(f"#define FX_RELAY_NUMBER    {c_num}u")
    L.append(f"#define FX_PRECOMMITS      {npre}u")
    L.append(f"#define FX_AH_NUMBER       {ah_num}u")
    L.append("")
    L.append(carray("FX_RELAY_HASH", c_hash))
    L.append(carray("FX_RELAY_STATE_ROOT", relay_state_root))
    L.append(carray("FX_AH_HASH", ah_hash))
    L.append(carray("FX_AH_STATE_ROOT", ah_state_root))
    L.append(carray("FX_KEY_PARAS_HEADS", pkey))
    for name, k2 in targets.items():
        L.append(carray("FX_KEY_" + name, k2))
    L.append("")
    for name, v in values.items():
        L.append(f"#define FX_VAL_{name} {int.from_bytes(v,'little')}ull")
    L.append("")
    L.append("#endif")
    open(os.path.join(OUT, "fixtures.h"), "w").write("\n".join(L) + "\n")

    print(f"\nwrote fixtures to {os.path.normpath(OUT)}")
    for f in sorted(os.listdir(OUT)):
        print(f"  {f:24s} {os.path.getsize(os.path.join(OUT,f)):>8} B")


if __name__ == "__main__":
    main()
