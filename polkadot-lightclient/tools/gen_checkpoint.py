#!/usr/bin/env python3
"""Generate src/checkpoint.h - the device's trust root.

Everything the light client trusts a priori lives in this one generated header:
the GRANDPA authority set, its set_id, and the storage keys we read. Nothing
else in the firmware takes anything on faith.

This is weak subjectivity. Whoever runs this script is choosing the chain the
device will follow, so run it against an endpoint you trust and sanity-check
the printed set_id against a block explorer before flashing.

The authority set rotates roughly every 24 h. Until authority-set-change
tracking lands (M2), re-run this and reflash when the device reports a stale set.

Also writes src/checkpoint_precomp.{c,h}: the eight odd multiples of each
authority key, which the verifier would otherwise rebuild from the encoded key
on every one of ~403 signatures per justification. That is a cache derived
from the keys in checkpoint.h, changes nothing about which signatures are
accepted, and is worth about 9% of verification time. --no-precomp skips it.

  python3 tools/gen_checkpoint.py [--endpoint URL] [-o src/checkpoint.h]
"""
import argparse, json, os, re, urllib.request, hashlib, sys, xxhash

REL = "https://polkadot.api.onfinality.io/public"
ASSET_HUB_PARA_ID = 1000


def rpc(method, params=None, endpoint=REL):
    req = urllib.request.Request(
        endpoint,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params or []}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "curl/8.0"})
    r = json.load(urllib.request.urlopen(req, timeout=45))
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def h2b(h):
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def twox128(s):
    b = s.encode() if isinstance(s, str) else s
    return b"".join(xxhash.xxh64(b, seed=i).intdigest().to_bytes(8, "little")
                    for i in (0, 1))


def twox64_concat(b):
    return xxhash.xxh64(b, seed=0).intdigest().to_bytes(8, "little") + b


class Dec:
    def __init__(self, b): self.b, self.i = b, 0
    def take(self, n):
        if self.i + n > len(self.b): raise ValueError("truncated")
        v = self.b[self.i:self.i + n]; self.i += n; return v
    def u64(self): return int.from_bytes(self.take(8), "little")
    def compact(self):
        b0 = self.b[self.i]; m = b0 & 3
        if m == 0: self.i += 1; return b0 >> 2
        if m == 1: return int.from_bytes(self.take(2), "little") >> 2
        if m == 2: return int.from_bytes(self.take(4), "little") >> 2
        n = (b0 >> 2) + 4; self.i += 1
        return int.from_bytes(self.take(n), "little")



# ---------------------------------------------------------------- precomputation
#
# The eight odd multiples A, 3A, ... 15A of each authority's decoded public key,
# in ref10's ge25519_precomp form, so the device does not rebuild them on every
# one of ~403 signatures per justification. See lib/ed25519_fast/src/ed25519_fast.h
# for why this is 9.4% of a verification and why it changes no accept/reject
# decision.
#
# What this must reproduce is a POINT, not a bit pattern. ref10's field elements
# are not canonical - the same point has many limb representations, depending on
# which addition chain produced it - and the verifier's result is compared after
# ge25519_tobytes(), which reduces. So affine coordinates written out in the
# canonical radix-2^25.5 split are exactly as correct as whatever ref10's own
# chain would have produced, and test/run_pre.sh checks that equality with
# ref10's own arithmetic rather than taking this code's word for it.

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
D2 = (2 * D) % P

# ref10's limb layout: 10 limbs alternating 26 and 25 bits.
LIMB_OFF = (0, 26, 51, 77, 102, 128, 153, 179, 204, 230)
LIMB_BITS = (26, 25, 26, 25, 26, 25, 26, 25, 26, 25)


def fe_limbs(x):
    """Split a field element into ref10's 10 signed, balanced limbs.

    The plain split would already be safe - every limb in [0, 2^26) is inside
    the |f_i| <= 1.65*2^26 that fe25519_mul documents as its precondition. This
    goes further and carries with round-to-nearest, so each limb ends up in
    roughly [-2^(b-1), 2^(b-1)): half the magnitude, and the same convention
    ref10's own precomputed table in fe_25_5/base2.h is written in. These
    entries are fed to exactly the same ge25519_madd/ge25519_msub as that table,
    so there is no reason for them to live in a wider range than it does, and
    every reason not to invent one on a consensus-critical path.

    Representation does not affect the result - test/run_pre.sh compares reduced
    encodings against ref10's own arithmetic, which is invariant under it - so
    this is purely about how much headroom the field multiplications keep.
    """
    h = [(x % P >> o) & ((1 << b) - 1) for o, b in zip(LIMB_OFF, LIMB_BITS)]
    for i in range(9):
        b = LIMB_BITS[i]
        c = (h[i] + (1 << (b - 1))) >> b
        h[i] -= c << b
        h[i + 1] += c
    # The top limb wraps into the bottom one, where 2^255 == 19 mod p.
    c = (h[9] + (1 << 24)) >> 25
    h[9] -= c << 25
    h[0] += 19 * c
    c = (h[0] + (1 << 25)) >> 26
    h[0] -= c << 26
    h[1] += c
    assert all(abs(v) <= 1 << (b - 1) for v, b in zip(h, LIMB_BITS)), h
    return h


def decode_negate(s):
    """ge25519_frombytes_negate_vartime, as arithmetic.

    Returns the affine (x, y) of MINUS the encoded point - the negation is
    upstream's, not ours: ref10 accumulates -A so that the verification equation
    can be a single double-scalar multiplication. Returns None if the encoding
    is not a point, which is the same -1 that function returns.
    """
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    if y >= P:
        return None                                # ge25519_is_canonical == 0
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    # x = uv^3 (uv^7)^((p-5)/8), then the root check ref10 performs.
    uv3 = (u * pow(v, 3, P)) % P
    uv7 = (u * pow(v, 7, P)) % P
    x = (uv3 * pow(uv7, (P - 5) // 8, P)) % P
    if (v * x * x - u) % P != 0:
        if (v * x * x + u) % P != 0:
            return None                            # no square root: not on the curve
        x = (x * pow(2, (P - 1) // 4, P)) % P       # multiply by sqrt(-1)
    if (x & 1) == sign:
        x = (-x) % P
    return (x, y)


def pt_add(p1, p2):
    """Extended-coordinate addition on the a = -1 twisted Edwards curve."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * D2 * t2) % P
    dd = (2 * z1 * z2) % P
    e, f, g, h = (b - a) % P, (dd - c) % P, (dd + c) % P, (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def small_order(pt):
    """True if the point has order dividing 8 - ge25519_has_small_order, for a
    canonical encoding, which is the only kind that reaches here."""
    q = pt
    for _ in range(3):
        q = pt_add(q, q)
    x, y, z, _ = q
    return x % P == 0 and (y - z) % P == 0        # the identity (0 : 1 : 1)


def authority_table(pk):
    """The eight ge25519_precomp entries for one public key.

    Refuses anything the device's verifier would refuse, because
    lc_ed25519_verify_pre() skips ge25519_frombytes_negate_vartime() when a
    table exists: this function's verdict is the one that stands in for it, and
    it must not be more permissive.
    """
    aff = decode_negate(pk)
    if aff is None:
        return None
    x, y = aff
    a = (x, y, 1, (x * y) % P)
    if small_order(a):
        return None
    out = []
    q = a
    a2 = pt_add(a, a)
    for i in range(8):
        if i:
            q = pt_add(a2, q)                     # q = (2i+1)A
        zi = pow(q[2], P - 2, P)
        qx, qy = (q[0] * zi) % P, (q[1] * zi) % P
        out.append([fe_limbs(qy + qx), fe_limbs(qy - qx),
                    fe_limbs(qx * qy % P * D2 % P)])
    return out


def read_header(path):
    """Pull (keys, set_id) back out of an already-generated checkpoint.h.

    So the tables can be rebuilt for the trust root that is already flashed,
    without going to the network and silently rotating the device onto a
    different authority set. Regenerating a cache must never be able to change
    what is trusted.
    """
    txt = open(path).read()
    m = re.search(r"#define CHECKPOINT_SET_ID\s+(\d+)", txt)
    if not m:
        sys.exit(f"{path}: no CHECKPOINT_SET_ID")
    set_id = int(m.group(1))
    m = re.search(r"CHECKPOINT_AUTHORITY_KEYS\[(\d+)\]\s*=\s*\{(.*?)\};",
                  txt, re.S)
    if not m:
        sys.exit(f"{path}: no CHECKPOINT_AUTHORITY_KEYS")
    blob = bytes(int(b, 16) for b in re.findall(r"0x([0-9a-fA-F]{2})", m.group(2)))
    if len(blob) != int(m.group(1)) or len(blob) % 32:
        sys.exit(f"{path}: authority key blob is {len(blob)} bytes, expected "
                 f"{m.group(1)} and a multiple of 32")
    return [(blob[i:i + 32], 1) for i in range(0, len(blob), 32)], set_id


def emit_precomp(auth, set_id, endpoint, out_c, out_h):
    """Write src/checkpoint_precomp.{c,h}."""
    tables = []
    for i, (pk, _) in enumerate(auth):
        t = authority_table(pk)
        if t is None:
            sys.exit(f"authority {i} ({pk.hex()}) is not a usable ed25519 key - "
                     "refusing to generate a precomputed table for it")
        tables.append(t)

    banner = [
        "/* GENERATED by tools/gen_checkpoint.py - do not edit by hand.",
        " *",
        " * The eight odd multiples A, 3A, ... 15A of each authority key in",
        f" * src/checkpoint.h, decoded and negated exactly as",
        " * ge25519_frombytes_negate_vartime does, in ref10's ge25519_precomp form.",
        " *",
        " * This is a cache, not a second trust root: it is derived from the keys in",
        " * checkpoint.h and nothing else, and it is bound to them by set_id below.",
        " * A verification using it accepts and rejects exactly what one without it",
        f" * does. Captured from {endpoint}.",
        " */",
    ]

    with open(out_h, "w") as f:
        f.write("\n".join(banner) + "\n")
        f.write(f"""#ifndef CHECKPOINT_PRECOMP_H
#define CHECKPOINT_PRECOMP_H

/* LC_ED25519_PRECOMP is what compiles the 562 KiB of tables in. Without it this
   whole file is empty and the firmware runs the unchanged per-signature path.
   It is deliberately NOT LC_USE_FAST_ED25519: src/mcbench.cpp wants the tables
   while keeping lc_ed25519_verify pointed at the framework's prebuilt libsodium,
   because that prebuilt copy is the in-image anchor every ratio is measured
   against. */
#ifdef LC_ED25519_PRECOMP

#include "ed25519_fast.h"

#define CHECKPOINT_HAVE_PRECOMP    1
/* Checked against CHECKPOINT_SET_ID at compile time by whoever includes both.
   A table built for a rotated set would reject every signature - fail-closed,
   but a fail-closed device is still a broken one, and this catches it at build
   time instead of in the field. */
#define CHECKPOINT_PRECOMP_SET_ID  {set_id}ull
#define CHECKPOINT_PRECOMP_COUNT   {len(auth)}

extern const lc_ed25519_pretab
    CHECKPOINT_AUTHORITY_PRECOMP[CHECKPOINT_PRECOMP_COUNT];

#endif
#endif
""")

    with open(out_c, "w") as f:
        f.write("\n".join(banner) + "\n")
        f.write('#include "checkpoint_precomp.h"\n\n'
                '/* Without the flag everything below is compiled out, and a\n'
                '   translation unit with no declarations in it is not legal C. */\n'
                'typedef int checkpoint_precomp_not_empty;\n\n'
                '#ifdef LC_ED25519_PRECOMP\n\n')
        f.write("const lc_ed25519_pretab\n"
                f"    CHECKPOINT_AUTHORITY_PRECOMP[CHECKPOINT_PRECOMP_COUNT] = {{\n")
        for i, t in enumerate(tables):
            f.write(f"/* {i} {auth[i][0].hex()} */ {{{{\n")
            for pt in t:
                f.write("{" + ",".join("{" + ",".join(map(str, fe)) + "}"
                                       for fe in pt) + "},\n")
            f.write("}},\n")
        f.write("};\n\n#endif\n")
    return len(tables)

def carray(name, data, per_line=16, indent="    "):
    """Emit a byte array as C source."""
    out = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), per_line):
        out.append(indent + " ".join(f"0x{b:02x}," for b in data[i:i + per_line]))
    out.append("};")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default=REL)
    ap.add_argument("--at", help="pin the authority snapshot to this finalized block hash")
    ap.add_argument("--expected-genesis", help="refuse an endpoint on a different chain")
    ap.add_argument("--check-endpoint", help="cross-check header and authority snapshot at a second provider")
    ap.add_argument("-o", "--out", default="src/checkpoint.h")
    ap.add_argument("--precomp-out", default="src/checkpoint_precomp.c",
                    help="where to write the per-authority precomputed tables; "
                         "the matching .h goes beside it")
    ap.add_argument("--precomp-only", action="store_true",
                    help="rebuild only the tables, from the keys already in "
                         "--out. Touches no network and cannot change the "
                         "trust root.")
    ap.add_argument("--no-precomp", action="store_true",
                    help="skip the precomputed tables. The firmware then runs "
                         "the unchanged per-signature path, about 9%% slower.")
    args = ap.parse_args()

    if args.precomp_only:
        auth, set_id = read_header(args.out)
        pc_c = args.precomp_out
        pc_h = os.path.splitext(pc_c)[0] + ".h"
        n_tab = emit_precomp(auth, set_id, f"the keys already in {args.out}",
                             pc_c, pc_h)
        print(f"wrote {pc_c} and {pc_h}")
        print(f"  from        : {args.out} (set_id {set_id}, unchanged)")
        print(f"  precomputed : {n_tab} authorities x 8 points"
              f"  ({n_tab * 960 / 1024:.0f} KiB of flash)")
        return

    if args.expected_genesis:
        for endpoint in filter(None, (args.endpoint, args.check_endpoint)):
            if rpc("chain_getBlockHash", [0], endpoint=endpoint) != args.expected_genesis:
                sys.exit("unexpected genesis at " + endpoint)
    head = args.at or rpc("chain_getFinalizedHead", endpoint=args.endpoint)
    hdr = rpc("chain_getHeader", [head], endpoint=args.endpoint)
    number = int(hdr["number"], 16)

    if args.check_endpoint:
        queries = [("chain_getHeader", [head]),
                   ("state_call", ["GrandpaApi_grandpa_authorities", "0x", head]),
                   ("state_call", ["GrandpaApi_current_set_id", "0x", head])]
        for method, params in queries:
            if rpc(method, params, endpoint=args.endpoint) != rpc(method, params, endpoint=args.check_endpoint):
                sys.exit("providers disagree on " + method)
        print("header and authority snapshot agree across providers at " + head)

    d = Dec(h2b(rpc("state_call", ["GrandpaApi_grandpa_authorities", "0x", head],
                    endpoint=args.endpoint)))
    n = d.compact()
    auth = [(d.take(32), d.u64()) for _ in range(n)]
    set_id = Dec(h2b(rpc("state_call", ["GrandpaApi_current_set_id", "0x", head],
                         endpoint=args.endpoint))).u64()

    total = sum(w for _, w in auth)
    threshold = total - (total - 1) // 3          # strictly more than 2/3

    # Sorted by public key so the firmware can binary-search instead of scanning
    # 600 entries for each of ~400 signatures.
    auth.sort(key=lambda x: x[0])
    if len(set(pk for pk, _ in auth)) != len(auth):
        sys.exit("duplicate authority public key - refusing to generate")

    keys = {
        "PARAS_HEADS": ("Paras::Heads(1000) on the relay chain",
                        twox128("Paras") + twox128("Heads")
                        + twox64_concat(ASSET_HUB_PARA_ID.to_bytes(4, "little"))),
        "AH_SYSTEM_NUMBER": ("System::Number on Asset Hub",
                             twox128("System") + twox128("Number")),
        "AH_TIMESTAMP_NOW": ("Timestamp::Now on Asset Hub",
                             twox128("Timestamp") + twox128("Now")),
        "AH_TOTAL_ISSUANCE": ("Balances::TotalIssuance on Asset Hub",
                              twox128("Balances") + twox128("TotalIssuance")),
    }

    L = []
    L.append("/* GENERATED by tools/gen_checkpoint.py - do not edit by hand.")
    L.append(" *")
    L.append(" * The device's trust root: the GRANDPA authority set it will accept")
    L.append(" * signatures from, and the storage keys it reads. Captured from")
    L.append(f" * {args.endpoint}")
    L.append(f" * at relay block #{number} ({head}).")
    L.append(" *")
    L.append(" * Weak subjectivity: a device flashed with this header follows whatever")
    L.append(" * chain these authorities sign. Verify set_id against an explorer.")
    L.append(" */")
    L.append("#ifndef CHECKPOINT_H")
    L.append("#define CHECKPOINT_H")
    L.append("")
    L.append("#include <stdint.h>")
    L.append("")
    L.append("#ifdef __cplusplus")
    L.append('extern "C" {')
    L.append("#endif")
    L.append("")
    L.append(f"#define CHECKPOINT_SET_ID      {set_id}ull")
    L.append(f"#define CHECKPOINT_AUTHORITIES {len(auth)}")
    L.append(f"#define CHECKPOINT_TOTAL_WEIGHT {total}ull")
    L.append(f"/* strictly more than 2/3 of {total} */")
    L.append(f"#define CHECKPOINT_THRESHOLD   {threshold}ull")
    L.append(f"#define CHECKPOINT_BLOCK       {number}u")
    L.append(f'#define CHECKPOINT_BLOCK_HASH  "{head}"')
    L.append(f"#define ASSET_HUB_PARA_ID      {ASSET_HUB_PARA_ID}u")
    L.append("")
    L.append("/* Public keys, sorted ascending so lookup can binary-search. */")
    L.append(carray("CHECKPOINT_AUTHORITY_KEYS", b"".join(pk for pk, _ in auth)))
    L.append("")
    if all(w == 1 for _, w in auth):
        L.append("/* Every authority currently has weight 1; kept explicit because"
                 "\n   GRANDPA does not require it. */")
    L.append(f"static const uint64_t CHECKPOINT_AUTHORITY_WEIGHTS"
             f"[{len(auth)}] = {{")
    for i in range(0, len(auth), 16):
        L.append("    " + " ".join(f"{w}," for _, w in auth[i:i + 16]))
    L.append("};")
    L.append("")
    for name, (desc, k) in keys.items():
        L.append(f"/* {desc}")
        L.append("   twox128(pallet) ++ twox128(item)"
                 + (" ++ twox64_concat(para_id)" if "PARAS" in name else ""))
        L.append(" */")
        L.append(carray(f"STORAGE_KEY_{name}", k))
        L.append("")
    L.append("#ifdef __cplusplus")
    L.append("}")
    L.append("#endif")
    L.append("#endif")

    with open(args.out, "w") as f:
        f.write("\n".join(L) + "\n")

    print(f"wrote {args.out}")

    n_tab = 0
    if not args.no_precomp:
        pc_c = args.precomp_out
        pc_h = os.path.splitext(pc_c)[0] + ".h"
        n_tab = emit_precomp(auth, set_id, args.endpoint, pc_c, pc_h)
        print(f"wrote {pc_c} and {pc_h}")

    print(f"  authorities : {len(auth)}  total weight {total}  threshold >{threshold - 1}")
    if n_tab:
        print(f"  precomputed : {n_tab} authorities x 8 points"
              f"  ({n_tab * 960 / 1024:.0f} KiB of flash)")
    print(f"  set_id      : {set_id}")
    print(f"  captured at : relay #{number} {head}")
    print(f"  {'SANITY-CHECK set_id AND THE BLOCK HASH BEFORE FLASHING':^60}")


if __name__ == "__main__":
    main()
