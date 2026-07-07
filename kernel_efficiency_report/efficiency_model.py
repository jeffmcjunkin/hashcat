#!/usr/bin/env python3
"""
Hashcat GPU kernel efficiency model for RTX 3090 (GA102, sm_86), clock-locked 1710 MHz.

Idea (per Jeff): ALU utilization != efficiency. A kernel can be ALU-bound yet doing
redundant work. The real basis for optimization is:

   measured integer-ops/hash  vs  the algorithm's THEORETICAL MINIMUM integer-ops/hash.

We compute a theoretical minimum (one FULL hash of one candidate, all mandated blocks &
iterations, minimal fused-integer-ISA op count), derive a roofline throughput, and compare
to the measured benchmark H/s:

   PEAK_INT   = 82 SM * 64 int32/SM/clk * 1.71e9 Hz          = 8.97e12 int ops/s
   roofline_Hs(mode) = PEAK_INT / theoretical_min_ops(mode)
   efficiency(mode)  = achieved_Hs / roofline_Hs
       efficiency >= 1  -> kernel BEATS a full hash (early-reject / meet-in-middle). Optimal.
       efficiency ~  1  -> computes ~full hash, little waste.
       efficiency << 1  -> RECOVERABLE HEADROOM (redundant ops, or latency/occupancy stalls).

theoretical_min is EXACT (hand-derived) for the well-known GPU-bound primitives, and a
labeled HEURISTIC (primitive-cost table x parsed composition) for the long tail.

Op-count convention (Ampere fused ISA: IADD3 3-in add, LOP3 arbitrary 3-in boolean, SHF rotate):
each 32-bit compression "step" ~ 1 boolean + 1-2 adds + 1 rotate. 64-bit-word primitives
cost 2x (each 64-bit ALU op lowers to two 32-bit ops). Values are per compression-function
BLOCK unless noted; documented, +-20% (fine for ranking, where gaps are multiples).
"""
import re, sys, json, os

PEAK_INT = 82 * 64 * 1.71e9   # 8.97e12 thread int-ops/s at locked 1710 MHz

# ---- per-primitive minimal integer ops for ONE compression block (32-bit-equivalent) ----
# derived: (rounds*ops_per_step) + message_schedule.  64-bit primitives already x2 folded in.
P = {
    'md4'      : 144,    # 48 steps * 3 (1 LOP3 +1 IADD3 +1 SHF); NTLM=1 block
    'md5'      : 288,    # 64 steps * ~4.5 (extra +b add)
    'sha1'     : 560,    # 80 steps*~5 + 64-word schedule*2
    'sha224'   : 1024,   # == sha256 core (CALIBRATED to ncu: m1400 meas ~1019 ops @98% ALU)
    'sha256'   : 1024,   # 64 steps*~16 + schedule (calibrated from measured, no early-reject)
    'sha384'   : 2432,   # == sha512 core (CALIBRATED: m1700 meas ~2408 ops @79% ALU)
    'sha512'   : 2432,   # 80 steps 64-bit, calibrated from measured
    'ripemd160': 1050,   # two parallel 80-step lines
    'whirlpool': 3600,   # 10 rounds, AES-like 8x8 MDS + Sboxes (table/heavy)
    'keccak'   : 3800,   # 24 rounds * (theta/rho/pi/chi/iota) on 25 x 64-bit lanes *2
    'blake2b'  : 1152,   # 12 rounds * 8 G-funcs * ~6 ARX * 2 (64-bit)
    'blake2s'  : 640,    # 10 rounds * 8 G * ~8 (32-bit)
    'gost2012' : 4200,   # Streebog: 12 rounds, 8x8 LPS table transforms, big
    'des'      : 256,    # 16 rounds * ~16 (bitsliced-ish / Sbox); LM uses DES
    'rc4_ksa'  : 1024,   # 256-iter key schedule, ~4 ops/iter (swap+add, S-box latency-heavy)
    'rc4_prga' : 512,    # keystream setup/drop, ~amortized
    'aes_enc'  : 600,    # one 128-bit AES block, 10-14 rounds T-table (heavy LSU)
    'sha3_256' : 3800,   # == keccak
}

# ---- EXACT compositions for the important / measured / pentest modes ----
# (primitive, blocks_per_hash, iterations, note). ops = sum(P[prim]*blocks)*iters
# For HMAC: 2 extra blocks (ipad,opad). For PBKDF2: iters * 2 * hmac_blocks.
EXACT = {
 0    : [('md5',1,1)],                              # MD5
 10   : [('md5',1,1)],                              # md5($pass.$salt)
 20   : [('md5',1,1)],                              # md5($salt.$pass)
 50   : [('md5',4,1)],                              # HMAC-MD5 (ipad+opad+2)
 100  : [('sha1',1,1)],                             # SHA1
 110  : [('sha1',1,1)],
 140  : [('sha1',1,1)],
 900  : [('md4',1,1)],                              # MD4
 1000 : [('md4',1,1)],                              # NTLM
 1300 : [('sha224',1,1)],
 1400 : [('sha256',1,1)],
 1450 : [('sha256',4,1)],                           # HMAC-SHA256
 1700 : [('sha512',1,1)],
 5100 : [('md5',1,1)],                              # Half-MD5 (one MD5, half compared)
 6000 : [('ripemd160',1,1)],
 6100 : [('whirlpool',1,1)],
 600  : [('blake2b',1,1)],
 10800: [('sha384',1,1)],
 11700: [('gost2012',1,1)],                         # Streebog-256
 17600: [('keccak',1,1)],                           # SHA3-512
 17800: [('keccak',1,1)],                           # Keccak-256
 17900: [('keccak',1,1)],                           # Keccak-384
 2600 : [('md5',2,1)],                              # md5(md5($pass))
 4300 : [('md5',2,1)],                              # md5(strtoupper(md5))
 3000 : [('des',1,1)],                              # LM (DES)
 5500 : [('md4',1,1),('des',3,1)],                  # NetNTLMv1: NTLM + 3xDES challenge
 5600 : [('md4',1,1),('md5',4,1)],                  # NetNTLMv2: NTLM + HMAC-MD5
 1100 : [('md4',1,1),('md4',1,1)],                  # DCC/MSCache: 2x MD4 (nt + dcc)
 16100: [('md5',4,1)],                              # TACACS+ (MD5-based)
 5300 : [('md5',6,1)],                              # IKE-PSK MD5 (HMAC-MD5 several)
 5400 : [('sha1',6,1)],                             # IKE-PSK SHA1
 # ---- pentest / Kerberos ----
 7500 : [('md4',1,1),('md5',4,1),('rc4_ksa',1,1),('rc4_prga',1,1)],  # Kerb etype23 AS-REQ (RC4-HMAC)
 13100: [('md4',1,1),('md5',4,1),('rc4_ksa',1,1),('rc4_prga',1,1)],  # Kerb etype23 TGS-REP
 18200: [('md4',1,1),('md5',4,1),('rc4_ksa',1,1),('rc4_prga',1,1)],  # Kerb etype23 AS-REP
 9700 : [('md5',3,1),('rc4_ksa',1,1),('rc4_prga',1,1)],              # Office<=2003 MD5+RC4
 9800 : [('sha1',3,1),('rc4_ksa',1,1),('rc4_prga',1,1)],             # Office<=2003 SHA1+RC4
 # ---- slow / iterated (theoretical = iters * inner primitive) ----
 2100 : [('md4',1,1),('sha1',4,10240)],            # DCC2: PBKDF2-HMAC-SHA1 10240
 19600: [('sha1',4,4096),('aes_enc',1,1)],         # Kerb etype17 TGS AES128 (PBKDF2-SHA1 4096)
 19700: [('sha1',4,4096),('aes_enc',1,1)],         # Kerb etype18 TGS AES256
 19800: [('sha1',4,4096),('aes_enc',1,1)],         # Kerb etype17 AS-REQ AES128
 19900: [('sha1',4,4096),('aes_enc',1,1)],         # Kerb etype18 AS-REQ AES256
 9400 : [('sha1',4,50000)],                        # Office 2007 (50000x SHA1)
 9500 : [('sha1',4,100000)],                       # Office 2010 (100000x SHA1)
 9600 : [('sha512',4,100000)],                     # Office 2013 (100000x SHA512)
 15300: [('sha1',4,10240)],                        # DPAPI v1 (approx)
 15900: [('sha512',4,8000)],                       # DPAPI v2 (approx)
}

def theo_ops_exact(mode):
    parts = EXACT[mode]
    total = 0
    for prim, blocks, iters in parts:
        total += P[prim] * blocks * iters
    return total

# ---- heuristic for long tail: parse mode name for primitive + iteration hints ----
def theo_ops_heuristic(name, exhash):
    n = name.lower()
    prim = None
    for key,alias in [('sha512',['sha512','sha-512','sha2-512']),('sha384',['sha384','sha-384']),
                      ('sha256',['sha256','sha-256','sha2-256']),('sha224',['sha224','sha-224']),
                      ('sha1',['sha1','sha-1']),('md5',['md5']),('md4',['md4','ntlm']),
                      ('ripemd160',['ripemd']),('whirlpool',['whirlpool']),('keccak',['keccak','sha3']),
                      ('blake2b',['blake2']),('gost2012',['streebog','gost r 34.11-2012']),
                      ('des',['descrypt','des(']),('aes_enc',['aes'])]:
        if any(a in n for a in alias): prim = key; break
    if prim is None:
        prim = 'sha256'   # default assumption for unknown raw hashes
    base = P[prim]
    if 'hmac' in n: base *= 4
    # iteration hint from example hash (many encode rounds) or name
    iters = 1
    m = re.search(r'(\d{3,7})', exhash or '')
    if 'pbkdf2' in n or 'iteration' in n or 'rounds' in n or 'bcrypt' in n or 'scrypt' in n or 'argon' in n:
        if m: iters = min(int(m.group(1)), 999999)
        else: iters = 4096
    return base * iters * (2 if 'hmac' in n else 1), prim, iters

def main():
    sp = os.path.dirname(os.path.abspath(__file__))
    # load achieved H/s from machine-readable all-modes benchmark: dev:mode:?:?:ms:speed
    hs = {}
    bench = os.path.join(sp,'allbench.txt')
    if os.path.exists(bench):
        for ln in open(bench):
            p = ln.strip().split(':')
            if len(p)>=6 and p[0]=='1':
                try: hs[int(p[1])] = float(p[5])
                except: pass
    # load JSON name/slow catalog if present
    cat = {}
    catf = os.path.join(sp,'modes_catalog.json')
    if os.path.exists(catf):
        cat = json.load(open(catf))
    rows = []
    modes = sorted(set(list(hs.keys()) + [int(k) for k in cat.keys()] + list(EXACT.keys())))
    for mode in modes:
        info = cat.get(str(mode), {})
        name = info.get('name','?'); slow = info.get('slow', None); exhash = info.get('example_hash','')
        achieved = hs.get(mode)
        if mode in EXACT:
            theo = theo_ops_exact(mode); tier='exact'; prim=EXACT[mode][0][0]
        else:
            theo, prim, it = theo_ops_heuristic(name, exhash); tier='heuristic'
        roofline = PEAK_INT/theo if theo else None
        eff = (achieved/roofline) if (achieved and roofline) else None
        rows.append(dict(mode=mode,name=name,slow=slow,tier=tier,prim=prim,
                         theo_ops=theo, achieved_Hs=achieved, roofline_Hs=roofline, eff=eff))
    return rows

def load_ncu(sp):
    """Merge ncu-profiled stats from the two survey CSVs. Returns {mode: {...}}."""
    import csv
    out={}
    for fn in ['mode_stats.csv','win_stats.csv']:
        p=os.path.join(sp,fn)
        if not os.path.exists(p): continue
        for r in csv.DictReader(open(p)):
            try: m=int(r['mode'])
            except: continue
            cp=r.get('compute_pct',''); tp=r.get('top_pipe',''); tpp=r.get('top_pipe_pct','')
            if cp=='' : continue
            try:
                compute=float(cp); toppct=float(tpp) if tpp else compute
            except: continue
            alu_frac = (toppct/100.0) if tp=='ALU' else (compute/100.0)
            ghs=None
            try:
                if r.get('GHs'): ghs=float(r['GHs'])*1e9
            except: pass
            out[m]=dict(ghs=ghs, compute=compute, top_pipe=tp, top_pipe_pct=(float(tpp) if tpp else None),
                        occ=(float(r['occ_pct']) if r.get('occ_pct') else None),
                        ipc=(float(r['ipc']) if r.get('ipc') else None),
                        alu_frac=alu_frac, kernel=r.get('kernel','_s'))
    return out

if __name__=='__main__':
    rows = main()
    sp = os.path.dirname(os.path.abspath(__file__))
    ncu = load_ncu(sp)
    # attach measured integer-ops/hash (est.) = ALU_pipe_frac * PEAK_INT / achieved_Hs
    for r in rows:
        n=ncu.get(r['mode'])
        r['ncu']=n
        # fallback: use ncu-survey H/s if the all-modes benchmark didn't cover this mode
        if r['achieved_Hs'] is None and n and n.get('ghs'):
            r['achieved_Hs']=n['ghs']
            r['roofline_Hs']=PEAK_INT/r['theo_ops'] if r['theo_ops'] else None
            r['eff']=(r['achieved_Hs']/r['roofline_Hs']) if r['roofline_Hs'] else None
        r['meas_ops']=None; r['ratio']=None
        if n and r['achieved_Hs']:
            r['meas_ops'] = n['alu_frac']*PEAK_INT / r['achieved_Hs']
            if r['theo_ops']: r['ratio'] = r['meas_ops']/r['theo_ops']

    # ---- FILE 2: measured tier (profiled modes) — the trustworthy basis ----
    prof=[r for r in rows if r['ncu']]
    prof.sort(key=lambda x:(x['ncu']['compute']))
    with open(os.path.join(sp,'efficiency_measured.txt'),'w') as f:
        f.write("MEASURED TIER — ncu-profiled modes, RTX 3090 @1710MHz locked. Ranked by ALU/compute saturation (ascending = most recoverable pipe headroom).\n")
        f.write("meas_ops/hash = ALU_pipe_frac * 8.97e12 / achieved_H/s (occupancy-independent instruction efficiency estimate).\n")
        f.write("ratio = meas_ops / theoretical_min_ops.  ratio<1 => early-reject shortcuts; ~1 => full hash; >1 => op overhead vs my model (or model underestimate).\n\n")
        f.write(f"{'mode':>6} {'cmp%':>5} {'ALU%':>5} {'occ%':>5} {'ipc':>4} {'achieved_H/s':>13} {'meas_ops':>9} {'theo_ops':>9} {'ratio':>6} {'kern':>5}  name\n")
        for r in prof:
            n=r['ncu']
            a=f"{r['achieved_Hs']:.2e}" if r['achieved_Hs'] else "n/a"
            mo=f"{r['meas_ops']:.0f}" if r['meas_ops'] else "n/a"
            rt=f"{r['ratio']:.2f}" if r['ratio'] else "n/a"
            tpp=f"{n['top_pipe_pct']:.0f}" if n['top_pipe_pct'] else "?"
            occ=f"{n['occ']:.0f}" if n['occ'] else "?"
            ipc=f"{n['ipc']:.2f}" if n['ipc'] else "?"
            f.write(f"{r['mode']:>6} {n['compute']:>5.0f} {tpp:>5} {occ:>5} {ipc:>4} {a:>13} {mo:>9} {r['theo_ops']:>9} {rt:>6} {n['kernel']:>5}  {r['name'][:40]}\n")

    # ---- FILE 1: all modes theoretical + roofline efficiency ----
    with open(os.path.join(sp,'efficiency_all.txt'),'w') as f:
        f.write("ALL MODES — theoretical-min integer-ops/hash & roofline efficiency. RTX 3090 @1710MHz (PEAK_INT=8.97e12).\n")
        f.write("eff = achieved_H/s / roofline_H/s; roofline = PEAK_INT/theo_ops. eff>=1 optimal (early-reject); eff<<1 headroom.\n")
        f.write("tier=exact: hand-derived composition; tier=heuristic: name-parsed primitive+iters (APPROXIMATE, esp. iterated).\n")
        f.write("SLOW modes are iteration-bound BY DESIGN (KDF rounds = security param); their _loop kernels measured ~98% ALU, so eff here is NOT recoverable headroom.\n\n")
        f.write(f"{'mode':>6} {'slow':>5} {'tier':>9} {'prim':>10} {'theo_ops/hash':>14} {'achieved_H/s':>13} {'roofline_H/s':>13} {'eff':>7}  name\n")
        for r in sorted(rows, key=lambda x:(x['eff'] is None, x['eff'] if x['eff'] else 9e9)):
            a = f"{r['achieved_Hs']:.3e}" if r['achieved_Hs'] else "n/a"
            rl= f"{r['roofline_Hs']:.3e}" if r['roofline_Hs'] else "n/a"
            e = f"{r['eff']:.3f}" if r['eff'] is not None else "n/a"
            sl= 'Y' if r['slow'] else ('.' if r['slow'] is not None else '?')
            f.write(f"{r['mode']:>6} {sl:>5} {r['tier']:>9} {r['prim']:>10} {r['theo_ops']:>14} {a:>13} {rl:>13} {e:>7}  {r['name']}\n")
    print(f"wrote efficiency_all.txt ({len(rows)} modes)")

    # ---- FILE 3: top least-optimized FAST modes (recoverable headroom) ----
    fast=[r for r in rows if r['eff'] is not None and not r['slow']]
    # prefer measured ranking where available, else modeled eff
    fast.sort(key=lambda x:(x['ncu']['compute'] if x['ncu'] else x['eff']*100))
    with open(os.path.join(sp,'least_optimized_fast.txt'),'w') as f:
        f.write("LEAST-OPTIMIZED FAST (non-iterated) MODES — recoverable kernel headroom. Measured (ncu compute%) where available, else modeled eff.\n\n")
        f.write(f"{'mode':>6} {'meas_cmp%':>9} {'model_eff':>9} {'tier':>9} {'achieved_H/s':>13}  name\n")
        for r in fast[:25]:
            cm=f"{r['ncu']['compute']:.0f}" if r['ncu'] else "-"
            a=f"{r['achieved_Hs']:.2e}" if r['achieved_Hs'] else "n/a"
            f.write(f"{r['mode']:>6} {cm:>9} {r['eff']:>9.3f} {r['tier']:>9} {a:>13}  {r['name'][:46]}\n")

    print("\nTOP 12 LEAST-OPTIMIZED FAST MODES (measured cmp% asc where profiled):")
    for r in fast[:12]:
        cm=f"cmp={r['ncu']['compute']:.0f}%" if r['ncu'] else f"eff={r['eff']:.2f}"
        print(f"  m{r['mode']:<6} {cm:<9} {r['tier']:9} {r['name'][:44]}")
    print("\nSLOW modes (iteration-bound by design; loop kernels ~98% ALU, not recoverable): excluded from targeting.")
