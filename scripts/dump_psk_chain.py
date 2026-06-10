"""
Run inside Binary Ninja: Tools → Script Console → exec(open(r"...\\dump_psk_chain.py").read())

Walks the call graph starting from PSK-related functions and dumps:
  - decompiled HLIL for every function in the chain
  - all string xrefs found along the way
  - a flat call graph
"""

from binaryninja import BinaryViewType
import os, re

# ── config ─────────────────────────────────────────────────────────────────
BNDB = r"C:\Users\mrcook1e\Fingerprint\raw\Wbdi.dll.bndb"
OUT  = r"C:\Users\mrcook1e\Documents\goodix-gm168\scripts\psk_chain_dump.txt"

# Seed addresses — everything we already know touches PSK
SEEDS = [
    0x18003a2e4,  # PresetPskWriteKey
    0x18003836c,  # GeneratePsk
    0x180001000,  # SecWhiteEncrypt / GoodixDataAesEncrypt
    0x180038ad0,  # gf_sgx_seal_data
    0x180004e50,  # wb_ctx_alloc
    0x180004f10,  # wb_ctx_init (hardcoded SHA-256 IV)
    0x180004e20,  # wb_update wrapper
    0x180006b10,  # HMAC finalize / j_sub_180006b10
    0x180006a30,  # sub called by wb_update
    0x180097a6c,  # PresetPskWriteG  (GM168/GM168SEC path)
    0x1800a9f14,  # PresetPskWriteR  (Realtek path)
    0x18019f118,  # PresetPskReadG   (string xref)
    0x18020e1c8,  # PresetPskReadR
    0x1801ff920,  # McuProcessPsk
    0x18019f330,  # ProcessPsk
    0x18020ded0,  # CleanPskCache
    0x1801ffda8,  # PresetPskPskSet
    0x1801ffdc8,  # PresetPskPskGet
]

MAX_DEPTH   = 4      # how deep to recurse from each seed
MAX_FUNC_SZ = 8000   # skip huge functions (image processing etc.)

# ── helpers ────────────────────────────────────────────────────────────────
def get_bv():
    # works both in headless and interactive mode
    try:
        return bv  # already open in interactive session
    except NameError:
        print(f"[*] opening {BNDB} ...")
        return BinaryViewType.get_view_of_file(BNDB)

def func_at(bv, addr):
    funcs = bv.get_functions_containing(addr)
    return funcs[0] if funcs else None

def decompile(func):
    try:
        hlil = func.hlil
        if hlil is None:
            return "  <no HLIL>"
        lines = []
        for blk in hlil:
            for insn in blk:
                lines.append(f"  {insn.address:016x}  {insn}")
        return "\n".join(lines) if lines else "  <empty>"
    except Exception as e:
        return f"  <decompile error: {e}>"

def callees(func, bv):
    """Return set of (addr, Function) this function calls."""
    result = set()
    for ref in func.call_sites:
        for callee_addr in ref.hlil.value.value if hasattr(ref.hlil, 'value') else []:
            pass
    # use callee list from HLIL call instructions
    try:
        for blk in func.hlil:
            for insn in blk:
                txt = str(insn)
                # grab hex addresses from call targets
                for m in re.finditer(r'sub_([0-9a-f]{8,16})', txt):
                    addr = int(m.group(1), 16)
                    f = func_at(bv, addr)
                    if f:
                        result.add((addr, f))
    except Exception:
        pass
    # also use binary ninja's callee API
    try:
        for callee in func.callees:
            result.add((callee.start, callee))
    except Exception:
        pass
    return result

def walk(bv, seed_addr, depth, visited, lines, graph):
    if seed_addr in visited or depth < 0:
        return
    visited.add(seed_addr)

    func = func_at(bv, seed_addr)
    if func is None:
        lines.append(f"\n{'='*72}")
        lines.append(f"  [!] No function at 0x{seed_addr:x}")
        return

    # skip huge functions that are not PSK-related
    size = func.highest_address - func.start
    if size > MAX_FUNC_SZ and seed_addr not in SEEDS:
        lines.append(f"\n{'='*72}")
        lines.append(f"  [SKIP large] {func.name}  @ 0x{func.start:x}  size={size:#x}")
        return

    lines.append(f"\n{'='*72}")
    lines.append(f"FUNCTION  {func.name}  @ 0x{func.start:x}  (size={size:#x}  depth={MAX_DEPTH - depth})")
    lines.append(f"{'='*72}")
    lines.append(decompile(func))

    children = callees(func, bv)
    graph[func.start] = [c[0] for c in children]

    for addr, child in sorted(children, key=lambda x: x[0]):
        if addr not in visited:
            walk(bv, addr, depth - 1, visited, lines, graph)

# ── main ───────────────────────────────────────────────────────────────────
def main():
    bv     = get_bv()
    lines  = ["PSK CHAIN DUMP — Wbdi.dll", "=" * 72]
    graph  = {}
    visited = set()

    for seed in SEEDS:
        walk(bv, seed, MAX_DEPTH, visited, lines, graph)

    # call graph summary
    lines.append(f"\n\n{'='*72}")
    lines.append("CALL GRAPH SUMMARY")
    lines.append(f"{'='*72}")
    for parent, children in sorted(graph.items()):
        pf = func_at(bv, parent)
        pname = pf.name if pf else f"0x{parent:x}"
        child_names = []
        for c in children:
            cf = func_at(bv, c)
            child_names.append(cf.name if cf else f"0x{c:x}")
        lines.append(f"  {pname:40s} -> {', '.join(child_names)}")

    output = "\n".join(lines)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[+] Done. {len(visited)} functions dumped.")
    print(f"[+] Output: {OUT}")
    return output

result = main()
