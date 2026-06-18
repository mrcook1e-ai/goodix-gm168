/**
 * gx_preproc_trace.js — narrow trace of the Wbdi.dll preprocessor pipeline.
 *
 * Goal: confirm which callees of sub_18010f650 actually fire on our sensor,
 * and capture input/output of each stage so we can match a Python prototype
 * byte-for-byte.
 *
 * Wbdi.dll RVAs (from static RE):
 *   0x10f650  preprocessor entry (sub_18010f650)
 *   0x10c610  geometry preprocess (clamp/invert/border)
 *   0x10a8e0  "is finger present" validator
 *   0x10d3d0  mask builder
 *   0x110350  mask builder helper
 *   0x10a460  *** main local-envelope stretch ***
 *   0x10b910  smoother (entry; calls sub_180112a00 / sub_180112820 / sub_180115410)
 *   0x10e0e0  horizontal sliding min/max envelope (low + high out)
 *   0x10ce20  vertical sliding min/max envelope (low + high out)
 *   0x10f1f0  3x3 morphological close on (low, high)
 *   0x10aa60  frame arbiter
 *
 * For each hook we dump pointer-args (sized via cfg struct: w=cfg[0], h=cfg[1],
 * nbuf=w*h*2 bytes). One file per buffer per call into C:\Windows\Temp\gx_dumps\.
 */
'use strict';

var wbdi = Process.findModuleByName("Wbdi.dll");
if (!wbdi) {
    console.log("ERROR: Wbdi.dll not found");
} else {
    console.log("OK Wbdi.dll @ " + wbdi.base);

    var DUMP_DIR = "C:\\Windows\\Temp\\gx_dumps\\";
    var SID = (new Date()).toISOString().replace(/[:.TZ-]/g, "").substring(0, 14);
    console.log("SID " + SID);

    function dumpBin(tag, id, ptr, len) {
        if (ptr.isNull() || len <= 0 || len > 0x100000) return null;
        try {
            var name = DUMP_DIR + SID + "_" + tag + "_" + ("00000" + id).slice(-5) + ".bin";
            var f = new File(name, "wb");
            f.write(ptr.readByteArray(len));
            f.close();
            return name;
        } catch (e) {
            console.log("DUMPERR " + tag + " " + id + ": " + e);
            return null;
        }
    }

    function hexHead(ptr, n) {
        if (ptr.isNull()) return "(null)";
        try {
            var b = new Uint8Array(ptr.readByteArray(Math.min(n, 32)));
            var s = "";
            for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
            return s;
        } catch (e) { return "(err)"; }
    }

    // cfg struct (int32_t[]): [0]=w, [1]=h, [2]=w*h, [6]=mode
    function readCfg(ptr) {
        try {
            return {
                w:    ptr.readU32(),
                h:    ptr.add(4).readU32(),
                npx:  ptr.add(8).readU32(),
                mode: ptr.add(24).readU32()
            };
        } catch (e) { return null; }
    }

    var ctr = {
        ENTRY: 0, INPUT: 0, FRAME: 0,
        GEOM: 0, VALID: 0, MASK: 0,
        STRETCH_IN: 0, STRETCH_OUT: 0,
        SMOOTH_IN: 0, SMOOTH_OUT: 0,
        HENV_IN: 0, HENV_LO: 0, HENV_HI: 0,
        VENV_IN: 0, VENV_LO: 0, VENV_HI: 0,
        MORPH_LO_IN: 0, MORPH_HI_IN: 0, MORPH_LO_OUT: 0, MORPH_HI_OUT: 0,
        CAL_IN: 0, CAL_OUT: 0, CAL_SCALE: 0,
        ARBITER: 0
    };

    // Latest nbuf snapshot, set by the preprocessor entry, reused by inner hooks
    // when they don't carry an explicit cfg struct.
    var lastNbuf = 0;
    var lastW = 0, lastH = 0, lastMode = 0;

    // -----------------------------------------------------------------------
    // 1) sub_18010f650 — preprocessor entry
    // sig: (state**, raw u16*, nBufferLen, workspace*, packedCfg, &calFlag,
    //       arg7, &out1, &out2, arg10, arg11, arg12)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10f650), {
        onEnter: function (a) {
            ctr.ENTRY++;
            var id = ctr.ENTRY;
            this.id = id;
            this.statePP = a[0];
            this.raw = a[1];
            this.nbuf = a[2].toInt32();
            this.ws = a[3];
            this.cfgWord = a[4].toUInt32();
            lastNbuf = this.nbuf;

            // Unpack cfgWord: w = >>23, h = (>>14)&0x1ff, mode = (>>3)&0x3f
            lastW = (this.cfgWord >>> 23) & 0x1ff;
            lastH = (this.cfgWord >>> 14) & 0x1ff;
            lastMode = (this.cfgWord >>> 3) & 0x3f;

            ctr.INPUT++;
            dumpBin("INPUT", ctr.INPUT, this.raw, this.nbuf);
            console.log("ENTRY " + id +
                        " nbuf=" + this.nbuf +
                        " cfg=0x" + this.cfgWord.toString(16) +
                        " w=" + lastW + " h=" + lastH + " mode=" + lastMode +
                        " raw_head=" + hexHead(this.raw, 16));
        },
        onLeave: function (rv) {
            // FRAME output lives at *(*statePP + 0x18) by the end of the func
            try {
                var statePtr = this.statePP.readPointer();
                if (!statePtr.isNull()) {
                    var framePtr = statePtr.add(0x18).readPointer();
                    if (!framePtr.isNull()) {
                        ctr.FRAME++;
                        dumpBin("FRAME", ctr.FRAME, framePtr, this.nbuf);
                        console.log("FRAME " + this.id +
                                    " head=" + hexHead(framePtr, 16) +
                                    " rv=0x" + rv.toUInt32().toString(16));
                    }
                }
            } catch (e) { console.log("FRAME-err " + this.id + ": " + e); }
        }
    });

    // -----------------------------------------------------------------------
    // 2) sub_18010c610 — geometry preprocess (clamp/invert/border)
    // sig: (cfg*, buf u16*, arg3, arg4)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10c610), {
        onEnter: function (a) {
            ctr.GEOM++;
            var id = ctr.GEOM;
            this.id = id;
            this.buf = a[1];
            var cfg = readCfg(a[0]);
            var n = cfg ? cfg.npx * 2 : lastNbuf;
            this.n = n;
            dumpBin("GEOM_IN", id, this.buf, n);
            console.log("GEOM " + id + " in_head=" + hexHead(this.buf, 16) +
                        (cfg ? " mode=" + cfg.mode : ""));
        },
        onLeave: function (rv) {
            dumpBin("GEOM_OUT", this.id, this.buf, this.n);
        }
    });

    // -----------------------------------------------------------------------
    // 3) sub_18010a8e0 — "is finger present" validator
    // sig: (buf u16*, h, w, mode, flag)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10a8e0), {
        onEnter: function (a) {
            ctr.VALID++;
            this.id = ctr.VALID;
            this.h = a[1].toInt32();
            this.w = a[2].toInt32();
            this.mode = a[3].toInt32();
        },
        onLeave: function (rv) {
            console.log("VALID " + this.id +
                        " w=" + this.w + " h=" + this.h +
                        " mode=" + this.mode + " rv=" + rv.toInt32());
        }
    });

    // -----------------------------------------------------------------------
    // 4) sub_18010d3d0 — mask builder
    // sig: (rawA u16*, rawB u16*, cfg*, maskOut*)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10d3d0), {
        onEnter: function (a) {
            ctr.MASK++;
            var id = ctr.MASK;
            this.id = id;
            this.maskOut = a[3];
            var cfg = readCfg(a[2]);
            this.maskSize = cfg ? (cfg.npx + 0x10) : 0;
            dumpBin("MASK_RAWA", id, a[0], cfg ? cfg.npx * 2 : lastNbuf);
            dumpBin("MASK_RAWB", id, a[1], cfg ? cfg.npx * 2 : lastNbuf);
            console.log("MASK " + id + " size=" + this.maskSize);
        },
        onLeave: function (rv) {
            if (this.maskSize > 0) dumpBin("MASK_OUT", this.id, this.maskOut, this.maskSize);
        }
    });

    // -----------------------------------------------------------------------
    // 5) sub_18010a460 — *** main local-envelope stretch ***
    // sig: (src u16*, dst u8*, cfg*, mask*, qual*)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10a460), {
        onEnter: function (a) {
            ctr.STRETCH_IN++;
            var id = ctr.STRETCH_IN;
            this.id = id;
            this.dst = a[1];
            var cfg = readCfg(a[2]);
            this.npx = cfg ? cfg.npx : (lastW * lastH);
            this.nbuf = this.npx * 2;
            dumpBin("STRETCH_IN", id, a[0], this.nbuf);
            console.log("STRETCH " + id + " npx=" + this.npx +
                        (cfg ? " w=" + cfg.w + " h=" + cfg.h + " mode=" + cfg.mode : ""));
        },
        onLeave: function (rv) {
            ctr.STRETCH_OUT++;
            // output is u8 per pixel
            dumpBin("STRETCH_OUT", this.id, this.dst, this.npx);
        }
    });

    // -----------------------------------------------------------------------
    // 6) sub_18010b910 — smoother
    // sig: (rawIn u16*, scratchOut u16*, mask u8*, cfg*)
    //
    // arg3 is the per-pixel quality mask consumed by sub_180112a00
    // (Wallis-style local mean normalisation). Dumped as SMOOTH_MASK so it
    // can be paired 1:1 with SMOOTH_IN/OUT by id, independent of MASK_OUT
    // from the mask builder (which fires once per capture, not per smoother).
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10b910), {
        onEnter: function (a) {
            ctr.SMOOTH_IN++;
            var id = ctr.SMOOTH_IN;
            this.id = id;
            this.scratch = a[1];
            var cfg = readCfg(a[3]);
            this.nbuf = cfg ? cfg.npx * 2 : lastNbuf;
            this.npx  = cfg ? cfg.npx     : (lastW * lastH);
            dumpBin("SMOOTH_IN",   id, a[0], this.nbuf);
            // arg3 = mask, one byte per pixel
            if (!a[2].isNull() && this.npx > 0) {
                dumpBin("SMOOTH_MASK", id, a[2], this.npx);
            }
        },
        onLeave: function (rv) {
            ctr.SMOOTH_OUT++;
            dumpBin("SMOOTH_OUT", this.id, this.scratch, this.nbuf);
            console.log("SMOOTH " + this.id + " nbuf=" + this.nbuf + " npx=" + this.npx);
        }
    });

    // -----------------------------------------------------------------------
    // 7) sub_18010e0e0 — horizontal sliding min/max
    // sig: (src u16*, h, w, lowOut u16*, highOut u16*)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10e0e0), {
        onEnter: function (a) {
            ctr.HENV_IN++;
            var id = ctr.HENV_IN;
            this.id = id;
            this.h = a[1].toInt32();
            this.w = a[2].toInt32();
            this.nbuf = this.h * this.w * 2;
            this.lo = a[3];
            this.hi = a[4];
            dumpBin("HENV_IN", id, a[0], this.nbuf);
        },
        onLeave: function (rv) {
            ctr.HENV_LO++; dumpBin("HENV_LO", ctr.HENV_LO, this.lo, this.nbuf);
            ctr.HENV_HI++; dumpBin("HENV_HI", ctr.HENV_HI, this.hi, this.nbuf);
            console.log("HENV " + this.id + " w=" + this.w + " h=" + this.h);
        }
    });

    // -----------------------------------------------------------------------
    // 8) sub_18010ce20 — vertical sliding min/max
    // sig: (src u16*, h, w, lowOut u16*, highOut u16*)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10ce20), {
        onEnter: function (a) {
            ctr.VENV_IN++;
            var id = ctr.VENV_IN;
            this.id = id;
            this.h = a[1].toInt32();
            this.w = a[2].toInt32();
            this.nbuf = this.h * this.w * 2;
            this.lo = a[3];
            this.hi = a[4];
            dumpBin("VENV_IN", id, a[0], this.nbuf);
        },
        onLeave: function (rv) {
            ctr.VENV_LO++; dumpBin("VENV_LO", ctr.VENV_LO, this.lo, this.nbuf);
            ctr.VENV_HI++; dumpBin("VENV_HI", ctr.VENV_HI, this.hi, this.nbuf);
            console.log("VENV " + this.id + " w=" + this.w + " h=" + this.h);
        }
    });

    // -----------------------------------------------------------------------
    // 9) sub_18010f1f0 — 3x3 morphological close on (low, high)
    // sig: (lowIn u16*, highIn u16*, h, w, lowOut u16*, highOut u16*)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10f1f0), {
        onEnter: function (a) {
            ctr.MORPH_LO_IN++;
            var id = ctr.MORPH_LO_IN;
            this.id = id;
            this.h = a[2].toInt32();
            this.w = a[3].toInt32();
            this.nbuf = this.h * this.w * 2;
            this.loOut = a[4];
            this.hiOut = a[5];
            dumpBin("MORPH_LO_IN",  id, a[0], this.nbuf);
            dumpBin("MORPH_HI_IN",  id, a[1], this.nbuf);
        },
        onLeave: function (rv) {
            ctr.MORPH_LO_OUT++; dumpBin("MORPH_LO_OUT", ctr.MORPH_LO_OUT, this.loOut, this.nbuf);
            ctr.MORPH_HI_OUT++; dumpBin("MORPH_HI_OUT", ctr.MORPH_HI_OUT, this.hiOut, this.nbuf);
            console.log("MORPH " + this.id + " w=" + this.w + " h=" + this.h);
        }
    });

    // -----------------------------------------------------------------------
    // 10) sub_18010aa60 — frame arbiter (just count + log mode)
    // -----------------------------------------------------------------------
    Interceptor.attach(wbdi.base.add(0x10aa60), {
        onEnter: function (a) {
            ctr.ARBITER++;
            console.log("ARBITER " + ctr.ARBITER);
        }
    });

    // -----------------------------------------------------------------------
    // 11) sub_1801123e0 — Cal2 stage (per-pixel gain map applied right
    //     before STRETCH; see docs/WBDI_STRETCH_RE.md §10 "Newly resolved").
    //
    //     Confirmed 2026-06-05 SID 20260605023330: CAL_OUT ≡ STRETCH_IN
    //     byte-for-byte (13/13). Formula per decompile is
    //         out[i] = (raw_x3[i] * 8192) / scale[i]    when mask[i] != 0
    //     where raw_x3 = arg1 tripled in scratch, scale[i] = rax_7[i]. But the
    //     empirically inferred scale[] does NOT correlate cross-frame
    //     (corr ≈ 0.12), so scale is per-frame computed at runtime via
    //     sub_1801121b0 + sub_180112e30. To RE the scale-building, dump:
    //
    //       arg2          — the secondary input (some smoothed buffer from
    //                        workspace[0x2649])  →  CAL_SECONDARY
    //       arg5[0]       — the actual scale[] buffer (= rax_7), captured at
    //                        instruction RVA 0x1127e7 just before its free()
    //                                                →  CAL_SCALE
    //
    //     For thread-safety we keep a per-thread map of holder ptrs.
    // -----------------------------------------------------------------------
    var calHolders = {};

    Interceptor.attach(wbdi.base.add(0x1123e0), {
        onEnter: function (a) {
            ctr.CAL_IN++;
            var id = ctr.CAL_IN;
            this.id = id;
            this.cfgPtr = a[6];                       // arg7 = cfg
            var cfg = readCfg(a[6]);
            this.npx  = cfg ? cfg.npx : (lastW * lastH);
            this.nbuf = this.npx * 2;
            this.workspace = a[2];                    // arg3 (int32_t*)
            this.outPtr = a[2].add(0x4c91 * 4);       // workspace[0x4c91] as dword offset
            this.holder = a[4];                       // arg5 = scale holder struct
            calHolders[this.threadId] = {
                id: id,
                nbuf: this.nbuf,
                npx: this.npx,
                holder: a[4]
            };
            dumpBin("CAL_IN",        id, a[0], this.nbuf);
            dumpBin("CAL_SECONDARY", id, a[1], this.nbuf);
            console.log("CAL " + id + " npx=" + this.npx +
                        " ws=" + a[2] + " outPtr=" + this.outPtr +
                        (cfg ? " mode=" + cfg.mode : ""));
        },
        onLeave: function (rv) {
            ctr.CAL_OUT++;
            dumpBin("CAL_OUT", this.id, this.outPtr, this.nbuf);
            delete calHolders[this.threadId];
        }
    });

    // ---- inner hook: snapshot scale[] just before free(rax_7) ----
    // RVA 0x1127e7 = call to sub_1800c1fc0(rax_8); the *NEXT* call (1127ef)
    // is sub_1800c1fc0(rax_7). We hook 1127ef and read scale from holder[0]
    // (which is rax_7) BEFORE that free() runs.
    Interceptor.attach(wbdi.base.add(0x1127ef), {
        onEnter: function () {
            var h = calHolders[this.threadId];
            if (!h) return;
            try {
                var scalePtr = h.holder.readPointer();   // *(arg5) = rax_7
                if (!scalePtr.isNull()) {
                    ctr.CAL_SCALE++;
                    dumpBin("CAL_SCALE", h.id, scalePtr, h.nbuf);
                }
            } catch (e) {
                console.log("CAL_SCALE dump err " + h.id + ": " + e);
            }
        }
    });

    console.log("HOOKS_READY (11 callees)");
}
