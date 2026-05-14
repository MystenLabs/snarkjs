import * as snarkjs from "../main.js";
import { getCurveFromName } from "../src/curves.js";
import assert from "assert";
import path from "path";

describe("v2params split-contribute pipeline", function () {
    this.timeout(1000000000);

    let curve;
    const ptau_final = {type: "mem"};

    // Full-zkey contribution path (sanity: standard contribute still works).
    const zkey_0 = {type: "mem"};
    const zkey_1_full = {type: "mem"};

    // v2params path.
    const v2params_0 = {type: "mem"};
    const v2params_1 = {type: "mem"};
    const v2params_2 = {type: "mem"};
    const v2params_1_p2c = {type: "mem"};
    const v2params_1_roundtrip = {type: "mem"};
    const zkey_assembled = {type: "mem"};

    before(async () => {
        curve = await getCurveFromName("bn128");
    });
    after(async () => {
        await curve.terminate();
    });

    it("phase 1 (powers of tau)", async () => {
        const ptau_init = {type: "mem"};
        const ptau_after = {type: "mem"};
        const ptau_beacon = {type: "mem"};
        await snarkjs.powersOfTau.newAccumulator(curve, 11, ptau_init);
        await snarkjs.powersOfTau.contribute(ptau_init, ptau_after, "C1", "Entropy1");
        await snarkjs.powersOfTau.beacon(
            ptau_after, ptau_beacon, "B",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 10
        );
        await snarkjs.powersOfTau.preparePhase2(ptau_beacon, ptau_final);
    });

    it("groth16 setup (zkey_0)", async () => {
        await snarkjs.zKey.newZKey(
            path.join("test", "groth16", "circuit.r1cs"), ptau_final, zkey_0
        );
    });

    it("standard full-zkey contribute still works (auto-detect 'zkey' magic)", async () => {
        await snarkjs.zKey.contribute(zkey_0, zkey_1_full, "full-C1", "full-entropy-1");
        const ok = await snarkjs.zKey.verifyFromInit(zkey_0, ptau_final, zkey_1_full);
        assert(ok, "verifyFromInit failed on full-zkey contribute");
    });

    it("extract emits p2u v2params", async () => {
        await snarkjs.zKey.extract(zkey_0, v2params_0);
        const m = v2params_0.data;
        assert.strictEqual(String.fromCharCode(m[0], m[1], m[2], m[3]), "p2u\0");
    });

    it("contribute auto-detects p2u and produces p2u", async () => {
        await snarkjs.zKey.contribute(v2params_0, v2params_1, "v2-C1", "v2-entropy-1");
        const m = v2params_1.data;
        assert.strictEqual(String.fromCharCode(m[0], m[1], m[2], m[3]), "p2u\0");
    });

    it("second v2params contribute chains", async () => {
        await snarkjs.zKey.contribute(v2params_1, v2params_2, "v2-C2", "v2-entropy-2");
    });

    it("compress + decompress round-trip is byte-identical", async () => {
        await snarkjs.zKey.compressV2Params(v2params_1, v2params_1_p2c);
        // p2c magic
        assert.strictEqual(
            String.fromCharCode(v2params_1_p2c.data[0], v2params_1_p2c.data[1], v2params_1_p2c.data[2], v2params_1_p2c.data[3]),
            "p2c\0"
        );
        await snarkjs.zKey.decompressV2Params(v2params_1_p2c, v2params_1_roundtrip);
        const a = v2params_1.data;
        const b = v2params_1_roundtrip.data;
        assert.strictEqual(a.length, b.length, "round-trip length mismatch");
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) assert.fail(`byte ${i} differs: ${a[i]} vs ${b[i]}`);
        }
    });

    it("assemble base + v2params -> full zkey", async () => {
        await snarkjs.zKey.assemble(zkey_0, v2params_2, zkey_assembled);
    });

    it("assembled zkey verifies against init zkey + ptau", async () => {
        const ok = await snarkjs.zKey.verifyFromInit(zkey_0, ptau_final, zkey_assembled);
        assert(ok, "verifyFromInit failed on assembled zkey");
    });

    it("contribute rejects unknown magic", async () => {
        const bad = {type: "mem", data: new Uint8Array([0x66, 0x6f, 0x6f, 0x00, 0, 0, 0, 0])};  // "foo\0"
        const out = {type: "mem"};
        await assert.rejects(
            () => snarkjs.zKey.contribute(bad, out, "x", "x"),
            /expected "zkey" or "p2u" magic/
        );
    });

    it("assemble rejects p2c input (magic mismatch, must zkdec first)", async () => {
        const out = {type: "mem"};
        await assert.rejects(
            () => snarkjs.zKey.assemble(zkey_0, v2params_1_p2c, out),
            /Invalid File format/
        );
    });
});
