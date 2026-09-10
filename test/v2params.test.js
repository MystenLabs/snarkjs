import * as snarkjs from "../main.js";
import { getCurveFromName } from "../src/curves.js";
import { readMPCParamsFile } from "../src/zkey_utils.js";
import { hashIsEqual } from "../src/misc.js";
import assert from "assert";
import path from "path";

describe("v2params split-contribute pipeline", function () {
    this.timeout(1000000000);

    let curve;
    const ptau_final = {type: "mem"};
    const zkey_0 = {type: "mem"};

    before(async () => { curve = await getCurveFromName("bn128"); });
    after(async () => { await curve.terminate(); });

    it("contribute rejects unknown magic", async () => {
        const bad = {type: "mem", data: new Uint8Array([0x66, 0x6f, 0x6f, 0x00, 0, 0, 0, 0])};
        const out = {type: "mem"};
        await assert.rejects(
            () => snarkjs.zKey.contribute(bad, out, "x", "x"),
            /expected "zkey" or "p2u" magic/
        );
    });

    it("phase 1 + groth16 setup (shared by following tests)", async () => {
        const ptau_init = {type: "mem"};
        const ptau_after = {type: "mem"};
        const ptau_beacon = {type: "mem"};
        await snarkjs.powersOfTau.newAccumulator(curve, 11, ptau_init);
        await snarkjs.powersOfTau.contribute(ptau_init, ptau_after, "C1", "Entropy1");
        await snarkjs.powersOfTau.beacon(ptau_after, ptau_beacon, "B",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 10);
        await snarkjs.powersOfTau.preparePhase2(ptau_beacon, ptau_final);
        await snarkjs.zKey.newZKey(path.join("test", "groth16", "circuit.r1cs"), ptau_final, zkey_0);
    });

    it("extract -> contribute(p2u) -> compress/decompress -> assemble -> verify", async () => {
        const v2u_0 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_0, v2u_0);
        assert.strictEqual(String.fromCharCode(...v2u_0.data.subarray(0, 4)), "p2u\0");

        const v2u_1 = {type: "mem"};
        await snarkjs.zKey.contribute(v2u_0, v2u_1, "C-v2", "entropy-v2");
        assert.strictEqual(String.fromCharCode(...v2u_1.data.subarray(0, 4)), "p2u\0");

        const v2c = {type: "mem"};
        const v2u_rt = {type: "mem"};
        await snarkjs.zKey.compressV2Params(v2u_1, v2c);
        assert.strictEqual(String.fromCharCode(...v2c.data.subarray(0, 4)), "p2c\0");
        await snarkjs.zKey.decompressV2Params(v2c, v2u_rt);
        assert.deepStrictEqual(v2u_rt.data, v2u_1.data, "compress/decompress not byte-identical");

        const zkey_full = {type: "mem"};
        await snarkjs.zKey.assemble(zkey_0, v2u_1, zkey_full);
        const ok = await snarkjs.zKey.verifyFromInit(zkey_0, ptau_final, zkey_full);
        assert(ok, "verifyFromInit failed");
    });

    it("three v2params contributions chain -> assemble -> verify", async () => {
        const v2u_0 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_0, v2u_0);

        const v2u_1 = {type: "mem"};
        const v2u_2 = {type: "mem"};
        const v2u_3 = {type: "mem"};
        await snarkjs.zKey.contribute(v2u_0, v2u_1, "C1", "entropy-1");
        await snarkjs.zKey.contribute(v2u_1, v2u_2, "C2", "entropy-2");
        await snarkjs.zKey.contribute(v2u_2, v2u_3, "C3", "entropy-3");

        const zkey_full = {type: "mem"};
        await snarkjs.zKey.assemble(zkey_0, v2u_3, zkey_full);
        const ok = await snarkjs.zKey.verifyFromInit(zkey_0, ptau_final, zkey_full);
        assert(ok, "verifyFromInit failed");
    });

    it("readMPCParamsFile reads the same chain from a zkey and its v2params", async () => {
        const v2u_0 = {type: "mem"};
        const v2u_1 = {type: "mem"};
        const p2c_1 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_0, v2u_0);
        await snarkjs.zKey.contribute(v2u_0, v2u_1, "C1", "entropy-1");
        await snarkjs.zKey.compressV2Params(v2u_1, p2c_1);
        const zkey_1 = {type: "mem"};
        await snarkjs.zKey.assemble(zkey_0, v2u_1, zkey_1);

        const fromZkey = await readMPCParamsFile(zkey_1);
        const fromP2u = await readMPCParamsFile(v2u_1);
        const fromP2c = await readMPCParamsFile(p2c_1);
        assert.strictEqual(fromZkey.hashes.length, 1);
        assert(hashIsEqual(fromZkey.hashes[0], fromP2u.hashes[0]));
        assert(hashIsEqual(fromZkey.hashes[0], fromP2c.hashes[0]));
        assert(hashIsEqual(fromZkey.mpcParams.csHash, fromP2c.mpcParams.csHash));
        assert.strictEqual(fromZkey.mpcParams.contributions[0].name, "C1");

        const bad = {type: "mem", data: new Uint8Array([0x66, 0x6f, 0x6f, 0x00, 0, 0, 0, 0])};
        await assert.rejects(() => readMPCParamsFile(bad), /expected zkey, p2u or p2c magic, got "foo"/);
        await assert.rejects(() => snarkjs.zKey.v2paramsExtends(zkey_1, p2c_1), /expected p2u or p2c magic, got "zkey"/);
    });

    it("v2paramsExtends checks exactly-one contribution prefix extension", async () => {
        const v2u_0 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_0, v2u_0);

        const v2u_1 = {type: "mem"};
        const v2u_2 = {type: "mem"};
        await snarkjs.zKey.contribute(v2u_0, v2u_1, "C1", "entropy-1");
        await snarkjs.zKey.contribute(v2u_1, v2u_2, "C2", "entropy-2");

        const p2c_0 = {type: "mem"};
        const p2c_1 = {type: "mem"};
        const p2c_2 = {type: "mem"};
        await snarkjs.zKey.compressV2Params(v2u_0, p2c_0);
        await snarkjs.zKey.compressV2Params(v2u_1, p2c_1);
        await snarkjs.zKey.compressV2Params(v2u_2, p2c_2);

        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(p2c_1, p2c_2), true);
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(v2u_1, v2u_2), true);
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(v2u_1, p2c_2), true);
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(p2c_1, v2u_2), true);
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(p2c_0, p2c_2), false);

        const v2u_x1 = {type: "mem"};
        const v2u_x2 = {type: "mem"};
        await snarkjs.zKey.contribute(v2u_0, v2u_x1, "X1", "entropy-x1");
        await snarkjs.zKey.contribute(v2u_x1, v2u_x2, "X2", "entropy-x2");

        const p2c_x1 = {type: "mem"};
        const p2c_x2 = {type: "mem"};
        await snarkjs.zKey.compressV2Params(v2u_x1, p2c_x1);
        await snarkjs.zKey.compressV2Params(v2u_x2, p2c_x2);

        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(p2c_1, p2c_x1), false);
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(p2c_1, p2c_x2), false);
    });

    it("v2paramsExtends rejects a different circuit in the 0-contribution case", async () => {
        // former has 0 contributions, so the prefix loop runs zero iterations.
        // Only the csHash check can catch a later file from a different circuit.
        const zkey_b = {type: "mem"};
        await snarkjs.zKey.newZKey(path.join("test", "circuit", "circuit.r1cs"), ptau_final, zkey_b);

        const a_0 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_0, a_0);

        const b_0 = {type: "mem"};
        const b_1 = {type: "mem"};
        await snarkjs.zKey.extract(zkey_b, b_0);
        await snarkjs.zKey.contribute(b_0, b_1, "B1", "entropy-b1");

        // exactly-one-more contribution, but a different circuit: must be false.
        assert.strictEqual(await snarkjs.zKey.v2paramsExtends(a_0, b_1), false);
    });
});
