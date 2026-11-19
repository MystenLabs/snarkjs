import assert from "assert";
import { blake2b } from "@noble/hashes/blake2b";

import { toPartialHash, fromPartialHash } from "../src/misc.js";

// Checkpoint and restore a streaming blake2b state, including counters above 2^32.
describe("partial hash serialization", function () {
    this.timeout(10000);

    // Use non-trivial state and simulate a large input by advancing the counter.
    function absorbedWithLength(length) {
        const h = blake2b.create({ dkLen: 64 });
        h.update(new Uint8Array(300).fill(7));
        h.length = length;
        return h;
    }

    const BIG = 2 ** 33 + 5 * 128 + 44; // > 2^32, with pos = 44

    it("round-trips length and pos above 2^32", () => {
        const h = absorbedWithLength(BIG);
        const r = fromPartialHash(toPartialHash(h));
        assert.strictEqual(r.length, h.length);
        assert.strictEqual(r.pos, h.pos);
    });

    it("a restored hasher above 2^32 finalizes to the same digest", () => {
        // A truncated counter would produce a different final digest.
        const tail = new Uint8Array(1000).fill(9);
        const a = absorbedWithLength(BIG);
        const b = fromPartialHash(toPartialHash(a));
        a.update(tail);
        b.update(tail);
        assert.deepStrictEqual(Buffer.from(b.digest()), Buffer.from(a.digest()));
    });

    it("still matches a fresh hasher below 2^32", () => {
        const data = new Uint8Array(5000).fill(3);
        const a = blake2b.create({ dkLen: 64 });
        a.update(data.subarray(0, 1234));
        const b = fromPartialHash(toPartialHash(a));
        a.update(data.subarray(1234));
        b.update(data.subarray(1234));
        const fresh = blake2b.create({ dkLen: 64 }).update(data).digest();
        assert.deepStrictEqual(Buffer.from(b.digest()), Buffer.from(fresh));
        assert.deepStrictEqual(Buffer.from(a.digest()), Buffer.from(fresh));
    });
});