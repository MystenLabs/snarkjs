/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

// Verify a single Phase 2 contribution against the immediately prior state,
// operating on `.v2params` (partial zkey) files.
//
// AUDIT MAPPING (against kobi's verify_contribution and snarkjs zkey_verify_frominit):
//
//   #1 single new contribution           -- contributions.length == before+1
//   #2 prior contributions unchanged     -- transcript & deltaAfter equal per index
//   #3 H/L lengths equal                 -- section sizes match nVars-nPublic-1 and domainSize
//   #4 byte-equal of frozen sections:
//        - alpha, beta_1, beta_2, gamma_2 (in section 2)  -- KEEP
//        - csHash (in section 10)                          -- KEEP
//        - IC, A, B1, B2 (sections 3, 5, 6, 7)             -- DROPPED: not in v2params
//          The drop is safe because v2params contributors never possess these
//          sections; assemble reinjects them from the trusted base zkey.
//   #5 transcript hash consistent
//   #6 Schnorr-style PoK on (g1_s, g1_sx, g2_sp, g2_spx)
//   #7 delta chain: deltaAfter = deltaBefore * x; header.delta_1 == newC.deltaAfter;
//      G1/G2 delta consistency
//   #8 L ratio: same_ratio((before.L, after.L), (after.delta_2, before.delta_2))
//      H ratio: same_ratio against ptau (snarkjs-style; stronger than kobi)

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import { blake2b } from "@noble/hashes/blake2b";
import * as misc from "./misc.js";
import { hashToG2 as hashToG2 } from "./keypair.js";
import { hashG1, hashPubKey } from "./zkey_utils.js";
import { Scalar, ChaCha, BigBuffer } from "ffjavascript";

const sameRatio = misc.sameRatio;

export default async function phase2verifyV2Params(beforeFileName, afterFileName, pTauFileName, logger) {
    let sr;

    const {fd: fdBefore, sections: sectionsBefore} = await binFileUtils.readBinFile(beforeFileName, "zkey", 2);
    const zkeyBefore = await zkeyUtils.readHeader(fdBefore, sectionsBefore, false);

    const {fd: fdAfter, sections: sectionsAfter} = await binFileUtils.readBinFile(afterFileName, "zkey", 2);
    const zkeyAfter = await zkeyUtils.readHeader(fdAfter, sectionsAfter, false);

    if (zkeyBefore.protocol != "groth16" || zkeyAfter.protocol != "groth16") {
        throw new Error("v2params files must be groth16");
    }

    const curve = await getCurve(zkeyAfter.q);
    const sG1 = curve.G1.F.n8 * 2;

    // #4 (kept portion): curve and circuit parameters
    if (!Scalar.eq(zkeyBefore.q, zkeyAfter.q) || !Scalar.eq(zkeyBefore.r, zkeyAfter.r)
        || zkeyBefore.n8q != zkeyAfter.n8q || zkeyBefore.n8r != zkeyAfter.n8r) {
        if (logger) logger.error("INVALID: Different curves");
        return false;
    }
    if (zkeyBefore.nVars != zkeyAfter.nVars
        || zkeyBefore.nPublic != zkeyAfter.nPublic
        || zkeyBefore.domainSize != zkeyAfter.domainSize) {
        if (logger) logger.error("INVALID: Different circuit parameters");
        return false;
    }
    if (!curve.G1.eq(zkeyBefore.vk_alpha_1, zkeyAfter.vk_alpha_1)) {
        if (logger) logger.error("INVALID: vk_alpha_1 changed");
        return false;
    }
    if (!curve.G1.eq(zkeyBefore.vk_beta_1, zkeyAfter.vk_beta_1)) {
        if (logger) logger.error("INVALID: vk_beta_1 changed");
        return false;
    }
    if (!curve.G2.eq(zkeyBefore.vk_beta_2, zkeyAfter.vk_beta_2)) {
        if (logger) logger.error("INVALID: vk_beta_2 changed");
        return false;
    }
    if (!curve.G2.eq(zkeyBefore.vk_gamma_2, zkeyAfter.vk_gamma_2)) {
        if (logger) logger.error("INVALID: vk_gamma_2 changed");
        return false;
    }

    // MPC params: csHash + contribution chain
    const mpcBefore = await zkeyUtils.readMPCParams(fdBefore, curve, sectionsBefore);
    const mpcAfter  = await zkeyUtils.readMPCParams(fdAfter,  curve, sectionsAfter);

    // #4 (kept): csHash equal
    if (!misc.hashIsEqual(mpcBefore.csHash, mpcAfter.csHash)) {
        if (logger) logger.error("INVALID: csHash changed");
        return false;
    }

    // #1: exactly one new contribution
    if (mpcAfter.contributions.length !== mpcBefore.contributions.length + 1) {
        if (logger) logger.error(`INVALID: Expected ${mpcBefore.contributions.length + 1} contributions, got ${mpcAfter.contributions.length}`);
        return false;
    }

    // #2: prior contributions unchanged (transcript + deltaAfter sufficient because
    // transcript commits to all prior pubkey bytes; this is double-checked via
    // pubkey field equality for defense-in-depth).
    for (let i = 0; i < mpcBefore.contributions.length; i++) {
        const cb = mpcBefore.contributions[i];
        const ca = mpcAfter.contributions[i];
        if (!misc.hashIsEqual(cb.transcript, ca.transcript)) {
            if (logger) logger.error(`INVALID: prior contribution #${i+1} transcript mismatch`);
            return false;
        }
        if (!curve.G1.eq(cb.deltaAfter, ca.deltaAfter)) {
            if (logger) logger.error(`INVALID: prior contribution #${i+1} deltaAfter mismatch`);
            return false;
        }
        if (!curve.G1.eq(cb.delta.g1_s, ca.delta.g1_s)
            || !curve.G1.eq(cb.delta.g1_sx, ca.delta.g1_sx)
            || !curve.G2.eq(cb.delta.g2_spx, ca.delta.g2_spx)) {
            if (logger) logger.error(`INVALID: prior contribution #${i+1} pubkey mismatch`);
            return false;
        }
    }

    // The new contribution: last entry of mpcAfter.contributions
    const newC = mpcAfter.contributions[mpcAfter.contributions.length - 1];

    // #5: transcript consistency for the new contribution
    const transcriptHasher = blake2b.create({ dkLen: 64 });
    transcriptHasher.update(mpcAfter.csHash);
    for (let i = 0; i < mpcBefore.contributions.length; i++) {
        hashPubKey(transcriptHasher, curve, mpcBefore.contributions[i]);
    }
    hashG1(transcriptHasher, curve, newC.delta.g1_s);
    hashG1(transcriptHasher, curve, newC.delta.g1_sx);
    if (!misc.hashIsEqual(transcriptHasher.digest(), newC.transcript)) {
        if (logger) logger.error("INVALID: Inconsistent transcript on new contribution");
        return false;
    }

    // #6: Schnorr-style PoK
    const delta_g2_sp = hashToG2(curve, newC.transcript);
    sr = await sameRatio(curve, newC.delta.g1_s, newC.delta.g1_sx, delta_g2_sp, newC.delta.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID: pubkey G1/G2 ratio mismatch");
        return false;
    }

    // #7: delta chain
    sr = await sameRatio(curve, zkeyBefore.vk_delta_1, newC.deltaAfter, delta_g2_sp, newC.delta.g2_spx);
    if (sr !== true) {
        if (logger) logger.error("INVALID: deltaAfter does not follow the public key");
        return false;
    }
    if (!curve.G1.eq(zkeyAfter.vk_delta_1, newC.deltaAfter)) {
        if (logger) logger.error("INVALID: header.vk_delta_1 doesn't match new contribution's deltaAfter");
        return false;
    }
    sr = await sameRatio(curve, curve.G1.g, zkeyAfter.vk_delta_1, curve.G2.g, zkeyAfter.vk_delta_2);
    if (sr !== true) {
        if (logger) logger.error("INVALID: header delta_2 inconsistent with delta_1");
        return false;
    }

    // Beacon-type contributions: also verify deterministic derivation from beacon hex
    if (newC.type == 1) {
        const rng = await misc.rngFromBeaconParams(newC.beaconHash, newC.numIterationsExp);
        const expected_prvKey = curve.Fr.fromRng(rng);
        const expected_g1_s   = curve.G1.toAffine(curve.G1.fromRng(rng));
        const expected_g1_sx  = curve.G1.toAffine(curve.G1.timesFr(expected_g1_s, expected_prvKey));
        if (!curve.G1.eq(expected_g1_s, newC.delta.g1_s)) {
            if (logger) logger.error("INVALID beacon: g1_s doesn't match derivation");
            return false;
        }
        if (!curve.G1.eq(expected_g1_sx, newC.delta.g1_sx)) {
            if (logger) logger.error("INVALID beacon: g1_sx doesn't match derivation");
            return false;
        }
    }

    // #3: section sizes
    const expectedLSize = sG1 * (zkeyAfter.nVars - zkeyAfter.nPublic - 1);
    const expectedHSize = sG1 * zkeyAfter.domainSize;
    if (sectionsBefore[8][0].size != expectedLSize || sectionsAfter[8][0].size != expectedLSize) {
        if (logger) logger.error("INVALID: L section size unexpected");
        return false;
    }
    if (sectionsBefore[9][0].size != expectedHSize || sectionsAfter[9][0].size != expectedHSize) {
        if (logger) logger.error("INVALID: H section size unexpected");
        return false;
    }

    // #8a: L ratio
    sr = await sectionHasSameRatio("G1", fdBefore, sectionsBefore, fdAfter, sectionsAfter, 8, zkeyAfter.vk_delta_2, zkeyBefore.vk_delta_2, "L section");
    if (sr !== true) {
        if (logger) logger.error("INVALID: L section ratio failed");
        return false;
    }

    // #8b: H ratio against ptau (snarkjs-style; uses τⁿ-1 structure from ptau)
    sr = await sameRatioH();
    if (sr !== true) {
        if (logger) logger.error("INVALID: H section ratio failed");
        return false;
    }

    if (logger) logger.info(misc.formatHash(mpcAfter.csHash, "Circuit Hash: "));

    await fdBefore.close();
    await fdAfter.close();

    if (logger) {
        logger.info("-------------------------");
        logger.info(misc.formatHash(newC.transcript, `New contribution #${mpcAfter.contributions.length} ${newC.name || ""}:`));
        if (newC.type == 1) {
            logger.info(`Beacon hex: ${misc.byteArray2hex(newC.beaconHash)}`);
            logger.info(`Beacon iterations exp: ${newC.numIterationsExp}`);
        }
        logger.info("-------------------------");
        logger.info("v2params Ok!");
    }

    return true;

    async function sectionHasSameRatio(groupName, fd1, sections1, fd2, sections2, idSection, g2sp, g2spx, sectionName) {
        const MAX_CHUNK_SIZE = 1 << 20;
        const G = curve[groupName];
        const sG = G.F.n8 * 2;
        await binFileUtils.startReadUniqueSection(fd1, sections1, idSection);
        await binFileUtils.startReadUniqueSection(fd2, sections2, idSection);
        let R1 = G.zero;
        let R2 = G.zero;
        const nPoints = sections1[idSection][0].size / sG;
        for (let i = 0; i < nPoints; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`Same ratio check ${sectionName}:  ${i}/${nPoints}`);
            const n = Math.min(nPoints - i, MAX_CHUNK_SIZE);
            const bases1 = await fd1.read(n * sG);
            const bases2 = await fd2.read(n * sG);
            const scalars = misc.getRandomBytes(4 * n);
            const r1 = await G.multiExpAffine(bases1, scalars);
            const r2 = await G.multiExpAffine(bases2, scalars);
            R1 = G.add(R1, r1);
            R2 = G.add(R2, r2);
        }
        await binFileUtils.endReadSection(fd1);
        await binFileUtils.endReadSection(fd2);
        if (nPoints == 0) return true;
        return (await sameRatio(curve, R1, R2, g2sp, g2spx)) === true;
    }

    // sameRatioH and batchSubtract*: structurally identical to the corresponding
    // helpers inside zkey_verify_frominit.js. Auditor: confirm byte-equivalent
    // semantics with that file.
    async function sameRatioH() {
        const MAX_CHUNK_SIZE = 1 << 20;
        const G = curve.G1;
        const Fr = curve.Fr;
        const sG = G.F.n8 * 2;
        const {fd: fdPTau, sections: sectionsPTau} = await binFileUtils.readBinFile(pTauFileName, "ptau", 1);

        let buff_r = new BigBuffer(zkeyAfter.domainSize * zkeyAfter.n8r);
        const seed = new Array(8);
        for (let i = 0; i < 8; i++) {
            seed[i] = misc.readUInt32BE(misc.getRandomBytes(4), 0);
        }
        const rng = new ChaCha(seed);
        for (let i = 0; i < zkeyAfter.domainSize - 1; i++) {
            const e = Fr.fromRng(rng);
            Fr.toRprLE(buff_r, i * zkeyAfter.n8r, e);
        }
        Fr.toRprLE(buff_r, (zkeyAfter.domainSize - 1) * zkeyAfter.n8r, Fr.zero);

        let R1 = G.zero;
        for (let i = 0; i < zkeyAfter.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verification(tau):  ${i}/${zkeyAfter.domainSize}`);
            const n = Math.min(zkeyAfter.domainSize - i, MAX_CHUNK_SIZE);
            const buff1 = await fdPTau.read(sG * n, sectionsPTau[2][0].p + zkeyAfter.domainSize * sG + i * sG);
            const buff2 = await fdPTau.read(sG * n, sectionsPTau[2][0].p + i * sG);
            const buffB = await batchSubtract(buff1, buff2);
            const buffS = buff_r.slice(i * zkeyAfter.n8r, (i + n) * zkeyAfter.n8r);
            const r = await G.multiExpAffine(buffB, buffS);
            R1 = G.add(R1, r);
        }

        buff_r = await Fr.batchToMontgomery(buff_r);
        let first;
        if (zkeyAfter.power < Fr.s) {
            first = Fr.neg(Fr.e(2));
        } else {
            const small_m = 2 ** Fr.s;
            const shift_to_small_m = Fr.exp(Fr.shift, small_m);
            first = Fr.sub(shift_to_small_m, Fr.one);
        }
        const inc = zkeyAfter.power < Fr.s ? Fr.w[zkeyAfter.power + 1] : Fr.shift;
        buff_r = await Fr.batchApplyKey(buff_r, first, inc);
        buff_r = await Fr.fft(buff_r);
        buff_r = await Fr.batchFromMontgomery(buff_r);

        await binFileUtils.startReadUniqueSection(fdAfter, sectionsAfter, 9);
        let R2 = G.zero;
        for (let i = 0; i < zkeyAfter.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verification(lagrange):  ${i}/${zkeyAfter.domainSize}`);
            const n = Math.min(zkeyAfter.domainSize - i, MAX_CHUNK_SIZE);
            const buff = await fdAfter.read(sG * n);
            const buffS = buff_r.slice(i * zkeyAfter.n8r, (i + n) * zkeyAfter.n8r);
            const r = await G.multiExpAffine(buff, buffS);
            R2 = G.add(R2, r);
        }
        await binFileUtils.endReadSection(fdAfter);

        return (await sameRatio(curve, R1, R2, zkeyAfter.vk_delta_2, zkeyBefore.vk_delta_2)) === true;
    }

    async function batchSubtract(buff1, buff2) {
        const sG = curve.G1.F.n8 * 2;
        const nPoints = buff1.byteLength / sG;
        const concurrency = curve.tm.concurrency;
        const nPointsPerThread = Math.floor(nPoints / concurrency);
        const opPromises = [];
        for (let i = 0; i < concurrency; i++) {
            let n;
            if (i < concurrency - 1) {
                n = nPointsPerThread;
            } else {
                n = nPoints - i * nPointsPerThread;
            }
            if (n == 0) continue;
            const subBuff1 = buff1.slice(i * nPointsPerThread * sG, (i * nPointsPerThread + n) * sG);
            const subBuff2 = buff2.slice(i * nPointsPerThread * sG, (i * nPointsPerThread + n) * sG);
            opPromises.push(batchSubtractThread(subBuff1, subBuff2));
        }
        const result = await Promise.all(opPromises);
        const fullBuffOut = new Uint8Array(nPoints * sG);
        let p = 0;
        for (let i = 0; i < result.length; i++) {
            fullBuffOut.set(result[i][0], p);
            p += result[i][0].byteLength;
        }
        return fullBuffOut;
    }

    async function batchSubtractThread(buff1, buff2) {
        const sG1 = curve.G1.F.n8 * 2;
        const sGmid = curve.G1.F.n8 * 3;
        const nPoints = buff1.byteLength / sG1;
        const task = [];
        task.push({cmd: "ALLOCSET", var: 0, buff: buff1});
        task.push({cmd: "ALLOCSET", var: 1, buff: buff2});
        task.push({cmd: "ALLOC", var: 2, len: nPoints * sGmid});
        for (let i = 0; i < nPoints; i++) {
            task.push({
                cmd: "CALL",
                fnName: "g1m_subAffine",
                params: [
                    {var: 0, offset: i * sG1},
                    {var: 1, offset: i * sG1},
                    {var: 2, offset: i * sGmid},
                ]
            });
        }
        task.push({cmd: "CALL", fnName: "g1m_batchToAffine", params: [
            {var: 2}, {val: nPoints}, {var: 2},
        ]});
        task.push({cmd: "GET", out: 0, var: 2, len: nPoints * sG1});
        return await curve.tm.queueAction(task);
    }
}
