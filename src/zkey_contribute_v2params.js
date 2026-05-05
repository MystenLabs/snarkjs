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

// Phase 2 contribution operating on a phase-2 params file (p2u or p2c).
//
// Input format (p2u = LEM, or p2c = compressed) is auto-detected from the
// file's magic. Output format mirrors input: a contributor handed a p2c gets
// back a p2c; a p2u gets back a p2u.
//
// Logic versus zkey_contribute.js: identical math (delta keypair + applyKey
// to L and H), but operates on the 5-section v2params layout (§1, §2, §8, §9,
// §10) instead of the full 10-section zkey. When input is p2c, §8 and §9
// are decompressed before applyKey and re-compressed before writing.

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import * as misc from "./misc.js";
import { blake2b } from "@noble/hashes/blake2b";
import * as utils from "./zkey_utils.js";
import { hashToG2 as hashToG2 } from "./keypair.js";
import { detectV2Magic, MAGIC_P2C } from "./v2params_magic.js";

export default async function phase2contributeV2Params(v2paramsOld, v2paramsNew, name, entropy, logger) {

    const magic = await detectV2Magic(v2paramsOld);
    const compressed = magic === MAGIC_P2C;

    const {fd: fdOld, sections: sections} = await binFileUtils.readBinFile(v2paramsOld, magic, 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);
    const sG = curve.G1.F.n8 * 2;
    const sGc = curve.G1.F.n8;

    const mpcParams = await zkeyUtils.readMPCParams(fdOld, curve, sections);

    // Output format mirrors input format.
    const fdNew = await binFileUtils.createBinFile(v2paramsNew, magic, 1, 5);

    const rng = await misc.getRandomRng(entropy);

    const transcriptHasher = blake2b.create({ dkLen: 64 });
    transcriptHasher.update(mpcParams.csHash);
    for (let i=0; i<mpcParams.contributions.length; i++) {
        utils.hashPubKey(transcriptHasher, curve, mpcParams.contributions[i]);
    }

    const curContribution = {};
    curContribution.delta = {};
    curContribution.delta.prvKey = curve.Fr.fromRng(rng);
    curContribution.delta.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta.g1_s, curContribution.delta.prvKey));
    utils.hashG1(transcriptHasher, curve, curContribution.delta.g1_s);
    utils.hashG1(transcriptHasher, curve, curContribution.delta.g1_sx);
    curContribution.transcript = transcriptHasher.digest();
    curContribution.delta.g2_sp = hashToG2(curve, curContribution.transcript);
    curContribution.delta.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta.g2_sp, curContribution.delta.prvKey));

    zkey.vk_delta_1 = curve.G1.timesFr(zkey.vk_delta_1, curContribution.delta.prvKey);
    zkey.vk_delta_2 = curve.G2.timesFr(zkey.vk_delta_2, curContribution.delta.prvKey);

    curContribution.deltaAfter = zkey.vk_delta_1;

    curContribution.type = 0;
    if (name) curContribution.name = name;

    mpcParams.contributions.push(curContribution);

    await zkeyUtils.writeHeader(fdNew, zkey);

    const invDelta = curve.Fr.inv(curContribution.delta.prvKey);
    await applyKeyG1Section(fdOld, sections, fdNew, 8, curve, invDelta, compressed, "L Section", logger);
    await applyKeyG1Section(fdOld, sections, fdNew, 9, curve, invDelta, compressed, "H Section", logger);

    await zkeyUtils.writeMPCParams(fdNew, curve, mpcParams);

    await fdOld.close();
    await fdNew.close();

    const contributionHasher = blake2b.create({ dkLen: 64 });
    utils.hashPubKey(contributionHasher, curve, curContribution);

    const contributionHash = contributionHasher.digest();

    if (logger) logger.info(misc.formatHash(mpcParams.csHash, "Circuit Hash: "));
    if (logger) logger.info(misc.formatHash(contributionHash, "Contribution Hash: "));

    return contributionHash;

    // Read §id from input (compressed or LEM), apply scalar `key` to each G1 point,
    // write back to output in the same format the input was in.
    async function applyKeyG1Section(fdOld, sections, fdNew, id, curve, key, compressed, label, logger) {
        const G = curve.G1;
        const sIn = compressed ? sGc : sG;
        const size = sections[id][0].size;
        if (size % sIn !== 0) throw new Error(`section ${id} size not aligned`);
        const nPoints = size / sIn;

        await binFileUtils.startReadUniqueSection(fdOld, sections, id);
        await binFileUtils.startWriteSection(fdNew, id);

        const t0 = Date.now();
        const buffIn = await fdOld.read(nPoints * sIn);

        let buffLEM;
        if (compressed) {
            const t = Date.now();
            buffLEM = await G.batchCtoLEM(buffIn);
            if (logger) logger.info(`${label}: decompressed ${nPoints} points in ${((Date.now()-t)/1000).toFixed(2)} s`);
        } else {
            buffLEM = buffIn;
        }

        const tApply = Date.now();
        const buffOutLEM = await G.batchApplyKey(buffLEM, key, curve.Fr.e(1));
        if (logger) logger.info(`${label}: applyKey on ${nPoints} points in ${((Date.now()-tApply)/1000).toFixed(2)} s`);

        let buffOut;
        if (compressed) {
            const t = Date.now();
            buffOut = await G.batchLEMtoC(buffOutLEM);
            if (logger) logger.info(`${label}: re-compressed in ${((Date.now()-t)/1000).toFixed(2)} s`);
        } else {
            buffOut = buffOutLEM;
        }
        await fdNew.write(buffOut);

        await binFileUtils.endReadSection(fdOld);
        await binFileUtils.endWriteSection(fdNew);
        if (logger) logger.info(`${label}: total ${((Date.now()-t0)/1000).toFixed(2)} s (${compressed ? "p2c" : "p2u"})`);
    }
}
