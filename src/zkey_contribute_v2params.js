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

// Phase 2 contribution on a v2params file (p2u, LEM/uncompressed).
//
// A v2params file carries only the 5 sections Phase 2 touches: §1, §2, §8,
// §9, §10. Sections 3-7 (IC, Coeffs, A, B1, B2) live in the base full zkey
// on the coordinator side and are reinjected by `zkey assemble` at the end
// of the ceremony.
//
// Math is identical to upstream `zkey_contribute.js`; this file differs
// only in file magic, section count, and the absence of the §3-7 verbatim
// copies. Format conversion (p2c <-> p2u) is the job of separate compress /
// decompress commands and is intentionally not part of contribute.

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import * as misc from "./misc.js";
import { blake2b } from "@noble/hashes/blake2b";
import * as utils from "./zkey_utils.js";
import { hashToG2 as hashToG2 } from "./keypair.js";
import { applyKeyToSection } from "./mpc_applykey.js";
import { MAGIC_P2U } from "./v2params_magic.js";

export default async function phase2contributeV2Params(v2paramsOld, v2paramsNew, name, entropy, logger) {

    const {fd: fdOld, sections: sections} = await binFileUtils.readBinFile(v2paramsOld, MAGIC_P2U, 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);
    if (zkey.protocol != "groth16") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);

    const mpcParams = await zkeyUtils.readMPCParams(fdOld, curve, sections);

    const fdNew = await binFileUtils.createBinFile(v2paramsNew, MAGIC_P2U, 1, 5);


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

    // §3-7 (IC, Coeffs, A, B1, B2) are absent in a v2params file; `zkey
    // assemble` reinjects them from the base zkey at the end of the ceremony.

    const invDelta = curve.Fr.inv(curContribution.delta.prvKey);
    await applyKeyToSection(fdOld, sections, fdNew, 8, curve, "G1", invDelta, curve.Fr.e(1), "L Section", logger);
    await applyKeyToSection(fdOld, sections, fdNew, 9, curve, "G1", invDelta, curve.Fr.e(1), "H Section", logger);

    await zkeyUtils.writeMPCParams(fdNew, curve, mpcParams);

    await fdOld.close();
    await fdNew.close();

    const contributionHasher = blake2b.create({ dkLen: 64 });
    utils.hashPubKey(contributionHasher, curve, curContribution);

    const contributionHash = contributionHasher.digest();

    if (logger) logger.info(misc.formatHash(mpcParams.csHash, "Circuit Hash: "));
    if (logger) logger.info(misc.formatHash(contributionHash, "Contribution Hash: "));

    return contributionHash;
}
