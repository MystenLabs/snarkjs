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

import * as binFileUtils from "@iden3/binfileutils";
import { blake2b } from "@noble/hashes/blake2b";

import { getCurveFromQ as getCurve } from "./curves.js";
import * as misc from "./misc.js";
import { detectV2Magic } from "./v2params_magic.js";
import * as zkeyUtils from "./zkey_utils.js";
import { hashPubKey } from "./zkey_utils.js";

async function readContributionHashes(v2paramsName) {
    const magic = await detectV2Magic(v2paramsName);
    const {fd, sections} = await binFileUtils.readBinFile(v2paramsName, magic, 2);
    let curve;
    try {
        const zkey = await zkeyUtils.readHeader(fd, sections);
        if (zkey.protocol !== "groth16") throw new Error("zkey is not groth16");

        curve = await getCurve(zkey.q);
        const mpcParams = await zkeyUtils.readMPCParams(fd, curve, sections);

        return mpcParams.contributions.map((c) => {
            const contributionHasher = blake2b.create({ dkLen: 64 });
            hashPubKey(contributionHasher, curve, c);
            return contributionHasher.digest();
        });
    } finally {
        await fd.close();
        if (curve) await curve.terminate();
    }
}

export default async function v2paramsExtends(formerV2Params, laterV2Params) {
    const formerHashes = await readContributionHashes(formerV2Params);
    const laterHashes = await readContributionHashes(laterV2Params);

    if (laterHashes.length !== formerHashes.length + 1) return false;

    for (let i=0; i<formerHashes.length; i++) {
        if (!misc.hashIsEqual(formerHashes[i], laterHashes[i])) return false;
    }

    return true;
}
