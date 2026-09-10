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

import * as misc from "./misc.js";
import { detectV2Magic } from "./v2params_magic.js";
import { readMPCParamsFile } from "./zkey_utils.js";

async function readContributionHashes(v2paramsName) {
    const magic = await detectV2Magic(v2paramsName);
    const { mpcParams, hashes } = await readMPCParamsFile(v2paramsName, magic);
    return { csHash: mpcParams.csHash, hashes };
}

export default async function v2paramsExtends(formerV2Params, laterV2Params) {
    const former = await readContributionHashes(formerV2Params);
    const later = await readContributionHashes(laterV2Params);

    // Bind both files to the same circuit. Without this, a former with 0
    // contributions would skip the prefix loop below and accept any
    // single-contribution later file, even from an unrelated circuit.
    if (!misc.hashIsEqual(former.csHash, later.csHash)) return false;

    if (later.hashes.length !== former.hashes.length + 1) return false;

    for (let i=0; i<former.hashes.length; i++) {
        if (!misc.hashIsEqual(former.hashes[i], later.hashes[i])) return false;
    }

    return true;
}
