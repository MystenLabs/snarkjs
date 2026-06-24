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

// Assemble a full zkey from a base zkey + a p2u v2params file.
//
// Sections 1, 2, 8, 9, 10 come from the v2params (post-contribution).
// Sections 3, 4, 5, 6, 7 (IC, Coeffs, A, B1, B2) come from the base zkey --
// these are not modified by Phase 2 contributions, so any prior full zkey
// from this circuit serves as a base (typically circuit_0000.zkey).
//
// Accepts only p2u (LEM) input. If you have p2c, run `zkey decompress
// v2params` first.

import * as binFileUtils from "@iden3/binfileutils";
import { MAGIC_P2U } from "./v2params_magic.js";

export default async function zkeyAssemble(baseZkeyName, v2paramsName, outZkeyName, logger) {
    const {fd: fdBase, sections: baseSections} = await binFileUtils.readBinFile(baseZkeyName, "zkey", 2);
    const {fd: fdParts, sections: partsSections} = await binFileUtils.readBinFile(v2paramsName, MAGIC_P2U, 2);
    const fdOut = await binFileUtils.createBinFile(outZkeyName, "zkey", 1, 10);

    // From v2params: §1 (protocol), §2 (header with updated delta)
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 1);
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 2);

    // From base: §3-7 (IC, Coeffs, A, B1, B2) -- frozen since g16s
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 3);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 4);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 5);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 6);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 7);

    // From v2params: §8 (L), §9 (H), §10 (MPC params)
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 8);
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 9);
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 10);

    await fdBase.close();
    await fdParts.close();
    await fdOut.close();

    if (logger) logger.info(`Assembled zkey: ${outZkeyName}`);
}
