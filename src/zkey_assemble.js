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

// Assemble a full zkey from a base zkey + a phase-2 params file.
//
// Sections 1, 2, 8, 9, 10 come from the v2params (post-contribution).
// Sections 3, 4, 5, 6, 7 (IC, Coeffs, A, B1, B2) come from the base zkey
// -- these are not modified by Phase 2 contributions, so any prior full
// zkey from this circuit serves as a base (typically circuit_0000.zkey).
//
// Accepts either p2u (LEM) or p2c (compressed) input. p2c's §8/§9 are
// decompressed on the fly so the assembled output is always a normal full
// zkey with LEM-encoded points.

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import { detectV2Magic, MAGIC_P2C } from "./v2params_magic.js";

export default async function zkeyAssemble(baseZkeyName, v2paramsName, outZkeyName, logger) {
    const partsMagic = await detectV2Magic(v2paramsName);

    const {fd: fdBase, sections: baseSections} = await binFileUtils.readBinFile(baseZkeyName, "zkey", 2);
    const {fd: fdParts, sections: partsSections} = await binFileUtils.readBinFile(v2paramsName, partsMagic, 2);
    const fdOut = await binFileUtils.createBinFile(outZkeyName, "zkey", 1, 10);

    // From v2params: section 1 (protocol) and section 2 (header with updated delta)
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 1);
    await binFileUtils.copySection(fdParts, partsSections, fdOut, 2);

    // From base: sections 3-7 (IC, Coeffs, A, B1, B2) -- frozen since g16s
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 3);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 4);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 5);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 6);
    await binFileUtils.copySection(fdBase, baseSections, fdOut, 7);

    if (partsMagic === MAGIC_P2C) {
        // §8/§9 are stored compressed; decompress on the way through.
        const zkey = await zkeyUtils.readHeader(fdParts, partsSections);
        const curve = await getCurve(zkey.q);
        const sG = curve.G1.F.n8 * 2;
        const sGc = curve.G1.F.n8;

        for (const id of [8, 9]) {
            const size = partsSections[id][0].size;
            const nPoints = size / sGc;

            await binFileUtils.startReadUniqueSection(fdParts, partsSections, id);
            await binFileUtils.startWriteSection(fdOut, id);
            const buffC = await fdParts.read(nPoints * sGc);
            const buffLEM = await curve.G1.batchCtoLEM(buffC);
            await fdOut.write(buffLEM);
            await binFileUtils.endReadSection(fdParts);
            await binFileUtils.endWriteSection(fdOut);
            if (logger) logger.info(`Decompressed §${id}: ${nPoints} points`);
        }
        await curve.terminate();
    } else {
        await binFileUtils.copySection(fdParts, partsSections, fdOut, 8);
        await binFileUtils.copySection(fdParts, partsSections, fdOut, 9);
    }

    await binFileUtils.copySection(fdParts, partsSections, fdOut, 10);

    await fdBase.close();
    await fdParts.close();
    await fdOut.close();

    const partsMagicLabel = partsMagic === MAGIC_P2C ? "p2c" : "p2u";
    if (logger) logger.info(`Assembled zkey from ${partsMagicLabel}: ${outZkeyName}`);
}
