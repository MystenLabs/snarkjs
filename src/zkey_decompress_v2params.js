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

// Convert a v2params file from p2c (compressed, 32 B/G1) to p2u (LEM, 64 B/G1).
// Sections 1, 2, 10 are copied verbatim; sections 8, 9 (G1 points) are
// decompressed via batchCtoLEM, which also validates each point is on-curve.

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import { MAGIC_P2U, MAGIC_P2C } from "./v2params_magic.js";

export default async function v2paramsDecompress(p2cName, p2uName, logger) {
    const {fd: fdOld, sections} = await binFileUtils.readBinFile(p2cName, MAGIC_P2C, 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);
    if (zkey.protocol !== "groth16") throw new Error("zkey is not groth16");

    const curve = await getCurve(zkey.q);
    const sGc = curve.G1.F.n8;

    const fdNew = await binFileUtils.createBinFile(p2uName, MAGIC_P2U, 1, 5);

    await binFileUtils.copySection(fdOld, sections, fdNew, 1);
    await binFileUtils.copySection(fdOld, sections, fdNew, 2);

    for (const id of [8, 9]) {
        const size = sections[id][0].size;
        if (size % sGc !== 0) throw new Error(`section ${id} size not a multiple of sGc`);
        const nPoints = size / sGc;

        await binFileUtils.startReadUniqueSection(fdOld, sections, id);
        await binFileUtils.startWriteSection(fdNew, id);
        const buffC = await fdOld.read(nPoints * sGc);
        const buffLEM = await curve.G1.batchCtoLEM(buffC);
        await fdNew.write(buffLEM);
        await binFileUtils.endReadSection(fdOld);
        await binFileUtils.endWriteSection(fdNew);
        if (logger) logger.info(`Decompressed §${id}: ${nPoints} points`);
    }

    await binFileUtils.copySection(fdOld, sections, fdNew, 10);

    await fdOld.close();
    await fdNew.close();
    await curve.terminate();
    if (logger) logger.info(`Decompressed p2c -> p2u: ${p2uName}`);
}
