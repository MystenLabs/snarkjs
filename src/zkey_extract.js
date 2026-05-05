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

// Extract the contribution-mutable sections of a zkey into a phase-2 params file.
//
// A full Groth16 zkey has 10 sections. Of those, only sections 1, 2, 8, 9, 10
// are read or modified by `zkey contribute`. Sections 3-7 (IC, Coeffs, A, B1, B2)
// are copied verbatim and never inspected. Shipping only the mutable sections
// to a contributor reduces transfer size by ~10x for large circuits and removes
// any opportunity for the contributor to tamper with the frozen sections.
//
// Two output formats:
//   p2u — sections 8/9 stored as 64 B/G1 LEM (uncompressed Montgomery).
//   p2c — sections 8/9 stored as 32 B/G1 compressed (x with sign bit).
//
// p2c is ~50% smaller; reading it back requires per-point decompression
// (~22 sec for 2M G1 points on a 9-core machine).

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { getCurveFromQ as getCurve } from "./curves.js";
import { MAGIC_P2U, MAGIC_P2C } from "./v2params_magic.js";

export default async function zkeyExtract(zkeyFullName, v2paramsName, compressed, logger) {
    const {fd: fdOld, sections} = await binFileUtils.readBinFile(zkeyFullName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);
    if (zkey.protocol !== "groth16") throw new Error("zkey is not groth16");

    const magic = compressed ? MAGIC_P2C : MAGIC_P2U;
    const fdNew = await binFileUtils.createBinFile(v2paramsName, magic, 1, 5);

    // §1, §2, §10 verbatim regardless of compression
    await binFileUtils.copySection(fdOld, sections, fdNew, 1);
    await binFileUtils.copySection(fdOld, sections, fdNew, 2);

    if (compressed) {
        const curve = await getCurve(zkey.q);
        const sG = curve.G1.F.n8 * 2;    // 64 on BN254
        const sGc = curve.G1.F.n8;       // 32 on BN254

        for (const id of [8, 9]) {
            const size = sections[id][0].size;
            if (size % sG !== 0) throw new Error(`section ${id} size not a multiple of sG`);
            const nPoints = size / sG;

            await binFileUtils.startReadUniqueSection(fdOld, sections, id);
            await binFileUtils.startWriteSection(fdNew, id);
            const buffLEM = await fdOld.read(nPoints * sG);
            const buffC = await curve.G1.batchLEMtoC(buffLEM);
            await fdNew.write(buffC);
            await binFileUtils.endReadSection(fdOld);
            await binFileUtils.endWriteSection(fdNew);
            if (logger) logger.info(`Compressed §${id}: ${nPoints} points`);
        }
        await curve.terminate();
    } else {
        await binFileUtils.copySection(fdOld, sections, fdNew, 8);
        await binFileUtils.copySection(fdOld, sections, fdNew, 9);
    }

    await binFileUtils.copySection(fdOld, sections, fdNew, 10);

    await fdOld.close();
    await fdNew.close();

    if (logger) logger.info(`Extracted ${compressed ? "p2c" : "p2u"}: ${v2paramsName}`);
}
