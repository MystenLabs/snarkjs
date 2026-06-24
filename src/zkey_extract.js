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

// Extract the contribution-mutable sections of a zkey into a p2u v2params file.
//
// A full Groth16 zkey has 10 sections. Of those, only sections 1, 2, 8, 9, 10
// are read or modified by `zkey contribute`. Sections 3-7 (IC, Coeffs, A, B1, B2)
// are copied verbatim and never inspected. Shipping only the mutable sections
// to a contributor reduces transfer size by ~10x for large circuits and removes
// any opportunity for the contributor to tamper with the frozen sections.
//
// Output is always p2u (LEM, 64 B/G1). If you want the compressed wire
// format (32 B/G1, ~50% smaller), pipe through `zkey compress v2params`.

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./zkey_utils.js";
import { MAGIC_P2U } from "./v2params_magic.js";

export default async function zkeyExtract(zkeyFullName, v2paramsName, logger) {
    const {fd: fdOld, sections} = await binFileUtils.readBinFile(zkeyFullName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);
    if (zkey.protocol !== "groth16") throw new Error("zkey is not groth16");

    const fdNew = await binFileUtils.createBinFile(v2paramsName, MAGIC_P2U, 1, 5);

    await binFileUtils.copySection(fdOld, sections, fdNew, 1);
    await binFileUtils.copySection(fdOld, sections, fdNew, 2);
    await binFileUtils.copySection(fdOld, sections, fdNew, 8);
    await binFileUtils.copySection(fdOld, sections, fdNew, 9);
    await binFileUtils.copySection(fdOld, sections, fdNew, 10);

    await fdOld.close();
    await fdNew.close();

    if (logger) logger.info(`Extracted p2u: ${v2paramsName}`);
}
