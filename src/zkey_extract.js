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

// Extract the contribution-mutable sections of a zkey into a `.v2params` file.
//
// A full Groth16 zkey has 10 sections. Of those, only sections 1, 2, 8, 9, 10
// are read or modified by `zkey contribute`. Sections 3-7 (IC, Coeffs, A, B1, B2)
// are copied verbatim by `zkey contribute` and never inspected. Shipping only
// the mutable sections to a contributor reduces transfer size by ~10x for large
// circuits and removes any opportunity for the contributor to tamper with the
// frozen sections (since they never possess them).
//
// The output file uses the same "zkey" binary magic as a full zkey -- it IS a
// zkey, just one that is missing sections 3-7. snarkjs readers will accept it,
// but operations that need sections 3-7 (like proof generation) will fail.

import * as binFileUtils from "@iden3/binfileutils";

export default async function zkeyExtract(zkeyFullName, v2paramsName, logger) {
    const {fd: fdOld, sections} = await binFileUtils.readBinFile(zkeyFullName, "zkey", 2);
    const fdNew = await binFileUtils.createBinFile(v2paramsName, "zkey", 1, 10);

    // Section 1: protocol id
    await binFileUtils.copySection(fdOld, sections, fdNew, 1);
    // Section 2: header (curve, sizes, vk_alpha/beta/gamma/delta)
    await binFileUtils.copySection(fdOld, sections, fdNew, 2);
    // Section 8: L points
    await binFileUtils.copySection(fdOld, sections, fdNew, 8);
    // Section 9: H points
    await binFileUtils.copySection(fdOld, sections, fdNew, 9);
    // Section 10: MPC params (csHash + contribution chain)
    await binFileUtils.copySection(fdOld, sections, fdNew, 10);

    await fdOld.close();
    await fdNew.close();

    if (logger) logger.info(`Extracted v2params: ${v2paramsName}`);
}
