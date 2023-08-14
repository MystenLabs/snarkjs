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

import * as fastFile from "fastfile";
import Blake2b from "blake2b-wasm";
import * as utils from "./powersoftau_utils.js";
import * as binFileUtils from "@iden3/binfileutils";
import * as misc from "./misc.js";

/**
 * This is to import multiple contributions as a whole from the community ppot 
 * on top of the initial ptau file. Mostly the same as src/powersoftau_import.js
 * except that we don't need oldPtauName and don't verify if contributionPreviousHash 
 * in community ppot challenge file matches lastChallengeHash in the ptau file. 
 * 
 * Note that the powersoftau_verify won't succeed because multiple contributions 
 * are imported as a whole but the public key is not available. To verify the 
 * new ptau file, however, we can simply do a bellman export and compare it 
 * with the original challenge file.
 *
 * @param {Object} curve - curve engine built from ffjavascript (e.g., buildBn128() for bn128)
 * @param {Number} power - circuit size exponent (support circuit size of at most 2^power), should be within range [1, 28]
 * @param {String} contributionFilename - name of the imported response file
 * @param {String} newPTauFilename - name of the new ptau file
 * @param {(String|null)} name - name of the contribution
 * @param {Boolean} importPoints - write imported ptau points into the new ptau file if true, otherwise only write contributions
 * @param {Object|null} logger - logplease logger for js (e.g., logger.info() for info logs and logger.debug() for debug logs)
 */
export default async function importResponseNoOrigin(curve, power, contributionFilename, newPTauFilename, importPoints, logger) {
    await Blake2b.ready();

    const noHash = new Uint8Array(64);
    for (let i=0; i<64; i++) noHash[i] = 0xFF;

    const currentContribution = {};

    const sG1 = curve.F1.n8*2;
    const scG1 = curve.F1.n8; // Compresed size
    const sG2 = curve.F2.n8*2;
    const scG2 = curve.F2.n8; // Compresed size

    const fdResponse = await fastFile.readExisting(contributionFilename);

    if  (fdResponse.totalSize !=
        64 +                            // Old Hash
        ((2 ** power)*2-1)*scG1 +
        (2 ** power)*scG2 +
        (2 ** power)*scG1 +
        (2 ** power)*scG1 +
        scG2 +
        sG1*6 + sG2*3)
        throw new Error("Size of the contribution is invalid");

    const fdNew = await binFileUtils.createBinFile(newPTauFilename, "ptau", 1, importPoints ? 7: 2);
    await utils.writePTauHeader(fdNew, curve, power);

    const contributionPreviousHash = await fdResponse.read(64);

    const hasherResponse = new Blake2b(64);
    hasherResponse.update(contributionPreviousHash);

    const startSections = [];
    let res;
    res = await processSection(fdResponse, fdNew, "G1", 2, (2 ** power) * 2 -1, [1], "tauG1");
    currentContribution.tauG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G2", 3, (2 ** power)       , [1], "tauG2");
    currentContribution.tauG2 = res[0];
    res = await processSection(fdResponse, fdNew, "G1", 4, (2 ** power)       , [0], "alphaG1");
    currentContribution.alphaG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G1", 5, (2 ** power)       , [0], "betaG1");
    currentContribution.betaG1 = res[0];
    res = await processSection(fdResponse, fdNew, "G2", 6, 1                  , [0], "betaG2");
    currentContribution.betaG2 = res[0];

    currentContribution.partialHash = hasherResponse.getPartialHash();


    const buffKey = await fdResponse.read(curve.F1.n8*2*6+curve.F2.n8*2*3);

    currentContribution.key = utils.fromPtauPubKeyRpr(buffKey, 0, curve, false);

    hasherResponse.update(new Uint8Array(buffKey));
    const hashResponse = hasherResponse.digest();

    if (logger) logger.info(misc.formatHash(hashResponse, "Contribution Response Hash imported: "));

    if (importPoints) {
        const nextChallengeHasher = new Blake2b(64);
        nextChallengeHasher.update(hashResponse);

        await hashSection(nextChallengeHasher, fdNew, "G1", 2, (2 ** power) * 2 -1, "tauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G2", 3, (2 ** power)       , "tauG2", logger);
        await hashSection(nextChallengeHasher, fdNew, "G1", 4, (2 ** power)       , "alphaTauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G1", 5, (2 ** power)       , "betaTauG1", logger);
        await hashSection(nextChallengeHasher, fdNew, "G2", 6, 1                  , "betaG2", logger);

        currentContribution.nextChallenge = nextChallengeHasher.digest();

        if (logger) logger.info(misc.formatHash(currentContribution.nextChallenge, "Next Challenge Hash: "));
    } else {
        currentContribution.nextChallenge = noHash;
    }

    const contributions = [currentContribution];

    await utils.writeContributions(fdNew, curve, contributions);

    await fdResponse.close();
    await fdNew.close();

    return currentContribution.nextChallenge;

    /**
     * This is to import each section in ptau file. 
     * Exactly the same as that in src/powersoftau_import.js. 
     *
     * @param {Object} fdFrom - Memfile object (from fastfile) for the response to be imported
     * @param {Object} fdTo - Memfile object (from fastfile) for the new ptau file
     * @param {String} groupName - group name (i.e., G1 or G2)
     * @param {Number} sectionId - section number in ptau file
     * @param {Number} nPoints - number of points in the section
     * @param {Number[]} singularPointIndexes - indexes of ptaus to be returned (i.e., [1] for TauG1 and TauG2; [0] for AlphaG1, BetaG1, and BetaG2)
     * @param {String} sectionName - type of powers of tau (i.e., TauG1, TauG2, AlphaTauG1, BetaTauG1, or BetaG2)
     */
    async function processSection(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {
        if (importPoints) {
            return await processSectionImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName);
        } else {
            return await processSectionNoImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName);
        }
    }

    /**
     * This is to import each section in ptau file while writing the points to the new ptau file. 
     * Exactly the same as that in src/powersoftau_import.js. 
     *
     * @param {Object} fdFrom - Memfile object (from fastfile) for the response to be imported
     * @param {Object} fdTo - Memfile object (from fastfile) for the new ptau file
     * @param {String} groupName - group name (i.e., G1 or G2)
     * @param {Number} sectionId - section number in ptau file
     * @param {Number} nPoints - number of points in the section
     * @param {Number[]} singularPointIndexes - indexes of ptaus to be returned (i.e., [1] for TauG1 and TauG2; [0] for AlphaG1, BetaG1, and BetaG2)
     * @param {String} sectionName - type of powers of tau (i.e., TauG1, TauG2, AlphaTauG1, BetaTauG1, or BetaG2)
     */
    async function processSectionImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {

        const G = curve[groupName];
        const scG = G.F.n8;
        const sG = G.F.n8*2;

        const singularPoints = [];

        await binFileUtils.startWriteSection(fdTo, sectionId);
        const nPointsChunk = Math.floor((1<<24)/sG);

        startSections[sectionId] = fdTo.pos;

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Importing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffC = await fdFrom.read(n * scG);
            hasherResponse.update(buffC);

            const buffLEM = await G.batchCtoLEM(buffC);

            await fdTo.write(buffLEM);
            for (let j=0; j<singularPointIndexes.length; j++) {
                const sp = singularPointIndexes[j];
                if ((sp >=i) && (sp < i+n)) {
                    const P = G.fromRprLEM(buffLEM, (sp-i)*sG);
                    singularPoints.push(P);
                }
            }
        }

        await binFileUtils.endWriteSection(fdTo);

        return singularPoints;
    }

    /**
     * This is to import each section in ptau file without writing the points to the new ptau file. 
     * Exactly the same as that in src/powersoftau_import.js. 
     *
     * @param {Object} fdFrom - Memfile object (from fastfile) for the response to be imported
     * @param {Object} fdTo - Memfile object (from fastfile) for the new ptau file
     * @param {String} groupName - group name (i.e., G1 or G2)
     * @param {Number} sectionId - section number in ptau file
     * @param {Number} nPoints - number of points in the section
     * @param {Number[]} singularPointIndexes - indexes of ptaus to be returned (i.e., [1] for TauG1 and TauG2; [0] for AlphaG1, BetaG1, and BetaG2)
     * @param {String} sectionName - type of powers of tau (i.e., TauG1, TauG2, AlphaTauG1, BetaTauG1, or BetaG2)
     */
    async function processSectionNoImportPoints(fdFrom, fdTo, groupName, sectionId, nPoints, singularPointIndexes, sectionName) {

        const G = curve[groupName];
        const scG = G.F.n8;

        const singularPoints = [];

        const nPointsChunk = Math.floor((1<<24)/scG);

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Importing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffC = await fdFrom.read(n * scG);
            hasherResponse.update(buffC);

            for (let j=0; j<singularPointIndexes.length; j++) {
                const sp = singularPointIndexes[j];
                if ((sp >=i) && (sp < i+n)) {
                    const P = G.fromRprCompressed(buffC, (sp-i)*scG);
                    singularPoints.push(P);
                }
            }
        }

        return singularPoints;
    }

    /**
     * This is to compute the hash for the next challenge. 
     * Exactly the same as that in src/powersoftau_import.js. 
     *
     * @param {Object} nextChallengeHasher - Blake2b hasher for the next challenge (e.g., hasher.update() to append the hash input, hasher.digest() to compute the hash)
     * @param {Object} fdTo - Memfile object (from fastfile) for the new ptau file
     * @param {String} groupName - group name (i.e., G1 or G2)
     * @param {Number} sectionId - section number in ptau file
     * @param {number} nPoints - number of points in the section
     * @param {String} sectionName - type of powers of tau (i.e., TauG1, TauG2, AlphaTauG1, BetaTauG1, or BetaG2)
     * @param {Object|null} logger - logplease logger for js (e.g., logger.info() for info logs and logger.debug() for debug logs)
     */
    async function hashSection(nextChallengeHasher, fdTo, groupName, sectionId, nPoints, sectionName, logger) {

        const G = curve[groupName];
        const sG = G.F.n8*2;
        const nPointsChunk = Math.floor((1<<24)/sG);

        const oldPos = fdTo.pos;
        fdTo.pos = startSections[sectionId];

        for (let i=0; i< nPoints; i += nPointsChunk) {
            if (logger) logger.debug(`Hashing ${sectionName}: ${i}/${nPoints}`);
            const n = Math.min(nPoints-i, nPointsChunk);

            const buffLEM = await fdTo.read(n * sG);

            const buffU = await G.batchLEMtoU(buffLEM);

            nextChallengeHasher.update(buffU);
        }

        fdTo.pos = oldPos;
    }

}