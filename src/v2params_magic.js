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

// Phase-2 params file magic detection.
//
// 3-char names "p2c" (compressed) and "p2u" (uncompressed); on disk they're
// 4-byte NUL-padded ("p2c\0" / "p2u\0") because binFileUtils reads/writes
// exactly 4 bytes.
//
//   p2u — sections 8/9 stored LEM uncompressed (64 B/G1)
//   p2c — sections 8/9 stored compressed (32 B/G1)
//
// Returns the 4-byte form (e.g., "p2c\0") so callers can pass it directly
// back to binFileUtils.{read,create}BinFile.

import * as fastFile from "fastfile";

export const MAGIC_P2U = "p2u\0";   // phase-2 params, uncompressed (LEM)
export const MAGIC_P2C = "p2c\0";   // phase-2 params, compressed

export async function detectV2Magic(fileNameOrFd) {
    let fd, owns = false;
    if (typeof fileNameOrFd === "string") {
        fd = await fastFile.readExisting(fileNameOrFd);
        owns = true;
    } else if (fileNameOrFd && fileNameOrFd.type === "mem") {
        const data = fileNameOrFd.data;
        if (!data || data.length < 4) throw new Error("file too short");
        return classify(data[0], data[1], data[2], data[3]);
    } else {
        fd = fileNameOrFd;
    }
    try {
        const savedPos = fd.pos;
        fd.pos = 0;
        const b = await fd.read(4);
        fd.pos = savedPos;
        return classify(b[0], b[1], b[2], b[3]);
    } finally {
        if (owns) await fd.close();
    }
}

function classify(b0, b1, b2, b3) {
    let s = "";
    for (const b of [b0, b1, b2, b3]) s += String.fromCharCode(b);
    if (s === MAGIC_P2U || s === MAGIC_P2C) return s;
    // Friendly preview for the error: strip trailing NULs.
    const preview = s.replace(/\0+$/, "");
    throw new Error(`expected p2u or p2c magic, got "${preview}"`);
}
