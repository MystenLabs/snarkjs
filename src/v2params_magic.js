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

import * as fastFile from "fastfile";

export const MAGIC_P2U = "p2u\0";   // phase-2 params, uncompressed (LEM)
export const MAGIC_P2C = "p2c\0";   // phase-2 params, compressed

// Read the first 4 bytes of a file (or mem object) as a string, without
// disturbing any caller-held position. Returns the raw 4-char magic; the
// caller is responsible for interpreting it.
export async function readMagic(fileNameOrFd) {
    let fd, owns = false;
    if (typeof fileNameOrFd === "string") {
        fd = await fastFile.readExisting(fileNameOrFd);
        owns = true;
    } else if (fileNameOrFd && fileNameOrFd.type === "mem") {
        const d = fileNameOrFd.data;
        if (!d || d.length < 4) throw new Error("file too short");
        return String.fromCharCode(d[0], d[1], d[2], d[3]);
    } else {
        fd = fileNameOrFd;
    }
    try {
        const savedPos = fd.pos;
        fd.pos = 0;
        const b = await fd.read(4);
        fd.pos = savedPos;
        return String.fromCharCode(b[0], b[1], b[2], b[3]);
    } finally {
        if (owns) await fd.close();
    }
}
