//
// (c) 2002-4 peercast.org
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//

package org.peercast.core.common;

import java.io.IOException;
import java.io.OutputStream;

import vavi.io.LittleEndianDataOutputStream;


/**
 * AtomStream.
 *
 * @version 1-mar-2004
 * @author giles
 */
class AtomOutputStream {

    AtomOutputStream(OutputStream os) {
        dos = new LittleEndianDataOutputStream(os);
    }

    void writeParent(ID4 id, int nc) throws IOException {
        dos.write(id.getData());
        dos.writeInt(nc | 0x80000000);
    }

    void writeInt(ID4 id, int d) throws IOException {
        dos.write(id.getData());
        dos.writeInt(4);
        dos.writeInt(d);
    }

    void writeID4(ID4 id, ID4 d) throws IOException {
        dos.write(id.getData());
        dos.writeInt(4);
        dos.write(d.getData());
    }

    void writeShort(ID4 id, short d) throws IOException {
        dos.write(id.getData());
        dos.writeInt(2);
        dos.writeShort(d);
    }

    void writeByte(ID4 id, byte d) throws IOException {
        dos.write(id.getData());
        dos.writeInt(1);
        dos.writeByte(d);
    }

    void writeBytes(ID4 id, final byte[] bytes, int length) throws IOException {
        dos.write(id.getData());
        dos.writeInt(length);
        dos.write(bytes, 0, length);
    }

    int writeStream(ID4 id, AtomInputStream atomIn, int length) throws IOException {
        dos.write(id.getData());
        dos.writeInt(length);
        dos.flush();
        atomIn.writeTo(dos, length);
        return (2 * 2) + length;
    }

    void writeString(ID4 id, final String string) throws IOException {
        writeBytes(id, string.getBytes(), string.length());
    }

    int writeAtoms(ID4 id, AtomInputStream atomIn, int childCount, int dataLength) throws IOException {
        int total = 0;

        if (childCount != 0) {
            writeParent(id, childCount);
            total += 2 * 2;

            for (int i = 0; i < childCount; i++) {
                ID4 cid = atomIn.read();
                int c = atomIn.childCount;
                int d = atomIn.dataLength;
                total += writeAtoms(cid, atomIn, c, d);
            }
        } else {
            total += writeStream(id, atomIn, dataLength);
        }

        return total;
    }

    private LittleEndianDataOutputStream dos;

    /** */
    public void flush() throws IOException {
        dos.flush();
    }
}

/* */
