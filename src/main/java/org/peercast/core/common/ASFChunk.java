/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


/**
 * ASFChunk.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ASFChunk {

    /** */
    int seq;
    /** */
    int dataLen;
    /** */
    short type;
    /** */
    short len;
    /** */
    short v1;
    /** */
    short v2;
    /** */
    byte[] data = new byte[8192];

    /** */
    public void read(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        type = dis.readShort();
        len = dis.readShort();
        seq = dis.readInt();
        v1 = dis.readShort();
        v2 = dis.readShort();

        dataLen = len - 8;
        if (dataLen > data.length) {
            throw new IOException("ASF chunk too big");
        }
        in.read(data, 0, dataLen);
    }

    /** */
    public void write(OutputStream out) throws IOException {
        DataOutputStream dos = new DataOutputStream(out);
        dos.writeShort(type);
        dos.writeShort(len);
        dos.writeInt(seq);
        dos.writeShort(v1);
        dos.writeShort(v2);
        dos.write(data, 0, dataLen);
    }
}

/* */
