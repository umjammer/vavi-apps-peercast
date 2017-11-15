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
import java.util.Arrays;


/**
 * ChanPacket.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelPacket {

    /** */
    static final int MAX_DATALEN = 16384;

    /** */
    enum Type {
        /** */
        UNKNOWN(0),
        /** */
        HEAD(1),
        /** */
        DATA(2),
        /** */
        META(4),
        /** */
        PCP(16),
        /** */
        ALL(0xff);
        /** */
        int value;
        /** */
        Type(int value) {
            this.value = value;
        }
    }

    /** */
    ChannelPacket() {
    }

    /** */
    ChannelPacket(Type type, final byte[] data, int length, int pos) throws IOException {
        this.type = type;
        if (length > MAX_DATALEN) {
            throw new IOException("Packet data too large");
        }
        this.data = new byte[length];
        System.arraycopy(data, 0, this.data, 0, length);
        this.pos = pos;
    }

    /** */
    void writeRaw(OutputStream out) throws IOException {
        out.write(data, 0, data.length);
    }

    /** */
    void writePeercast(OutputStream out) throws IOException {

        if (!type.equals(Type.UNKNOWN)) {
            DataOutputStream dos = new DataOutputStream(out);
            dos.writeBytes(type.name());
            dos.writeShort(data.length);
            dos.writeShort(0);
            dos.write(data, 0, data.length);
        }
    }

    /** */
    void readPeercast(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        byte[] tp = new byte[4];
        dis.readFully(tp);

        if (Arrays.equals(tp, "HEAD".getBytes())) {
            type = Type.HEAD;
        } else if (Arrays.equals(tp, "DATA".getBytes())) {
            type = Type.DATA;
        } else if (Arrays.equals(tp, "META".getBytes())) {
            type = Type.META;
        } else {
            type = Type.UNKNOWN;
        }
        int length = dis.readShort();
        dis.readShort();
        if (length > MAX_DATALEN) {
            throw new IOException("Packet data too large");
        }
        data = new byte[length];
        dis.readFully(data, 0, length);
    }

    int sync = 0;

    int pos = 0;

    Type type = Type.UNKNOWN;

    byte[] data;
}

/* */
