/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * OGGPage.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class OGGPage {

    Log log = LogFactory.getLog(OGGPage.class);

    static final int MAX_BODYLEN = 65536;

    static final int MAX_HEADERLEN = 27 + 256;

    /** */
    boolean isBOS() {
        return (data[5] & 0x02) != 0;
    }

    /** */
    boolean isEOS() {
        return (data[5] & 0x04) != 0;
    }

    /** */
    boolean isNewPacket() {
        return (data[5] & 0x01) == 0;
    }

    /** */
    boolean isHeader() {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            DataInputStream dis = new DataInputStream(bais);
            dis.skip(6);
            int a = dis.readInt();
            int b = dis.readInt();
            return a != 0 || b == 0;
        } catch (IOException e) {
            throw (RuntimeException) new IllegalStateException().initCause(e);
        }
    }

    /** */
    int getSerialNo() {
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            DataInputStream dis = new DataInputStream(bais);
            dis.skip(14);
            return dis.readInt();
        } catch (IOException e) {
            throw (RuntimeException) new IllegalStateException().initCause(e);
        }
    }

    /** */
    void read(InputStream in) throws IOException {
        // skip until we get OGG capture pattern
        boolean gotOgg = false;
        while (!gotOgg) {
            if (in.read() == 'O') {
                if (in.read() == 'g') {
                    if (in.read() == 'g') {
                        if (in.read() == 'S') {
                            gotOgg = true;
                        }
                    }
                }
            }
            if (!gotOgg) {
                log.debug("Skipping OGG packet");
            }
        }

        System.arraycopy("OggS".getBytes(), 0, data, 0, 4);

        in.read(data, 4, 27 - 4);

        int numSegs = data[26];
        bodyLen = 0;

        // read segment table
        in.read(data, 27, numSegs);
        for (int i = 0; i < numSegs; i++) {
            bodyLen += data[27 + i];
        }

        if (bodyLen >= MAX_BODYLEN) {
            throw new IOException("OGG body too big");
        }

        headLen = 27 + numSegs;

        if (headLen > MAX_HEADERLEN) {
            throw new IOException("OGG header too big");
        }

        in.read(data, headLen, bodyLen);

        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);
        dis.skip(6);
        int l = dis.readInt(); // 6
        int h = dis.readInt(); // 10
        granPos = h << 32 | l;

        int page = dis.readInt(); // 14
        int id = dis.readInt(); // 18

        log.debug(String.format("OGG Packet - page %d, id = %x - %s %s %s - %d:%d - %d segs, %d bytes",
                                page,
                                id,
                                (data[5] & 0x1) != 0 ? "cont" : "new",
                                (data[5] & 0x2) != 0 ? "bos" : "",
                                (data[5] & 0x4) != 0 ? "eos" : "",
                                (int) (granPos >> 32),
                                (int) (granPos & 0xffffffff),
                                numSegs,
                                headLen + bodyLen));
    }

    /** */
    boolean detectVorbis() {
        return new String(data, headLen + 1, 6).equals("vorbis");
    }

    /** */
    boolean detectTheora() {
        return new String(data, headLen + 1, 6).equals("theora");
    }

    long granPos;

    int headLen, bodyLen;

    byte[] data = new byte[MAX_HEADERLEN + MAX_BODYLEN];
}

/* */
