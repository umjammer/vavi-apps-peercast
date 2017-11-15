/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import vavi.io.LittleEndianDataInputStream;


/**
 * AtomInputStream.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050813 nsano initial version <br>
 */
public class AtomInputStream {

    /** */
    AtomInputStream(InputStream s) {
        dis = new LittleEndianDataInputStream(s);
        childCount = 0;
        dataLength = 0;
    }

    /** */
//    private void checkData(int d) throws IOException {
//        if (dataLength != d) {
//            throw new IOException("Bad atom data");
//        }
//    }

    /**
     * below two fields will be orver written.
     * @see #childCount
     * @see #dataLength
     */
    ID4 read() throws IOException {
        ID4 id = readID4Internal();

        int v = dis.readInt();
        if ((v & 0x80000000) != 0) {
            childCount = v & 0x7fffffff;
            dataLength = 0;
        } else {
            childCount = 0;
            dataLength = v;
        }

        return id;
    }

    /** */
    private ID4 readID4Internal() throws IOException {
        ID4 id = ID4.read(dis);
        return id;
    }

    /**
     * @param c children counts
     * @param d self data length
     */
    void skip(int c, int d) throws IOException {
        if (d != 0) {
            dis.skip(d);
        }

        for (int i = 0; i < c; i++) {
            read();
            skip(this.childCount, this.dataLength);
        }

    }

    /** */
    int readInt() throws IOException {
//        checkData(4);
        return dis.readInt();
    }

    /**
     * Just reads an ID4 only. different from {@link #read()}
     */
    ID4 readID4() throws IOException {
//        checkData(4);
        ID4 id = ID4.read(dis);
        return id;
    }

    /** */
    int readShort() throws IOException {
//        checkData(2);
        return dis.readUnsignedShort();
    }

    /** */
    int readByte() throws IOException {
//        checkData(1);
        return dis.readUnsignedByte();
    }

    /** */
    int readBytes(byte[] bytes, int length) throws IOException {
//        checkData(length);
        return dis.read(bytes, 0, length);
    }

    /** TODO max check */
    String readString(int max, int length) throws IOException {
        byte[] bytes = new byte[max];
//        checkData(length);
        readBytes(bytes, max, length);
//System.err.print("\n" + StringUtil.getDump(bytes));
        return new String(bytes, 0, length - 1, "UTF-8");
    }

    /** */
    void readBytes(byte[] bytes, int max, int dataLength) throws IOException {
//        checkData(dataLength);
        if (max > dataLength) {
            readBytes(bytes, dataLength);
        } else {
            readBytes(bytes, max);
            dis.skip(dataLength - max);
        }
    }

    /** */
    void writeTo(OutputStream os, int length) throws IOException {
        byte[] tmp = new byte[4096];
        while (length > 0) {
            int rlen = tmp.length;
            if (rlen > length) {
                rlen = length;
            }

            dis.read(tmp, 0, rlen);
            os.write(tmp, 0, rlen);

            length -= rlen;
        }
    }

    boolean eof() throws IOException {
        return dis.available() > 0;
    }

    int childCount, dataLength;

    private LittleEndianDataInputStream dis;
}

/* */
