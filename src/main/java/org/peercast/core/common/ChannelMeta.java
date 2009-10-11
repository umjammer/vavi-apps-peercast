/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.w3c.dom.Document;

import vavi.xml.util.PrettyPrinter;


/**
 * ChanMeta.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelMeta {

    static final int MAX_DATALEN = 65536;

    ChannelMeta() {
        len = 0;
        cnt = 0;
        startPos = 0;
    }

    /** */
    void fromXML(Document xml) throws IOException {
        ByteArrayOutputStream tout = new ByteArrayOutputStream(MAX_DATALEN);
        PrettyPrinter pp = new PrettyPrinter(tout);
        pp.print(xml);

        data = tout.toByteArray();
        len = data.length;
    }

    /** */
    void fromMem(byte[] p, int l) {
        len = l;
        System.arraycopy(p, 0, data, 0, len);
    }

    /** */
    void addMem(byte[] p, int l) {
        if ((len + l) <= MAX_DATALEN) {
            System.arraycopy(p, 0, data, len, l);
            len += l;
        }
    }

    int len, cnt, startPos;

    byte[] data = new byte[MAX_DATALEN];
}

/* */
