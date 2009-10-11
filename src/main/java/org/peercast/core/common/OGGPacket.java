/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;


/**
 * OggPacket.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class OGGPacket {

    // probably too small
    static final int MAX_BODYLEN = 65536;

    // prolly too small too, but realloc?!?!?!
    static final int MAX_PACKETS = 256;

    /** */
    void addLacing(OGGPage ogg) throws IOException {

        int numSegs = ogg.data[26];
        for (int i = 0; i < numSegs; i++) {
            int seg = ogg.data[27 + i];

            packetSizes[numPackets] += seg;

            if (seg < 255) {
                numPackets++;
                if (numPackets >= MAX_PACKETS) {
                    throw new IOException("Too many OGG packets");
                }
                packetSizes[numPackets] = 0;
            }
        }

    }

    int bodyLen;

    byte[] body = new byte[MAX_BODYLEN];

    int numPackets;

    int[] packetSizes = new int[MAX_PACKETS];
}

/* */
