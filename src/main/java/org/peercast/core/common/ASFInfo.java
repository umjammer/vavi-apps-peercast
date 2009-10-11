/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;


/**
 * ASFInfo. 
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ASFInfo {

    static final int MAX_STREAMS = 128;

    ASFInfo() {
        numPackets = 0;
        packetSize = 0;
        flags = 0;
        bitrate = 0;
        for (int i = 0; i < MAX_STREAMS; i++) {
            streams[i].reset();
        }
    }

    int packetSize, numPackets, flags, bitrate;

    ASFStream[] streams = new ASFStream[MAX_STREAMS];
}

/* */
