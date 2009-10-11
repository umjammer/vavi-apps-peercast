/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;


/**
 * ASFStream. 
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ASFStream {

    enum TYPE {
        T_UNKNOWN,
        T_AUDIO,
        T_VIDEO
    }

    void read(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        MSID sid = new MSID();
        sid.read(dis);

        if (sid == MSID.videoStreamObjID) {
            type = TYPE.T_VIDEO;
        } else if (sid == MSID.audioStreamObjID) {
            type = TYPE.T_AUDIO;
        } else {
            type = TYPE.T_UNKNOWN;
        }

        dis.skip(32);
        id = dis.readShort() & 0x7f;
    }


    final String getTypeName() {
        switch (type) {
        case T_VIDEO:
            return "Video";
        case T_AUDIO:
            return "Audio";
        }
        return "Unknown";
    }

    void reset() {
        id = 0;
        bitrate = 0;
        type = TYPE.T_UNKNOWN;
    }

    int id;
    int bitrate;
    TYPE type;
}

/* */
