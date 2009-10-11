//
// (c) 2002 peercast.org
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


/**
 * Stats.
 *
 * @version 4-apr-2002
 * @author giles
 */
class Stats {

    enum STAT {
        /** */
        NONE,

        /** */
        PACKETSSTART,
        /** */
        NUMQUERYIN,
        /** */
        NUMQUERYOUT,
        /** */
        NUMPINGIN,
        /** */
        NUMPINGOUT,
        /** */
        NUMPONGIN,
        /** */
        NUMPONGOUT,
        /** */
        NUMPUSHIN,
        /** */
        NUMPUSHOUT,
        /** */
        NUMHITIN,
        /** */
        NUMHITOUT,
        /** */
        NUMOTHERIN,
        /** */
        NUMOTHEROUT,
        /** */
        NUMDROPPED,
        /** */
        NUMDUP,
        /** */
        NUMACCEPTED,
        /** */
        NUMOLD,
        /** */
        NUMBAD,
        /** */
        NUMHOPS1,
        /** */
        NUMHOPS2,
        /** */
        NUMHOPS3,
        /** */
        NUMHOPS4,
        /** */
        NUMHOPS5,
        /** */
        NUMHOPS6,
        /** */
        NUMHOPS7,
        /** */
        NUMHOPS8,
        /** */
        NUMHOPS9,
        /** */
        NUMHOPS10,
        /** */
        NUMPACKETSIN,
        /** */
        NUMPACKETSOUT,
        /** */
        NUMROUTED,
        /** */
        NUMBROADCASTED,
        /** */
        NUMDISCARDED,
        /** */
        NUMDEAD,
        /** */
        PACKETDATAIN,
        /** */
        PACKETDATAOUT,
        /** */
        PACKETSEND,

        /** */
        BYTESIN,
        /** */
        BYTESOUT,
        /** */
        LOCALBYTESIN,
        /** */
        LOCALBYTESOUT;

        int current;
        int last;
        int perSec;
    }

    /** */
    void update() {
        long ctime = System.currentTimeMillis();

        long diff = ctime - lastUpdate;
        if (diff >= 5) {

            for (STAT stat : STAT.values()) {
                stat.perSec = (int) ((stat.current - stat.last) / diff);
                stat.last = stat.current;
            }

            lastUpdate = ctime;
        }

    }

    /** */
    boolean writeVariable(OutputStream out, final String var) throws IOException {
        String buf;

        if (var == "totalInPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.BYTESIN)));
        } else if (var == "totalOutPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.BYTESOUT)));
        } else if (var == "totalPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.BYTESIN) + getPerSecond(STAT.BYTESOUT)));
        } else if (var == "wanInPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.BYTESIN) - getPerSecond(STAT.LOCALBYTESIN)));
        } else if (var == "wanOutPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.BYTESOUT) - getPerSecond(STAT.LOCALBYTESOUT)));
        } else if (var == "wanTotalPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS((getPerSecond(STAT.BYTESIN) - getPerSecond(STAT.LOCALBYTESIN)) + (getPerSecond(STAT.BYTESOUT) - getPerSecond(STAT.LOCALBYTESOUT))));
        } else if (var == "netInPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.PACKETDATAIN)));
        } else if (var == "netOutPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.PACKETDATAOUT)));
        } else if (var == "netTotalPerSec") {
            buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(getPerSecond(STAT.PACKETDATAOUT) + getPerSecond(STAT.PACKETDATAIN)));
        } else if (var == "packInPerSec") {
            buf = String.format("%.1f", getPerSecond(STAT.NUMPACKETSIN));
        } else if (var == "packOutPerSec") {
            buf = String.format("%.1f", getPerSecond(STAT.NUMPACKETSOUT));
        } else if (var == "packTotalPerSec") {
            buf = String.format("%.1f", getPerSecond(STAT.NUMPACKETSOUT) + getPerSecond(STAT.NUMPACKETSIN));
        } else {
            return false;
        }

        out.write(buf.getBytes());

        return true;
    }

    void clearRange(STAT s, STAT e) {
        for (STAT stat : STAT.values()) {
            if (stat.ordinal() >= s.ordinal() && stat.ordinal() <= e.ordinal()) {
                stat.current = 0;
            }
        }
    }

    void clear(STAT s) {
        s.current = 0;
    }

    void add(STAT s) {
        add(s, 1);
    }

    void add(STAT s, int n) {
        s.current += n;
    }

    int getPerSecond(STAT s) {
        return s.perSec;
    }

    int getCurrent(STAT s) {
        return s.current;
    }

    long lastUpdate;
}

/* */
