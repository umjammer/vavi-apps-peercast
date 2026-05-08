/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;
import java.util.Arrays;


/**
 * ChanPacketBuffer.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelPacketBuffer {

    /** */
    static final int MAX_PACKETS = 64;

    /** */
    static final int NUM_SAFEPACKETS = 56;

    /** */
    ChannelPacketBuffer() {
        init();
    }

    /** */
    void init() {
        synchronized (this) {
            lastPos = firstPos = safePos = 0;
            readPos = writePos = 0;
            accept = 0;
            lastWriteTime = 0;
            Arrays.fill(packets, null);
        }
    }

    /** */
    int copyFrom(ChannelPacketBuffer buf, int reqPos) {
        synchronized (this) {
            synchronized (buf) {

                firstPos = 0;
                lastPos = 0;
                safePos = 0;
                readPos = 0;

                for (int i = buf.firstPos; i <= buf.lastPos; i++) {
                    ChannelPacket src = buf.packets[i % MAX_PACKETS];
                    if (src != null && (src.type.value & accept) != 0) {
                        if (src.pos >= reqPos) {
                            lastPos = writePos;
                            packets[writePos % MAX_PACKETS] = src;
                            writePos++;
                        }
                    }
                }
            }
        }
        return lastPos - firstPos;
    }

    /** */
    ChannelPacket findPacket(int spos) {
        if (writePos == 0) {
            return null;
        }

        synchronized (this) {

            int fpos = getStreamPos(firstPos);
            if (spos < fpos)
                spos = fpos;

            for (int i = firstPos; i <= lastPos; i++) {
                ChannelPacket pack = packets[i % MAX_PACKETS];
                if (pack != null && pack.pos >= spos) {
                    return pack;
                }
            }

            return null;
        }
    }

    /** */
    int getLatestPos() {
        if (writePos == 0) {
            return 0;
        } else {
            return getStreamPos(lastPos);
        }
    }

    /** */
    int getOldestPos() {
        if (writePos == 0) {
            return 0;
        } else {
            return getStreamPos(firstPos);
        }
    }

    /** */
    int findOldestPos(int spos) {
        int min = getStreamPos(safePos);
        int max = getStreamPos(lastPos);

        if (min > spos) {
            return min;
        }

        return Math.min(max, spos);

    }

    /** */
    int getStreamPos(int index) {
        ChannelPacket pack = packets[index % MAX_PACKETS];
        if (pack == null) {
            return 0; // TODO check
        } else {
            return pack.pos;
        }
    }

    /** */
    int getStreamPosEnd(int index) {
        ChannelPacket pack = packets[index % MAX_PACKETS];
        return pack.pos + pack.data.length;
    }

    /** */
    boolean writePacket(ChannelPacket pack, boolean updateReadPos) {
        if (pack.data.length != 0) {
            if (willSkip()) { // too far behind
                return false;
            }

            synchronized (this) {

                pack.sync = writePos;
                packets[writePos % MAX_PACKETS] = pack;
                lastPos = writePos;
                writePos++;

                if (writePos >= MAX_PACKETS) {
                    firstPos = writePos - MAX_PACKETS;
                } else {
                    firstPos = 0;
                }
                if (writePos >= NUM_SAFEPACKETS) {
                    safePos = writePos - NUM_SAFEPACKETS;
                } else {
                    safePos = 0;
                }

                if (updateReadPos) {
                    readPos = writePos;
                }

                lastWriteTime = System.currentTimeMillis();

            }
            return true;
        }

        return false;
    }

    /** */
    ChannelPacket readPacket() throws IOException {
        ChannelPacket packet = null;
        long time = System.currentTimeMillis();

        if (readPos < firstPos) {
            throw new IOException("Read too far behind");
        }

        while (readPos >= writePos) {
            try {
                Thread.sleep(Peercast.idleSleepTime);
            } catch (InterruptedException e) {
            }
            if ((System.currentTimeMillis() - time) > 30 * 1000) { // TODO time unit
                throw new IOException("timeout");
            }
        }
        synchronized (this) {
            packet = packets[readPos % MAX_PACKETS];
            readPos++;
        }

        try {
            Thread.sleep(Peercast.idleSleepTime);
        } catch (InterruptedException e) {
        }

        return packet;
    }

    /** */
    boolean willSkip() {
        return (writePos - readPos) >= MAX_PACKETS;
    }

    /** */
    public boolean numPending() {
        return writePos - readPos != 0;
    }

    /** */
    private final ChannelPacket[] packets = new ChannelPacket[MAX_PACKETS];

    /** */
    private volatile int lastPos, firstPos, safePos;

    /** */
    private volatile int readPos;

    /** */
    volatile int writePos;

    /** */
    int accept;

    /** */
    long lastWriteTime;
}
