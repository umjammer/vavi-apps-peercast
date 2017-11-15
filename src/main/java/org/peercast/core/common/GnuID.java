/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.util.Random;


/**
 * GUID (extends UUID).
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class GnuID {

    GnuID() {
        // its a nasty hack, but it just might work jim.
        // insert a 6 digit code in the bottom of the ID string
        // so that we can tell what versions are out there.
        // also used to detect version changes/fixes in packets.
        random.nextBytes(id);

        IntBuffer ib = ByteBuffer.wrap(id).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        ib.position(3);
        ib.put(GnuPacket.PEERCAST_PACKETID);
    }

    /**
     * @param str "23450ABCDEF1..." 32 �����܂ł�����͂��Ȃ��A���̌�؂�̂�
     */
    GnuID(String str) {
        if (str == null || str.length() < 32) {
            return;
        }

        for (int i = 0; i < 16; i++) {
            String one = str.substring(i * 2, i * 2 + 2);
            id[i] = (byte) Integer.parseInt(one, 16);
        }
    }

    public boolean equals(Object gid) {
        return Arrays.equals(id, GnuID.class.cast(gid).id);
    }

    boolean isSet() {
        for (int i = 0; i < 16; i++) {
            if (id[i] != 0) {
                return true;
            }
        }
        return false;
    }

    void clear() {
        Arrays.fill(id, (byte) 0);
        storeTime = 0;
    }

    static final Random random = new Random(System.currentTimeMillis());

    void generate() {
        random.nextBytes(id);
    }

    void encode(final InetSocketAddress address, final String salt1, final String salt2, byte salt3) {
        int s1 = 0, s2 = 0;
        for (int i = 0; i < 16; i++) {
            byte ipBytes = id[i];

            // encode with IP address
            if (address != null) {
                ipBytes ^= address.getAddress().getAddress()[i & 3];
            }

            // add a bit of salt
            if (salt1 != null) {
                if (s1 < salt1.length()) {
                    ipBytes ^= salt1.charAt(s1++);
                } else {
                    s1 = 0;
                }
            }

            // and some more
            if (salt2 != null) {
                if (s2 < salt2.length()) {
                    ipBytes ^= salt2.charAt(s2++);
                } else {
                    s2 = 0;
                }
            }

            // plus some pepper
            ipBytes ^= salt3;

            id[i] = ipBytes;
        }
    }

    /**  */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(String.format("%02X", id[i]));
        }
        return sb.toString();
    }

    /** */
    int getVersion() {
        IntBuffer ib = ByteBuffer.wrap(id).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        ib.position(3);
        int pid = ib.get();

        int ver = pid & 0xfffff;
        return ver;
    }

    byte[] id = new byte[16];

    int storeTime;
}

/* */
