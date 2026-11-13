/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;
import java.io.InputStream;


/**
 * RawStream.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 2005/08/11 nsano initial version <br>
 */
class RawStream extends ChannelStream {

    @Override
    int readHeader(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    @Override
    int readPacket(InputStream is, Channel channel) throws IOException {
        final int readLen = 8192;
        byte[] buf = new byte[readLen];

        int l = is.read(buf, 0, readLen);
        if (l == -1) {
            return -1;
        }

        ChannelPacket pack = new ChannelPacket();
        pack.type = ChannelPacket.Type.DATA;
        pack.data = new byte[l];
        System.arraycopy(buf, 0, pack.data, 0, l);
        pack.pos = channel.streamPos;

        channel.newPacket(pack);
        channel.checkReadDelay(pack.data.length);

        channel.streamPos += pack.data.length;

        return 0;
    }

    @Override
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }
}
