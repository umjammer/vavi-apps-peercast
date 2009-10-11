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
    /** */
    int readHeader(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readPacket(InputStream is, Channel channel) throws IOException {
        ChannelPacket pack = null;

        final int readLen = 8192;

        pack = new ChannelPacket(ChannelPacket.Type.DATA, pack.data, readLen, channel.streamPos);
        int l = is.read(pack.data, 0, pack.data.length);
        channel.newPacket(pack);
        channel.checkReadDelay(pack.data.length);

        channel.streamPos += pack.data.length;

        return l;
    }

    /** */
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }
}

/* */
