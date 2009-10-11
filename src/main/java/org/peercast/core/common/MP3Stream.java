//
// (c) 2002-3 peercast.org
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
import java.io.InputStream;


/**
 * MP3Stream.
 *
 * @version 28-may-2003
 * @author giles
 */
class MP3Stream extends ChannelStream {
    /** */
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readHeader(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readPacket(InputStream is, Channel channel) throws IOException {
        ChannelPacket pack = null;

        if (channel.icyMetaInterval != 0) {

            int rlen = channel.icyMetaInterval;

            while (rlen > 0) {
                int rl = rlen;
                if (rl > ChannelManager.MAX_METAINT) {
                    rl = ChannelManager.MAX_METAINT;
                }

                pack = new ChannelPacket(ChannelPacket.Type.DATA, pack.data, rl, channel.streamPos);
                is.read(pack.data, 0, pack.data.length);
                channel.newPacket(pack);
                channel.checkReadDelay(pack.data.length);
                channel.streamPos += pack.data.length;

                rlen -= rl;
            }

            int len;
            len = is.read();
            if (len > 0) {
                if (len * 16 > 1024) {
                    len = 1024 / 16;
                }
                byte[] buf = new byte[1024];
                is.read(buf, 0, len * 16);
                channel.processMp3Metadata(buf);
            }

        } else {

            pack = new ChannelPacket(ChannelPacket.Type.DATA, pack.data, ChannelManager.MAX_METAINT, channel.streamPos);
            is.read(pack.data, 0, pack.data.length);
            channel.newPacket(pack);
            channel.checkReadDelay(pack.data.length);

            channel.streamPos += pack.data.length;
        }
        return 0;
    }
}

/* */
