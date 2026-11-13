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
 * NSVStream.
 *
 * @author giles
 * @version 28-may-2003
 */
class NSVStream extends ChannelStream {

    @Override
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    @Override
    int readHeader(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    @Override
    int readPacket(InputStream is, Channel channel) throws IOException {
        ChannelPacket pack = null;

        if (channel.icyMetaInterval != 0) {

            int rlen = channel.icyMetaInterval;

            while (rlen > 0) {
                int rl = rlen;
                if (rl > ChannelManager.MAX_METAINT) {
                    rl = ChannelManager.MAX_METAINT;
                }

                byte[] buf = new byte[rl];
                int n = is.read(buf, 0, rl);
                if (n == -1) return -1;

                pack = new ChannelPacket();
                pack.type = ChannelPacket.Type.DATA;
                pack.data = new byte[n];
                System.arraycopy(buf, 0, pack.data, 0, n);
                pack.pos = channel.streamPos;

                channel.newPacket(pack);
                channel.checkReadDelay(pack.data.length);
                channel.streamPos += pack.data.length;

                rlen -= n;
            }

            int len;
            len = is.read();
            if (len == -1) return -1;
            if (len > 0) {
                if (len * 16 > 1024) {
                    len = 1024 / 16;
                }
                byte[] buf = new byte[len * 16];
                int n = is.read(buf, 0, buf.length);
                if (n == -1) return -1;
                channel.processMp3Metadata(buf);
            }

        } else {

            byte[] buf = new byte[ChannelManager.MAX_METAINT];
            int n = is.read(buf, 0, buf.length);
            if (n == -1) return -1;

            pack = new ChannelPacket();
            pack.type = ChannelPacket.Type.DATA;
            pack.data = new byte[n];
            System.arraycopy(buf, 0, pack.data, 0, n);
            pack.pos = channel.streamPos;

            channel.newPacket(pack);
            channel.checkReadDelay(pack.data.length);

            channel.streamPos += pack.data.length;
        }
        return 0;
    }
}
