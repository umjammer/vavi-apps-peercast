//
// (c) 2002-4 peercast.org
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * ICYSource.
 *
 * @version 20-feb-2004
 * @author giles
 */
class ICYSource extends ChannelSource {
    static Log log = LogFactory.getLog(ICYSource.class);

    void stream(Channel ch) throws IOException {
        ChannelStream source = null;
        try {

            if (ch.sock != null) {
                throw new IOException("ICY channel has no socket");
            }

            ch.resetPlayTime();

            ch.setStatus(Channel.Status.BROADCASTING);
            source = ch.createSource();
            ch.readStream(ch.sock.getInputStream(), source);

        } catch (IOException e) {
            log.error(String.format("Ch.%d aborted: %s", ch.index, e.getMessage()));
        }


        ch.setStatus(Channel.Status.CLOSING);

        if (ch.sock != null) {
            ch.sock.close();
            ch.sock = null;
        }
    }
}

/* */
