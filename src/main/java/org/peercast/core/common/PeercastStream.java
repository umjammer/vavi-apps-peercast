/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import vavi.util.Singleton;


/**
 * PeercastStream.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class PeercastStream extends ChannelStream {

    private final ChannelManager chanMgr = Peercast.channelManager;

    @Override
    int readHeader(InputStream is, Channel channel) throws IOException {
        byte[] tp = new byte[4];
        int l = is.read(tp, 0, 4);
        if (!Arrays.equals(tp, "PCST".getBytes())) {
            throw new IOException("Not PeerCast stream");
        }
        return l;
    }

    @Override
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    @Override
    int readPacket(InputStream is, Channel channel) throws IOException {
        ChannelPacket pack = new ChannelPacket();

        pack.readPeercast(is);

        ByteArrayInputStream mem = new ByteArrayInputStream(pack.data);

        switch (pack.type) {
            case HEAD:
                // update sync pos
                channel.headPack = pack;
                pack.pos = channel.streamPos;
                channel.newPacket(pack);
                channel.streamPos += pack.data.length;
                break;
            case DATA:
                pack.pos = channel.streamPos;
                channel.newPacket(pack);
                channel.streamPos += pack.data.length;
                break;
            case META:
                channel.insertMeta.fromMem(pack.data, pack.data.length);
                if (pack.data.length != 0) {
                    Document xml;
                    try {
                        xml = Peercast.db.parse(mem);
                    } catch (SAXException e) {
                        throw (IOException) new IOException(e);
                    }
                    Element n = (Element) xml.getElementsByTagName("channel").item(0);
                    if (n != null) {
                        ChannelInfo newInfo = channel.info;
                        newInfo.updateFromXML(n);
                        ChannelHitList chl = chanMgr.findHitList(channel.info);
                        if (chl != null) {
                            newInfo.updateFromXML(n);
                        }
                        channel.updateInfo(newInfo);
                    }
                }
                break;
        }
        return 0;
    }
}
