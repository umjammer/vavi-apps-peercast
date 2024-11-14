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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.peercast.core.common.GnuPacket.GnuFunction;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import vavi.util.Singleton;

import static java.lang.System.getLogger;


/**
 * GnuStream.
 *
 * @author giles
 * @version 4-apr-2002
 */
class GnuStream {

    private static final Logger logger = getLogger(GnuStream.class.getName());

    /** */
    private final ServentManager servMgr = Peercast.serventManager;

    /** */
    private static final ChannelManager chanMgr = Peercast.channelManager;

    /** */
    enum ResultType {
        /** */
        PROCESS,
        /** */
        DEAD,
        /** */
        DISCARD,
        /** */
        ACCEPTED,
        /** */
        BROADCAST,
        /** */
        ROUTE,
        /** */
        DUPLICATE,
        /** */
        BADVERSION,
        /** */
        DROP
    }

    /** */
    GnuStream(Socket socket) {
        this.socket = socket;
        packetsIn = packetsOut = 0;
    }

    /** */
    Socket socket;

    /** */
    void ping(int ttl) throws IOException {
        GnuPacket ping = new GnuPacket(ttl);
        servMgr.addReplyID(ping.id);
        sendPacket(ping);
        logger.log(Level.DEBUG, "ping out %02x%02x%02x%02x".formatted(ping.id.id[0], ping.id.id[1], ping.id.id[2], ping.id.id[3]));
    }

    /** */
    void sendPacket(GnuPacket packet) throws IOException {
        synchronized (this) {
            packetsOut++;
            Peercast.getInstance().stats.add(Stats.STAT.NUMPACKETSOUT);
            Peercast.getInstance().stats.add(packet.func.getOutStat());

            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            dos.write(packet.id.id, 0, 16);
            dos.writeByte(packet.func.getNumber()); // ping func
            dos.writeByte((int) packet.ttl); // ttl
            dos.writeByte(packet.hops); // hops
            dos.writeInt(packet.len); // len

            if (packet.len != 0) {
                dos.write(packet.data, 0, packet.len);
            }

            Peercast.getInstance().stats.add(Stats.STAT.PACKETDATAOUT, 23 + packet.len);
        }
    }

    /** */
    synchronized boolean readPacket(GnuPacket packet) throws IOException {
        packetsIn++;
        Peercast.getInstance().stats.add(Stats.STAT.NUMPACKETSIN);

        DataInputStream dis = new DataInputStream(socket.getInputStream());
        dis.read(packet.id.id, 0, 16);
        packet.func = findGnuFunc(dis.readByte());
        packet.ttl = dis.readByte();
        packet.hops = dis.readByte();
        packet.len = dis.readInt();

        if ((packet.hops >= 1) && (packet.hops <= 10)) {
            Peercast.getInstance().stats.add(Stats.STAT.values()[packet.hops - 1]);
        }

        Peercast.getInstance().stats.add(Stats.STAT.PACKETDATAIN, 23 + packet.len);
        Peercast.getInstance().stats.add(packet.func.getInStat());

        if (packet.len != 0) {
            if (packet.len > GnuPacket.MAX_DATA) {
                while (packet.len-- > 0) {
                    dis.readByte();
                }
                return false;
            }
            dis.read(packet.data, 0, packet.len);
        }

        return true;
    }

    static GnuFunction[] functions = {
            GnuPacket.PING,
            GnuPacket.PONG,
            GnuPacket.QUERY,
            GnuPacket.HIT,
            GnuPacket.PUSH
    };

    /** */
    static GnuFunction findGnuFunc(int functionNumber) {
        for (GnuFunction gnuFunction : functions) {
            if (gnuFunction.getNumber() == functionNumber) {
                return gnuFunction;
            }
        }
        throw new IllegalArgumentException("unknown functionNumber: " + functionNumber);
    }

    /** */
    static ResultType processPacket(GnuPacket in, Servent servent, GnuID routeID) throws IOException {

        ResultType ret = null;


        in.ttl--;
        in.hops++;

        routeID = in.id;

        int ver = in.getVersion();

        if (in.func != null) {
            ret = in.func.exec(in, servent, routeID);
        } else {
            logger.log(Level.DEBUG, "packet: %d".formatted(in.func));
        }

        if ((in.ttl > 10) || (in.hops > 10) || (in.ttl == 0)) {
            if ((ret == ResultType.BROADCAST) || (ret == ResultType.ROUTE)) {
                ret = ResultType.DEAD;
            }
        }

        return ret;
    }

    /** */
    static boolean readHit(InputStream dataIn, ChannelHit ch, int hops, GnuID id) throws IOException {
        DataInputStream data = new DataInputStream(dataIn);
        int i;
        int num = data.readByte(); // hits
        int port = data.readShort(); // port
        int ip = data.readInt(); // ip
        int spd = data.readInt(); // speed/broadcast

        InetSocketAddress h = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(ip)), port);
        String hostName = h.getHostName();

        boolean dataValid = true;

        ChannelHit[] hits = new ChannelHit[100];
        int numHits = 0;

        for (i = 0; i < num; i++) {
            int index, bitrate, listeners;

            index = data.readInt(); // index
            bitrate = data.readShort(); // bitrate
            listeners = data.readShort(); // listeners

            // read name .. not used.
            String fname = data.readUTF();

            ch.init();
            ch.firewalled = false; // default to NO as we dont get the info until the next section.
            ch.setAddress(h);
            ch.numListeners = listeners;
            ch.numHops = hops;
            ch.remoteAddresses[0] = ch.getAddress();

            ChannelInfo info = new ChannelInfo();

            {
                String xmlData;
                xmlData = data.readUTF();

                if (xmlData.startsWith("<?xml") && (xmlData.length() < GnuPacket.MAX_DATA)) {
// logger.log(Level.DEBUG, "Hit XML: %s".formatted(xmlData));

                    ByteArrayInputStream xm = new ByteArrayInputStream(xmlData.getBytes());
                    Document xml = null;
                    try {
                        xml = Peercast.db.parse(xm);
                    } catch (SAXException e) {
                        throw (RuntimeException) new IllegalStateException(e);
                    }
                    Element n = (Element) xml.getElementsByTagName("channel").item(0);
                    if (n != null) {
                        info.init(n);
                        String idStr = info.id.toString();
                        logger.log(Level.DEBUG, String.format("got hit %s %s", idStr, info.name));

                        ch.upTime = Integer.parseInt(n.getAttribute("uptime"));

                    } else
                        logger.log(Level.DEBUG, "Missing Channel node");
                } else {
                    logger.log(Level.DEBUG, "Missing XML data");
                    dataValid = false;
                }
            }

            if (info.id.isSet()) {
                if (chanMgr.findHitList(info) == null) {
                    chanMgr.addHitList(info);
                }

                ch.receiver = true;
                ch.channelID = info.id;
                ChannelHit chp = chanMgr.addHit(ch);

                if ((chp != null) && (numHits < 100)) {
                    hits[numHits++] = chp;
                }
            }

        }

        int vendor = data.readInt(); // vendor ID

        int pubLen = data.readByte(); // public sec length - should be 2

        int f1 = data.readByte() & 0xff; // flags 1
        int f2 = data.readByte() & 0xff; // flags 2

        pubLen -= 2;
        while (pubLen-- > 0) {
            data.readByte();
        }

        String agentStr = null;
        int maxPreviewTime = 0;

        // read private sector with peercast servant specific info
        int privLen = data.readByte();

        if (privLen != 0) {
            byte[] privData = new byte[256];
            data.read(privData, 0, privLen);
            if (new String(privData, 0, 5).equals("<?xml")) {
                ByteArrayInputStream xm = new ByteArrayInputStream(privData, 0, privLen);
                Document xml;
                try {
                    xml = Peercast.db.parse(xm);
                } catch (SAXException e) {
                    throw (RuntimeException) new IllegalStateException(e);
                }
                Element sn = (Element) xml.getElementsByTagName("servent").item(0);
                if (sn != null) {
                    agentStr = sn.getAttribute("agent");
                    maxPreviewTime = Integer.parseInt(sn.getAttribute("preview"));
                }

            }
        }

        // not used anymore
        GnuID queryID = new GnuID();
        data.read(queryID.id, 0, 16);

        boolean isBroadcastHit = false;
        if ((f1 & 32) > 0) {
            isBroadcastHit = (f2 & 32) != 0;
        }

        for (i = 0; i < numHits; i++) {
            if ((f1 & 1) > 0) {
                hits[i].firewalled = (f2 & 1) != 0;
            }

            if ((f1 & 64) > 0) {
                hits[i].tracker = (f2 & 64) != 0;
            }

            hits[i].agentStr = agentStr;
        }

        return dataValid;
    }

    int packetsIn, packetsOut;
}
