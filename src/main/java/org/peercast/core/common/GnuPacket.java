/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.xml.sax.SAXException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.peercast.core.common.GnuStream.ResultType;
import org.peercast.core.common.Stats.STAT;

import vavi.io.UtilInputStream;
import vavi.util.Singleton;
import vavi.xml.util.PrettyPrinter;


/**
 * GnuPacket.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class GnuPacket {

    /** */
    private static Log log = LogFactory.getLog(GnuPacket.class);

    private static ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    private static ChannelManager channelMabager = Singleton.getInstance(ChannelManager.class);

    /** */
    static final int GNUTELLA_SETUP = 0;

    /** */
    interface GnuFunction {
        ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException;

        int getNumber();

        STAT getInStat();

        STAT getOutStat();
    }

    /** */
    static GnuFunction PING = new GnuFunction() {
        public ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException {
            InetSocketAddress remoteHost = serv.getHost();

            ResultType ret = ResultType.DISCARD;

log.debug(String.format("ping: from %d.%d.%d.%d : %02x%02x%02x%02x", remoteHost.getAddress().getAddress()[0], remoteHost.getAddress().getAddress()[1], remoteHost.getAddress().getAddress()[2], remoteHost.getAddress().getAddress()[0], in.id.id[0], in.id.id[1], in.id.id[2], in.id.id[3]));
            InetSocketAddress sh = serventManager.serverHost;
            if (sh.getAddress() != null) {
                if ((serventManager.getFirewall() != ServentManager.FirewallState.ON) && (!serventManager.pubInFull())) {
                    GnuPacket pong = new GnuPacket(sh, true, in);
                    if (serv.outputPacket(pong, true)) {
                        log.debug("pong out");
                    }
                }
                ret = ResultType.BROADCAST;
            }
            return ret;
        }

        public String toString() {
            return "PING";
        }

        public int getNumber() {
            return 0;
        }

        public STAT getInStat() {
            return Stats.STAT.NUMPINGIN;
        }

        public STAT getOutStat() {
            return Stats.STAT.NUMPINGOUT;
        }
    };

    /** */
    static GnuFunction PONG = new GnuFunction() {
        public ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException {
            ByteArrayInputStream data = new ByteArrayInputStream(in.data); // , in.len
            DataInputStream dis = new DataInputStream(data);

            InetSocketAddress remoteHost = serv.getHost();

            ResultType resultt = ResultType.DISCARD;

            int port = dis.readShort();
            int ip = dis.readInt();
            int count = dis.readInt();
log.debug("count: " + count);
            int total = dis.readInt();
log.debug("total: " + total);

            InetSocketAddress h = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(ip)), port);

            String sIP = h.getHostName();
            String rIP = remoteHost.getHostName();

log.debug(String.format("pong: %s via %s : %02x%02x%02x%02x", sIP, ip, rIP, in.id.id[0], in.id.id[1], in.id.id[2], in.id.id[3]));

            resultt = ResultType.DISCARD;

            if (h.getAddress() != null) {

                // accept if this pong is a reply from one of our own pings, otherwise route back
                if (serventManager.isReplyID(in.id)) {
                    serventManager.addHost(h, ServHost.Type.SERVENT, System.currentTimeMillis());
                    resultt = ResultType.ACCEPTED;
                } else {
                    resultt = ResultType.ROUTE;
                }
            }

            return resultt;
        }

        public String toString() {
            return "PONG";
        }

        public int getNumber() {
            return 1;
        }

        public STAT getInStat() {
            return Stats.STAT.NUMPONGIN;
        }

        public STAT getOutStat() {
            return Stats.STAT.NUMPONGOUT;
        }
    };

    /** */
    static GnuFunction QUERY = new GnuFunction() {
        public ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException {
            ByteArrayInputStream data = new ByteArrayInputStream(in.data); // in.len
            DataInputStream dis = new DataInputStream(data);
            UtilInputStream uis = new UtilInputStream(data);

            ResultType ret = ResultType.BROADCAST;

            InetSocketAddress sh = serventManager.serverHost;
            if (sh.getAddress() == null) {
                sh = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(127 << 24 | 1)), sh.getPort());
            }

            short spd = dis.readShort();
log.debug("spd: " + spd);
            String words = uis.readAsciiz();

            String xm = dis.readUTF(); // TODO check

            List<Channel> hitChannels = null;

            if (xm.startsWith("<?xml")) {
                Document xml = null;
                try {
                    xml = Peercast.db.parse(xm);
                } catch (SAXException e) {
                    throw (RuntimeException) new IllegalStateException().initCause(e);
                }
                NodeList nodeList = xml.getElementsByTagName("channel");
                if (nodeList.getLength() > 0) {
                    Element cn = (Element) nodeList.item(0);
                    ChannelInfo info = new ChannelInfo();
                    info.init(cn);
                    info.status = ChannelInfo.Status.PLAY;
                    hitChannels = channelMabager.findChannels(info, 16);
                }
log.debug(String.format("query XML: %s : found %d", xm, hitChannels.size()));
            } else {
                ChannelInfo info = new ChannelInfo();
                info.name = words;
                info.genre = words;
                info.id = new GnuID(words);
                info.status = ChannelInfo.Status.PLAY;
                hitChannels = channelMabager.findChannels(info, 16);
log.debug(String.format("query STR: %s : found %d", words, hitChannels.size()));
            }

            for (Channel channel : hitChannels) {
                boolean push = (serventManager.getFirewall() != ServentManager.FirewallState.OFF);
                boolean busy = (serventManager.pubInFull() && serventManager.outFull()) || serventManager.relaysFull();
                boolean stable = serventManager.totalStreams > 0;
                boolean tracker = channel.isBroadcasting();

                try {
                    GnuPacket hit = new GnuPacket(sh, channel, in, push, busy, stable, tracker, in.hops);
                    serv.outputPacket(hit, true);
                } catch (Exception e) {
                    System.err.println(e);
                }
            }

            return ret;
        }

        public String toString() {
            return "QUERY";
        }

        public int getNumber() {
            return 128;
        }

        public STAT getInStat() {
            return Stats.STAT.NUMQUERYIN;
        }

        public STAT getOutStat() {
            return Stats.STAT.NUMQUERYOUT;
        }
    };

    /** */
    static GnuFunction HIT = new GnuFunction() {
        public ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException {
            ByteArrayInputStream data = new ByteArrayInputStream(in.data); // in.len

            ResultType ret = ResultType.DISCARD;

            ChannelHit hit = new ChannelHit();
            if (GnuStream.readHit(data, hit, in.hops, in.id)) {

                String flstr = "";
                if (hit.firewalled) {
                    flstr += "Push,";
                }
                if (hit.tracker) {
                    flstr += "Tracker,";
                }

                ret = ResultType.BROADCAST;
log.debug(String.format("broadcast-hit: %s", flstr));
            }

            return ret;
        }

        public String toString() {
            return "HIT";
        }

        public int getNumber() {
            return 129;
        }

        public STAT getInStat() {
            return Stats.STAT.NUMHITIN;
        }

        public STAT getOutStat() {
            return Stats.STAT.NUMHITOUT;
        }
    };

    /** */
    static GnuFunction PUSH = new GnuFunction() {
        public ResultType exec(GnuPacket in, Servent serv, GnuID routeID) throws IOException {
            ByteArrayInputStream data = new ByteArrayInputStream(in.data); // in.len
            DataInputStream dis = new DataInputStream(data);

            ResultType ret = ResultType.DISCARD;

            GnuID pid = new GnuID();
            data.read(pid.id, 0, 16);

            int index = dis.readInt();
            int ip = dis.readInt();
            int port = dis.readShort();

            InetSocketAddress h = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(ip)), port);
            String hostName = h.getHostName();

            if (serventManager.isReplyID(pid)) {
                ret = ResultType.ACCEPTED;
            } else {
log.debug(String.format("push: 0x%x to %s: ROUTE", index, hostName));
                System.arraycopy(pid.id, 0, routeID.id, 0, pid.id.length);
                ret = ResultType.ROUTE;
            }
            return ret;
        }

        public String toString() {
            return "PUSH";
        }

        public int getNumber() {
            return 64;
        }

        public STAT getInStat() {
            return Stats.STAT.NUMPUSHIN;
        }

        public STAT getOutStat() {
            return Stats.STAT.NUMPUSHOUT;
        }
    };

    /** */
    static final String GNU_PEERCONN = "PEERCAST CONNECT/0.1";
    static final String GNU_CONNECT = "GNUTELLA CONNECT/0.6";
    static final String GNU_OK = "GNUTELLA/0.6 200 OK";

    static final String PCX_PCP_CONNECT = "pcp";
    
    static final String PCX_HS_OS = "x-peercast-os";
    static final String PCX_HS_DL = "x-peercast-download";
    static final String PCX_HS_ID = "x-peercast-id";
    static final String PCX_HS_CHANNELID = "x-peercast-channelid";
    static final String PCX_HS_NETWORKID = "x-peercast-networkid";
    static final String PCX_HS_MSG = "x-peercast-msg";
    static final String PCX_HS_SUBNET = "x-peercast-subnet";
    static final String PCX_HS_FULLHIT = "x-peercast-fullhit";
    static final String PCX_HS_MINBCTTL = "x-peercast-minbcttl";
    static final String PCX_HS_MAXBCTTL = "x-peercast-maxbcttl";
    static final String PCX_HS_RELAYBC = "x-peercast-relaybc";
    static final String PCX_HS_PRIORITY = "x-peercast-priority";
    static final String PCX_HS_FLOWCTL = "x-peercast-flowctl";
    static final String PCX_HS_PCP = "x-peercast-pcp";
    static final String PCX_HS_PINGME = "x-peercast-pingme";
    static final String PCX_HS_PORT = "x-peercast-port";
    static final String PCX_HS_REMOTEIP = "x-peercast-remoteip";
    static final String PCX_HS_POS = "x-peercast-pos";
    static final String PCX_HS_SESSIONID = "x-peercast-sessionid";

    // official version number sent to relay to check for updates
    static final String PCX_OS_WIN32 = "Win32";
    static final String PCX_OS_LINUX = "Linux";
    static final String PCX_OS_MACOSX = "Apple-OSX";
    static final String PCX_OS_WINAMP2 = "Win32-WinAmp2";
    static final String PCX_OS_ACTIVEX = "Win32-ActiveX";

    static final String PCX_DL_URL = "http://www.peercast.org/download.php";

    // version number sent to other clients
    static final String PCX_OLDAGENT = "PeerCast/0.119E";
    static final String PCX_AGENT = "PeerCast/0.1211";

    static final String PCX_VERSTRING = "v0.1211";

    // version number used inside packets GUIDs
    static final int PEERCAST_PACKETID = 0x0000119E;

    static final String MIN_ROOTVER = "0.119E";
    static final String MIN_CONNECTVER = "0.119D";

    static final int MIN_PACKETVER = 0x0000119D;

    static final String ICY_OK = "ICY 200 OK";

    /** */
    static final int DEFAULT_PORT = 7144;

    /** */
    static final int MAX_DATA = 2000;

    /** */
    void makeChecksumID() {
        for (int i = 0; i < len; i++) {
            id.id[i % 16] += data[i];
        }
    }

    /** */
    GnuPacket() {
    }

    /** ping */
    GnuPacket(int ttl) {
        func = PING;
        this.ttl = ttl;
        hops = 0;
        len = 0;

        id = new GnuID();
        id.generate();
    }

    /** pong */
    GnuPacket(InetSocketAddress h, boolean ownPong, GnuPacket ping) throws IOException {
        func = PONG;
        ttl = ping.hops;
        hops = 0;
        len = 14;
        id = ping.id;

        ByteArrayOutputStream data = new ByteArrayOutputStream(); // data
        DataOutputStream dos = new DataOutputStream(data);

        dos.writeShort(h.getPort()); // port
        dos.writeInt(Peercast.byteToInt(h.getAddress().getAddress())); // ip
        if (ownPong) {
            dos.writeLong(channelMabager.numChannels()); // cnt
            dos.writeLong(serventManager.totalOutput(false)); // total
        } else {
            dos.writeLong(0); // cnt
            dos.writeLong(0); // total
        }
    }

    /** */
    void initPush(ChannelHit ch, InetSocketAddress sh) {
        // func = GNU_FUNC_PUSH;
        // ttl = ch.numHops;
        // hops = 0;
        // len = 26;
        // id.generate();
        //
        // MemoryStream data(data, len);
        //
        // // ID of Hit packet
        // data.write(ch.packetID.id, 16);
        //
        // // index of channel
        // data.writeLong(ch.index);
        //
        // data.writeLong(SWAP4(sh.ip)); // ip
        // data.writeShort(sh.port); // port
    }

    /** hit */
    GnuPacket(InetSocketAddress h, Channel ch, GnuPacket query, boolean push, boolean busy, boolean stable, boolean tracker, long maxttl) throws IOException {
        if (ch == null) {
            throw new IllegalArgumentException("ch is null");
        }

        func = HIT;
        hops = 0;
        id = new GnuID();
        id.generate();

        ttl = maxttl;

        ByteArrayOutputStream mem = new ByteArrayOutputStream(); // MAX_DATA;
        DataOutputStream dos = new DataOutputStream(mem);

        dos.writeByte(1); // num hits
        dos.writeShort(h.getPort()); // port
        dos.writeInt(Peercast.byteToInt(h.getAddress().getAddress())); // ip

        if (query != null) {
            dos.writeInt(0); // speed - route
        } else {
            dos.writeInt(1); // broadcast
        }

        dos.writeInt(ch.index); // index
        dos.writeShort(ch.getBitrate()); // bitrate
        dos.writeShort(ch.localListeners()); // num listeners

        dos.writeByte(0); // no name

        Document xml = Peercast.db.newDocument();
        Element cn = ch.info.createChannelXML();
        cn.appendChild(ch.info.createTrackXML());
        xml.appendChild(cn);
        PrettyPrinter pp = new PrettyPrinter(mem);
        pp.print(xml);

        dos.writeByte(0); // extra null

        // QHD
        dos.writeUTF("PCST"); // vendor ID
        dos.writeByte(2); // public sector length

        int f1 = 0, f2 = 0;

        f1 = 0x01 | 0x04 | 0x08 | 0x20 | 0x40; // use push | busy | stable | broadcast | tracker

        if (push) {
            f2 |= 0x01;
        }
        if (busy) {
            f2 |= 0x04;
        }
        if (stable) {
            f2 |= 0x08;
        }
        if (query == null) {
            f2 |= 0x20;
        }
        if (tracker) {
            f2 |= 0x40;
        }

        dos.writeByte(f1);
        dos.writeByte(f2);

        {
            // write private sector
//          byte[] pbuf;
            ByteArrayOutputStream pmem = new ByteArrayOutputStream(); // , sizeof(pbuf)
            DataOutputStream pdos = new DataOutputStream(pmem);
            xml = Peercast.db.newDocument();
            Element pn = serventManager.createServentXML();
            xml.appendChild(pn);
            pp = new PrettyPrinter(pmem);
            pp.print(xml);
            pdos.writeByte(0); // add null terminator
            if (pmem.size() <= 255) {
                pdos.writeChar(pmem.size());
                pdos.write(pmem.toByteArray(), 0, pmem.size());
            } else {
                pdos.writeByte(0);
            }
        }

        // queryID/not used
        if (query != null) {
            mem.write(query.id.id, 0, 16);
        } else {
            mem.write(id.id, 0, 16);
        }

        data = mem.toByteArray();
        len = data.length;

        log.debug(String.format("Created Hit packet: %d bytes", len));

        if (len >= MAX_DATA) {
            throw new IllegalArgumentException("len >= MAX_DATA");
        }

        serventManager.addReplyID(id);
    }

    /** */
    void initFind(String str, Document xml, int maxTTL) throws IOException {

        func = QUERY;
        ttl = maxTTL;
        hops = 0;
        id = new GnuID();
        id.generate();

        ByteArrayOutputStream mem = new ByteArrayOutputStream(); // data, MAX_DATA

        DataOutputStream dos = new DataOutputStream(mem);
        dos.writeShort(0); // min speed

        if (str != null) {
            int slen = str.length();
            dos.write(str.getBytes(), 0, slen + 1); // string
        } else
            dos.writeByte(0); // null string

        if (xml != null) {
            PrettyPrinter pp = new PrettyPrinter(mem);
            pp.print(xml);
        }

        data = mem.toByteArray();
        len = data.length;
    }

    int getVersion() {
        return id.getVersion();
    }

    GnuFunction func;

    long ttl;

    int hops;

    int len;

    GnuID id;

    byte[] data = new byte[MAX_DATA];
}

/** */
class GnuPacketBuffer {

    GnuPacketBuffer(int s) {
        packets = new GnuPacket[size];
        reset();
    }

    void reset() {
        readPtr = writePtr = 0;
    }

    GnuPacket curr() {
        if (numPending() != 0) {
            return packets[readPtr % size];
        } else {
            return null;
        }
    }

    void next() {
        readPtr++;
    }

    int findMinHop() {
        int min = 100;
        int n = numPending();
        for (int i = 0; i < n; i++) {
            int idx = (readPtr + i) % size;
            if (packets[idx].hops < min) {
                min = packets[idx].hops;
            }
        }
        return min;
    }

    int findMaxHop() {
        int max = 0;
        int n = numPending();
        for (int i = 0; i < n; i++) {
            int idx = (readPtr + i) % size;
            if (packets[idx].hops > max) {
                max = packets[idx].hops;
            }
        }
        return max;
    }

    int percentFull() {
        return (numPending() * 100) / size;
    }

    int sizeOfPending() {
        int tot = 0;
        int n = numPending();
        for (int i = 0; i < n; i++) {
            tot += packets[(readPtr + i) % size].len;
        }
        return tot;
    }

    int numPending() {
        return writePtr - readPtr;
    }

    boolean write(GnuPacket p) {
        if ((writePtr - readPtr) >= size) {
            return false;
        } else {
            packets[writePtr % size] = p;
            writePtr++;
            return true;
        }
    }

    int size;

    GnuPacket[] packets;

    int readPtr, writePtr;
}

/* */
