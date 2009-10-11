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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.util.Debug;
import vavi.util.Singleton;
import vavi.util.StringUtil;


/** */
class BroadcastState {
    BroadcastState() {
        chanID = new GnuID();
        chanID.clear();
        bcID = new GnuID();
        bcID.clear();
    }

    void initPacketSettings() {
        forMe = false;
        group = 0;
        numHops = 0;
        bcID.clear();
        chanID.clear();
    }

    GnuID chanID, bcID;

    int numHops = 0;

    boolean forMe = false;

    int streamPos = 0;

    int group = 0;
}

/**
 * 
 * @version 1-mar-2004
 * @author giles
 */
class PCPStream extends ChannelStream {
    private ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    private ChannelManager chanelManager = Singleton.getInstance(ChannelManager.class);

    static final int PCP_CLIENT_VERSION = 1211;

    /** */
    static final int PCP_CLIENT_MINVERSION = 1200;

    /** */
    static final ID4 PCP_CONNECT = new ID4("pcp\n");

    static final ID4 PCP_OK = new ID4("ok");

    static final ID4 PCP_HELO = new ID4("helo");

    static final ID4 PCP_HELO_AGENT = new ID4("agnt");

    static final ID4 PCP_HELO_OSTYPE = new ID4("ostp");

    static final ID4 PCP_HELO_SESSIONID = new ID4("sid");

    static final ID4 PCP_HELO_PORT = new ID4("port");

    static final ID4 PCP_HELO_PING = new ID4("ping");

    static final ID4 PCP_HELO_PONG = new ID4("pong");

    static final ID4 PCP_HELO_REMOTEIP = new ID4("rip");

    static final ID4 PCP_HELO_VERSION = new ID4("ver");

    static final ID4 PCP_OLEH = new ID4("oleh");

    static final ID4 PCP_MODE = new ID4("mode");

    static final ID4 PCP_MODE_GNUT06 = new ID4("gn06");

    static final ID4 PCP_ROOT = new ID4("root");

    static final ID4 PCP_ROOT_UPDINT = new ID4("uint");

    static final ID4 PCP_ROOT_CHECKVER = new ID4("chkv");

    static final ID4 PCP_ROOT_URL = new ID4("url");

    static final ID4 PCP_ROOT_UPDATE = new ID4("upd");

    static final ID4 PCP_ROOT_NEXT = new ID4("next");

    static final ID4 PCP_OS_LINUX = new ID4("lnux");

    static final ID4 PCP_OS_WINDOWS = new ID4("w32");

    static final ID4 PCP_OS_OSX = new ID4("osx");

    static final ID4 PCP_OS_WINAMP = new ID4("wamp");

    static final ID4 PCP_OS_ZAURUS = new ID4("zaur");

    static final ID4 PCP_GET = new ID4("get");

    static final ID4 PCP_GET_ID = new ID4("id");

    static final ID4 PCP_GET_NAME = new ID4("name");

    static final ID4 PCP_HOST = new ID4("host");

    static final ID4 PCP_HOST_ID = new ID4("id");

    static final ID4 PCP_HOST_IP = new ID4("ip");

    static final ID4 PCP_HOST_PORT = new ID4("port");

    static final ID4 PCP_HOST_NUML = new ID4("numl");

    static final ID4 PCP_HOST_NUMR = new ID4("numr");
    @Deprecated
    static final ID4 PCP_HOST_AGENT = new ID4("agnt");
    @Deprecated
    static final ID4 PCP_HOST_SKIP = new ID4("skip");

    static final ID4 PCP_HOST_UPTIME = new ID4("uptm");

    static final ID4 PCP_HOST_TRACKER = new ID4("trkr");

    static final ID4 PCP_HOST_CHANID = new ID4("cid");

    static final ID4 PCP_HOST_VERSION = new ID4("ver");
    /** @deprecated use flg1 */
    @Deprecated()
    static final ID4 PCP_HOST_BUSY = new ID4("busy");
    /** @deprecated use flg1 */
    @Deprecated
    static final ID4 PCP_HOST_PUSH = new ID4("push");
    /** @deprecated use flg1 */
    @Deprecated
    static final ID4 PCP_HOST_RECV = new ID4("recv");

    static final ID4 PCP_HOST_FLAGS1 = new ID4("flg1");

    static final ID4 PCP_QUIT = new ID4("quit");

    static final ID4 PCP_CHAN = new ID4("chan");

    static final ID4 PCP_CHAN_ID = new ID4("id");

    static final ID4 PCP_CHAN_KEY = new ID4("key");

    static final ID4 PCP_CHAN_PKT = new ID4("pkt");

    static final ID4 PCP_CHAN_PKT_TYPE = new ID4("type");

    static final ID4 PCP_CHAN_PKT_POS = new ID4("pos");

    static final ID4 PCP_CHAN_PKT_HEAD = new ID4("head");

    static final ID4 PCP_CHAN_PKT_DATA = new ID4("data");

    static final ID4 PCP_CHAN_PKT_META = new ID4("meta");

    static final ID4 PCP_CHAN_INFO = new ID4("info");

    static final ID4 PCP_CHAN_INFO_TYPE = new ID4("type");

    static final ID4 PCP_CHAN_INFO_BITRATE = new ID4("bitr");

    static final ID4 PCP_CHAN_INFO_GENRE = new ID4("gnre");

    static final ID4 PCP_CHAN_INFO_NAME = new ID4("name");

    static final ID4 PCP_CHAN_INFO_URL = new ID4("url");

    static final ID4 PCP_CHAN_INFO_DESC = new ID4("desc");

    static final ID4 PCP_CHAN_INFO_COMMENT = new ID4("cmnt");

    static final ID4 PCP_CHAN_TRACK = new ID4("trck");

    static final ID4 PCP_CHAN_TRACK_TITLE = new ID4("titl");

    static final ID4 PCP_CHAN_TRACK_CREATOR = new ID4("crea");

    static final ID4 PCP_CHAN_TRACK_URL = new ID4("url");

    static final ID4 PCP_CHAN_TRACK_ALBUM = new ID4("albm");

    static final ID4 PCP_MESG = new ID4("mesg");

    // ascii/sjis to be depreciated.. utf8/unicode is the only supported format
    static final ID4 PCP_MESG_ASCII = new ID4("asci");

    // from now.
    static final ID4 PCP_MESG_SJIS = new ID4("sjis");

    static final ID4 PCP_BCST = new ID4("bcst");

    static final ID4 PCP_BCST_TTL = new ID4("ttl");

    static final ID4 PCP_BCST_HOPS = new ID4("hops");

    static final ID4 PCP_BCST_FROM = new ID4("from");

    static final ID4 PCP_BCST_DEST = new ID4("dest");

    static final ID4 PCP_BCST_GROUP = new ID4("grp");

    static final ID4 PCP_BCST_CHANID = new ID4("cid");

    static final ID4 PCP_BCST_VERSION = new ID4("vers");

    static final ID4 PCP_PUSH = new ID4("push");

    static final ID4 PCP_PUSH_IP = new ID4("ip");

    static final ID4 PCP_PUSH_PORT = new ID4("port");

    static final ID4 PCP_PUSH_CHANID = new ID4("cid");

    static final ID4 PCP_SPKT = new ID4("spkt");

    static final ID4 PCP_ATOM = new ID4("atom");

    static final ID4 PCP_SESSIONID = new ID4("sid");

    static final int PCP_BCST_GROUP_ALL = (char) 0xff;

    static final int PCP_BCST_GROUP_ROOT = 1;

    static final int PCP_BCST_GROUP_TRACKERS = 2;

    static final int PCP_BCST_GROUP_RELAYS = 4;

    static final int PCP_ERROR_QUIT = 1000;

    static final int PCP_ERROR_BCST = 2000;

    static final int PCP_ERROR_READ = 3000;

    static final int PCP_ERROR_WRITE = 4000;

    static final int PCP_ERROR_GENERAL = 5000;

    static final int PCP_ERROR_SKIP = 1;

    static final int PCP_ERROR_ALREADYCONNECTED = 2;

    static final int PCP_ERROR_UNAVAILABLE = 3;

    static final int PCP_ERROR_LOOPBACK = 4;

    static final int PCP_ERROR_NOTIDENTIFIED = 5;

    static final int PCP_ERROR_BADRESPONSE = 6;

    static final int PCP_ERROR_BADAGENT = 7;

    static final int PCP_ERROR_OFFAIR = 8;

    static final int PCP_ERROR_SHUTDOWN = 9;

    static final int PCP_ERROR_NOROOT = 10;

    static final int PCP_HOST_FLAGS1_TRACKER = 0x01;

    static final int PCP_HOST_FLAGS1_RELAY = 0x02;

    static final int PCP_HOST_FLAGS1_DIRECT = 0x04;

    static final int PCP_HOST_FLAGS1_PUSH = 0x08;

    static final int PCP_HOST_FLAGS1_RECV = 0x10;

    static final int PCP_HOST_FLAGS1_CIN = 0x20;

    static Log log = LogFactory.getLog(PCPStream.class);

    PCPStream(GnuID rid) {
        routeList = new ArrayList<GnuID>(1000);
        init(rid);
    }

    void kill() {
        try {
            inData.wait();
            outData.wait();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /** */
    void init(GnuID rid) {
        remoteID = rid;
        routeList.clear();

        lastPacketTime = 0;
        nextRootPacket = 0; // 0 seconds (never)

        inData = new ChannelPacketBuffer();
        inData.accept = ChannelPacket.Type.PCP.value;

        outData = new ChannelPacketBuffer();
        outData.accept = ChannelPacket.Type.PCP.value;
    }

    /** */
    static void readVersion(InputStream in) throws IOException {
Debug.println("available: " + in.available());
        DataInputStream dis = new DataInputStream(in);
        int len = dis.readInt();

        if (len != 4) {
            throw new IOException("Invalid PCP");
        }

        int ver = dis.readInt();

        log.debug(String.format("PCP ver: %d", ver));
    }

    /** */
    int readHeader(InputStream is, Channel channel) throws IOException {
        // AtomStream atom(is);

        // if (is.readInt() != PCP_CONNECT) {
        //     throw IOException("Not PCP");
        // }

        // readVersion(is);
        return 0;
    }

    /** */
    boolean sendPacket(ChannelPacket pack, GnuID destID) {
        if (destID.isSet()) {
            if (!destID.equals(remoteID)) {
                if (!routeList.contains(destID)) {
                    return false;
                }
            }
        }

        return outData.writePacket(pack, false);
    }

    /** send outward packets */
    void flush(OutputStream in) throws IOException {
        while (outData.numPending()) {
            ChannelPacket pack = outData.readPacket();
            pack.writeRaw(in);
        }
    }

    /** */
    int readPacket(InputStream is, Channel channel) throws IOException {
        BroadcastState bcs = new BroadcastState();
        return readPacket(is, channel.sock.getOutputStream(), bcs);
    }

    /** */
    int readPacket(InputStream is, OutputStream os, BroadcastState bcs) {
        int error = PCP_ERROR_GENERAL;
        try {
            AtomInputStream atomIn = new AtomInputStream(is);

            ChannelPacket pack = null;
            ByteArrayOutputStream mem = new ByteArrayOutputStream(); // , sizeof(pack.data)
            AtomOutputStream patomOut = new AtomOutputStream(mem);
            AtomInputStream patomIn = null;

            // send outward packets
            error = PCP_ERROR_WRITE;
            if (outData.numPending()) {
                pack = outData.readPacket();
                pack.writeRaw(os);
                os.flush();
            }
            error = PCP_ERROR_GENERAL;

            if (outData.willSkip()) {
                error = PCP_ERROR_WRITE | PCP_ERROR_SKIP;
                throw new IOException("Send too slow");
            }

            error = PCP_ERROR_READ;
            // poll for new downward packet
            if (is.available() > 0) {
                ID4 id = atomIn.read();
                mem.reset();
                patomOut.writeAtoms(id, atomIn, atomIn.childCount, atomIn.dataLength);
                pack = new ChannelPacket();
                pack.type = ChannelPacket.Type.PCP;
                pack.data = mem.toByteArray();

                inData.writePacket(pack, false);
            }
            error = PCP_ERROR_GENERAL;

            // process downward packets
            if (inData.numPending()) {
                pack = inData.readPacket();

                mem.reset();
                patomIn = new AtomInputStream(new ByteArrayInputStream(pack.data));

                ID4 id = patomIn.read();
                error = procAtom(patomIn, patomOut, id, patomIn.childCount, patomIn.dataLength, bcs);

                if (error != 0) {
                    throw new IOException("PCP exception");
                }
            }

            error = 0;

        } catch (IOException e) {
if (error != 1003) { // PCP EOS
 Debug.printStackTrace(e);
}
            log.error(String.format("PCP readPacket: %s (%d)", e.getMessage(), error));
        }

        return error;
    }

    /** */
    int readEnd(InputStream is, Channel channel) {
        return 0;
    }

    /** */
    private void readPushAtoms(AtomInputStream atom, int numc, BroadcastState bcs) throws IOException {
        InetSocketAddress host = null;
        InetAddress address = null;
        GnuID chanID = new GnuID();

        chanID.clear();

        for (int i = 0; i < numc; i++) {
            ID4 id = atom.read();
            int c = atom.childCount;
            int d = atom.dataLength;

            if (id.equals(PCP_PUSH_IP)) {
                address = InetAddress.getByAddress(Peercast.intToByte(atom.readInt()));
            } else if (id.equals(PCP_PUSH_PORT)) {
                host = new InetSocketAddress(address, atom.readShort());
            } else if (id.equals(PCP_PUSH_CHANID)) {
                atom.readBytes(chanID.id, 16);
            } else {
                log.debug(String.format("PCP skip: %s,%d,%d", id.toString(), c, d));
                atom.skip(c, d);
            }
        }

        if (bcs.forMe) {
            String ipstr = host.toString();

            Servent servent = null;

            if (chanID.isSet()) {
                Channel ch = chanelManager.findChannelByID(chanID);
                if (ch != null) {
                    if (ch.isBroadcasting() || !ch.isFull() && !serventManager.relaysFull() && ch.info.id.equals(chanID)) {
                        servent = serventManager.allocServent();
                    }
                }
            } else {
                servent = serventManager.allocServent();
            }

            if (servent != null) {
                log.debug(String.format("GIVing to %s", ipstr));
                servent.initGIV(host, chanID);
            }
        }

    }

    /** */
    private void readRootAtoms(AtomInputStream atomIn, int childCount, BroadcastState bcs) throws IOException {
        String url = null;

        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();
            if (id.equals(PCP_ROOT_UPDINT)) {
                int si = atomIn.readInt();

                chanelManager.setUpdateInterval(si);
                log.debug(String.format("PCP got new host update interval: %ds", si));
            } else if (id.equals(PCP_ROOT_URL)) {
                url = "http://www.peercast.org/";
                String loc = null;
                loc = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
                url += loc;

            } else if (id.equals(PCP_ROOT_CHECKVER)) {
                int newVer = atomIn.readInt();
                if (newVer > PCP_CLIENT_VERSION) {
                    serventManager.downloadURL = url;
                    Peercast.getInstance().notifyMessage(ServentManager.NotifyType.UPGRADE, "There is a new version available, please click here to upgrade your client.");
                }
                log.debug(String.format("PCP got version check: %d / %d", newVer, PCP_CLIENT_VERSION));

            } else if (id.equals(PCP_ROOT_NEXT)) {
                int time = atomIn.readInt();

                if (time != 0) {
                    long ctime = System.currentTimeMillis();
                    nextRootPacket = ctime + time;
                    log.debug(String.format("PCP expecting next root packet in %ds", time));
                } else {
                    nextRootPacket = 0;
                }

            } else if (id.equals(PCP_ROOT_UPDATE)) {
                atomIn.skip(atomIn.childCount, atomIn.dataLength);

                chanelManager.broadcastTrackerUpdate(remoteID, true);

            } else if (id.equals(PCP_MESG_ASCII) || id.equals(PCP_MESG)) { // PCP_MESG_ASCII to be depreciated
                String newMsg = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
                if (!newMsg.equals(serventManager.rootMsg)) {
                    serventManager.rootMsg = newMsg;
                    log.debug(String.format("PCP got new root mesg: %s", serventManager.rootMsg));
                    Peercast.getInstance().notifyMessage(ServentManager.NotifyType.PEERCAST, serventManager.rootMsg);
                }
            } else {
                log.debug(String.format("PCP skip: %s,%d,%d", id.toString(), atomIn.childCount, atomIn.dataLength));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }
    }

    /** */
    private void readPktAtoms(Channel ch, AtomInputStream atomIn, int childCount, BroadcastState bcs) throws IOException {
        ChannelPacket pack = new ChannelPacket();
        ID4 type;

        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();
            if (id.equals(PCP_CHAN_PKT_TYPE)) {
                type = atomIn.readID4();

                if (type.equals(PCP_CHAN_PKT_HEAD)) {
                    pack.type = ChannelPacket.Type.HEAD;
                } else if (type.equals(PCP_CHAN_PKT_DATA)) {
                    pack.type = ChannelPacket.Type.DATA;
                } else {
                    pack.type = ChannelPacket.Type.UNKNOWN;
                }

            } else if (id.equals(PCP_CHAN_PKT_POS)) {
                pack.pos = atomIn.readInt();

            } else if (id.equals(PCP_CHAN_PKT_DATA)) {
if (pack.data == null) { // TODO check initialize
 pack.data = new byte[atomIn.dataLength];
}
                atomIn.readBytes(pack.data, pack.data.length);
            } else {
                log.debug(String.format("PCP skip: %s,%d,%d", id.toString(), atomIn.childCount, atomIn.dataLength));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }

        if (ch != null) {

            int diff = pack.pos - ch.streamPos;
            if (diff != 0) {
                log.debug(String.format("PCP skipping %s%d (%d -> %d)", (diff > 0) ? "+" : "", diff, ch.streamPos, pack.pos));
            }

            if (pack.type.equals(ChannelPacket.Type.HEAD)) {
                log.debug(String.format("New head packet at %d", pack.pos));

                // check for stream restart
                if (pack.pos == 0) {
                    log.debug("PCP resetting stream");
                    ch.streamIndex++;
                    ch.rawData.init();
                }

                ch.headPack = pack;

                ch.rawData.writePacket(pack, true);
                ch.streamPos = pack.pos + pack.data.length;

            } else if (pack.type.equals(ChannelPacket.Type.DATA)) {
                ch.rawData.writePacket(pack, true);
                ch.streamPos = pack.pos + pack.data.length;
            }
        }

        // update this parent packet stream position
        if ((pack.pos != 0) && (bcs.streamPos == 0 || (pack.pos < bcs.streamPos))) {
            bcs.streamPos = pack.pos;
        }
    }

    /** */
    private void readHostAtoms(AtomInputStream atomIn, int childCount, BroadcastState bcs) throws IOException {
        ChannelHit hit = new ChannelHit();
        GnuID chanID = bcs.chanID; // use default

        boolean busy = false;

        int ipNum = 0;

        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();
            if (id.equals(PCP_HOST_IP)) {
                int ip = atomIn.readInt();
                hit.remoteAddresses[ipNum] = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(ip)), hit.remoteAddresses[ipNum] == null ? 0 : hit.remoteAddresses[ipNum].getPort());
            } else if (id.equals(PCP_HOST_PORT)) {
                int port = atomIn.readShort();
                hit.remoteAddresses[ipNum] = new InetSocketAddress(hit.remoteAddresses[ipNum].getAddress(), port);
                ipNum++;

                if (ipNum > 1) {
                    ipNum = 1;
                }
            } else if (id.equals(PCP_HOST_BUSY)) { // depreciated
                busy = atomIn.readByte() != 0;

            } else if (id.equals(PCP_HOST_PUSH)) { // depreciated
                hit.firewalled = atomIn.readByte() != 0;
            } else if (id.equals(PCP_HOST_NUML)) {
                hit.numListeners = atomIn.readInt();
            } else if (id.equals(PCP_HOST_NUMR)) {
                hit.numRelays = atomIn.readInt();
            } else if (id.equals(PCP_HOST_AGENT)) { // depreciated
                hit.agentStr = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCP_HOST_UPTIME)) {
                hit.upTime = atomIn.readInt();
            } else if (id.equals(PCP_HOST_VERSION)) {
                hit.version = atomIn.readInt();
            } else if (id.equals(PCP_HOST_RECV)) { // depreciated
                hit.receiver = atomIn.readByte() != 0;
            } else if (id.equals(PCP_HOST_FLAGS1)) {
                int fl1 = atomIn.readByte();

                hit.receiver = (fl1 & PCP_HOST_FLAGS1_RECV) != 0;
                hit.relay = (fl1 & PCP_HOST_FLAGS1_RELAY) != 0;
                hit.direct = (fl1 & PCP_HOST_FLAGS1_DIRECT) != 0;
                hit.cin = (fl1 & PCP_HOST_FLAGS1_CIN) != 0;
                hit.tracker = (fl1 & PCP_HOST_FLAGS1_TRACKER) != 0;
                hit.firewalled = (fl1 & PCP_HOST_FLAGS1_PUSH) != 0;

            } else if (id.equals(PCP_HOST_ID)) {
                atomIn.readBytes(hit.sessionID.id, 16);
            } else if (id.equals(PCP_HOST_CHANID)) {
                atomIn.readBytes(chanID.id, 16);
            } else if (id.equals(PCP_HOST_TRACKER)) { // depreciated
                hit.tracker = atomIn.readByte() != 0;
            } else {
                log.debug(String.format("PCP skip: %s,%d,%d", id.toString(), atomIn.childCount, atomIn.dataLength));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }

        // depreciated
        if (busy) {
            if (hit.tracker) {
                hit.cin = false;
            } else {
                hit.relay = false;
            }
        }

        hit.setAddress(hit.remoteAddresses[0]);
        hit.channelID = chanID;

        hit.numHops = bcs.numHops;

        if (hit.receiver) {
            chanelManager.addHit(hit);
        } else {
            chanelManager.delHit(hit);
        }
    }

    /** */
    private void readChanAtoms(AtomInputStream atomIn, int childCount, BroadcastState bcs) throws IOException {
        ChannelInfo newInfo = new ChannelInfo(); // TODO –³‘Ê‚È‹C‚ª...

        Channel ch = chanelManager.findChannelByID(bcs.chanID);
        ChannelHitList chl = chanelManager.findHitListByID(bcs.chanID);

        if (ch != null) {
            newInfo = ch.info;
        } else if (chl != null) {
            newInfo = chl.info;
        }
if (newInfo == null) { // TODO @@@ newInfo is null, cause bcs.chanId is cleared
 new Exception("newInfo: " + newInfo).printStackTrace(System.err);
}
        for (int i = 0; i < childCount; i++) {

            ID4 id = atomIn.read();
            if (id.equals(PCP_CHAN_PKT) && ch != null) {
                readPktAtoms(ch, atomIn, atomIn.childCount, bcs);
            } else if (id.equals(PCP_CHAN_INFO)) {
                newInfo.readInfoAtoms(atomIn, atomIn.childCount);

            } else if (id.equals(PCP_CHAN_TRACK)) {
                newInfo.readTrackAtoms(atomIn, atomIn.childCount);

            } else if (id.equals(PCP_CHAN_KEY)) {
                atomIn.readBytes(newInfo.bcID.id, 16);

            } else if (id.equals(PCP_CHAN_ID)) {
                atomIn.readBytes(newInfo.id.id, 16);

                ch = chanelManager.findChannelByID(newInfo.id);
                chl = chanelManager.findHitListByID(newInfo.id);

            } else {
                log.debug(String.format("PCP skip: %s,%d,%d", id.toString(), atomIn.childCount, atomIn.dataLength));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }

        if (chl == null) {
            chl = chanelManager.addHitList(newInfo);
        }

        if (chl != null) {
            chl.info.update(newInfo);
        }

        if (ch != null && !ch.isBroadcasting()) {
            ch.updateInfo(newInfo);
        }
    }

    /** */
    private int readBroadcastAtoms(AtomInputStream atomIn, int childCount, BroadcastState bcs) throws IOException {

        ChannelPacket pack = new ChannelPacket();
        int ttl = 1;
        int ver = 0;
        GnuID fromID = new GnuID(), destID = new GnuID();

        bcs.initPacketSettings();

        ByteArrayOutputStream pmem = new ByteArrayOutputStream();
        AtomOutputStream patomOut = new AtomOutputStream(pmem);
        AtomInputStream patomIn = null;

        patomOut.writeParent(PCP_BCST, childCount);

        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();

            if (id.equals(PCP_BCST_TTL)) {
                ttl = atomIn.readByte() - 1;
                patomOut.writeByte(id, (byte) ttl);

            } else if (id.equals(PCP_BCST_HOPS)) {
                bcs.numHops = atomIn.readByte() + 1;
                patomOut.writeByte(id, (byte) bcs.numHops);

            } else if (id.equals(PCP_BCST_FROM)) {
                atomIn.readBytes(fromID.id, 16);
                patomOut.writeBytes(id, fromID.id, 16);

                routeList.add(fromID);
            } else if (id.equals(PCP_BCST_GROUP)) {
                bcs.group = atomIn.readByte();
                patomOut.writeByte(id, (byte) bcs.group);
            } else if (id.equals(PCP_BCST_DEST)) {
                atomIn.readBytes(destID.id, 16);
                patomOut.writeBytes(id, destID.id, 16);
                bcs.forMe = destID.equals(serventManager.sessionID);

Debug.println("idstr1: " + destID + ", idstr2: " + serventManager.sessionID);

            } else if (id.equals(PCP_BCST_CHANID)) {
                atomIn.readBytes(bcs.chanID.id, 16);
                patomOut.writeBytes(id, bcs.chanID.id, 16);
            } else if (id.equals(PCP_BCST_VERSION)) {
                ver = atomIn.readInt();
                patomOut.writeInt(id, ver);
            } else {
Debug.println("*** HERE");
                // copy and process atoms
                ByteArrayOutputStream pmem2 = new ByteArrayOutputStream();
                AtomOutputStream patomOut2 = new AtomOutputStream(pmem2);
                patomOut2.writeAtoms(id, atomIn, atomIn.childCount, atomIn.dataLength);
                pmem.write(pmem2.toByteArray());
                patomIn = new AtomInputStream(new ByteArrayInputStream(pmem2.toByteArray()));
                readAtom(patomIn, patomOut, bcs);
            }
        }

        pack.data = pmem.toByteArray();

        String fromStr = null;
        if (fromID.isSet()) {
            fromStr = fromID.toString();
        }
        String destStr = null;
        if (destID.isSet()) {
            destStr = destID.toString();
        }

log.debug(String.format("PCP bcst: group=%d, hops=%d, ver=%d, from=%s, dest=%s", bcs.group, bcs.numHops, ver, fromStr, destStr));

        if (fromID.isSet()) {
            if (fromID.equals(serventManager.sessionID)) {
                log.error("BCST loopback");
                return PCP_ERROR_BCST + PCP_ERROR_LOOPBACK;
            }
        }

        // broadcast back out if ttl > 0
        if (ttl > 0 && !bcs.forMe) {
            pack.type = ChannelPacket.Type.PCP;

            if ((bcs.group & (PCP_BCST_GROUP_ROOT | PCP_BCST_GROUP_TRACKERS | PCP_BCST_GROUP_RELAYS)) != 0) {
                chanelManager.broadcastPacketUp(pack, bcs.chanID, remoteID, destID);
            }

            if ((bcs.group & (PCP_BCST_GROUP_ROOT | PCP_BCST_GROUP_TRACKERS | PCP_BCST_GROUP_RELAYS)) != 0) {
                serventManager.broadcastPacket(pack, bcs.chanID, remoteID, destID, Servent.Type.COUT);
            }

            if ((bcs.group & (PCP_BCST_GROUP_RELAYS | PCP_BCST_GROUP_TRACKERS)) != 0) {
                serventManager.broadcastPacket(pack, bcs.chanID, remoteID, destID, Servent.Type.CIN);
            }

            if ((bcs.group & (PCP_BCST_GROUP_RELAYS)) != 0) {
                serventManager.broadcastPacket(pack, bcs.chanID, remoteID, destID, Servent.Type.RELAY);
            }
        }
        return 0;
    }

    /**
     * @return  
     */
    private int procAtom(AtomInputStream atomIn, AtomOutputStream atomOut, ID4 id, int childCount, int dataLength, BroadcastState bcs) throws IOException {
        int result = 0;

        if (id.equals(PCP_CHAN)) {
            readChanAtoms(atomIn, childCount, bcs);
        } else if (id.equals(PCP_ROOT)) {
            readRootAtoms(atomIn, childCount, bcs);

        } else if (id.equals(PCP_HOST)) {
            readHostAtoms(atomIn, childCount, bcs);

        } else if (id.equals(PCP_MESG_ASCII) || id.equals(PCP_MESG)) { // PCP_MESG_ASCII to be depreciated
            String msg = atomIn.readString(dataLength, dataLength);
            log.debug(String.format("PCP got text: %s", msg));
        } else if (id.equals(PCP_BCST)) {
            result = readBroadcastAtoms(atomIn, childCount, bcs);
        } else if (id.equals(PCP_HELO)) {
            atomIn.skip(childCount, dataLength);
            atomOut.writeParent(PCP_OLEH, 1);
            atomOut.writeBytes(PCP_HELO_SESSIONID, serventManager.sessionID.id, 16);
Debug.println("*** MEM WRITE: " + atomOut);
        } else if (id.equals(PCP_PUSH)) {

            readPushAtoms(atomIn, childCount, bcs);
        } else if (id.equals(PCP_OK)) {
            atomIn.readInt();

        } else if (id.equals(PCP_QUIT)) {
            result = atomIn.readInt();
            if (result == 0) {
                result = PCP_ERROR_QUIT;
            }

        } else if (id.equals(PCP_ATOM)) {
            for (int i = 0; i < childCount; i++) {
                ID4 childId = atomIn.read();
                int childResult = procAtom(atomIn, atomOut, childId, atomIn.childCount, atomIn.dataLength, bcs);
                if (childResult != 0) {
                    result = childResult;
                }
            }

        } else {
new Exception("*** DUMMY ***").printStackTrace(System.err);
            log.debug(String.format("PCP skip: %s: ", id.toString()) + StringUtil.getDump(id.getData()));
            atomIn.skip(childCount, dataLength);
        }

        return result;
    }

    /** */
    private int readAtom(AtomInputStream atom, AtomOutputStream atomOut, BroadcastState bcs) throws IOException {
        ID4 id = atom.read();

        return procAtom(atom, atomOut, id, atom.childCount, atom.dataLength, bcs);
    }

    private ChannelPacketBuffer inData, outData;

    private int lastPacketTime;

    long nextRootPacket;

    private List<GnuID> routeList;

    private GnuID remoteID;
}

/* */
