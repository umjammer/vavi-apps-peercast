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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.util.StringTokenizer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.w3c.dom.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.net.http.HttpContext;
import vavi.net.http.HttpProtocol;
import vavi.net.http.HttpUtil;
import vavi.util.Debug;
import vavi.util.Singleton;


/**
 * Channel.
 * 
 * @version 4-apr-2002
 * @author giles
 */
class Channel {

    /** */
    private static final Log log = LogFactory.getLog(Channel.class);

    /** */
    private final ServentManager serverManager = Singleton.getInstance(ServentManager.class);

    /** */
    private final ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

    /** */
    enum Status {
        /** */
        NONE,
        /** */
        WAIT,
        /** */
        CONNECTING,
        /** */
        REQUESTING,
        /** */
        CLOSING,
        /** */
        RECEIVING,
        /** */
        BROADCASTING,
        /** */
        ABORT,
        /** */
        SEARCHING,
        /** */
        NOHOSTS,
        /** */
        IDLE,
        /** */
        ERROR,
        /** */
        NOTFOUND
    }

    /** */
    enum Type {
        /** */
        NONE,
        /** */
        ALLOCATED,
        /** */
        BROADCAST,
        /** */
        RELAY
    }

    /** */
    enum SourceType {
        /** */
        NONE,
        /** */
        PEERCAST,
        /** */
        SHOUTCAST,
        /** */
        ICECAST,
        /** */
        URL
    }

    /** */
    boolean checkBump() {
        if (!isBroadcasting() && !sourceHost.tracker) {
            if (rawData.lastWriteTime != 0 && ((System.currentTimeMillis() - rawData.lastWriteTime) > 30 * 1000)) {
                log.error(String.format("Ch.%d Auto bumped", index));
                bump = true;
            }
        }

        if (bump) {
            bump = false;
            return true;
        } else {
            return false;
        }
    }

    /** */
    int readStream(InputStream is, ChannelStream source) throws IOException {
        int error = 0;

        info.numSkips = 0;

        source.readHeader(is, this);

        Peercast.getInstance().channelStart(info);

        rawData.lastWriteTime = 0;

        boolean wasBroadcasting = false;

        try {
            while (!streaming.isCancelled() && !Peercast.getInstance().isQuitting) {
                if (checkIdle()) {
                    log.debug(String.format("Ch.%d idle", index));
                    break;
                }

                if (checkBump()) {
                    log.debug(String.format("Ch.%d bumped", index));
                    error = -1;
                    break;
                }

//new Exception("***DUMMY***: " + is.available()).printStackTrace();
                if (is.available() <= 0) {
                    log.debug(String.format("Ch.%d eof", index));
                    break;
                }

                if (is.available() > 0) {
                    error = source.readPacket(is, this);

                    if (error != 0) {
                        break;
                    }

                    if (rawData.writePos > 0) {
                        if (isBroadcasting()) {
                            if ((System.currentTimeMillis() - lastTrackerUpdate) >= channelManager.hostUpdateInterval) {
                                GnuID noID = new GnuID();
                                noID.clear();
                                broadcastTrackerUpdate(noID, false);
                            }
                            wasBroadcasting = true;

                        } else {
                            setStatus(Status.RECEIVING);
                        }
                        source.updateStatus(this);
                    }
                }

                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }
        } catch (IOException e) {
            log.error(String.format("readStream: %s", e.getMessage()));
            error = -1;
        }

        setStatus(Status.CLOSING);

        if (wasBroadcasting) {
            GnuID noID = new GnuID();
            noID.clear();
            broadcastTrackerUpdate(noID, true);
        }

        Peercast.getInstance().channelStop(info);

        source.readEnd(is, this);

        return error;
    }

    /** */
    boolean writeVariable(OutputStream out, final String var, int index) throws IOException {
        String buf = null;

        if (var.equals("name")) {
            buf = info.name;

        } else if (var.equals("bitrate")) {
            buf = String.format("%d", info.bitrate);

        } else if (var.equals("srcrate")) {
            if (sourceData != null) {
                int tot = sourceData.getSourceRate();
                buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(tot));
            } else {
                buf = "0";
            }
        } else if (var.equals("genre")) {
            buf = info.genre;
        } else if (var.equals("desc")) {
            buf = info.desc;
        } else if (var.equals("comment")) {
            buf = info.comment;
        } else if (var.equals("uptime")) {
            buf = Peercast.getFromStopwatch((int) ((System.currentTimeMillis() - info.lastPlayStart) / 1000));
        } else if (var.equals("type")) {
            buf = String.format("%s", info.contentType.toString());
        } else if (var.equals("ext")) {
            buf = String.format("%s", info.contentType.toString());

        } else if (var.equals("localRelays")) {
            buf = String.format("%d", localRelays());
        } else if (var.equals("localListeners")) {
            buf = String.format("%d", localListeners());

        } else if (var.equals("totalRelays")) {
            buf = String.format("%d", totalRelays());
        } else if (var.equals("totalListeners")) {
            buf = String.format("%d", totalListeners());

        } else if (var.equals("status")) {
            buf = status.toString();
        } else if (var.equals("keep")) {
            buf = String.format("%s", stayConnected ? "Yes" : "No");
        } else if (var.equals("id")) {
            buf = info.id.toString();
        } else if (var.startsWith("track.")) {

            if (var.equals("track.title")) {
                buf = info.track.title;
            } else if (var.equals("track.artist")) {
                buf = info.track.artist;
            } else if (var.equals("track.album")) {
                buf = info.track.album;
            } else if (var.equals("track.genre")) {
                buf = info.track.genre;
            } else if (var.equals("track.contactURL")) {
                buf = info.track.contact;
            }

        } else if (var.equals("contactURL")) {
            buf = String.format("%s", info.url);
        } else if (var.equals("streamPos")) {
            buf = String.format("%d", streamPos);
        } else if (var.equals("sourceType")) {
            buf = status.toString();
        } else if (var.equals("sourceProtocol")) {
            buf = info.srcProtocol.name();
        } else if (var.equals("sourceURL")) {
            if (sourceURL.length() ==0) {
                buf = sourceHost.getAddress().toString();
            } else {
                buf = sourceURL;
            }
        } else if (var.equals("headPos")) {
            buf = String.format("%d", headPack.pos);
        } else if (var.equals("headLen")) {
            buf = String.format("%d", headPack.data.length);
        } else if (var.equals("numHits")) {
            ChannelHitList chl = channelManager.findHitListByID(info.id);
            int numHits = 0;
            if (chl != null) {
                numHits = chl.numHits();
            }
            buf = String.format("%d", numHits);
        } else {
            return false;
        }

        out.write(buf.getBytes()); // TODO encoding
        return true;
    }

    /** */
    String getStreamPath() {
        return String.format("/stream/%s%s", getIDString(), info.contentType.name());
    }

    /** */
    void resetPlayTime() {
        info.lastPlayStart = System.currentTimeMillis();
    }

    /** */
    void setStatus(Status status) {
        if (status != this.status) {
            boolean wasPlaying = isPlaying();

            this.status = status;

            if (isPlaying()) {
                info.status = ChannelInfo.Status.PLAY;
                resetPlayTime();
            } else {
                if (wasPlaying) {
                    info.lastPlayEnd = System.currentTimeMillis();
                }
                info.status = ChannelInfo.Status.UNKNOWN;
            }

            if (isBroadcasting()) {
                ChannelHitList chl = channelManager.findHitListByID(info.id);
                if (chl == null) {
                    channelManager.addHitList(info);
                }
            }

            Peercast.getInstance().channelUpdate(info);
        }
    }

    /**
     * Initialise the channel to its default settings of unallocated and reset.
     */
    Channel() {
        rawData.accept = ChannelPacket.Type.HEAD.value | ChannelPacket.Type.DATA.value;
    }

    /** */
    void newPacket(ChannelPacket packet) {
        if (packet.type != ChannelPacket.Type.PCP) {
            rawData.writePacket(packet, true);
        }
    }

    /** */
    boolean checkIdle() {
//Debug.println(String.format("idle: %b, uptime: %d, prefetchtime: %d, listeners: %d, stay: %b, status: %s", info.getUptime() > channelManager.prefetchTime && localListeners() == 0 && !stayConnected && !status.equals(Status.BROADCASTING), info.getUptime(), channelManager.prefetchTime, localListeners(), stayConnected, status));
        return info.getUptime() > channelManager.prefetchTime && localListeners() == 0 && !stayConnected && !status.equals(Status.BROADCASTING);
    }

    /** */
    boolean isFull() {
        return channelManager.maxRelaysPerChannel != 0 ? localRelays() >= channelManager.maxRelaysPerChannel : false;
    }

    /** */
    int localRelays() {
        return serverManager.numStreams(info.id, Servent.Type.RELAY, true);
    }

    /** */
    int localListeners() {
        return serverManager.numStreams(info.id, Servent.Type.DIRECT, true);
    }

    /** */
    int totalRelays() {
        int count = 0;
        ChannelHitList chl = channelManager.findHitListByID(info.id);
        if (chl != null) {
            count += chl.numHits();
        }
        return count;
    }

    /** */
    int totalListeners() {
        int total = localListeners();
        ChannelHitList chl = channelManager.findHitListByID(info.id);
        if (chl != null) {
            total += chl.numListeners();
        }
        return total;
    }

    /** */
    void startGet() {
        sourceType = SourceType.PEERCAST;
        type = Type.RELAY;
        info.srcProtocol = ChannelInfo.Protocol.PCP;

        sourceData = new PeercastSource();

        startStream();
    }

    /** */
    void startURL(final String url) {
        sourceURL = url;

        sourceType = SourceType.URL;
        type = Type.BROADCAST;
        stayConnected = true;

        resetPlayTime();

        sourceData = new URLSource(url);

        startStream();
    }

    private final ExecutorService executorService = Executors.newCachedThreadPool();

    /** */
    void startStream() {
//new Exception("*** Channel [" + info.id + "] ***").printStackTrace();
        streaming = executorService.submit(stream);
    }

    /** */
    void sleepUntil(double time) {
        double sleepTime = time - (System.currentTimeMillis() - startTime);

        // log.debug("sleep %g", sleepTime);
        if (sleepTime > 0) {
            if (sleepTime > 60) {
                sleepTime = 60;
            }

            double sleepMS = sleepTime * 1000;

            try {
                Thread.sleep((int) sleepMS);
            } catch (InterruptedException e) {
            }
        }
    }

    /**
     * @param len [sec] TODO time unit
     */
    void checkReadDelay(int len) {
        if (readDelay) {
            int time = (len * 1000) / ((info.bitrate * 1024) / 8);
            try {
                Thread.sleep(time);
            } catch (InterruptedException e) {
            }
        }
    }

    /** */
    final Runnable stream = new Runnable() {
        public void run() {
Debug.println("+++ Channel thread started");
            try {
                while (!Peercast.getInstance().isQuitting) {
                    log.debug(String.format("Ch.%d started", index));

                    ChannelHitList chl = channelManager.findHitList(info);
                    if (chl == null) {
                        channelManager.addHitList(info);
                    }

                    try {
                        sourceData.stream(Channel.this);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                    log.debug(String.format("Ch.%d stopped", index));

                    if (!stayConnected) {
                        break;
                    } else {
                        if (info.lastPlayEnd == 0) {
                            info.lastPlayEnd = System.currentTimeMillis();
                        }

                        long diff = (System.currentTimeMillis() - info.lastPlayEnd) + 5000;

                        log.debug(String.format("Ch.%d sleeping for %d micro seconds", index, diff));
                        for (int i = 0; i < diff; i++) {
                            if (Peercast.getInstance().isQuitting) {
                                break;
                            }
                            try {
                                Thread.sleep(1000);
                            } catch (InterruptedException e) {
                            }
                        }
                    }
                }
            } catch (Throwable t) {
                t.printStackTrace();
            } finally {
                try {
                    if (pushSock != null) {
                        pushSock.close();
                        pushSock = null;
                    }

                    if (sock != null) {
                        sock.close();
                        sock = null;
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
Debug.println("--- Channel thread stopped");
            }
        }
    };

    /** */
    boolean acceptGIV(Socket givSock) {
        if (pushSock == null) {
            pushSock = givSock;
            return true;
        } else {
            return false;
        }
    }

    /** */
    void connectFetch() throws IOException {
        sock = new Socket();

        if (sourceHost.tracker || sourceHost.yp) {
            sock.setSoTimeout(30 * 1000);
            log.debug(String.format("Ch.%d using longer timeouts", index));
        }
Debug.println("address: " + sourceHost.getAddress() + ": @" + sourceHost.hashCode());
        sock.connect(sourceHost.getAddress());
    }

    /**
     * @return 0 success 
     */
    int handshakeFetch() throws IOException {
//      String sidStr = ServMgr.sessionID.toString();

        HttpContext requestContext = new HttpContext();
        requestContext.setRemoteHost(sock.getInetAddress().getHostName());
        requestContext.setRemotePort(sock.getPort());
        requestContext.setMethod("GET");
        requestContext.setRequestURI("/channel/" +  info.id.toString());
        requestContext.setProtocol(new HttpProtocol());
        requestContext.setHeader(GnuPacket.PCX_HS_POS, String.valueOf(streamPos));
        requestContext.setHeader(GnuPacket.PCX_HS_PCP, "1");
        
        HttpContext responseContext = HttpUtil.postRequest(requestContext, sock);

log.debug("Got response: " + responseContext.getStatus());
        if (responseContext.getStatus() != 200 && responseContext.getStatus() != 503) {
            return responseContext.getStatus();
        }

        String value = responseContext.getHeader(GnuPacket.PCX_HS_POS);
        streamPos = value != null ? Integer.parseInt(value) : 0;
        Servent.readICYHeader(responseContext, info, null);
//log.debug("Channel fetch: " + http.cmdLine);

        if (rawData.getLatestPos() > streamPos) {
            rawData = new ChannelPacketBuffer();
        }

        String agent = null;

        InetSocketAddress remoteHost = (InetSocketAddress) sock.getRemoteSocketAddress();

        if (info.srcProtocol.equals(ChannelInfo.Protocol.PCP)) {
            AtomInputStream atomIn = new AtomInputStream(sock.getInputStream());
            AtomOutputStream atomOut = new AtomOutputStream(sock.getOutputStream());
            // don't need PCP_CONNECT here
            Servent.handshakeOutgoingPCP(atomIn, atomOut, remoteHost, remoteID, agent, sourceHost.yp | sourceHost.tracker);
        }

        return 0;
    }

    /** */
    void startICY(Socket cs, SourceType sourceType) throws SocketException {
        this.sourceType = sourceType;
        this.type = Type.BROADCAST;
        cs.setSoTimeout(0); // stay connected even when theres no data coming through
        this.sock = cs;
        info.srcProtocol = ChannelInfo.Protocol.HTTP;

        streamIndex = ++channelManager.icyIndex;

        sourceData = new ICYSource();
        startStream();
    }

    /** */
    void processMp3Metadata(byte[] str) throws IOException {
        ChannelInfo newInfo = info;

        String cmd = new String(str);
        StringTokenizer st = new StringTokenizer(cmd, ";");
        while (st.hasMoreTokens()) {
            StringTokenizer st2 = new StringTokenizer(cmd, "= ;\t");
            String name = null;
            String value = null;
            if (st2.hasMoreTokens()) {
                name = st2.nextToken();
            }
            if (st2.hasMoreTokens()) {
                value = st2.nextToken();
            }

            if (name.equals("StreamTitle")) {
                newInfo.track.title = value;

            } else if (name.equals("StreamUrl")) {
                newInfo.track.contact = value;
            }
        }

        updateInfo(newInfo);
    }

    /** */
    void broadcastTrackerUpdate(GnuID serventID, boolean force) throws IOException {
        long currentTime = System.currentTimeMillis();

        if (force || (currentTime - lastTrackerUpdate) > 30) {
            ChannelPacket packet = new ChannelPacket();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(); // 

            AtomOutputStream atom = new AtomOutputStream(baos);

            ChannelHit hit = new ChannelHit();

            ChannelHitList chl = channelManager.findHitListByID(info.id);
            if (chl == null) {
                throw new IOException("Broadcast channel has no hitlist");
            }

            int numListeners = totalListeners();
            int numRelays = totalRelays();

            hit.initLocal(numListeners, numRelays, info.numSkips, info.getUptime(), isPlaying());
            hit.tracker = true;

            atom.writeParent(PCPStream.PCP_BCST, 7);
            atom.writeByte(PCPStream.PCP_BCST_GROUP, (byte) PCPStream.PCP_BCST_GROUP_ROOT);
            atom.writeByte(PCPStream.PCP_BCST_HOPS, (byte) 0);
            atom.writeByte(PCPStream.PCP_BCST_TTL, (byte) 7);
            atom.writeBytes(PCPStream.PCP_BCST_FROM, serverManager.sessionID.id, 16);
            atom.writeInt(PCPStream.PCP_BCST_VERSION, PCPStream.PCP_CLIENT_VERSION);
            atom.writeParent(PCPStream.PCP_CHAN, 4);
            atom.writeBytes(PCPStream.PCP_CHAN_ID, info.id.id, 16);
            atom.writeBytes(PCPStream.PCP_CHAN_KEY, channelManager.broadcastID.id, 16);
            info.writeInfoAtoms(atom);
            info.writeTrackAtoms(atom);
            hit.writeAtoms(atom, false, info.id);

            packet.data = baos.toByteArray();
            packet.type = ChannelPacket.Type.PCP;

//            GnuID noID = new GnuID();
            int count = serverManager.broadcastPacket(packet, serverManager.sessionID, serventID, null, Servent.Type.COUT); // TODO check null

            if (count != 0) {
                log.debug(String.format("Sent tracker update for %s to %d client(s)", info.name, count));
                lastTrackerUpdate = currentTime;
            }
        }
    }

    /** */
    boolean sendPacketUp(ChannelPacket packet, GnuID cid, GnuID sid, GnuID did) {
        if (isActive() && (!cid.isSet() || info.id.equals(cid)) && (!sid.isSet() || !remoteID.equals(sid)) && sourceStream != null) {
            return sourceStream.sendPacket(packet, did);
        }

        return false;
    }

    /** */
    void updateInfo(ChannelInfo newInfo) throws IOException {
        if (info.update(newInfo)) {
            if (isBroadcasting()) {
                long currentTime = System.currentTimeMillis();
                if ((currentTime - lastMetaUpdate) > 30 * 1000) {
                    lastMetaUpdate = currentTime;

                    ChannelPacket packet = new ChannelPacket();

                    ByteArrayOutputStream baos = new ByteArrayOutputStream(); // 

                    AtomOutputStream atom = new AtomOutputStream(baos);

                    atom.writeParent(PCPStream.PCP_BCST, 7);
                    atom.writeByte(PCPStream.PCP_BCST_HOPS, (byte) 0);
                    atom.writeByte(PCPStream.PCP_BCST_TTL, (byte) 7);
                    atom.writeByte(PCPStream.PCP_BCST_GROUP, (byte) PCPStream.PCP_BCST_GROUP_RELAYS);
                    atom.writeBytes(PCPStream.PCP_BCST_FROM, serverManager.sessionID.id, 16);
                    atom.writeInt(PCPStream.PCP_BCST_VERSION, PCPStream.PCP_CLIENT_VERSION);
                    atom.writeBytes(PCPStream.PCP_BCST_CHANID, info.id.id, 16);
                    atom.writeParent(PCPStream.PCP_CHAN, 3);
                    atom.writeBytes(PCPStream.PCP_CHAN_ID, info.id.id, 16);
                    info.writeInfoAtoms(atom);
                    info.writeTrackAtoms(atom);

                    packet.data = baos.toByteArray();
                    packet.type = ChannelPacket.Type.PCP;
                    GnuID noID = new GnuID();
                    serverManager.broadcastPacket(packet, info.id, serverManager.sessionID, noID, Servent.Type.RELAY);

                    broadcastTrackerUpdate(noID, false); // TODO check false
                }
            }

        }

        ChannelHitList chl = channelManager.findHitList(info);
        if (chl != null) {
            chl.info = info;
        }

        Peercast.getInstance().channelUpdate(info);
    }

    /** */
    ChannelStream createSource() throws IOException {
        return info.srcProtocol.getChannelStream(this);
    }

    /** */
    Element createRelayXML(boolean showStat) {
        String ststr = status.toString();
        if (!showStat) {
            if ((status == Status.RECEIVING) || (status == Status.BROADCASTING)) {
                ststr = "OK";
            }
        }

        ChannelHitList chl = channelManager.findHitList(info);

        Element e = Peercast.newElement("relay");
        e.setAttribute("relay", String.valueOf(localListeners()));
        e.setAttribute("relays", String.valueOf(localRelays()));
        e.setAttribute("hosts", (chl != null) ? String.valueOf(chl.numHits()) : "0");
        e.setAttribute("status", ststr);
        return e;
    }

    boolean notFound() {
        return status.equals(Status.NOTFOUND);
    }

    boolean isPlaying() {
        return status.equals(Status.RECEIVING) || status.equals(Status.BROADCASTING);
    }

    boolean isReceiving() {
        return status.equals(Status.RECEIVING);
    }

    boolean isBroadcasting() {
//Debug.println(StringUtil.paramString(this));
        return status.equals(Status.BROADCASTING);
    }

    boolean isActive() {
        return type != Type.NONE;
    }

    boolean isIdle() {
        return isActive() && status.equals(Status.IDLE);
    }

    final String getName() {
        return info.name;
    }

    GnuID getID() {
        return info.id;
    }

    int getBitrate() {
        return info.bitrate;
    }

    /** */
    String getIDString() {
        return info.id.toString();
    }

    String mount;

    ChannelMeta insertMeta = new ChannelMeta();

    ChannelPacket headPack = new ChannelPacket();

    ChannelPacketBuffer rawData = new ChannelPacketBuffer();

    ChannelStream sourceStream;

    int streamIndex = 0;

    ChannelInfo info = new ChannelInfo();

    ChannelHit sourceHost = new ChannelHit();

    GnuID remoteID = new GnuID();

    String sourceURL;

    boolean bump = false, stayConnected = false;

    int icyMetaInterval = 0;

    int streamPos = 0;

    boolean readDelay = false;

    Type type = Type.NONE;

    ChannelSource sourceData;

    SourceType sourceType = SourceType.NONE;

    MP3Header mp3Head;

    Future<?> streaming;

    long lastIdleTime = 0;

    int index;

    Status status = Status.NONE;

    Socket sock;

    Socket pushSock;

    long lastTrackerUpdate = 0;

    long lastMetaUpdate = 0;

    double startTime = 0, syncTime = 0;
}

/* */
