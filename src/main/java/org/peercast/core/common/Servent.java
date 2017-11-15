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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.net.http.HttpContext;
import vavi.net.http.HttpProtocol;
import vavi.net.http.HttpServletRequestAdapter;
import vavi.net.http.HttpServletResponseAdapter;
import vavi.net.http.HttpUtil;
import vavi.net.inet.InetServer;
import vavi.net.inet.SocketHandlerFactory;
import vavi.util.Debug;
import vavi.util.Singleton;
import vavi.xml.util.PrettyPrinter;


/**
 * Servent handles the actual connection between clients
 *
 * @version 4-apr-2002
 * @author giles
 */
class Servent {

    /** */
    private static Log log = LogFactory.getLog(Servent.class);

    /** */
    private ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    /** */
    private ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

    /** max. amount of packet hashes Servents can store */
    static final int MAX_HASH = 500;

    /** max. output packets per queue (normal/priority) */
    static final int MAX_OUTPACKETS = 32;

    /** */
    enum Type {
        /** Not allocated */
        NONE,
        /** Unknown incoming */
        INCOMING,
        /** The main server */
        SERVER,
        /** Outgoing relay */
        RELAY,
        /** Outgoing direct connection */
        DIRECT,
        /** PCP out connection */
        COUT,
        /** PCP in connection */
        CIN,
        /** old protocol connection */
        PGNU
    }

    /** */
    enum Status {
        /** */
        NONE,
        /** */
        CONNECTING,
        /** */
        PROTOCOL,
        /** */
        HANDSHAKE,
        /** */
        CONNECTED,
        /** */
        CLOSING,
        /** */
        LISTENING,
        /** */
        TIMEOUT,
        /** */
        REFUSED,
        /** */
        VERIFIED,
        /** */
        ERROR,
        /** */
        WAIT,
        /** */
        FREE
    }

    /** */
    enum Protocol {
        /** */
        UNKNOWN,
        /** */
        GNUTELLA06,
        /** */
        PCP
    }

    enum Sort {
        /** */
        BY_NAME {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.name.compareToIgnoreCase(c2.info.name);
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.name.compareToIgnoreCase(c2.info.name);
                        }
                    };
                }
            }
        },
        /** */
        BY_BITRATE {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.bitrate - c2.info.bitrate;
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.bitrate - c2.info.bitrate;
                        }
                    };
                }
            }
        },
        /** */
        BY_LISTENERS {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.numListeners() - c2.numListeners();
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.numListeners() - c2.numListeners();
                        }
                    };
                }
            }
        },
        /** */
        BY_HOSTS {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.numHits() - c2.numHits();
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.numHits() - c2.numHits();
                        }
                    };
                }
            }
        },
        /** */
        BY_TYPE {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.contentType.compareTo(c2.info.contentType);
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.contentType.compareTo(c2.info.contentType);
                        }
                    };
                }
            }
        },
        /** */
        BY_GENRE {
            public Comparator<ChannelHitList> getComparator(boolean isDown) {
                if (isDown) {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.genre.compareToIgnoreCase(c2.info.genre);
                        }
                    };
                } else {
                    return new Comparator<ChannelHitList>() {
                        public int compare(ChannelHitList c1, ChannelHitList c2) {
                            return c1.info.genre.compareToIgnoreCase(c2.info.genre);
                        }
                    };
                }
            }
        };
        /** */
        public abstract Comparator<ChannelHitList> getComparator(boolean isDown);
    }

    /** [msec] */
    static final int DIRECT_WRITE_TIMEOUT = 60 * 1000;

    /** */
    boolean isPrivate() {
        InetSocketAddress h = getHost();
        return serventManager.isFiltered(ServFilter.Type.PRIVATE.value, h) || h.getAddress().isAnyLocalAddress();
    }

    /** */
    boolean isAllowed(ServentManager.Allow a) {
        InetSocketAddress h = getHost();

        if (serventManager.isFiltered(ServFilter.Type.BAN.value, h)) {
            return false;
        }

        return (allow & a.value) != 0;
    }

    /** */
    boolean isFiltered(int f) {
        InetSocketAddress h = getHost();
        return serventManager.isFiltered(f, h);
    }

    /** */
    Servent(int index) {
        outPacketsPri = new GnuPacketBuffer(MAX_OUTPACKETS);
        outPacketsNorm = new GnuPacketBuffer(MAX_OUTPACKETS);
        seenIDs = new ArrayList<>();
        serventIndex = index;
        remoteID = new GnuID();
        networkID = new GnuID();
        chanID = new GnuID();
        pack = new GnuPacket();
        reset();
    }

    /** */
    void kill() throws IOException {

        setStatus(Status.CLOSING);

        if (pcpStream != null) {
            PCPStream pcp = pcpStream;
            pcpStream = null;
            pcp.kill();
        }

        if (sock != null) {
            sock.close();
            sock = null;
        }

        if (pushSock != null) {
            pushSock.close();
            pushSock = null;
        }

        if (type != Type.SERVER) {
            reset();
            setStatus(Status.FREE);
        }
    }

    /** */
    void abort() throws IOException {
        server.stop();
    }

    /** */
    void reset() {

        remoteID.clear();

        servPort = 0;

        pcpStream = null;

        flowControl = false;
        networkID.clear();

        chanID.clear();

        outputProtocol = ChannelInfo.Protocol.UNKNOWN;

        agent = null;
        sock = null;
        allow = ServentManager.Allow.ALL.value;
        syncPos = 0;
        addMetadata = false;
        nsSwitchNum = 0;
        pack.func = null;
        lastConnect = lastPing = lastPacket = 0;
        loginPassword = null;
        loginMount = null;
        bytesPerSecond = 0;
        priorityConnect = false;
        pushSock = null;
        sendHeader = true;

        outPacketsNorm = null;
        outPacketsPri = null;

        seenIDs.clear();

        status = Status.NONE;
        type = Type.NONE;
    }

    /** */
    boolean sendPacket(ChannelPacket pack, GnuID cid, GnuID sid, GnuID did, Type type) {

        if (this.type.equals(type) && isConnected() && (!cid.isSet() || chanID.equals(cid)) && (!sid.isSet() || !sid.equals(remoteID)) && pcpStream != null) {
            return pcpStream.sendPacket(pack, did);
        }
        return false;
    }

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
    InetSocketAddress getHost() {
        InetSocketAddress h = new InetSocketAddress((InetAddress) null, 0);

        if (sock != null) {
            h = (InetSocketAddress) sock.getLocalSocketAddress();
        }

        return h;
    }

    /**
     * @param usePrimary use primary
     */
    synchronized boolean outputPacket(GnuPacket packet, boolean usePrimary) {

        boolean result = false;
        if (usePrimary) {
            result = outPacketsPri.write(packet);
        } else {
            if (serventManager.useFlowControl) {
                int per = outPacketsNorm.percentFull();
                if (per > 50) {
                    flowControl = true;
                } else if (per < 25) {
                    flowControl = false;
                }
            }

            boolean send = true;
            if (flowControl) {
                // if in flowcontrol, only allow packets with less of a hop count than already in queue
                if (packet.hops >= outPacketsNorm.findMinHop()) {
                    send = false;
                }
            }

            if (send) {
                result = outPacketsNorm.write(packet);
            }
        }

        return result;
    }

    /** root server */
    boolean initServer(String host, int port) {
        try {
            this.type = Type.SERVER;
            this.status = Status.WAIT;

            server = new InetServer(port);
            server.setSocketHandlerFactory(serverProc);
            server.start();

            this.status = Status.LISTENING;

            if (serventManager.isRoot) {
                log.debug(String.format("Root Server started: %s:%d", host, port));
            } else {
                log.debug(String.format("Server started: %s:%d", host, port));
            }

        } catch (IOException e) {
e.printStackTrace();
            log.error(String.format("Bad server: %s", e.getMessage()));
            try {
                kill();
            } catch (IOException e1) {
            }
            return false;
        }

        return true;
    }

    /** */
    void initOutgoing(Type ty) {
        try {
            type = ty;

            Thread thread = new Thread(outgoingProc);
            thread.start();

        } catch (Exception e) {
            log.error(String.format("Unable to start outgoing: %s", e.getMessage()));
            try {
                kill();
            } catch (IOException e1) {
            }
        }
    }

    /** */
    void initPCP(InetSocketAddress rh) {
        String ipStr = rh.toString();
        try {
            type = Type.COUT;

            if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK)) {
                throw new IOException("Servent not allowed");
            }

            sock.connect(rh);

            Thread thread = new Thread(outgoingProc);
            log.debug(String.format("Outgoing to %s", ipStr));

            thread.start();

        } catch (IOException e) {
            log.error(String.format("Unable to open connection to %s - %s", ipStr, e.getMessage()));
            try {
                kill();
            } catch (IOException e1) {
            }
        }
    }

    /** */
    void initGIV(InetSocketAddress h, GnuID id) {
        try {
            givID = id;

            if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK)) {
                throw new IOException("Servent not allowed");
            }

            sock.connect(h);

            Thread thread = new Thread(givProc);
            type = Type.RELAY;

            thread.start();

        } catch (IOException e) {
            log.error(String.format("GIV error to %s: %s", h.getHostName(), e.getMessage()));
            try {
                kill();
            } catch (IOException e1) {
            }
        }
    }

    /** */
    void setStatus(Status s) {
        if (s != status) {
            status = s;

            if (s.equals(Status.HANDSHAKE) || s.equals(Status.CONNECTED) || s.equals(Status.LISTENING)) {
                lastConnect = System.currentTimeMillis();
            }
        }

    }

    /** */
    void handshakeOut() throws IOException {

        HttpContext request = new HttpContext();

        request.setMethod(GnuPacket.GNU_PEERCONN);
        request.setHeader(Peercast.HTTP_HS_AGENT, GnuPacket.PCX_AGENT);
        request.setHeader(GnuPacket.PCX_HS_PCP, "1");
        if (priorityConnect) {
            request.setHeader(GnuPacket.PCX_HS_PRIORITY, "1");
        }
        if (networkID.isSet()) {
            request.setHeader(GnuPacket.PCX_HS_NETWORKID, networkID.toString());
        }
        request.setHeader(GnuPacket.PCX_HS_ID, serventManager.sessionID.toString());
        request.setHeader(GnuPacket.PCX_HS_OS, System.getProperty("os.name"));

        HttpContext response = HttpUtil.postRequest(request);
        if (response.getStatus() != 200) {
log.error("Expected 200, got " + response.getStatus());
            throw new IOException("Unexpected HTTP response");
        }

        boolean versionValid = false;

        GnuID clientID = new GnuID();
        clientID.clear();

        for (Map.Entry<String, String> header : response.getHeaders().entrySet()) {
            log.debug(header);

            if (header.getKey().equals(Peercast.HTTP_HS_AGENT)) {
                agent = header.getValue();

                if (agent.toLowerCase().startsWith("peercast/")) {
                    versionValid = agent.substring(9).compareTo(GnuPacket.MIN_CONNECTVER) >= 0;
                }
            } else if (header.getKey().equals(GnuPacket.PCX_HS_NETWORKID)) {
                clientID = new GnuID(header.getValue());
            }
        }

        if (!clientID.equals(networkID)) {
            throw new IOException(String.valueOf(HttpServletResponse.SC_SERVICE_UNAVAILABLE));
        }

        if (!versionValid) {
            throw new IOException(String.valueOf(HttpServletResponse.SC_UNAUTHORIZED));
        }

        response.setStatus(0); // {@link GnuPacket#GNU_OK}
    }

    /** */
    void processOutChannel() {
    }

    /** */
    void handshakeIn(HttpServletRequest request, HttpServletResponse response) throws IOException {

        int osType = 0;

        boolean versionValid = false;
        boolean diffRootVer = false;

        GnuID clientID = null;

        Enumeration<?> e = request.getHeaderNames();
        while (e.hasMoreElements()) {

            String name = (String) e.nextElement();
            String value = request.getHeader(name);

            if (name.equals(Peercast.HTTP_HS_AGENT)) {

                if (value.toLowerCase().startsWith("peercast/")) {
                    versionValid = value.substring(9).equalsIgnoreCase(GnuPacket.MIN_CONNECTVER);
                    diffRootVer = value.substring(9).equalsIgnoreCase(GnuPacket.MIN_ROOTVER);
                }
            } else if (name.equals(GnuPacket.PCX_HS_NETWORKID)) {
                clientID = new GnuID(value);

            } else if (name.equals(GnuPacket.PCX_HS_PRIORITY)) {
                priorityConnect = Integer.parseInt(value) != 0;

            } else if (name.equals(GnuPacket.PCX_HS_ID)) {
                GnuID id = new GnuID(value);
                if (id.equals(serventManager.sessionID)) {
                    throw new IOException("Servent loopback");
                }

            } else if (name.equals(GnuPacket.PCX_HS_OS)) {
                if (value.equalsIgnoreCase(GnuPacket.PCX_OS_LINUX)) {
                    osType = 1;
                } else if (value.equalsIgnoreCase(GnuPacket.PCX_OS_WIN32)) {
                    osType = 2;
                } else if (value.equalsIgnoreCase(GnuPacket.PCX_OS_MACOSX)) {
                    osType = 3;
                } else if (value.equalsIgnoreCase(GnuPacket.PCX_OS_WINAMP2)) {
                    osType = 4;
                }
            }

        }

        if (!clientID.equals(networkID)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }

        // if this is a priority connection and all incoming connections
        // are full then kill an old connection to make room. Otherwise reject connection.
        // if (!priorityConnect) {
        if (!isPrivate()) {
            if (serventManager.pubInFull()) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                return;
            }
        }
        // }

        if (!versionValid) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        response.setStatus(0); // GnuPacket.GNU_OK

        response.setHeader(Peercast.HTTP_HS_AGENT, GnuPacket.PCX_OLDAGENT);

        if (networkID.isSet()) {
            String idStr = networkID.toString();
            response.setHeader(GnuPacket.PCX_HS_NETWORKID, idStr);
        }

        if (serventManager.isRoot) {
            response.setHeader(GnuPacket.PCX_HS_FLOWCTL, serventManager.useFlowControl ? "1" : "0");
            response.setHeader(GnuPacket.PCX_HS_MINBCTTL, String.valueOf(channelManager.minBroadcastTTL));
            response.setHeader(GnuPacket.PCX_HS_MAXBCTTL, String.valueOf(channelManager.maxBroadcastTTL));
            response.setHeader(GnuPacket.PCX_HS_RELAYBC, String.valueOf(serventManager.relayBroadcast));
//          response.setHeader(GnuPacket.PCX_HS_FULLHIT, "2");

            if (diffRootVer) {
                response.setHeader(GnuPacket.PCX_HS_DL, "");
                response.setHeader(GnuPacket.PCX_DL_URL, "");
            }

            response.setHeader(GnuPacket.PCX_HS_MSG, serventManager.rootMsg);
        }

        String hostIP = InetAddress.getLocalHost().getHostName();
        response.setHeader(GnuPacket.PCX_HS_REMOTEIP, hostIP);
    }

    /** */
    boolean pingHost(InetSocketAddress rhost, GnuID rsid) throws IOException {
log.debug(String.format("Ping host %s: trying..", rhost.getHostName()));
        Socket socket = null;
        boolean hostOK = false;

        try {
            socket = new Socket();
            socket.setSoTimeout(15000);
            socket.connect(rhost);

            AtomOutputStream atomOut = new AtomOutputStream(socket.getOutputStream());
            AtomInputStream atomIn = new AtomInputStream(socket.getInputStream());

            atomOut.writeInt(PCPStream.PCP_CONNECT, 1);
            atomOut.writeParent(PCPStream.PCP_HELO, 1);
            atomOut.writeBytes(PCPStream.PCP_HELO_SESSIONID, serventManager.sessionID.id, 16);
            atomOut.flush();

            GnuID sid = new GnuID();

            ID4 id = atomIn.read();
            if (id == PCPStream.PCP_OLEH) {
                for (int i = 0; i < atomIn.childCount; i++) {
                    ID4 pid = atomIn.read();
                    if (pid == PCPStream.PCP_SESSIONID) {
                        atomIn.readBytes(sid.id, 16, atomIn.dataLength);
                    } else {
                        atomIn.skip(atomIn.childCount, atomIn.dataLength);
                    }
                }
            } else {
                log.debug(String.format("Ping response: %s", id.toString()));
                throw new IOException("Bad ping response");
            }

            if (!sid.equals(rsid)) {
                throw new IOException("SIDs don't match");
            }

            hostOK = true;
log.debug(String.format("Ping host %s: OK", rhost.getHostName()));
            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT);
            atomOut.flush();

        } catch (IOException e) {
            log.debug(String.format("Ping host %s: %s", rhost.getHostName(), e.getMessage()));
        } finally {
            if (socket != null) {
                socket.close();
            }
        }

        if (!hostOK) {
            rhost = new InetSocketAddress(rhost.getAddress(), 0);
        }

        return true;
    }

    /** */
    private boolean handshakeStream(HttpServletRequest request, HttpServletResponse response, ChannelInfo chanInfo) throws IOException {

        boolean gotPCP = false;
        int reqPos = 0;

        nsSwitchNum = 0;

        Enumeration<?> e = request.getHeaderNames();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            String value = request.getHeader(name);

            if (name.equals(GnuPacket.PCX_HS_PCP)) {
                gotPCP = Integer.parseInt(value) != 0;
            } else if (name.equals(GnuPacket.PCX_HS_POS)) {
                reqPos = Integer.parseInt(value);
            } else if (name.equals("icy-metadata")) {
                addMetadata = Integer.parseInt(value) > 0;
            } else if (name.equals(Peercast.HTTP_HS_AGENT)) {
                agent = value;
            } else if (name.equals("pragma")) {
                int ssc = value.indexOf("stream-switch-count=");
                int so = value.indexOf("stream-offset");

                if (ssc != 0 || so != 0) {
                    nsSwitchNum = 1;
                }
            }

            // log.debug("Stream: %s", http.cmdLine);
        }

        if (!gotPCP && outputProtocol.equals(ChannelInfo.Protocol.PCP)) {
            outputProtocol = ChannelInfo.Protocol.PEERCAST;
        }

        if (outputProtocol.equals(ChannelInfo.Protocol.HTTP)) {
            if (chanInfo.srcProtocol.equals(ChannelInfo.Protocol.MMS) ||
                chanInfo.contentType.equals(ChannelInfo.ContentType.WMA) ||
                chanInfo.contentType.equals(ChannelInfo.ContentType.WMV) ||
                chanInfo.contentType.equals(ChannelInfo.ContentType.ASX)) {
                outputProtocol = ChannelInfo.Protocol.MMS;
            }
        }

        boolean chanFound = false;
        boolean chanReady = false;

        Channel ch = channelManager.findChannelByID(chanInfo.id);
        if (ch != null) {
            sendHeader = true;
            if (reqPos != 0) {
                streamPos = ch.rawData.findOldestPos(reqPos);
            } else {
                streamPos = ch.rawData.getLatestPos();
            }

            chanReady = canStream(ch);
        }

        ChannelHitList chl = channelManager.findHitList(chanInfo);
        if (chl != null) {
            chanFound = true;
        }

        boolean result = false;

        String idStr = chanInfo.id.toString();

        String sidStr = serventManager.sessionID.toString();

        InetSocketAddress rhost = (InetSocketAddress) sock.getRemoteSocketAddress();

        AtomOutputStream atomOut = new AtomOutputStream(response.getOutputStream());

        if (!chanFound) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            log.debug("Sending channel not found");
            return false;
        }

        if (!chanReady) {
Debug.println("outputProtocol: " + outputProtocol);
            if (outputProtocol.equals(ChannelInfo.Protocol.PCP)) {

                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_XPCP);

                handshakeIncomingPCP(request, response, rhost, remoteID, agent);

                String ripStr = rhost.getHostName();

                log.debug("Sending channel unavailable");

                ChannelHitSearch chs = new ChannelHitSearch();

                int error = PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_UNAVAILABLE;

                if (chl != null) {
                    ChannelHit best = new ChannelHit();

                    // search for up to 8 other hits
                    int cnt = 0;
                    for (int i = 0; i < 8; i++) {
                        best.init();

                        // find best hit this network if local IP
                        if (rhost.getAddress().isAnyLocalAddress()) {
                            chs.init();
                            chs.matchHost = serventManager.serverHost;
                            chs.waitDelay = 2;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        // find best hit on same network
                        if (best.getAddress() == null) {
                            chs.init();
                            chs.matchHost = rhost;
                            chs.waitDelay = 2;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        // find best hit on other networks
                        if (best.getAddress() == null) {
                            chs.init();
                            chs.waitDelay = 2;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        if (best.getAddress() == null) {
                            break;
                        }

                        best.writeAtoms(atomOut, true, chanInfo.id);
                        cnt++;
                    }

                    if (cnt != 0) {
                        log.debug(String.format("Sent %d channel hit(s) to %s", cnt, ripStr));

                    } else if (rhost.getPort() != 0) {
                        // find firewalled host
                        chs.init();
                        chs.waitDelay = 30;
                        chs.useFirewalled = true;
                        chs.excludeID = remoteID;
                        if (chl.pickHits(chs) != 0) {
                            best = chs.bestHits.get(0);
                            cnt = serventManager.broadcastPushRequest(best, rhost, chl.info.id, Type.RELAY);
                            log.debug(String.format("Broadcasted channel push request to %d clients for %s", cnt, ripStr));
                        }
                    }

                    // if all else fails, use tracker
                    if (best.getAddress() == null) {
                        // find best tracker on this network if local IP
                        if (rhost.getAddress().isAnyLocalAddress()) {
                            chs.init();
                            chs.matchHost = serventManager.serverHost;
                            chs.trackersOnly = true;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        // find local tracker
                        if (best.getAddress() == null) {
                            chs.init();
                            chs.matchHost = rhost;
                            chs.trackersOnly = true;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        // find global tracker
                        if (best.getAddress() == null) {
                            chs.init();
                            chs.trackersOnly = true;
                            chs.excludeID = remoteID;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                            }
                        }

                        if (best.getAddress() != null) {
                            best.writeAtoms(atomOut, true, chanInfo.id);
                            log.debug(String.format("Sent 1 tracker hit to %s", ripStr));
                        } else if (rhost.getPort() != 0) {
                            // find firewalled tracker
                            chs.init();
                            chs.useFirewalled = true;
                            chs.trackersOnly = true;
                            chs.excludeID = remoteID;
                            chs.waitDelay = 30;
                            if (chl.pickHits(chs) != 0) {
                                best = chs.bestHits.get(0);
                                cnt = serventManager.broadcastPushRequest(best, rhost, chl.info.id, Type.CIN);
                                log.debug(String.format("Broadcasted tracker push request to %d clients for %s", cnt, ripStr));
                            }
                        }

                    }

                }
                // return not available yet code
                atomOut.writeInt(PCPStream.PCP_QUIT, error);
                result = false;

            } else {
                log.debug("Sending channel unavailable (!channel.ready, pcp)");
                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                result = false;
            }

        } else {

            if (!chanInfo.contentType.equals(ChannelInfo.ContentType.MP3)) {
                addMetadata = false;
            }

            if (addMetadata && outputProtocol.equals(ChannelInfo.Protocol.HTTP)) { // winamp mp3 metadata check

                // GnuPacket.ICY_OK;
//              response.setProtocol("ICY"); // TODO protocol is icy
                response.setStatus(200, "OK");

                response.setHeader(Peercast.HTTP_HS_SERVER, GnuPacket.PCX_AGENT);
                response.setHeader("icy-name", chanInfo.name);
                response.setHeader("icy-br", String.valueOf(chanInfo.bitrate));
                response.setHeader("icy-genre", chanInfo.genre);
                response.setHeader("icy-url", chanInfo.url);
                response.setHeader("icy-metaint", String.valueOf(channelManager.icyMetaInterval));
                response.setHeader(GnuPacket.PCX_HS_CHANNELID, idStr);

                response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_MP3);

            } else {

                response.setStatus(HttpServletResponse.SC_OK);

                if (!chanInfo.contentType.equals(ChannelInfo.ContentType.ASX) &&
                    !chanInfo.contentType.equals(ChannelInfo.ContentType.WMV) &&
                    !chanInfo.contentType.equals(ChannelInfo.ContentType.WMA)) {
                    response.setHeader(Peercast.HTTP_HS_SERVER, GnuPacket.PCX_AGENT);

                    response.setHeader("Accept-Ranges", "none");

                    response.setHeader("x-audiocast-name", chanInfo.name);
                    response.setHeader("x-audiocast-bitrate", String.valueOf(chanInfo.bitrate));
                    response.setHeader("x-audiocast-genre", chanInfo.genre);
                    response.setHeader("x-audiocast-description", chanInfo.desc);
                    response.setHeader("x-audiocast-url", chanInfo.url);
                    response.setHeader(GnuPacket.PCX_HS_CHANNELID, idStr);
                }

                if (outputProtocol.equals(ChannelInfo.Protocol.HTTP)) {
                    switch (chanInfo.contentType) {
                    case OGG:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_XOGG);
                        break;
                    case MP3:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_MP3);
                        break;
                    case MOV:
                        response.setHeader("Connection", "close");
                        response.setHeader("Content-Length", "10000000");
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_MOV);
                        break;
                    case MPG:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_MPG);
                        break;
                    case NSV:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_NSV);
                        break;
                    case ASX:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_ASX);
                        break;
                    case WMA:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_WMA);
                        break;
                    case WMV:
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_WMV);
                        break;
                    }
                } else if (outputProtocol.equals(ChannelInfo.Protocol.MMS)) {
                    response.setHeader("Server", "Rex/9.0.0.2980");
                    response.setHeader("Cache-Control", "no-cache");
                    response.setHeader("Pragma", "no-cache");
                    response.setHeader("Pragma", "client-id=3587303426");
                    response.setHeader("Pragma", "features=\"broadcast,playlist\"");

                    if (nsSwitchNum != 0) {
                        response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_MMS);
                    } else {
                        response.setHeader("Content-Type", "application/vnd.ms.wms-hdr.asfv1");
                        if (ch != null) {
                            response.setHeader("Content-Length", String.valueOf(ch.headPack.data.length));
                        }
                        response.setHeader("Connection", "Keep-Alive");
                    }

                } else if (outputProtocol.equals(ChannelInfo.Protocol.PCP)) {
                    response.setHeader(GnuPacket.PCX_HS_POS, String.valueOf(streamPos));
                    response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_XPCP);

                } else if (outputProtocol.equals(ChannelInfo.Protocol.PEERCAST)) {
                    response.setHeader(Peercast.HTTP_HS_CONTENT, Peercast.MIME_XPEERCAST);
                }
            }

            result = true;

            if (gotPCP) {
                handshakeIncomingPCP(request, response, rhost, remoteID, agent);
                atomOut.writeInt(PCPStream.PCP_OK, 0);
            }
        }

        return result;
    }

    /** */
    void handshakeGiv(GnuID id) throws IOException {
        PrintStream ps = new PrintStream(sock.getOutputStream());
        if (id.isSet()) {
            ps.println("GIV /" + id.toString());
        } else {
            ps.println("GIV");
        }

        ps.println();
    }

    /** */
    void processGnutella() throws IOException {
        type = Type.PGNU;

        if (serventManager.isRoot) {
            processRoot();
            return;
        }

        gnuStream = new GnuStream(sock);
        setStatus(Status.CONNECTED);

        if (!serventManager.isRoot) {
            channelManager.broadcastRelays(this, 1, 1);
            GnuPacket p;

            if ((p = outPacketsNorm.curr()) != null) {
                gnuStream.sendPacket(p);
            }
            return;
        }

        gnuStream.ping(2);

        lastPacket = lastPing = System.currentTimeMillis();
        boolean doneBigPing = false;

        final int abortTimeoutSecs = 60; // abort connection after 60 secs of no activitiy
        final int packetTimeoutSecs = 30; // ping connection after 30 secs of no activity

        int currBytes = 0;
        int lastWait = 0;

        int lastTotalIn = 0, lastTotalOut = 0;

        while (sock.getInputStream().available() > 0) {

            if (sock.getInputStream().available() > 0) {
                lastPacket = System.currentTimeMillis();

                if (gnuStream.readPacket(pack)) {
                    int ver = pack.id.getVersion();

                    String ipstr;
                    ipstr = ((InetSocketAddress) sock.getRemoteSocketAddress()).getHostName();

                    GnuID routeID = new GnuID();
                    GnuStream.ResultType ret = GnuStream.ResultType.PROCESS;

                    if (ver < GnuPacket.MIN_PACKETVER) {
                        ret = GnuStream.ResultType.BADVERSION;
                    }

                    if (pack.func != GnuPacket.PONG) {
                        if (serventManager.seenPacket(pack)) {
                            ret = GnuStream.ResultType.DUPLICATE;
                        }
                    }

                    seenIDs.add(pack.id);

                    serventManager.addVersion(ver);

                    if (ret == GnuStream.ResultType.PROCESS) {

                        ret = gnuStream.processPacket(pack, this, routeID);

                        if (flowControl && (ret == GnuStream.ResultType.BROADCAST)) {
                            ret = GnuStream.ResultType.DROP;
                        }
                    }

                    switch (ret) {
                    case BROADCAST:
                        if (serventManager.broadcast(pack, this) != 0) {
                            Peercast.getInstance().stats.add(Stats.STAT.NUMBROADCASTED);
                        } else {
                            Peercast.getInstance().stats.add(Stats.STAT.NUMDROPPED);
                        }
                        break;
                    case ROUTE:
                        if (serventManager.route(pack, routeID, null) != 0) {
                            Peercast.getInstance().stats.add(Stats.STAT.NUMROUTED);
                        } else {
                            Peercast.getInstance().stats.add(Stats.STAT.NUMDROPPED);
                        }
                        break;
                    case ACCEPTED:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMACCEPTED);
                        break;
                    case DUPLICATE:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMDUP);
                        break;
                    case DEAD:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMDEAD);
                        break;
                    case DISCARD:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMDISCARDED);
                        break;
                    case BADVERSION:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMOLD);
                        break;
                    case DROP:
                        Peercast.getInstance().stats.add(Stats.STAT.NUMDROPPED);
                        break;
                    }

                    log.debug(String.format("packet in: %s-%s, %d bytes, %d hops, %d ttl, v%05x from %s", pack.func, ret, pack.len, pack.hops, pack.ttl, pack.id.getVersion(), ipstr));

                } else {
                    log.error("Bad packet");
                }
            }

            GnuPacket p;

            if ((p = outPacketsPri.curr()) != null) { // priority packet
                gnuStream.sendPacket(p);
                seenIDs.add(p.id);
                outPacketsPri.next();
            } else if ((p = outPacketsNorm.curr()) != null) { // or.. normal packet
                gnuStream.sendPacket(p);
                seenIDs.add(p.id);
                outPacketsNorm.next();
            }

            long lpt = System.currentTimeMillis() - lastPacket;

            if (!doneBigPing) {
                if ((System.currentTimeMillis() - lastPing) > 15) {
                    gnuStream.ping(7);
                    lastPing = System.currentTimeMillis();
                    doneBigPing = true;
                }
            } else {
                if (lpt > packetTimeoutSecs) {

                    if ((System.currentTimeMillis() - lastPing) > packetTimeoutSecs) {
                        gnuStream.ping(1);
                        lastPing = System.currentTimeMillis();
                    }

                }
            }
            if (lpt > abortTimeoutSecs) {
                throw new IOException("timeout");
            }

            int totIn = Peercast.getInstance().totalBytesIn - lastTotalIn;
            int totOut = Peercast.getInstance().totalBytesOut - lastTotalOut;

            int bytes = totIn + totOut;

            lastTotalIn = Peercast.getInstance().totalBytesIn;
            lastTotalOut = Peercast.getInstance().totalBytesOut;

            final int serventBandwidth = 1000;

            int delay = Peercast.idleSleepTime;
            if ((bytes != 0) && (serventBandwidth >= 8)) {
                delay = (bytes * 1000) / (serventBandwidth / 8); // set delay relative packetsize
            }

            if (delay < Peercast.idleSleepTime) {
                delay = Peercast.idleSleepTime;
            }

            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /** */
    void processRoot() {
        try {

            gnuStream = new GnuStream(sock);
            setStatus(Status.CONNECTED);

            gnuStream.ping(2);

            long lastConnect = System.currentTimeMillis();

            while (sock.getInputStream().available() > 0) {
                if (gnuStream.readPacket(pack)) {
                    String ipstr = ((InetSocketAddress) sock.getRemoteSocketAddress()).getHostName();
                    int ver = pack.id.getVersion();

                    serventManager.addVersion(ver);

                    log.debug(String.format("packet in: %d v%05x from %s", pack.func, pack.getVersion(), ipstr));

                    if (pack.func.equals(GnuPacket.PING)) { // if ping then pong back some hosts and close

                        InetSocketAddress[] hl = new InetSocketAddress[32];
                        int cnt = serventManager.getNewestServents(hl, 32, (InetSocketAddress) sock.getRemoteSocketAddress());
                        if (cnt != 0) {
                            int start = new Random(lastConnect).nextInt() % cnt;
                            int max = cnt > 8 ? 8 : cnt;

                            for (int i = 0; i < max; i++) {
                                pack.hops = 1;
                                GnuPacket pong = new GnuPacket(hl[start], false, pack);
                                gnuStream.sendPacket(pong);

                                ipstr = hl[start].getHostName();

                                // log.debug("Pong %d: %s", start + 1, ipstr);
                                start = (start + 1) % cnt;
                            }
                            String str = ((InetSocketAddress) sock.getRemoteSocketAddress()).getHostName();
                            log.debug(String.format("Sent %d pong(s) to %s", max, str));
                        } else {
                            log.debug("No Pongs to send");
                            // return;
                        }
                    } else if (pack.func.equals(GnuPacket.PONG)) { // pong?
                        DataInputStream pong = new DataInputStream(new ByteArrayInputStream(pack.data));

                        int ip, port;
                        port = pong.readShort();
                        ip = pong.readInt();

                        InetSocketAddress h = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(ip)), port);
                        if ((ip != 0) && (port != 0) && (!h.getAddress().isAnyLocalAddress())) {

                            log.debug(String.format("added pong: %d.%d.%d.%d:%d", ip >> 24 & 0xff, ip >> 16 & 0xff, ip >> 8 & 0xff, ip & 0xff, port));
                            serventManager.addHost(h, ServHost.Type.SERVENT, System.currentTimeMillis());
                        }
                    } else if (pack.func.equals(GnuPacket.HIT)) {
                        ByteArrayInputStream data = new ByteArrayInputStream(pack.data);
                        ChannelHit hit = new ChannelHit();
                        GnuStream.readHit(data, hit, pack.hops, pack.id);
                    }

                    // if (gnuStream.packetsIn > 5) // die if we get too many packets
                    // return;
                }

                if ((System.currentTimeMillis() - lastConnect > 60)) {
                    break;
                }
            }

        } catch (IOException e) {
            log.error(String.format("Relay: %s", e.getMessage()));
        }

    }

    /** */
    private Runnable givProc = new Runnable() {
        public void run() {
            Servent servent = serventManager.allocServent();
            try {
                servent.handshakeGiv(givID);
                servent.handshakeIncoming();

                servent.kill();
            } catch (IOException e) {
                log.error(String.format("GIV: %s", e.getMessage()));
            }
        }
    };

    /** */
    static void handshakeOutgoingPCP(AtomInputStream atomIn, AtomOutputStream atomOut, InetSocketAddress rhost, GnuID rid, String agent, boolean isTrusted) throws IOException {

        ServentManager serventManager = Singleton.getInstance(ServentManager.class);

        boolean nonFW = serventManager.getFirewall() != ServentManager.FirewallState.ON;
        boolean testFW = serventManager.getFirewall() == ServentManager.FirewallState.UNKNOWN;

        atomOut.writeParent(PCPStream.PCP_HELO, 3 + (testFW ? 1 : 0) + (nonFW ? 1 : 0));
        atomOut.writeString(PCPStream.PCP_HELO_AGENT, GnuPacket.PCX_AGENT);
        atomOut.writeInt(PCPStream.PCP_HELO_VERSION, PCPStream.PCP_CLIENT_VERSION);
        atomOut.writeBytes(PCPStream.PCP_HELO_SESSIONID, serventManager.sessionID.id, 16);
        if (nonFW) {
            atomOut.writeShort(PCPStream.PCP_HELO_PORT, (short) serventManager.serverHost.getPort());
        }
        if (testFW) {
            atomOut.writeShort(PCPStream.PCP_HELO_PING, (short) serventManager.serverHost.getPort());
        }
        atomOut.flush();

log.debug("PCP outgoing waiting for OLEH.. ");

        ID4 id = atomIn.read();
        int numc = atomIn.childCount;
        int numd = atomIn.dataLength;
//Debug.println("id: " + id + ", numc: " + numc + ", numd: " + numd);
        if (!id.equals(PCPStream.PCP_OLEH)) {
log.debug(String.format("PCP outgoing reply: %s", id.toString()));
            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_BADRESPONSE);
            atomOut.flush();
            throw new IOException("Got unexpected PCP response");
        }

//      GnuID clientID = new GnuID();
        rid.clear();

        InetAddress thisAddress = null;
        InetSocketAddress thisHost = null;

        // read OLEH response
        for (int i = 0; i < numc; i++) {
            id = atomIn.read();
//Debug.println("id: " + id + ", numc: " + atomIn.childCount + ", numd: " + atomIn.dataLength);

            if (id.equals(PCPStream.PCP_HELO_AGENT)) {
                String arg = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
                agent = arg;

            } else if (id.equals(PCPStream.PCP_HELO_REMOTEIP)) {
                byte[] address = Peercast.intToByte(atomIn.readInt());
//Debug.println("address: " + (address[0] & 0xff) + "." + (address[1] & 0xff) + "." + (address[2] & 0xff) + "." + (address[3] & 0xff));
                thisAddress = InetAddress.getByAddress(address);
//Debug.println("thisAddress: " + thisAddress);

            } else if (id.equals(PCPStream.PCP_HELO_PORT)) {
                int port = atomIn.readShort();
//Debug.println("port: " + port);
                thisHost = new InetSocketAddress(thisAddress, port);
//Debug.println("thisHost: " + thisHost);

            } else if (id.equals(PCPStream.PCP_HELO_VERSION)) {
                int version = atomIn.readInt();
//Debug.println("version: " + version);

            } else if (id.equals(PCPStream.PCP_HELO_SESSIONID)) {
                atomIn.readBytes(rid.id, 16);
                if (rid.equals(serventManager.sessionID)) {
                    throw new IOException("Servent loopback");
                }
//Debug.println("rid: " + rid);

            } else {
                log.debug(String.format("PCP handshake skip: %s", id.toString()));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }

        }

        // update server ip/firewall status
        if (isTrusted) {
            if (thisHost != null) {
                if (!serventManager.serverHost.getAddress().equals(thisHost.getAddress()) && serventManager.forceIP.length() == 0) {
                    String ipstr = thisHost.getHostName();
                    log.debug(String.format("Got new ip: %s", ipstr));
                    serventManager.serverHost = new InetSocketAddress(thisHost.getAddress(), serventManager.serverHost.getPort());
                }

                if (serventManager.getFirewall().equals(ServentManager.FirewallState.UNKNOWN)) {
                    if (thisHost.getPort() != 0 && !thisHost.getAddress().isAnyLocalAddress()) {
                        serventManager.setFirewall(ServentManager.FirewallState.OFF);
                    } else {
                        serventManager.setFirewall(ServentManager.FirewallState.ON);
                    }
                }
            }
        }

        if (!rid.isSet()) {
            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_NOTIDENTIFIED);
            atomOut.flush();
            throw new IOException("Remote host not identified");
        }

        log.debug("PCP Outgoing handshake complete.");
    }

    /** */
    void handshakeIncomingPCP(HttpServletRequest request, HttpServletResponse response, InetSocketAddress rhost, GnuID rid, String agent) throws IOException {
        AtomInputStream atomIn = new AtomInputStream(request.getInputStream());
        AtomOutputStream atomOut = new AtomOutputStream(response.getOutputStream());
        ID4 id = atomIn.read();
//      int numd = atomIn.numData;

        if (id != PCPStream.PCP_HELO) {
            log.debug(String.format("PCP incoming reply: %s", id.toString()));
            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT + PCPStream.PCP_ERROR_BADRESPONSE);
            throw new IOException("Got unexpected PCP response");
        }

        ID4 osType;
        int version = 0;
        int pingPort = 0;

        GnuID clientID = new GnuID();
        clientID.clear();

        for (int i = 0; i < atomIn.childCount; i++) {

            id = atomIn.read();
            if (id.equals(PCPStream.PCP_HELO_AGENT)) {
                agent = atomIn.readString(atomIn.dataLength, atomIn.dataLength);

            } else if (id.equals(PCPStream.PCP_HELO_VERSION)) {
                version = atomIn.readInt();

            } else if (id.equals(PCPStream.PCP_HELO_SESSIONID)) {
                atomIn.readBytes(rid.id, 16);
                if (rid.equals(serventManager.sessionID)) {
                    throw new IOException("Servent loopback");
                }

            } else if (id.equals(PCPStream.PCP_HELO_OSTYPE)) {
                osType = atomIn.readID4();
            } else if (id.equals(PCPStream.PCP_HELO_PORT)) {
                rhost = new InetSocketAddress(rhost.getAddress(), atomIn.readShort());
            } else if (id.equals(PCPStream.PCP_HELO_PING)) {
                pingPort = atomIn.readShort();
            } else {
                log.debug(String.format("PCP handshake skip: %s", id.toString()));
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }

        }

        if (version != 0) {
            log.debug(String.format("Incoming PCP is %s : v%d", agent, version));
        }

        if (rhost.getAddress().isAnyLocalAddress() && serventManager.serverHost.getAddress().isAnyLocalAddress())
            rhost = new InetSocketAddress(rhost.getAddress(), serventManager.serverHost.getPort());

        if (pingPort != 0) {
            String ripStr = rhost.getHostName();
            log.debug(String.format("Incoming firewalled test request: %s ", ripStr));
            rhost = new InetSocketAddress(rhost.getAddress(), pingPort);
            if (rhost.getAddress().isAnyLocalAddress() || !pingHost(rhost, rid)) {
                rhost = new InetSocketAddress(rhost.getAddress(), 0);
            }
        }

        atomOut.writeParent(PCPStream.PCP_OLEH, 5);
        atomOut.writeString(PCPStream.PCP_HELO_AGENT, GnuPacket.PCX_AGENT);
        atomOut.writeBytes(PCPStream.PCP_HELO_SESSIONID, serventManager.sessionID.id, 16);
        atomOut.writeInt(PCPStream.PCP_HELO_VERSION, PCPStream.PCP_CLIENT_VERSION);
        atomOut.writeInt(PCPStream.PCP_HELO_REMOTEIP, Peercast.byteToInt(rhost.getAddress().getAddress()));
        atomOut.writeShort(PCPStream.PCP_HELO_PORT, (short) rhost.getPort());

        if (version != 0) {
            if (version < PCPStream.PCP_CLIENT_MINVERSION) {
                atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT + PCPStream.PCP_ERROR_BADAGENT);
                throw new IOException("Agent is not valid");
            }
        }

        if (!rid.isSet()) {
            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT + PCPStream.PCP_ERROR_NOTIDENTIFIED);
            throw new IOException("Remote host not identified");
        }

        if (serventManager.isRoot) {
            serventManager.writeRootAtoms(atomOut, false);
        }

        log.debug("PCP Incoming handshake complete.");
    }

    /** */
    void processIncomingPCP(HttpServletRequest request, HttpServletResponse response, boolean suggestOthers) throws IOException {
        PCPStream.readVersion(request.getInputStream());

        AtomOutputStream atom = new AtomOutputStream(response.getOutputStream());
        InetSocketAddress rhost = (InetSocketAddress) sock.getLocalSocketAddress();

        handshakeIncomingPCP(request, response, rhost, remoteID, agent);

        boolean alreadyConnected = (serventManager.findConnection(Type.COUT, remoteID) != null) || (serventManager.findConnection(Type.CIN, remoteID) != null);
        boolean unavailable = serventManager.controlInFull();
        boolean offair = !serventManager.isRoot && !channelManager.isBroadcasting();

        String rstr = rhost.getHostName();

        if (unavailable || alreadyConnected || offair) {
            int error;

            if (alreadyConnected) {
                error = PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_ALREADYCONNECTED;
            } else if (unavailable) {
                error = PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_UNAVAILABLE;
            } else if (offair) {
                error = PCPStream.PCP_ERROR_QUIT | PCPStream.PCP_ERROR_OFFAIR;
            } else {
                error = PCPStream.PCP_ERROR_QUIT;
            }

            if (suggestOthers) {

                ChannelHit best = new ChannelHit();
                ChannelHitSearch chs = new ChannelHitSearch();

                int cnt = 0;
                for (int i = 0; i < 8; i++) {
                    best.init();

                    // find best hit on this network
                    if (rhost.getAddress().isAnyLocalAddress()) {
                        chs.init();
                        chs.matchHost = serventManager.serverHost;
                        chs.waitDelay = 2;
                        chs.excludeID = remoteID;
                        chs.trackersOnly = true;
                        chs.useBusyControls = false;
                        if (channelManager.pickHits(chs) != 0) {
                            best = chs.bestHits.get(0);
                        }
                    }

                    // find best hit on same network
                    if (best.getAddress() == null) {
                        chs.init();
                        chs.matchHost = rhost;
                        chs.waitDelay = 2;
                        chs.excludeID = remoteID;
                        chs.trackersOnly = true;
                        chs.useBusyControls = false;
                        if (channelManager.pickHits(chs) != 0) {
                            best = chs.bestHits.get(0);
                        }
                    }

                    // else find best hit on other networks
                    if (best.getAddress() != null) {
                        chs.init();
                        chs.waitDelay = 2;
                        chs.excludeID = remoteID;
                        chs.trackersOnly = true;
                        chs.useBusyControls = false;
                        if (channelManager.pickHits(chs) != 0) {
                            best = chs.bestHits.get(0);
                        }
                    }

                    if (best.getAddress() == null) {
                        break;
                    }

                    GnuID noID = new GnuID();
                    noID.clear();
                    best.writeAtoms(atom, true, noID);
                    cnt++;
                }
                if (cnt != 0) {
                    log.debug(String.format("Sent %d tracker(s) to %s", cnt, rstr));
                } else if (rhost.getPort() != 0) {
                    // send push request to best firewalled tracker on other network
                    chs.init();
                    chs.waitDelay = 30;
                    chs.excludeID = remoteID;
                    chs.trackersOnly = true;
                    chs.useFirewalled = true;
                    chs.useBusyControls = false;
                    if (channelManager.pickHits(chs) != 0) {
                        best = chs.bestHits.get(0);
                        GnuID noID = new GnuID();
                        noID.clear();
                        cnt = serventManager.broadcastPushRequest(best, rhost, noID, Type.CIN);
                        log.debug(String.format("Broadcasted tracker push request to %d clients for %s", cnt, rstr));
                    }
                }
            }

            log.error(String.format("Sending QUIT to incoming: %d", error));

            atom.writeInt(PCPStream.PCP_QUIT, error);
            return;
        }

        type = Type.CIN;
        setStatus(Status.CONNECTED);

        atom.writeInt(PCPStream.PCP_OK, 0);

        // ask for update
        atom.writeParent(PCPStream.PCP_ROOT, 1);
        atom.writeParent(PCPStream.PCP_ROOT_UPDATE, 0);

        pcpStream = new PCPStream(remoteID);

        int error = 0;
        BroadcastState bcs = new BroadcastState();
        while (error == 0 && sock.getInputStream().available() > 0) {
            error = pcpStream.readPacket(sock.getInputStream(), sock.getOutputStream(), bcs);
            try {
                Thread.sleep(Peercast.idleSleepTime);
            } catch (InterruptedException e) {
            }

            if (!serventManager.isRoot && !channelManager.isBroadcasting()) {
                error = PCPStream.PCP_ERROR_OFFAIR;
            }
            if (Peercast.getInstance().isQuitting) {
                error = PCPStream.PCP_ERROR_SHUTDOWN;
            }
        }

        pcpStream.flush(response.getOutputStream());

        error += PCPStream.PCP_ERROR_QUIT;
        atom.writeInt(PCPStream.PCP_QUIT, error);

        log.debug(String.format("PCP Incoming to %s closed: %d", rstr, error));
    }

    /** */
    private Runnable outgoingProc = new Runnable() {
        public void run() {
            log.debug("COUT started");

            GnuID noID = new GnuID();
            pcpStream = new PCPStream(noID);

            setStatus(Status.WAIT);

            if (channelManager.isBroadcasting() && serventManager.autoServe) {
                ChannelHit bestHit = new ChannelHit();
                ChannelHitSearch chs = new ChannelHitSearch();

                do {
                    bestHit.init();

                    if (serventManager.rootHost.length() == 0) {
                        break;
                    }

                    if (pushSock != null) {
                        sock = pushSock;
                        pushSock = null;
                        bestHit.setAddress((InetSocketAddress) sock.getRemoteSocketAddress()); // TODO remote?
                        break;
                    }

                    noID = new GnuID();
                    ChannelHitList chl = channelManager.findHitListByID(noID);
                    if (chl != null) {
                        // find local tracker
                        chs.init();
                        chs.matchHost = serventManager.serverHost;
                        chs.waitDelay = ServentManager.MIN_TRACKER_RETRY;
                        chs.excludeID = serventManager.sessionID;
                        chs.trackersOnly = true;
                        if (chl.pickHits(chs) == 0) {
                            // else find global tracker
                            chs.init();
                            chs.waitDelay = ServentManager.MIN_TRACKER_RETRY;
                            chs.excludeID = serventManager.sessionID;
                            chs.trackersOnly = true;
                            chl.pickHits(chs);
                        }

                        if (chs.bestHits.size() != 0) {
                            bestHit = chs.bestHits.get(0);
                        }
                    }

                    long currentTime = System.currentTimeMillis();

                    if (bestHit.getAddress() == null && (currentTime - channelManager.lastYPConnect) > ServentManager.MIN_YP_RETRY) {
                        bestHit.setAddress(new InetSocketAddress(serventManager.rootHost, GnuPacket.DEFAULT_PORT));
                        bestHit.yp = true;
                        channelManager.lastYPConnect = currentTime;
                    }
                    try {
                        Thread.sleep(Peercast.idleSleepTime);
                    } catch (InterruptedException e) {
                    }

                } while (bestHit.getAddress() == null);

                if (bestHit.getAddress() == null) { // give up
                    log.error("COUT giving up");
                    return;
                }

                String bestHitHostName = bestHit.getAddress().getHostName();

                int error = 0;
                try {

                    log.debug(String.format("COUT to %s: Connecting..", bestHitHostName));

                    if (sock == null) {
                        setStatus(Status.CONNECTING);
                        sock = new Socket();
                        sock.connect(bestHit.getAddress());
                    }

                    sock.setSoTimeout(30 * 1000);

                    setStatus(Status.HANDSHAKE);

                    InetSocketAddress remoteAddress = (InetSocketAddress) sock.getRemoteSocketAddress();
                    AtomInputStream atomIn = new AtomInputStream(sock.getInputStream());
                    AtomOutputStream atomOut = new AtomOutputStream(sock.getOutputStream());
                    atomOut.writeInt(PCPStream.PCP_CONNECT, 1);
                    handshakeOutgoingPCP(atomIn, atomOut, remoteAddress, remoteID, agent, bestHit.yp);

                    setStatus(Status.CONNECTED);

                    log.debug(String.format("COUT to %s: OK", bestHitHostName));

                    pcpStream.init(remoteID);

                    BroadcastState bcs = new BroadcastState();
                    error = 0;
                    while (error == 0 && sock.getInputStream().available() > 0 && serventManager.autoServe) {
                        error = pcpStream.readPacket(sock.getInputStream(), sock.getOutputStream(), bcs);

                        try {
                            Thread.sleep(Peercast.idleSleepTime);
                        } catch (InterruptedException e) {
                        }

                        if (!channelManager.isBroadcasting()) {
                            error = PCPStream.PCP_ERROR_OFFAIR;
                        }
                        if (Peercast.getInstance().isQuitting) {
                            error = PCPStream.PCP_ERROR_SHUTDOWN;
                        }

                        if (pcpStream.nextRootPacket != 0) {
                            if (System.currentTimeMillis() > pcpStream.nextRootPacket + 30) {
                                error = PCPStream.PCP_ERROR_NOROOT;
                            }
                        }
                    }
                    setStatus(Status.CLOSING);

                    pcpStream.flush(sock.getOutputStream());

                    error += PCPStream.PCP_ERROR_QUIT;
                    atomOut.writeInt(PCPStream.PCP_QUIT, error);

                    log.error(String.format("COUT to %s closed: %d", bestHitHostName, error));

                    // } catch (TimeoutException e) {
                    // log.error(String.format("COUT to %s: timeout (%s)", ipStr, e.getMessage()));
                    // sv.setStatus(STATUS.S_TIMEOUT);
                } catch (IOException e) {
                    log.error(String.format("COUT to %s: %s", bestHitHostName, e.getMessage()));
                    setStatus(Status.ERROR);
                }

                try {
                    if (sock != null) {
                        sock.close();
                        sock = null;
                    }

                } catch (IOException e) {
                }

                // don`t discard this hit if we caused the disconnect (stopped broadcasting)
                if (error != (PCPStream.PCP_ERROR_QUIT + PCPStream.PCP_ERROR_OFFAIR)) {
                    channelManager.deadHit(bestHit);
                }


                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }

            try {
                kill();
            } catch (IOException e) {
            }
            log.debug("COUT ended");
        }
    };

    /** */
    void processServent(HttpServletRequest request, HttpServletResponse response) throws IOException {
        setStatus(Status.HANDSHAKE);

        handshakeIn(request, response);

        if (sock == null) {
            throw new IOException("Servent has no socket");
        }

        processGnutella();
    }

    /** */
    void processStream(HttpServletRequest request, HttpServletResponse response, boolean doneHandshake, ChannelInfo chanInfo) throws IOException {
        if (!doneHandshake) {
            setStatus(Status.HANDSHAKE);

            if (!handshakeStream(request, response, chanInfo)) {
                return;
            }
        }

        if (chanInfo.id.isSet()) {

            chanID = chanInfo.id;

            log.debug(String.format("Sending channel: %s ", outputProtocol.name()));

            if (!waitForChannelHeader(request, chanInfo)) {
                throw new IOException("Channel not ready");
            }

            serventManager.totalStreams++;

//            InetSocketAddress host = (InetSocketAddress) sock.getRemoteSocketAddress();
//            host = new InetSocketAddress(host.getAddress(), 0); // force to 0 so we ignore the incoming port

            Channel ch = channelManager.findChannelByID(chanID);
            if (ch == null) {
                throw new IOException("Channel not found");
            }

            if (outputProtocol == ChannelInfo.Protocol.HTTP) {
                if ((addMetadata) && (channelManager.icyMetaInterval != 0)) {
                    sendRawMetaChannel(channelManager.icyMetaInterval);
                } else {
                    sendRawChannel(request, response, true, true);
                }

            } else if (outputProtocol == ChannelInfo.Protocol.MMS) {
                if (nsSwitchNum != 0) {
                    sendRawChannel(request, response, true, true);
                } else {
                    sendRawChannel(request, response, true, false);
                }

            } else if (outputProtocol == ChannelInfo.Protocol.PCP) {
                sendPCPChannel();

            } else if (outputProtocol == ChannelInfo.Protocol.PEERCAST) {
                sendPeercastChannel();
            }
        }

        setStatus(Status.CLOSING);
    }

    /** */
    private boolean waitForChannelHeader(HttpServletRequest request, ChannelInfo info) throws IOException {
        for (int i = 0; i < 30 * 10; i++) {
            Channel ch = channelManager.findChannelByID(info.id);
            if (ch == null) {
                return false;
            }

            if (ch.isPlaying() && (ch.rawData.writePos > 0)) {
                return true;
            }

            if (request.getInputStream().available() > 0) {
                break;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
        }
        return false;
    }

    /** */
    private void sendRawChannel(HttpServletRequest request, HttpServletResponse response, boolean sendHead, boolean sendData) {
        try {
Debug.println("head: " + sendHead + ", body: " + sendData);
            sock.setSoTimeout(DIRECT_WRITE_TIMEOUT);

            Channel ch = channelManager.findChannelByID(chanID);
            if (ch == null) {
                throw new IOException("Channel not found");
            }

            setStatus(Status.CONNECTED);

            log.debug(String.format("Starting Raw stream of %s at %d", ch.info.name, streamPos));

            if (sendHead) {
                ch.headPack.writeRaw(response.getOutputStream());
                streamPos = ch.headPack.pos + ch.headPack.data.length;
                log.debug(String.format("Sent %d bytes header ", ch.headPack.data.length));
            }

            if (sendData) {

                int streamIndex = ch.streamIndex;
                long connectTime = System.currentTimeMillis();
                long lastWriteTime = connectTime;

                while (request.getInputStream().available() > 0) {
                    ch = channelManager.findChannelByID(chanID);

                    if (ch != null) {

                        if (streamIndex != ch.streamIndex) {
                            streamIndex = ch.streamIndex;
                            streamPos = ch.headPack.pos;
                            log.debug("sendRaw got new stream index");
                        }

                        ChannelPacket rawPack = ch.rawData.findPacket(streamPos);
                        if (rawPack!= null) {
                            if (syncPos != rawPack.sync) {
                                log.error(String.format("Send skip: %d", rawPack.sync - syncPos));
                            }
                            syncPos = rawPack.sync + 1;

                            if (rawPack.type.equals(ChannelPacket.Type.DATA) ||
                                rawPack.type.equals(ChannelPacket.Type.HEAD)) {
                                rawPack.writeRaw(response.getOutputStream());
                                lastWriteTime = System.currentTimeMillis();
                            }

                            if (rawPack.pos < streamPos) {
                                log.debug(String.format("raw: skip back %d", rawPack.pos - streamPos));
                            }
                            streamPos = rawPack.pos + rawPack.data.length;
                        }
                    }

                    if ((System.currentTimeMillis() - lastWriteTime) > DIRECT_WRITE_TIMEOUT) {
                        throw new IOException("timeout");
                    }

                    try {
                        Thread.sleep(Peercast.idleSleepTime);
                    } catch (InterruptedException e) {
                    }
                }
            }
        } catch (IOException e) {
            log.error(String.format("Stream channel: %s", e.getMessage()));
        }
    }

    /** */
    void sendRawMultiChannel(boolean sendHead, boolean sendData) {
        try {
            int[] chanStreamIndex = new int[ChannelManager.MAX_CHANNELS];
            int[] chanStreamPos = new int[ChannelManager.MAX_CHANNELS];
            GnuID[] chanIDs = new GnuID[ChannelManager.MAX_CHANNELS];
            int numChanIDs = 0;
            for (Channel channel : channelManager.channels) {
                if (channel.isPlaying()) {
                    chanIDs[numChanIDs++] = channel.info.id;
                }
            }

            setStatus(Status.CONNECTED);

            if (sendHead) {
                for (int i = 0; i < numChanIDs; i++) {
                    Channel ch = channelManager.findChannelByID(chanIDs[i]);
                    if (ch != null) {
                        log.debug(String.format("Starting RawMulti stream: %s", ch.info.name));
                        ch.headPack.writeRaw(sock.getOutputStream());
                        chanStreamPos[i] = ch.headPack.pos + ch.headPack.data.length;
                        chanStreamIndex[i] = ch.streamIndex;
                        log.debug(String.format("Sent %d bytes header", ch.headPack.data.length));

                    }
                }
            }

            if (sendData) {

                long connectTime = System.currentTimeMillis();

                while (sock.getInputStream().available() > 0) {

                    for (int i = 1; i < numChanIDs; i++) {
                        Channel ch = channelManager.findChannelByID(chanIDs[i]);
                        if (ch != null) {
                            if (chanStreamIndex[i] != ch.streamIndex) {
                                chanStreamIndex[i] = ch.streamIndex;
                                chanStreamPos[i] = ch.headPack.pos;
                                log.debug(String.format("sendRawMulti got new stream index for chan %d", i));
                            }

                            ChannelPacket rawPack = ch.rawData.findPacket(chanStreamPos[i]);
                            if (rawPack != null) {
                                if (rawPack.type.equals(ChannelPacket.Type.DATA) ||
                                    rawPack.type.equals(ChannelPacket.Type.HEAD)) {
                                    rawPack.writeRaw(sock.getOutputStream());
                                }

                                if (rawPack.pos < chanStreamPos[i]) {
                                    log.debug(String.format("raw: skip back %d", rawPack.pos - chanStreamPos[i]));
                                }
                                chanStreamPos[i] = rawPack.pos + rawPack.data.length;

                            }
                        }
                        break;
                    }

                    try {
                        Thread.sleep(Peercast.idleSleepTime);
                    } catch (InterruptedException e) {
                    }
                }
            }
        } catch (IOException e) {
            log.error(String.format("Stream channel: %s", e.getMessage()));
        }
    }

    /**
     * @param interval
     */
    void sendRawMetaChannel(int interval) {

        try {
            Channel ch = channelManager.findChannelByID(chanID);
            if (ch == null) {
                throw new IOException("Channel not found");
            }

            sock.setSoTimeout(DIRECT_WRITE_TIMEOUT * 1000);

            setStatus(Status.CONNECTED);

            log.debug(String.format("Starting Raw Meta stream of %s (metaint: %d) at %d", ch.info.name, interval, streamPos));

            String lastTitle = null, lastURL = null;

            long lastMsgTime = System.currentTimeMillis();
            boolean showMsg = true;

            byte[] buf = new byte[16384];
            int bufPos = 0;

            if ((interval > buf.length) || (interval < 1))
                throw new IOException("Bad ICY Meta Interval value");

            long connectTime = System.currentTimeMillis();
            long lastWriteTime = connectTime;

            streamPos = 0; // raw meta channel has no header (its MP3)

            while (sock.getInputStream().available() > 0) {
                ch = channelManager.findChannelByID(chanID);

                if (ch != null) {

                    ChannelPacket rawPack = ch.rawData.findPacket(streamPos);
                    if (rawPack != null) {

                        if (syncPos != rawPack.sync) {
                            log.error(String.format("Send skip: %d", rawPack.sync - syncPos));
                        }
                        syncPos = rawPack.sync + 1;

                        ByteArrayOutputStream mem = new ByteArrayOutputStream(); // TODO rawPack.data

                        if (rawPack.type.equals(ChannelPacket.Type.DATA)) {

                            int len = rawPack.data.length;
                            int p = 0; // rawPack.data
                            while (len != 0) {
                                int rl = len;
                                if ((bufPos + rl) > interval) {
                                    rl = interval - bufPos;
                                }
                                System.arraycopy(rawPack.data, p, buf, bufPos, rl);
                                bufPos += rl;
                                p += rl;
                                len -= rl;

                                if (bufPos >= interval) {
                                    bufPos = 0;
                                    sock.getOutputStream().write(buf, 0, interval);
                                    lastWriteTime = System.currentTimeMillis();

                                    if (channelManager.broadcastMsgInterval != 0) {
                                        if ((System.currentTimeMillis() - lastMsgTime) >= channelManager.broadcastMsgInterval) {
                                            showMsg ^= true;
                                            lastMsgTime = System.currentTimeMillis();
                                        }
                                    }

                                    String metaTitle = ch.info.track.title;
                                    if (ch.info.comment.length() != 0 && (showMsg)) {
                                        metaTitle = ch.info.comment;
                                    }

                                    if (!metaTitle.equals(lastTitle) || !ch.info.url.equals(lastURL)) {

                                        String tmp;
                                        String title, url;

                                        title = metaTitle;
                                        url = ch.info.url;

                                        tmp = String.format("StreamTitle='%s';StreamUrl='%s';\0", title, url);
                                        len = (tmp.length() + 15 + 1) / 16;
                                        sock.getOutputStream().write(len);
                                        sock.getOutputStream().write(tmp.getBytes(), 0, len * 16);

                                        lastTitle = metaTitle;
                                        lastURL = ch.info.url;

                                        log.debug(String.format("StreamTitle: %s, StreamURL: %s", lastTitle, lastURL));

                                    } else {
                                        sock.getOutputStream().write(0);
                                    }

                                }
                            }
                        }
                        streamPos = rawPack.pos + rawPack.data.length;
                    }
                }
                if ((System.currentTimeMillis() - lastWriteTime) > DIRECT_WRITE_TIMEOUT) {
                    throw new IOException("timeout");
                }

                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }

            }
        } catch (IOException e) {
            log.error(String.format("Stream channel: %s", e.getMessage()));
        }
    }

    /** */
    void sendPeercastChannel() {
        try {
            setStatus(Status.CONNECTED);

            Channel ch = channelManager.findChannelByID(chanID);
            if (ch == null) {
                throw new IOException("Channel not found");
            }

            log.debug(String.format("Starting PeerCast stream: %s", ch.info.name));

            DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
            dos.write("PCST".getBytes());

            ChannelPacket pack = null;

            ch.headPack.writePeercast(sock.getOutputStream());

            pack = new ChannelPacket(ChannelPacket.Type.META, ch.insertMeta.data, ch.insertMeta.len, ch.streamPos);
            pack.writePeercast(sock.getOutputStream());

            streamPos = 0;
            int syncPos = 0;
            while (sock.getInputStream().available() > 0) {
                ch = channelManager.findChannelByID(chanID);
                if (ch != null) {

                    ChannelPacket rawPack = ch.rawData.findPacket(streamPos);
                    if (rawPack != null) {
                        if (rawPack.type.equals(ChannelPacket.Type.DATA) ||
                            rawPack.type.equals(ChannelPacket.Type.HEAD)) {
                            dos.write("SYNC".getBytes());
                            dos.writeShort(4);
                            dos.writeShort(0);
                            dos.writeInt(syncPos);
                            syncPos++;

                            rawPack.writePeercast(sock.getOutputStream());
                        }
                        streamPos = rawPack.pos + rawPack.data.length;
                    }
                }
                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }

        } catch (IOException e) {
            log.error(String.format("Stream channel: %s", e.getMessage()));
        }
    }

    /** */
    void sendPCPChannel() throws IOException {
        Channel ch = channelManager.findChannelByID(chanID);
        if (ch == null) {
            throw new IOException("Channel not found");
        }

        AtomOutputStream atom = new AtomOutputStream(sock.getOutputStream());

        pcpStream = new PCPStream(remoteID);
        int error = 0;

        try {

            log.debug(String.format("Starting PCP stream of channel at %d", streamPos));

            setStatus(Status.CONNECTED);

            atom.writeParent(PCPStream.PCP_CHAN, 3 + ((sendHeader) ? 1 : 0));
            atom.writeBytes(PCPStream.PCP_CHAN_ID, chanID.id, 16);
            ch.info.writeInfoAtoms(atom);
            ch.info.writeTrackAtoms(atom);
            if (sendHeader) {
                atom.writeParent(PCPStream.PCP_CHAN_PKT, 3);
                atom.writeID4(PCPStream.PCP_CHAN_PKT_TYPE, PCPStream.PCP_CHAN_PKT_HEAD);
                atom.writeInt(PCPStream.PCP_CHAN_PKT_POS, ch.headPack.pos);
                atom.writeBytes(PCPStream.PCP_CHAN_PKT_DATA, ch.headPack.data, ch.headPack.data.length);

                streamPos = ch.headPack.pos + ch.headPack.data.length;
                log.debug(String.format("Sent %d bytes header", ch.headPack.data.length));
            }

            int streamIndex = ch.streamIndex;

            while (true) {

                ch = channelManager.findChannelByID(chanID);

                if (ch != null) {

                    if (streamIndex != ch.streamIndex) {
                        streamIndex = ch.streamIndex;
                        streamPos = ch.headPack.pos;
                        log.debug("sendPCPStream got new stream index");
                    }

                    ChannelPacket rawPack = ch.rawData.findPacket(streamPos);

                    if (rawPack != null) {

                        if (rawPack.type.equals(ChannelPacket.Type.HEAD)) {
                            atom.writeParent(PCPStream.PCP_CHAN, 2);
                            atom.writeBytes(PCPStream.PCP_CHAN_ID, chanID.id, 16);
                            atom.writeParent(PCPStream.PCP_CHAN_PKT, 3);
                            atom.writeID4(PCPStream.PCP_CHAN_PKT_TYPE, PCPStream.PCP_CHAN_PKT_HEAD);
                            atom.writeInt(PCPStream.PCP_CHAN_PKT_POS, rawPack.pos);
                            atom.writeBytes(PCPStream.PCP_CHAN_PKT_DATA, rawPack.data, rawPack.data.length);

                        } else if (rawPack.type.equals(ChannelPacket.Type.DATA)) {
                            atom.writeParent(PCPStream.PCP_CHAN, 2);
                            atom.writeBytes(PCPStream.PCP_CHAN_ID, chanID.id, 16);
                            atom.writeParent(PCPStream.PCP_CHAN_PKT, 3);
                            atom.writeID4(PCPStream.PCP_CHAN_PKT_TYPE, PCPStream.PCP_CHAN_PKT_DATA);
                            atom.writeInt(PCPStream.PCP_CHAN_PKT_POS, rawPack.pos);
                            atom.writeBytes(PCPStream.PCP_CHAN_PKT_DATA, rawPack.data, rawPack.data.length);

                        }

                        if (rawPack.pos < streamPos) {
                            log.debug(String.format("pcp: skip back %d", rawPack.pos - streamPos));
                        }

                        streamPos = rawPack.pos + rawPack.data.length;
                    }

                }
                BroadcastState bcs = new BroadcastState();
                error = pcpStream.readPacket(sock.getInputStream(), sock.getOutputStream(), bcs);
                if (error != 0) {
                    throw new IOException("PCP exception");
                }

                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }

        } catch (IOException e) {
            log.error(String.format("Stream channel: %s", e.getMessage()));
        }

        try {
            atom.writeInt(PCPStream.PCP_QUIT, error);
        } catch (IOException e) {
        }

        log.debug("PCP channel stream closed normally.");
    }

    /** serverProc */
    private SocketHandlerFactory serverProc = new SocketHandlerFactory() {
        /** */
        public Runnable getSocketHandler(final Socket socket) {
            return new Runnable() {
                public void run() {
Debug.println("socket: " + socket);
                    try {
                        if (serventManager.numActiveOnPort(((InetSocketAddress) socket.getLocalSocketAddress()).getPort()) < serventManager.maxServIn) {
                            log.debug("accepted incoming");
                            Servent ns = serventManager.allocServent();
                            serventManager.lastIncoming = System.currentTimeMillis();
                            ns.servPort = ((InetSocketAddress) socket.getLocalSocketAddress()).getPort();
                            ns.networkID = serventManager.networkID;

                            // initIncoming()
                            ns.type = Type.INCOMING;
                            ns.sock = socket;
                            ns.allow = allow;
                            ns.setStatus(Status.PROTOCOL);
                            log.debug("Incoming from " + socket.getRemoteSocketAddress());

                            ns.handshakeIncoming();
                        }
                    } catch (Exception e) {
Debug.printStackTrace(e);
                        try {
                            kill();
                        } catch (IOException f) {
                            f.printStackTrace();
                        }
                        log.error("Server Error: " + e.getMessage());
                    } finally {
//                        log.debug("Server stopped");
Debug.println("one request done");
                    }
                }
            };
        }
    };

    /** */
    boolean writeVariable(OutputStream s, final String var) throws IOException {
        String buf;

        if (var.equals("type")) {
            buf = type.name();
        } else if (var.equals("status")) {
            buf = status.name();
        } else if (var.equals("address")) {
            buf = getHost().getHostName();
        } else if (var.equals("agent")) {
            buf = agent;
        } else if (var.equals("bitrate")) {
            if (sock != null) {
                int tot = Peercast.getInstance().bytesInPerSec + Peercast.getInstance().bytesOutPerSec;
                buf = String.format("%.1f", Peercast.BYTES_TO_KBPS(tot));
            } else {
                buf = "0";
            }
        } else if (var.equals("uptime")) {
            buf = Peercast.getFromStopwatch((int) ((System.currentTimeMillis() - lastConnect) / 1000));
        } else if (var.startsWith("gnet.")) {

            float ctime = (System.currentTimeMillis() - lastConnect);
            if (var == "gnet.packetsIn") {
                buf = String.format("%d", gnuStream.packetsIn);
            } else if (var.equals("gnet.packetsInPerSec")) {
                buf = String.format("%.1f", ctime > 0 ? gnuStream.packetsIn / ctime : 0);
            } else if (var.equals("gnet.packetsOut")) {
                buf = String.format("%d", gnuStream.packetsOut);
            } else if (var.equals("gnet.packetsOutPerSec")) {
                buf = String.format("%.1f", ctime > 0 ? gnuStream.packetsOut / ctime : 0);
            } else if (var.equals("gnet.normQueue")) {
                buf = String.format("%d", outPacketsNorm.numPending());
            } else if (var.equals("gnet.priQueue")) {
                buf = String.format("%d", outPacketsPri.numPending());
            } else if (var.equals("gnet.flowControl")) {
                buf = String.format("%d", flowControl ? 1 : 0);
            } else if (var.equals("gnet.routeTime")) {
                int nr = numUsed();
                long tim = System.currentTimeMillis() - getOldest();

                String tstr = Peercast.getFromStopwatch((int) (tim / 1000));

                if (nr != 0) {
                    buf = tstr;
                } else {
                    buf = "-";
                }
            } else {
                return false;
            }

        } else {
            return false;
        }

        s.write(buf.getBytes());

        return true;
    }

    /** */
    long getOldest() {
        long t = -1;
        for (int i = 0; i < seenIDs.size(); i++) {
            if (seenIDs.get(i).storeTime > 0) {
                if (seenIDs.get(i).storeTime < t) {
                    t = seenIDs.get(i).storeTime;
                }
            }
        }
        return t;
    }

    boolean isOlderThan(Servent s) {
        if (s != null) {
            long t = System.currentTimeMillis();
            return ((t - lastConnect) > (t - s.lastConnect));
        } else {
            return true;
        }
    }

    /** */
    Node addBasicHeader(Document document) {
        writeOK(Peercast.MIME_HTML);
        Element html = Peercast.newElement("html");
        document.appendChild(html);
        addHead(html);
        Element body = Peercast.newElement("body");
        html.appendChild(body);
        return body;
    }

    void writeOK(String type) {
        // out.writeLine(HTTP_SC_OK);
        // out.writeLine("%s %s", HTTP_HS_SERVER, PCX_AGENT);
        // out.writeLine("%s %s", HTTP_HS_CONNECTION, "close");
        // out.writeLine("%s %s", HTTP_HS_CONTENT, type);
        // out.writeLine("");
    }

    void addHead(Element html) {
        Element head = Peercast.newElement("head");

        Element e = Peercast.newElement("title");
        e.setTextContent("title"); // TODO title is variable
        head.appendChild(e);

        e = Peercast.newElement("meta");
        e.setAttribute("http-equiv", "Content-Type\" content=\"text/html; charset=iso-8859-1\"");
        head.appendChild(e);

        e = Peercast.newElement("meta");
        if (refreshURL != null) {
            e.setAttribute("http-equiv", String.format("http-equiv=\"refresh\" content=\"%d;URL=%s\"", refresh, refreshURL));
        } else if (refresh != 0) {
            e.setAttribute("http-equiv", String.format("http-equiv=\"refresh\" content=\"%d\"", refresh));
        }
        head.appendChild(e);

        html.appendChild(head);
    }

    /** */
    void addHeader(Document html, int sel) {
        addBasicHeader(html);

        Element e = Peercast.newElement("div");
        e.setAttribute("align", "center"); // GnuPacket.PCX_VERSTRING
        html.appendChild(e);

        if (serventManager.downloadURL.length() != 0) {

            Element e1 = Peercast.newElement("font");
            e1.setAttribute("color", "#FF0000");
            Element e2 = Peercast.newElement("div");
            e2.setAttribute("align", "center");
            Element e3 = Peercast.newElement("h2");
            e3.setTextContent("! Attention !");
            e1.appendChild(e2.appendChild(e3));
            html.appendChild(e1);

            e1 = Peercast.newElement("h3");
            e2 = Peercast.newElement("div");
            e2.setAttribute("align", "center");
            e3 = Peercast.newElement("a");
            e3.setAttribute("href", "/admin?cmd=upgrade");
            e3.setTextContent("Click here to update your client");
            e1.appendChild(e2.appendChild(e3));
            html.appendChild(e1);
        }

        if (serventManager.rootMsg.length() != 0) {

            Element e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            Element e2 = Peercast.newElement("h3");
            e2.setTextContent(serventManager.rootMsg);
            e1.appendChild(e2);
            html.appendChild(e1);
        }

        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#CCCCCC");

        if (sel >= 0) {
            Element td = Peercast.newElement("td");
            tr.setAttribute("bgcolor", "#CCCCCC");
            Element e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            Element e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=index");
            e2.setTextContent(sel == 1 ? "<b>Index</b>" : "Index");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            tr.setAttribute("bgcolor", "#CCCCCC");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            if (serventManager.isRoot) {
                e2.setAttribute("href", "/admin?page=chans");
                e2.setTextContent(sel == 2 ? "<b>All channels</b>" : "All channels");
            } else {
                e2.setAttribute("href", String.format("http://yp.peercast.org?port=%d", serventManager.serverHost.getPort()));
                e2.setAttribute("target", "_blank");
                e2.setTextContent("Yellow Pages");
            }
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=mychans");
            e2.setTextContent(sel == 3 ? "<b>Relayed channels</b>" : "Relayed channels");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=broadcast");
            e2.setTextContent(sel == 8 ? "<b>Broadcast</b>" : "Broadcast");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=connections");
            e2.setTextContent(sel == 4 ? "<b>Connections</b>" : "Connections");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=settings");
            e2.setTextContent(sel == 5 ? "<b>Settings</b>" : "Settings");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=viewlog");
            e2.setTextContent(sel == 7 ? "<b>View Log</b>" : "View Log");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));

            td = Peercast.newElement("td");
            e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            e2 = Peercast.newElement("a");
            e2.setAttribute("href", "/admin?page=logout");
            e2.setTextContent(sel == 6 ? "<b>Logout</b>" : "Logout");
            tr.appendChild(td.appendChild(e1.appendChild(e2)));
        } else {
            Element td = Peercast.newElement("td");
            html.appendChild(td);
        }

        table.appendChild(tr); // tr

        html.appendChild(table); // table

        e = Peercast.newElement("b");
        Element e1 = Peercast.newElement("br");
        html.appendChild(e.appendChild(e1));
    }

    /** */
    void addFooter(Document html) {
        Element e1 = Peercast.newElement("p");
        e1.setAttribute("width", "100%");
        Element e2 = Peercast.newElement("br");
        html.appendChild(e1.appendChild(e2));

        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#CCCCCC");

        Element td = Peercast.newElement("td");

        e1 = Peercast.newElement("div");
        e1.setAttribute("align", "center");
        e1.setTextContent("&copy; <a target=\"_blank\" href=/admin?cmd=redirect&url=www.peercast.org>peercast.org</a> 2004");
        td.appendChild(e1);
        tr.appendChild(td);

        table.appendChild(tr); // body
        html.appendChild(table); // html
    }

    /** */
    void addAdminPage(Document html) {
        refresh = serventManager.refreshHTML;
        addHeader(html, 1);

        Element table = Peercast.newElement("table");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("valign", "top");
        addInformation(html); // TODO html structure

        tr.appendChild(td);

        td = Peercast.newElement("td");
        td.setAttribute("valign", "top");
        addStatistics(html); // TODO html structure

        tr.appendChild(td);

        table.appendChild(tr);
        addFooter(html);
    }

    /** */
    void addLogPage(Document html) {
        addHeader(html, 7);

        Element element = Peercast.newElement("a");
        element.setAttribute("href", "/admin?cmd=clearlog");
        element.setTextContent("Clear log<br>");
        html.appendChild(element);

        element = Peercast.newElement("a");
        element.setAttribute("href", "#bottom");
        element.setTextContent(" View tail<br><br>");
        html.appendChild(element);

        element = Peercast.newElement("font");
        element.setAttribute("size", "-1");
        element.setTextContent(" View tail<br><br>");

        try {
            PrettyPrinter pp = new PrettyPrinter(System.err);
            pp.print(html);
        } catch (IOException e) {
        }

        html.appendChild(element);

        element = Peercast.newElement("a");
        element.setAttribute("href", "/admin?page=viewlog");
        element.setTextContent("<br>View top");
        html.appendChild(element);

        element = Peercast.newElement("a");
        element.setAttribute("name", "bottom");
        html.appendChild(element);

        addFooter(html);
    }

    /** */
    void addLoginPage(Document html) {
        addHeader(html, -1);

        Element table = Peercast.newElement("table");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Login</b>");

        Element form = Peercast.newElement("form");
        form.setAttribute("method", "get");
        form.setAttribute("action", "/admin?");

        Element input = Peercast.newElement("input");
        input.setAttribute("name", "cmd");
        input.setAttribute("type", "hidden");
        input.setAttribute("value", "login");

        form.appendChild(input);
        td.appendChild(form);
        tr.appendChild(td);

        int row = 0;
        // password
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Password");

        td = Peercast.newElement("td");

        input = Peercast.newElement("input");
        input.setAttribute("name", "pass");
        input.setAttribute("size", "10");
        input.setAttribute("type", "password");

        td.appendChild(input);
        tr.appendChild(td);

        // login
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("");

        td = Peercast.newElement("td");

        input = Peercast.newElement("input");
        input.setAttribute("name", "submit");
        input.setAttribute("type", "submit");
        input.setAttribute("id", "submit");
        input.setAttribute("value", "Login");

        td.appendChild(input);
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);

        addFooter(html);
    }

    /** */
    void addLogoutPage(Document html) {
        addHeader(html, 6);

        html.setTextContent("table border=\"0\" align=\"center\"");

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td colspan=\"2\" valign=\"top\"");

        html.setTextContent("tr align=\"center\"");
        Element td = Peercast.newElement("td");
        if ((serventManager.authType != ServentManager.AuthType.HTTPBASIC) && !((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
            html.setTextContent("form method=\"get\" action=\"/admin\"");
            html.setTextContent("input name=\"logout\" type=\"submit\" value=\"Logout\"");
            html.setTextContent("input name=\"cmd\" type=\"hidden\" value=\"logout\"");
            html.appendChild(null);
        }
        html.appendChild(null);
        td = Peercast.newElement("td");
        html.setTextContent("form method=\"get\" action=\"/admin\"");
        html.setTextContent("input name=\"logout\" type=\"submit\" value=\"Shutdown\"");
        html.setTextContent("input name=\"page\" type=\"hidden\" value=\"shutdown\"");
        html.appendChild(null);
        html.appendChild(null);

        html.appendChild(null);
        html.appendChild(null);

        html.appendChild(null); // form

        html.appendChild(null); // table

        addFooter(html);
    }

    /** */
    void addShutdownPage(Document html) {
        Element e1 = Peercast.newElement("h1");
        Element e2 = Peercast.newElement("div");
        e2.setAttribute("align", "center");
        e2.setTextContent("PeerCast will shutdown in 3 seconds");
        e1.appendChild(e2);
        html.appendChild(e1);
        serventManager.shutdownTimer = 3;
    }

    /** */
    void addChannelSourceTag(Document html, Channel c) {
        String stype = c.sourceType.toString();
        String ptype = c.info.srcProtocol.name();

        if (c.sourceURL.length() != 0) {
            Element td = Peercast.newElement("td");
            td.setTextContent(String.format("%s-%s:<br>%s", stype, ptype, c.sourceURL));
        } else {
            String ipStr;
            if (c.sock != null)
                ipStr = ((InetSocketAddress) c.sock.getRemoteSocketAddress()).getHostName();
            else {
                ipStr = "Unknown";
            }

            Element td = Peercast.newElement("td");
            td.setTextContent(String.format("%s-%s:<br>%s", stype, ptype, ipStr));
        }
    }

    /** */
    void addChanInfo(Document html, ChannelInfo info, Channel ch) {
        int row = 0;

        TrackInfo track;
        String name, genre, url, desc, comment, temp, hitTime;

        track = info.track;
        name = info.name;
        genre = info.genre;
        url = info.url;
        desc = info.desc;
        comment = info.comment;

        String idStr = info.id.toString();

        Element table = Peercast.newElement("table");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Channel Information</b>");
        tr.appendChild(td);

        row++;
        tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        td = Peercast.newElement("td");
        td.setTextContent("Name");
        tr.appendChild(td);

        td = Peercast.newElement("td");
        Element a = Peercast.newElement("a");
        a.setAttribute("href", String.format("peercast://pls/%s", idStr));
        a.setTextContent(name);
        td.appendChild(a);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        td = Peercast.newElement("td");
        td.setTextContent("Genre");
        tr.appendChild(td);

        td = Peercast.newElement("td");
        td.setTextContent(genre);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Desc.");
        td = Peercast.newElement("td");
        td.setTextContent(desc);
        html.appendChild(null);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("URL");

        td = Peercast.newElement("td");
        String tmp = String.format("/admin?cmd=redirect&url=%s", url);
        Element e = Peercast.newElement("a");
        e.setAttribute("hraf", url);
        e.setAttribute("target", "_blank"); // TODO html structure
        e.setTextContent(tmp);
        td.appendChild(e);

        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Comment");
        td = Peercast.newElement("td");
        td.setTextContent(comment);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("ID");
        td = Peercast.newElement("td");
        td.setTextContent(idStr);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Type");
        td = Peercast.newElement("td");
        td.setTextContent(info.contentType.name());
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Bitrate");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d kb/s", info.bitrate));
        tr.appendChild(td);

        if (ch != null) {
            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Source");
            addChannelSourceTag(html, ch);
            tr.appendChild(td);

            table.appendChild(tr);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Uptime");
            tr.appendChild(td);
            String uptime;
            if (Peercast.getInstance().lastPlayTime != 0) {
                uptime = Peercast.getFromStopwatch((int) ((System.currentTimeMillis() - Peercast.getInstance().lastPlayTime) / 1000));
            } else {
                uptime = "-";
            }
            td = Peercast.newElement("td");
            td.setTextContent(uptime);
            tr.appendChild(td);

            table.appendChild(tr);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Skips");
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", info.numSkips));
            tr.appendChild(td);

            table.appendChild(tr);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Status");
            td = Peercast.newElement("td");
            td.setTextContent(ch.status.toString());
            tr.appendChild(td);

            table.appendChild(tr);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Position");
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", ch.streamPos));
            tr.appendChild(td);

            table.appendChild(tr);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Head");
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d (%d bytes)", ch.headPack.pos, ch.headPack.data.length));
            tr.appendChild(td);

            table.appendChild(tr);
        }

        row++;
        td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setAttribute("align", "center");
        td.setTextContent("<b>Current Track</b>");
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Artist");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(track.artist);
        html.appendChild(null);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Title");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(track.title);
        html.appendChild(null);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Album");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(track.album);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Genre");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(track.genre);
        tr.appendChild(td);

        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Contact");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(track.contact);
        tr.appendChild(td);

        table.appendChild(tr);

        html.appendChild(table);
    }

    /** */
    void addChanHits(Document html, ChannelHitList chl, ChannelHit source, ChannelInfo info) {

        html.setTextContent("br");

        html.setTextContent("table border=\"0\" align=\"center\"");

        html.setTextContent("tr bgcolor=\"#cccccc\" align=\"center\"");
        Element td = Peercast.newElement("td");
        td.setTextContent(" ");
        td = Peercast.newElement("td");
        td.setTextContent("<b>IP:Port</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Hops</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Listeners</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Relays</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Uptime</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Skips</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Push</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Busy</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Tracker</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Agent</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Update</b>");
        html.appendChild(null);

        int row = 0;

        Collections.sort(chl.hits);

        for (ChannelHit ch : chl.hits) {
            if (ch.getAddress() != null) {
                row++;

                boolean isSource = false;

                if (source != null) {
                    if (source.getAddress().equals(ch.getAddress())) {
                        isSource = true;
                    }
                }

                td = Peercast.newElement("td");
                td.setTextContent(isSource ? "*" : "");

                // IP
                String ip0Str = ch.remoteAddresses[0].getHostName();
                String ip1Str = ch.remoteAddresses[1].getHostName();

                // ID
                String idStr = info.id.toString();

                if ((ch.remoteAddresses[0].getAddress() != ch.remoteAddresses[1].getAddress()) && (ch.remoteAddresses[1].getAddress() != null)) {
                    td = Peercast.newElement("td");
                    td.setTextContent(String.format("%s/%s", ip0Str, ip1Str));
                } else {
                    td = Peercast.newElement("td");
                    td.setTextContent(ip0Str);
                }

                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", ch.numHops));
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", ch.numListeners));
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", ch.numRelays));

                String hitTime;
                hitTime = Peercast.getFromStopwatch((int) (ch.upTime / 1000));
                td = Peercast.newElement("td");
                td.setTextContent(hitTime);

                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", 0)); // ch.numSkips

                td = Peercast.newElement("td");
                td.setTextContent(String.format("%s", ch.firewalled ? "Yes" : "No"));
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%s", "No")); // ch.busy ? "Yes" : "No"
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%s", ch.tracker ? "Yes" : "No"));

                if (ch.agentStr.length() != 0) {
                    td = Peercast.newElement("td");
                    td.setTextContent(String.format("%s", ch.agentStr));
                } else {
                    td = Peercast.newElement("td");
                    td.setTextContent("-");
                }

                if (ch.time != 0) {
                    hitTime = Peercast.getFromStopwatch((int) ((System.currentTimeMillis() - ch.time) / 1000));
                } else {
                    hitTime = "-";
                }
                td = Peercast.newElement("td");
                td.setTextContent(hitTime);

                html.appendChild(null);
            }
        }

        html.appendChild(null);
    }

    /** */
    void addSettingsPage(Document html) {
        addHeader(html, 5);

        html.setTextContent("table border=\"0\" align=\"center\"");

        html.setTextContent("form method=\"get\" action=\"/admin\"");

        html.setTextContent("input name=\"cmd\" type=\"hidden\" value=\"apply\"");

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td valign=\"top\"");
        addBroadcasterOptions(html);
        html.appendChild(null);
        html.appendChild(null);

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td valign=\"top\"");
        addServerOptions(html);
        html.appendChild(null);
        html.setTextContent("td valign=\"top\"");
        addRelayOptions(html);
        html.appendChild(null);
        html.appendChild(null);

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td valign=\"top\"");
        addFilterOptions(html);
        html.appendChild(null);
        html.setTextContent("td valign=\"top\"");
        addSecurityOptions(html);
        html.appendChild(null);
        html.appendChild(null);

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td valign=\"top\"");
        addAuthOptions(html);
        html.appendChild(null);
        html.setTextContent("td valign=\"top\"");
        addLogOptions(html);
        html.appendChild(null);
        html.appendChild(null);

        if (serventManager.isRoot) {
            html.setTextContent("tr align=\"center\"");
            html.setTextContent("td valign=\"top\"");
            addRootOptions(html);
            html.appendChild(null);
            html.appendChild(null);
        }

        html.setTextContent("tr align=\"center\"");
        html.setTextContent("td colspan=\"2\"");
        html.setTextContent("input name=\"submit\" type=\"submit\" value=\"Save Settings\"");
        html.appendChild(null);
        html.appendChild(null);

        html.appendChild(null); // form

        html.appendChild(null); // table

        addFooter(html);
    }

    /** */
    void addWinampSettingsPage(Document html) {
        addBasicHeader(html);

        html.setTextContent("form method=\"get\" action=\"/admin\"");
        html.setTextContent("input name=\"submit\" type=\"submit\" value=\"Save Settings\"");
        html.setTextContent("input name=\"cmd\" type=\"hidden\" value=\"apply\"");

        addServerOptions(html);
        addBroadcasterOptions(html);
        addRelayOptions(html);
        addFilterOptions(html);
        addSecurityOptions(html);
        addAuthOptions(html);
        addLogOptions(html);

        if (serventManager.isRoot) {
            addRootOptions(html);
        }

        html.appendChild(null); // form

        addFooter(html);
    }

    /** */
    static int addStat(Document html, int row, int totIn, int totOut, final String name, Stats.STAT in, Stats.STAT out) {
        row++;
        Element td = Peercast.newElement("td");
        td.setTextContent(name);
        int v;

        if ((in.ordinal() != 0) && (totIn != 0)) {
            v = Peercast.getInstance().stats.getCurrent(in);
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", v));
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", totIn != 0 ? ((v * 100) / totIn) : 0));
        } else {
            td = Peercast.newElement("td");
            td.setTextContent("-");
            td = Peercast.newElement("td");
            td.setTextContent("-");
        }

        if ((out.ordinal() != 0) && (totOut != 0)) {
            v = Peercast.getInstance().stats.getCurrent(out);
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", v));
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", totOut != 0 ? ((v * 100) / totOut) : 0));
        } else {
            td = Peercast.newElement("td");
            td.setTextContent("-");
            td = Peercast.newElement("td");
            td.setTextContent("-");
        }

        html.appendChild(null);
        return row;
    }

    /** */
    void addNetStatsPage(Document html) {
        addHeader(html, 0);

        int row = 0;
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "50%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("width", "100%");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "5");
        td.setTextContent("<b>Packets</b>");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent(" ");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>In</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(String.format("<b>In %s</b>", "%%"));
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>Out</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(String.format("<b>Out %s</b>", "%%"));
        tr.appendChild(td);

        int totalIn = Peercast.getInstance().stats.getCurrent(Stats.STAT.NUMPACKETSIN);
        int totalOut = Peercast.getInstance().stats.getCurrent(Stats.STAT.NUMPACKETSOUT);

        row = addStat(html, row, totalIn, totalOut, "Total", Stats.STAT.NUMPACKETSIN, Stats.STAT.NUMPACKETSOUT);
        row = addStat(html, row, totalIn, totalOut, "Ping", Stats.STAT.NUMPINGIN, Stats.STAT.NUMPINGOUT);
        row = addStat(html, row, totalIn, totalOut, "Pong", Stats.STAT.NUMPONGIN, Stats.STAT.NUMPONGOUT);
        row = addStat(html, row, totalIn, totalOut, "Push", Stats.STAT.NUMPUSHIN, Stats.STAT.NUMPUSHOUT);
        row = addStat(html, row, totalIn, totalOut, "Query", Stats.STAT.NUMQUERYIN, Stats.STAT.NUMQUERYOUT);
        row = addStat(html, row, totalIn, totalOut, "Hit", Stats.STAT.NUMHITIN, Stats.STAT.NUMHITOUT);
        row = addStat(html, row, totalIn, totalOut, "Other", Stats.STAT.NUMOTHERIN, Stats.STAT.NUMOTHEROUT);
        row = addStat(html, row, totalIn, totalOut, "Accepted", Stats.STAT.NUMACCEPTED, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Dropped", Stats.STAT.NUMDROPPED, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Duplicate", Stats.STAT.NUMDUP, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Old", Stats.STAT.NUMOLD, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Dead", Stats.STAT.NUMDEAD, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Routed", Stats.STAT.NUMROUTED, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Broadcasted", Stats.STAT.NUMBROADCASTED, Stats.STAT.NONE);
        row = addStat(html, row, totalIn, totalOut, "Discarded", Stats.STAT.NUMDISCARDED, Stats.STAT.NONE);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Avg. Size");
        tr.appendChild(td);

        if (totalIn != 0) {
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", Peercast.getInstance().stats.getCurrent(Stats.STAT.PACKETDATAIN) / totalIn));
        } else {
            td = Peercast.newElement("td");
            td.setTextContent("-");
        }
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("-");
        tr.appendChild(td);

        if (totalOut != 0) {
            td = Peercast.newElement("td");
            td.setTextContent(String.format("%d", Peercast.getInstance().stats.getCurrent(Stats.STAT.PACKETDATAOUT) / totalOut));
        } else {
            td = Peercast.newElement("td");
            td.setTextContent("-");
        }
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("-");
        tr.appendChild(td);

        int i;
        for (i = 0; i < 10; i++) {
            String str;
            str = String.format("Hops %d", i + 1);
            row = addStat(html, row, totalIn, totalOut, str, Stats.STAT.values()[i], Stats.STAT.NONE);
        }

        if (totalIn != 0) {
            for (i = 0; i < serventManager.numVersions; i++) {
                row++;
                td = Peercast.newElement("td");
                td.setTextContent(String.format("v%05X", serventManager.clientVersions[i]));
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", serventManager.clientCounts[i]));
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", (serventManager.clientCounts[i] * 100) / totalIn));
                td = Peercast.newElement("td");
                td.setTextContent("-");
                td = Peercast.newElement("td");
                td.setTextContent("-");
                tr.appendChild(td);
            }
        }

        row++;
        td = Peercast.newElement("td");
        td.setAttribute("colspan", "5");
        td.setTextContent("<a href=\"/admin?cmd=clear&packets=1\">Reset</a>");
        tr.appendChild(td);

        html.appendChild(table);

        addFooter(html);
    }

    /** */
    void addInformation(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        tr.setAttribute("colspan", "2");
        td.setTextContent("<b>Information</b>");
        tr.appendChild(td);

        int row = 0;

        // server IP
        String ipStr = serventManager.serverHost.getHostName();
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Server IP");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%s", ipStr));
        tr.appendChild(td);

        // uptime
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Uptime");
        String upt = Peercast.getFromStopwatch((int) (serventManager.getUptime() / 1000));
        td = Peercast.newElement("td");
        td.setTextContent(upt);
        tr.appendChild(td);

        // channels found
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Channels found");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", channelManager.numHitLists()));
        tr.appendChild(td);

        // channels relayed
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Total relays");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d / %d", 0, channelManager.numChannels())); // chanMgr.numRelayed()
        tr.appendChild(td);

        // direct listeners
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Total listeners");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", 0)); // chanMgr.numListeners()
        tr.appendChild(td);

        // total streams
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Total streams");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d / %d", serventManager.numStreams(null, false), serventManager.numStreams(null, true)));
        tr.appendChild(td);

        // total connected
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Total connected");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", serventManager.totalConnected()));
        tr.appendChild(td);

        // outgoing
        // row++;
        // html.startTagEnd("td","Num outgoing");
        // html.startTagEnd("td","%d",servMgr.numConnected(T_OUTGOING));
        // html.end();

        // host cache
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Host cache (Servents)");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d - <a href=\"/admin?cmd=clear&hostcache=1\">Clear</a>", serventManager.getServiceHostsCount(ServHost.Type.SERVENT)));
        tr.appendChild(td);

        // XML stats
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("XML stats");
        td = Peercast.newElement("td");
        td.setTextContent("<a href=\"/admin?cmd=viewxml\">View</a>");
        tr.appendChild(td);

        // Network stats
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Network stats");
        td = Peercast.newElement("td");
        td.setTextContent("<a href=\"/admin?page=viewnet\">View</a>");
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void printTest(String tag, Object fmt) {
        if (fmt != null) {

            // va_list ap;
            // va_start(ap, fmt);

            // char tmp[512];
            System.out.printf("%f", 10);
            // vsprintf(tmp,fmt,ap);
            // startNode(tag,tmp);

            // va_end(ap);
        } else {
            // startNode(tag,NULL);
        }
        // end();
    }

    /** */
    void addStatistics(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "4");
        td.setTextContent("<b>Bandwidth</b>");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent(" ");
        td = Peercast.newElement("td");
        td.setTextContent("<b>In</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Out</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Total</b>");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Total (Kbit/s)");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESIN))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESOUT))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESIN) + Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESOUT))));
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Internet (Kbit/s)");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESIN) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESIN))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESOUT) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESOUT))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESIN) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESIN) + Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESOUT) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESOUT))));
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Network (Kbit/s)");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.PACKETDATAIN))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.PACKETDATAOUT))));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(Peercast.getInstance().stats.getPerSecond(Stats.STAT.PACKETDATAIN) + Peercast.getInstance().stats.getPerSecond(Stats.STAT.PACKETDATAOUT))));
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Packets/sec");
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", Peercast.getInstance().stats.getPerSecond(Stats.STAT.NUMPACKETSIN)));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", Peercast.getInstance().stats.getPerSecond(Stats.STAT.NUMPACKETSOUT)));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("%d", Peercast.getInstance().stats.getPerSecond(Stats.STAT.NUMPACKETSIN) + Peercast.getInstance().stats.getPerSecond(Stats.STAT.NUMPACKETSOUT)));
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addServerOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Server</b>");
        tr.appendChild(td);

        // password
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Password");
        tr.appendChild(td);

        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("name", "passnew");
        e.setAttribute("size", "10");
        e.setAttribute("type", "password");
        e.setAttribute("value", serventManager.password);
        tr.appendChild(td.appendChild(e));

        // firewall
        row++;

        td = Peercast.newElement("td");
        td.setTextContent("Type");
        tr.appendChild(td);
        {
            switch (serventManager.getFirewall()) {
            case ON:
                td = Peercast.newElement("td");
                td.setTextContent("Firewalled");
                break;
            case OFF:
                td = Peercast.newElement("td");
                td.setTextContent("Normal");
                break;
            default:
                td = Peercast.newElement("td");
                td.setTextContent("Unknown");
                break;
            }
        }
        tr.appendChild(td);

        // icy meta interval
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("ICY MetaInterval");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("name", "icymeta");
        e.setAttribute("size", "5");
        e.setAttribute("type", "text");
        e.setAttribute("value", String.valueOf(channelManager.icyMetaInterval));
        tr.appendChild(td.appendChild(e));

        // mode
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Mode");
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "radio");
        e.setAttribute("name", "root");
        e.setAttribute("value", "0");
        e.setAttribute("checked", !serventManager.isRoot ? "1" : "");
        e.setTextContent("Normal");
        td.appendChild(e);
        e = Peercast.newElement("i");
        e.setTextContent("Normal<br>");
        td.appendChild(e);
        e.setAttribute("type", "radio");
        e.setAttribute("name", "root");
        e.setAttribute("value", "1");
        e.setAttribute("checked", !serventManager.isRoot ? "1" : "");
        td.appendChild(e);
        e = Peercast.newElement("i");
        e.setTextContent("Root");
        td.appendChild(e);
        tr.appendChild(td);

        // refresh HTML
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Refresh HTML (sec)");
        td = Peercast.newElement("td");
        td.appendChild(e);
        e = Peercast.newElement("input");
        e.setAttribute("name", "refresh");
        e.setAttribute("size", "5");
        e.setAttribute("type", "text");
        e.setAttribute("value", String.valueOf(serventManager.refreshHTML));
        td.appendChild(e);
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addClientOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Client</b>");
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addBroadcasterOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Broadcasting</b>");
        tr.appendChild(td);

        // YP
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("YP Address");
        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("name", "yp");
        e.setAttribute("type", "text");
        e.setAttribute("value", serventManager.rootHost);
        td.appendChild(e);
        tr.appendChild(td);

        // DJ message
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("DJ Message");
        td = Peercast.newElement("td");
        {
            String djMsg = channelManager.broadcastMessage;
            e = Peercast.newElement("input");
            e.setAttribute("name", "djmsg");
            e.setAttribute("type", "text");
            e.setAttribute("value", djMsg);
            td.appendChild(e);
            tr.appendChild(td);
        }
        tr.appendChild(td);
        table.appendChild(tr);

        html.appendChild(table);
    }

    /** */
    void addRelayOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Network</b>");
        tr.appendChild(td);

        // max streams
        // row++;
        // td = Peercast.newElement("td");
        // td.setAttribute("width", "50%");
        // td.setTextContent("Max. Total Streams");
        // tr.appendChild(td);
        // td = Peercast.newElement("td");
        // Element e = Peercast.newElement("input");
        // e.setAttribute("name", "maxstream");
        // e.setAttribute("size", "5");
        // e.setAttribute("type", "text");
        // e.setAttribute("value", String.valueOf(servMgr.maxStreams));
        // td.appendChild(e);
        // tr.appendChild(td);

        // max streams/channel
        // row++;
        // td = Peercast.newElement("td");
        // td.setAttribute("width", "50%");
        // td.setTextContent("Max. Streams Per Channel");
        // tr.appendChild(td);
        // td = Peercast.newElement("td");
        // e = Peercast.newElement("input");
        // e.setAttribute("name", "maxlisten");
        // e.setAttribute("size", "5");
        // e.setAttribute("type", "text");
        // e.setAttribute("value", String.valueOf(chanMgr.maxStreamsPerChannel));
        // td.appendChild(e);
        // tr.appendChild(td);

        // max bitrate out
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Max. Output (Kbits/s)");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("name", "maxup");
        e.setAttribute("size", "5");
        e.setAttribute("type", "text");
        e.setAttribute("value", String.valueOf(serventManager.maxBitrateOut));
        td.appendChild(e);
        tr.appendChild(td);

        // max control connections
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Max. Controls In");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("name", "maxcin");
        e.setAttribute("size", "5");
        e.setAttribute("type", "text");
        e.setAttribute("value", String.valueOf(serventManager.maxControl));
        td.appendChild(e);
        tr.appendChild(td);

        html.appendChild(table);
    }

    /** */
    void addFilterOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "5");
        td.setTextContent("<b>Filters</b>");
        tr.appendChild(td);

        // ip
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("<b>IP Mask</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>Network</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>Direct</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>Private</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent("<b>Ban</b>");
        tr.appendChild(td);

        // filters
        int i = 0;
        for (ServFilter f : serventManager.filters) {

            row++;
            td = Peercast.newElement("td");
            Element e = Peercast.newElement("input");
            e.setAttribute("name", "filt_ip" + i);
            e.setAttribute("type", "text");
            e.setAttribute("value", f.getMask());
            td.appendChild(e);
            tr.appendChild(td);
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", String.format("filt_nw%d", i));
            e.setAttribute("type", "checkbox");
            e.setAttribute("value", "1");
            e.setAttribute("checked", (f.flags & ServFilter.Type.NETWORK.value) != 0 ? "1" : "");
            td.appendChild(e);
            tr.appendChild(td);
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("type", "checkbox");
            e.setAttribute("name", "filt_di");
            e.setAttribute("value", "1");
            e.setAttribute("checked", (f.flags & ServFilter.Type.DIRECT.value) != 0 ? "1" : "");
            td.appendChild(e);
            tr.appendChild(td);
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("type", "checkbox");
            e.setAttribute("name", "filt_pr");
            e.setAttribute("value", "1");
            e.setAttribute("checked", (f.flags & ServFilter.Type.PRIVATE.value) != 0 ? "1" : "");
            td.appendChild(e);
            tr.appendChild(td);
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("type", "checkbox");
            e.setAttribute("name", "filt_bn");
            e.setAttribute("value", "1");
            e.setAttribute("checked", (f.flags & ServFilter.Type.BAN.value) != 0 ? "1" : "");
            td.appendChild(e);
            tr.appendChild(td);

            table.appendChild(tr);
            i++;
        }

        html.appendChild(table);
    }

    /** */
    void addLogOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Log</b>");
        tr.appendChild(td);

        // Debug
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Debug");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "logDebug");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (serventManager.showLog & (1 << 1)) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);

        // Errors
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Errors");
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "logErrors");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (serventManager.showLog & (1 << 2)) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);

        // Network
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Network");
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "logNetwork");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (serventManager.showLog & (1 << 3)) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);

        // channels
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Channels");
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "logChannel");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (serventManager.showLog & (1 << 4)) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addRootOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        tr.appendChild(td);
        td.setTextContent("<b>Root Mode</b>");
        tr.appendChild(td);

        // host update interval
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Host Update (sec)");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("type", "text");
        e.setAttribute("name", "huint");
        e.setAttribute("size", "5");
        e.setAttribute("value", String.valueOf(channelManager.hostUpdateInterval));
        td.appendChild(e);
        tr.appendChild(td);

        // Message
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Message");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        String pcMsg = serventManager.rootMsg;
        e = Peercast.newElement("input");
        e.setAttribute("type", "text");
        e.setAttribute("name", "pcmsg");
        e.setAttribute("size", "50");
        e.setAttribute("value", pcMsg);
        td.appendChild(e);
        tr.appendChild(td);

        // get update
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Get Update");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "getupd");
        e.setAttribute("value", "1");
        td.appendChild(e);
        tr.appendChild(td);

        // broadcast settings
        row++;
        td = Peercast.newElement("td");
        td.setAttribute("width", "50%");
        td.setTextContent("Send");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "brroot");
        e.setAttribute("value", "1");
        td.appendChild(e);
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addAuthOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "2");
        td.setTextContent("<b>Authentication</b>");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("HTML Authentication");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        Element e1 = Peercast.newElement("input");
        e1.setAttribute("type", "radio");
        e1.setAttribute("name", "auth");
        e1.setAttribute("value", "cookie");
        e1.setAttribute("checked", serventManager.authType == ServentManager.AuthType.COOKIE ? "1" : "");
        Element e2 = Peercast.newElement("i");
        e2.setTextContent("Cookies<br>");
        e1 = Peercast.newElement("input");
        e1.setAttribute("type", "radio");
        e1.setAttribute("name", "auth");
        e1.setAttribute("value", "http");
        e1.setAttribute("checked", serventManager.authType == ServentManager.AuthType.HTTPBASIC ? "1" : "");
        e2 = Peercast.newElement("i");
        e2.setTextContent("Basic HTTP");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Cookies Expire");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e1 = Peercast.newElement("input");
        e1.setAttribute("type", "radio");
        e1.setAttribute("name", "expire");
        e1.setAttribute("value", "session");
        e1.setAttribute("checked", serventManager.neverExpire == false ? "1" : "");
        e2 = Peercast.newElement("i");
        e2.setTextContent("End of session<br>");
        e1 = Peercast.newElement("input");
        e1.setAttribute("type", "radio");
        e1.setAttribute("name", "expire");
        e1.setAttribute("value", "never");
        e1.setAttribute("checked", serventManager.neverExpire ? "1" : "");
        e2 = Peercast.newElement("i");
        e2.setTextContent("Never");
        tr.appendChild(td);

        table.appendChild(tr);
        html.appendChild(table);
    }

    /** */
    void addSecurityOptions(Document html) {
        Element table = Peercast.newElement("table");
        table.setAttribute("width", "100%");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");

        int row = 0;
        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("colspan", "3");
        td.setTextContent("<b>Security</b>");
        tr.appendChild(td);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("<b>Allow on port:</b>");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(String.format("<b>%d<b>", serventManager.serverHost.getPort()));
        tr.appendChild(td);
        td = Peercast.newElement("td");
        td.setTextContent(String.format("<b>%d<b>", serventManager.serverHost.getPort() + 1));
        tr.appendChild(td);
        table.appendChild(tr);

        int a1 = serventManager.allowServer1;
        int a2 = serventManager.allowServer2;

        // port 1
        row++;
        td = Peercast.newElement("td");
        td.setTextContent("HTML");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        Element e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowHTML1");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a1 & ServentManager.Allow.HTML.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowHTML2");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a2 & ServentManager.Allow.HTML.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Broadcasting");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowBroadcast1");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a1 & ServentManager.Allow.BROADCAST.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowBroadcast2");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a2 & ServentManager.Allow.BROADCAST.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Network");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowNetwork1");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a1 & ServentManager.Allow.ALLOW_NETWORK.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        td = Peercast.newElement("td");
        tr.appendChild(td);
        table.appendChild(tr);

        row++;
        td = Peercast.newElement("td");
        td.setTextContent("Direct");
        tr.appendChild(td);
        td = Peercast.newElement("td");
        e = Peercast.newElement("input");
        e.setAttribute("type", "checkbox");
        e.setAttribute("name", "allowDirect1");
        e.setAttribute("value", "1");
        e.setAttribute("checked", (a1 & ServentManager.Allow.ALLOW_DIRECT.value) != 0 ? "1" : "");
        td.appendChild(e);
        tr.appendChild(td);
        td = Peercast.newElement("td");
        tr.appendChild(td);
        table.appendChild(tr);

        html.appendChild(table);
    }

    /** */
    void addConnectionsPage(Document html) {

        refresh = serventManager.refreshHTML;
        addHeader(html, 4);

        html.setTextContent("table border=\"0\" width=\"95%%\" align=\"center\"");

        html.setTextContent("form method=\"get\" action=\"/admin\"");

        html.setTextContent("tr bgcolor=\"#cccccc\" align=\"center\"");
        Element td = Peercast.newElement("td");
        td.setTextContent("");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Type<b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Status</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Time</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>IP:Port (net)</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>In (pack/s)</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Out (pack/s)</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Queue<br>(nrm/pri)</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Route</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Agent</b>");
        td = Peercast.newElement("td");
        td.setTextContent("<b>Kbits/s</b>");
        html.appendChild(null);

        int count = 0;
        for (Servent servent : serventManager.servents) {
            if (servent.type != Type.NONE) {
                InetSocketAddress h = servent.getHost();
                {
                    InetAddress ip = h.getAddress();
                    int port = h.getPort();

                    h = new InetSocketAddress(ip, port);
                    String hostName = h.getHostName();

                    if (servent.priorityConnect) {
                        hostName += "*";
                    }

                    if (servent.networkID.isSet()) {
                        String netidStr = servent.networkID.toString();
                        hostName += "<br>";
                        hostName += "(";
                        hostName += netidStr;
                        hostName += ")";
                    }

                    long tnum = 0;
                    char tdef = 's';
                    if (servent.lastConnect != 0) {
                        tnum = System.currentTimeMillis() - servent.lastConnect;
                    }

                    count++;

                    td = Peercast.newElement("td");
                    Element e1 = Peercast.newElement("b");
                    Element e2 = Peercast.newElement("a");
                    e2.setAttribute("href", String.format("/admin?cmd=stopserv&index=%d", servent.serventIndex));
                    e2.setTextContent("Stop");
                    e1.appendChild(e2);
                    td.appendChild(e1);

                    if (servent.type.equals(ServHost.Type.STREAM)) { // TODO ServHost.TYPE ???
                        td = Peercast.newElement("td");
                        td.setTextContent(servent.type.name());
                        td = Peercast.newElement("td");
                        td.setTextContent(servent.status.toString());
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%d%c", tnum, tdef));
                        td = Peercast.newElement("td");
                        td.setTextContent(hostName);
                        td = Peercast.newElement("td");
                        td.setTextContent("-");
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%d", servent.syncPos));
                        td = Peercast.newElement("td");
                        td.setTextContent("-");
                        td = Peercast.newElement("td");
                        td.setTextContent("-");
                    } else {

                        td = Peercast.newElement("td");
                        td.setTextContent(servent.type.name());
                        td = Peercast.newElement("td");
                        td.setTextContent(servent.status.toString());
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%d%c", tnum, tdef));
                        td = Peercast.newElement("td");
                        td.setTextContent(hostName);
                        if (tnum != 0) {
                            td = Peercast.newElement("td");
                            td.setTextContent(String.format("%d (%.1f)", servent.gnuStream.packetsIn, ((float) servent.gnuStream.packetsIn) / ((float) tnum)));
                            td = Peercast.newElement("td");
                            td.setTextContent(String.format("%d (%.1f)", servent.gnuStream.packetsOut, ((float) servent.gnuStream.packetsOut) / ((float) tnum)));
                        } else {
                            td = Peercast.newElement("td");
                            td.setTextContent("-");
                            td = Peercast.newElement("td");
                            td.setTextContent("-");
                        }
                        // html.startTagEnd("td","%d / %d",s.outPacketsNorm.numPending(),s.outPacketsPri.numPending());
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%s %d / %d", servent.flowControl ? "FC" : "", servent.outPacketsNorm.numPending(), servent.outPacketsPri.numPending()));

                        int nr = servent.numUsed();
                        long tim = System.currentTimeMillis() - servent.getOldest();

                        String tstr = Peercast.getFromStopwatch((int) (tim / 1000));

                        if (nr != 0) {
                            td = Peercast.newElement("td");
                            td.setTextContent(String.format("%s (%d)", tstr, nr));
                        } else {
                            td = Peercast.newElement("td");
                            td.setTextContent("-");
                        }
                    }

                    td = Peercast.newElement("td");
                    td.setTextContent(servent.agent);

                    if (servent.sock != null) {
                        int tot = Peercast.getInstance().bytesInPerSec + Peercast.getInstance().bytesOutPerSec;
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%.1f", Peercast.BYTES_TO_KBPS(tot)));
                    } else {
                        td = Peercast.newElement("td");
                        td.setTextContent("-");
                    }
                    html.appendChild(null); // tr

                }
            }
        }
        html.appendChild(null);
        html.appendChild(null);

        addFooter(html);
    }

    /** */
    private int numUsed() {
        int cnt = 0;
        for (int i = 0; i < seenIDs.size(); i++) {
            if (seenIDs.get(i).storeTime > 0) {
                cnt++;
            }
        }
        return cnt;
    }

    /** */
    static void addChanInfoLink(Document html, ChannelInfo info, boolean fromRelay) {
        String idstr = info.id.toString();
        Element e = Peercast.newElement("a");
        e.setAttribute("href", String.format("/admin?page=chaninfo&id=%s&relay=%d", idstr, fromRelay ? 1 : 0));
        e.setTextContent("Info");
        html.appendChild(e);
    }

    /** */
    void addChannelInfo(Document html, ChannelInfo info, boolean fromRelay, boolean showPlay, boolean showInfo, boolean showURL, boolean showRelay) {
        String name, url, desc;
        name = info.name;
        TrackInfo track = info.track;
        url = info.url;
        desc = info.desc;

        String idStr = info.id.toString();
        {
            String tmp = String.format("/pls/%s", idStr);

            Element td = Peercast.newElement("td");
            td.setAttribute("align", "left");
            html.appendChild(td);

            Element e1 = Peercast.newElement("b");
            e1.setTextContent(name);
            td.appendChild(e1);

            Element e2 = Peercast.newElement("font");
            e2.setAttribute("size", "-1");
            e2.setTextContent("");
            e1.appendChild(e2);
            if (desc.length() == 0) {
                Element e3 = Peercast.newElement("i");
                e3.setTextContent(String.format("<br>%s", desc));
                e2.appendChild(e3);
            }

            if (track.artist.length() != 0 || track.title.length() != 0) {
                Element e3 = Peercast.newElement("i");
                e3.setTextContent(String.format("<br>(%s - %s)", track.artist, track.title));
                e2.appendChild(e3);
            }
            td.appendChild(e1.appendChild(e2));

            html.setTextContent("font size=\"-1\"");
            if (showPlay) {
                e1 = Peercast.newElement("b");
                e1.setTextContent("<br>");
                e2 = Peercast.newElement("a");
                e2.setAttribute("href", tmp);
                e2.setTextContent("Play");
                td.appendChild(null);
            }

            if ((!fromRelay) && (showRelay)) {
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                e2 = Peercast.newElement("a");
                e2.setAttribute("href", String.format("/admin?cmd=relay&id=%s", idStr));
                e2.setTextContent("Relay");
                e1.appendChild(e2);
            }

            if (showRelay) {
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                addChanInfoLink(html, info, fromRelay);
                html.appendChild(null);
            }

            if ((url.length() != 0) && (showURL)) {
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                if (url.indexOf("mailto:") > 0) {
                    e2 = Peercast.newElement("a");
                    e2.setAttribute("href", url);
                    e2.setTextContent("MAIL");
                } else {
                    tmp = String.format("/admin?cmd=redirect&url=%s", url);
                    e2 = Peercast.newElement("a");
                    e2.setAttribute("href", tmp);
                    e2.setAttribute("target", "_blank"); // TODO html structure
                    e2.setTextContent("WWW");
                }
                e1.appendChild(e2);
            }

            if (fromRelay) {
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                tmp = String.format("/admin?cmd=bump&id=%s", idStr);
                e2 = Peercast.newElement("a");
                e2.setAttribute("href", tmp);
                e2.setTextContent("Bump");
                e1.appendChild(e2);
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                tmp = String.format("/admin?cmd=keep&id=%s", idStr);
                e2 = Peercast.newElement("a");
                e2.setAttribute("href", tmp);
                e2.setTextContent("Keep");
                e1.appendChild(e2);
                e1 = Peercast.newElement("b");
                e1.setTextContent(" - ");
                tmp = String.format("/admin?cmd=stop&id=%s", idStr);
                e2 = Peercast.newElement("a");
                e2.setAttribute("href", tmp);
                e2.setTextContent("Stop");
                e1.appendChild(e2);
            }

            html.appendChild(null);

            html.appendChild(null);
        }
    }

    /** html */
    int refresh;

    /** html */
    String refreshURL;

    /** */
    void addAllChannelsPage(Document html, Sort sort, boolean dir, ChannelInfo info) {
        boolean showFind = true;

        if (!showFind) {
            refresh = serventManager.refreshHTML;
        }
        addHeader(html, 2);

        Element table = Peercast.newElement("table");
        table.setAttribute("border", "0");
        table.setAttribute("align", "center");
        Element form = Peercast.newElement("form");
        table.setAttribute("method", "get");
        table.setAttribute("action", "/admin");

        Element tr;

        if (!showFind) {
            html.setTextContent("input name=\"cmd\" type=\"hidden\" value=\"stopfind\"");
            tr = Peercast.newElement("tr");
            Element td = Peercast.newElement("td");
            html.setTextContent("input name=\"stop\" type=\"submit\" value=\"  Stop Search \"");
            html.appendChild(null);
            html.appendChild(null);
        } else {

            html.setTextContent("input name=\"page\" type=\"hidden\" value=\"chans\"");

            tr = Peercast.newElement("tr");
            Element td = Peercast.newElement("td");
            td.setTextContent("Name");
            td = Peercast.newElement("td");
            td.setTextContent("Genre");
            td = Peercast.newElement("td");
            td.setTextContent("Bitrate");
            td = Peercast.newElement("td");
            td.setTextContent("ID");
            html.appendChild(null);

            tr = Peercast.newElement("tr");
            td = Peercast.newElement("td");
            html.setTextContent("input name=\"find\" type=\"submit\" value=\"  Search  \"");
            html.appendChild(null);

            String name, genre;
            int bitrate;
            // ChanInfo *info = &chanMgr.searchInfo;

            name = info.name;
            genre = info.genre;
            bitrate = info.bitrate;
            String idStr, brStr;

            if (info.id.isSet()) {
                idStr = info.id.toString();
            } else {
                idStr = "";
            }

            if (bitrate != 0) {
                brStr = String.format("%d", bitrate);
            } else {
                brStr = "";
            }

            td = Peercast.newElement("td");
            Element e = Peercast.newElement("input");
            e.setAttribute("name", "name");
            e.setAttribute("type", "text");
            e.setAttribute("value", name);
            td.appendChild(e);

            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "genre");
            e.setAttribute("type", "text");
            e.setAttribute("value", genre);
            td.appendChild(e);

            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "bitrate");
            e.setAttribute("type", "text");
            e.setAttribute("size", "5");
            e.setAttribute("value", brStr);
            td.appendChild(e);

            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "id");
            e.setAttribute("type", "text");
            e.setAttribute("size", "34");
            e.setAttribute("value", idStr);
            td.appendChild(e);

            table.appendChild(tr); // tr
        }

        html.appendChild(null); // form
        html.appendChild(null); // table

        html.setTextContent("table border=\"0\" width=\"95%%\" align=\"center\"");

        tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setTextContent(String.format("<b><a href=\"/admin?page=chans&sort=name&dir=%s\">Channel</a></b>", dir ? "down" : "up"));
        td = Peercast.newElement("td");
        td.setTextContent(String.format("<b><a href=\"/admin?page=chans&sort=genre&dir=%s\">Genre</a></b>", dir ? "down" : "up"));
        td = Peercast.newElement("td");
        td.setAttribute("width", "1%");
        td.setTextContent(String.format("<b><a href=\"/admin?page=chans&sort=bitrate&dir=%s\">Bitrate (kb/s)</a></b>", dir ? "down" : "up"));
        td = Peercast.newElement("td");
        td.setAttribute("width", "1%");
        td.setTextContent(String.format("<b><a href=\"/admin?page=chans&sort=type&dir=%s\">Type</a></b>", dir ? "down" : "up"));
        td = Peercast.newElement("td");
        td.setAttribute("width", "2%");
        td.setTextContent(String.format("<b><a href=\"/admin?page=chans&sort=hosts&dir=%s\">Hits</a></b>", dir ? "down" : "up"));

        ChannelHitList[] hits = new ChannelHitList[ChannelManager.MAX_HITLISTS];
        int numHits = 0;
        for (ChannelHitList chl : channelManager.channelHitLists) {
            if (chl.isUsed()) {
                if (chl.info.match(info)) {
                    hits[numHits++] = chl;
                }
            }
        }

        if (numHits == 0) {
            tr = Peercast.newElement("tr");
            if (showFind) {
                td = Peercast.newElement("td");
                td.setTextContent("No channels found");
            } else {
                td = Peercast.newElement("td");
                td.setTextContent("Searching...");
            }
            html.appendChild(null);
        } else {
            Arrays.sort(hits, sort.getComparator(dir));

            for (int i = 0; i < numHits; i++) {
                ChannelHitList chl = hits[i];

                // row = i;

                addChannelInfo(html, chl.info, false, true, true, true, true);

                String genre = chl.info.genre;
                td = Peercast.newElement("td");
                td.setTextContent(genre);

                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", chl.info.bitrate));

                td = Peercast.newElement("td");
                td.setTextContent(chl.info.contentType.name());

                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d / %d", chl.numListeners(), chl.numHits()));

                html.appendChild(null); // tr
            }
        }

        html.appendChild(null); // table

        addFooter(html);
    }

    /** */
    void addWinampChansPage(Document html, final String wildcard, String type, boolean stop) {
        int maxHits = ChannelManager.MAX_HITLISTS;

        if (type.length() == 0) {
            type = "name";
        }

        if ((channelManager.numHitLists() < maxHits) && (!stop)) {
            refresh = serventManager.refreshHTML;
        }
        addBasicHeader(html);

        ChannelHitList[] hits = new ChannelHitList[ChannelManager.MAX_HITLISTS];
        int numHits = 0;
        int i;

        ChannelInfo searchInfo = new ChannelInfo();
        searchInfo.init();

        if (type.equals("name")) {
            searchInfo.name = wildcard;
        } else if (type.equals("genre")) {
            searchInfo.genre = wildcard;
        } else if (type.equals("bitrate")) {
            searchInfo.bitrate = Integer.parseInt(wildcard);
        }

        for (ChannelHitList chl : channelManager.channelHitLists) {
            if (chl.isUsed() && chl.hits.size() > 0) { // TODO chl.isAvailable()
                if (chl.info.match(searchInfo)) {
                    hits[numHits++] = chl;
                }
            }
        }

        boolean maxShown = false;
        if (numHits >= maxHits) {
            numHits = maxHits;
            maxShown = true;
        }

        if (serventManager.downloadURL.length() != 0) {

            Element e1 = Peercast.newElement("font");
            e1.setAttribute("color", "#FF0000");
            Element e2 = Peercast.newElement("div");
            e2.setAttribute("align", "center");
            Element e3 = Peercast.newElement("b");
            e3.setTextContent("! Attention !");
            e2.appendChild(e3);
            e1.appendChild(e2);

            e1 = Peercast.newElement("b");
            e2 = Peercast.newElement("div");
            e2.setAttribute("align", "center");
            e3 = Peercast.newElement("b");
            e3.setAttribute("href", "/admin?cmd=upgrade");
            e3.setAttribute("target", "_blank"); // TODO html structure
            e3.setTextContent("Click here to update your client");
            html.appendChild(null);
            html.appendChild(null);
        }

        if (serventManager.rootMsg.length() != 0) {
            String pcMsg = serventManager.rootMsg;
            Element e1 = Peercast.newElement("div");
            e1.setAttribute("align", "center");
            Element e2 = Peercast.newElement("b");
            e2.setTextContent(pcMsg);
            e1.appendChild(e2);
        }

        html.setTextContent("form method=\"get\" action=\"/admin?\"");

        html.setTextContent("input name=\"page\" type=\"hidden\" value=\"winamp-chans\"");
        if (!stop) {
            Element e1 = Peercast.newElement("select");
            e1.setAttribute("name", "stop");
            e1.setAttribute("type", "submit");
            e1.setAttribute("value", "Stop Search");

            e1 = Peercast.newElement("input");
            e1.setAttribute("name", "wildcard");
            e1.setAttribute("type", "hidden");
            e1.setAttribute("value", wildcard);

            e1 = Peercast.newElement("input");
            e1.setAttribute("name", "type");
            e1.setAttribute("type", "hidden");
            e1.setAttribute("value", type);
        } else {
            Element e1 = Peercast.newElement("select");
            e1.setAttribute("name", "type");
            Element e2 = Peercast.newElement("option");
            e2.setAttribute("value", "name");
            if (type.equals("name")) {
                e2.setAttribute("selected", "");
            }
            e2.setTextContent("Name");
            e1.appendChild(e2);
            e2 = Peercast.newElement("option");
            e2.setAttribute("value", "genre");
            if (type.equals("genre")) {
                e2.setAttribute("selected", "");
            }
            e2.setTextContent("Genre");
            e1.appendChild(e2);
            e2 = Peercast.newElement("option");
            e2.setAttribute("value", "bitrate");
            if (type.equals("bitrate")) {
                e2.setAttribute("selected", "");
            }
            e2.setTextContent("BitRate");
            e1.appendChild(e2);
            html.appendChild(null);

            e1 = Peercast.newElement("input");
            e1.setAttribute("name", "wildcard");
            e1.setAttribute("type", "text");
            e1.setAttribute("value", wildcard);

            e1 = Peercast.newElement("input");
            e1.setAttribute("name", "search");
            e1.setAttribute("type", "submit");
            e1.setAttribute("value", "Search");
        }

        // html.startTagEnd("input name=\"search\" type=\"submit\" value=\"Stop Search\"");
        html.appendChild(null);

        Element table = Peercast.newElement("table");
        table.setAttribute("border", "0");
        table.setAttribute("width", "100%");
        table.setAttribute("align", "center");

        Element tr = Peercast.newElement("tr");
        tr.setAttribute("bgcolor", "#cccccc");
        tr.setAttribute("align", "center");

        Element td = Peercast.newElement("td");
        td.setAttribute("width", "5%");
        td.setTextContent("<b><font size=\"-1\">Play</font></b>");
        // html.startTagEnd("td width=\"20%%\"","<b><font size=\"-1\">Type</font></b>");
        td = Peercast.newElement("td");
        td.setAttribute("width", "95%");
        td.setTextContent("<b><font size=\"-1\">PeerCast Channel</font></b>");
        tr.appendChild(td);

        if (numHits != 0) {

            Arrays.sort(hits, Sort.BY_NAME.getComparator(false));

            for (i = 0; i < numHits; i++) {
                ChannelHitList chl = hits[i];

                // row = i;

                String idStr = chl.info.id.toString();
                String playURL = String.format("/pls/%s", idStr);

                String genre = chl.info.genre;
                String name = chl.info.name;
                td = Peercast.newElement("td");
                td.setTextContent(String.format("<font face=\"Webdings\" size=\"+2\"><a href=\"%s\">U</a></font>", playURL));

                td = Peercast.newElement("td");
                td.setTextContent(String.format("<font size=\"-1\"><b>%s</b><br>%s %d kb/s - (%s)</font>", name, chl.info.contentType.name(), chl.info.bitrate, genre));

                html.appendChild(null); // tr
            }

        }
        html.appendChild(null); // table

        if (stop) {
            Element e = Peercast.newElement("b");
            e.setTextContent(String.format("<font size=\"-1\">Displayed %d out of %d channels.</b>", numHits, channelManager.numHitLists()));
            html.appendChild(e);
        } else {
            Element e = Peercast.newElement("b");
            e.setTextContent("Searching...");
            html.appendChild(e);
        }

        addFooter(html);
    }

    /** */
    void addMyChannelsPage(Document html) {
        refresh = serventManager.refreshHTML;
        addHeader(html, 3);

        ChannelInfo info = new ChannelInfo();
        List<Channel> clist = channelManager.findChannels(info, ChannelManager.MAX_CHANNELS);


            Element table = Peercast.newElement("table");
            table.setAttribute("border", "0");
            table.setAttribute("width", "95%");
            table.setAttribute("align", "center");

            Element tr = Peercast.newElement("tr");
            tr.setAttribute("bgcolor", "#cccccc");
            tr.setAttribute("align", "center");
            table.appendChild(tr);

            Element td = Peercast.newElement("td");
            td.setTextContent("<b>Channel</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setTextContent("<b>Genre</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "1%");
            td.setTextContent("<b>Bitrate (kb/s)</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "1%");
            td.setTextContent("<b>Stream</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "2%");
            td.setTextContent("<b>Relays</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "2%");
            td.setTextContent("<b>Listeners</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "1%");
            td.setTextContent("<b>Status</b>");
            tr.appendChild(td);

            td = Peercast.newElement("td");
            td.setAttribute("width", "1%");
            td.setTextContent("<b>Keep</b>");
            tr.appendChild(td);

            for (Channel c : clist) {

                String genre = c.info.genre;

                addChannelInfo(html, c.info, true, true, true, true, true);

                td = Peercast.newElement("td");
                td.setTextContent(genre);

                // bitrate
                if (c.getBitrate() != 0) {
                    td = Peercast.newElement("td");
                    td.setTextContent(String.format("%d", c.getBitrate()));
                } else {
                    td = Peercast.newElement("td");
                    td.setTextContent("-");
                }

                // stream/type
                td = Peercast.newElement("td");
                td.setAttribute("align", "center");
                {
                    String path = c.getStreamPath();
                    Element a = Peercast.newElement("a");
                    a.setAttribute("href", path);
                    a.setTextContent(c.info.contentType.name());
                    td.appendChild(a);
                }
                tr.appendChild(td);

                // relays
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", c.totalRelays())); // TODO orig is numRelays
                // listeners
                td = Peercast.newElement("td");
                td.setTextContent(String.format("%d", c.totalListeners())); // TODO orig is numListeners
                // status
                td = Peercast.newElement("td");
                td.setTextContent(c.status.toString());
                // keep
                td = Peercast.newElement("td");
                td.setTextContent(c.stayConnected ? "Yes" : "No");

                tr.appendChild(td);
            }
            html.appendChild(table); // table

        addFooter(html);
    }

    /** */
    void addBroadcastPage(Document html) {
        addHeader(html, 8);

        ChannelInfo info = new ChannelInfo();
        List<Channel> clist = channelManager.findChannels(info, ChannelManager.MAX_CHANNELS);


            Element table = Peercast.newElement("table");
            table.setAttribute("border", "0");
            table.setAttribute("align", "center");

            html.setTextContent("form method=\"get\" action=\"/admin\"");
            html.setTextContent("input name=\"cmd\" type=\"hidden\" value=\"fetch\"");

            Element tr = Peercast.newElement("tr");
            tr.setAttribute("bgcolor", "#cccccc");
            tr.setAttribute("align", "center");
            table.appendChild(tr);

            Element td = Peercast.newElement("td");
            td.setAttribute("colspan", "2");
            td.setTextContent("<b>External Source</b>");
            html.appendChild(null);

            int row = 0;

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("URL (Required)");
            td = Peercast.newElement("td");
            Element e = Peercast.newElement("input");
            e.setAttribute("name", "url");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Name");
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "name");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Description");
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "desc");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Genre");
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "genre");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Contact");
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "contact");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Bitrate (kb/s)");
            td = Peercast.newElement("td");
            e = Peercast.newElement("input");
            e.setAttribute("name", "bitrate");
            e.setAttribute("size", "40");
            e.setAttribute("type", "text");
            e.setAttribute("value", "");
            td.appendChild(e);
            tr.appendChild(td);

            row++;
            td = Peercast.newElement("td");
            td.setTextContent("Type");
            td = Peercast.newElement("td");
            html.setTextContent("select name=\"type\"");
            e = Peercast.newElement("option");
            e.setAttribute("value", "UNKNOWN");
            e.setAttribute("selected", "");
            e.setTextContent("Unknown");
            e = Peercast.newElement("option");
            e.setAttribute("value", "MP3");
            e.setTextContent("MP3");
            e = Peercast.newElement("option");
            e.setAttribute("value", "OGG");
            e.setTextContent("OGG");
            e = Peercast.newElement("option");
            e.setAttribute("value", "WMA");
            e.setTextContent("WMA");
            e = Peercast.newElement("option");
            e.setAttribute("value", "NSV");
            e.setTextContent("NSV");
            e = Peercast.newElement("option");
            e.setAttribute("value", "WMV");
            e.setTextContent("WMV");
            e = Peercast.newElement("option");
            e.setAttribute("value", "RAW");
            e.setTextContent("RAW");
            html.appendChild(null);
            html.appendChild(null);
            html.appendChild(null);

            row++;
            td = Peercast.newElement("td");
            e.setAttribute("colspan", "2");
            e.setAttribute("align", "center");
            html.setTextContent("input name=\"stream\" type=\"submit\" value=\"Create Relay\"");
            html.appendChild(null);
            html.appendChild(null);

            html.appendChild(null);
            html.appendChild(null);

            html.setTextContent("br");

            html.setTextContent("table border=\"0\" width=\"95%%\" align=\"center\"");

            html.setTextContent("tr bgcolor=\"#cccccc\" align=\"center\"");
            td = Peercast.newElement("td");
            td.setTextContent("<b>Channel</b>");
            td = Peercast.newElement("td");
            td.setTextContent("<b>Source</b>");
            td = Peercast.newElement("td");
            td.setTextContent("<b>Pos</b>");
            td = Peercast.newElement("td");
            td.setTextContent("<b>Bitrate (kb/s)</b>");
            td = Peercast.newElement("td");
            td.setTextContent("<b>Type</b>");
            html.appendChild(null);

            for (Channel c : clist) {
                if (c.isBroadcasting()) {
                    long uptime = Peercast.getInstance().lastPlayTime != 0 ? (System.currentTimeMillis() - Peercast.getInstance().lastPlayTime) : 0;
                    String uptimeStr = Peercast.getFromStopwatch((int) (uptime / 1000));

                    String idStr = c.getIDString();

                    row++;

                    String name = c.info.name;

                    String ipStr = serventManager.serverHost.getHostName();

                    // use global peercast URL as name link
                    td = Peercast.newElement("td");
                    String temp = String.format("peercast://pls/%s?ip=%s", idStr, ipStr);
                    e = Peercast.newElement("a");
                    e.setAttribute("href", temp);
                    e.setTextContent(name);
                    html.appendChild(e);

                    addChannelSourceTag(html, c);

                    td = Peercast.newElement("td");
                    td.setTextContent(String.format("%d", c.streamPos));

                    if (c.getBitrate() != 0) {
                        td = Peercast.newElement("td");
                        td.setTextContent(String.format("%d", c.getBitrate()));
                    } else {
                        td = Peercast.newElement("td");
                        td.setTextContent("-");
                    }

                    td = Peercast.newElement("td");
                    td.setTextContent(c.info.contentType.name());

                    html.appendChild(null);
            }
            html.appendChild(null); // table

        }
        addFooter(html);
    }

    /** */
    void handshakeHTTP_get(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String fn = request.getRequestURI();
Debug.println("uri: " + fn);

        if (fn.startsWith("/admin?")) {
            if (!isAllowed(ServentManager.Allow.HTML)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            log.debug("Admin client");
            handshakeCMD(request, response, fn.substring(7));

        } else if (fn.startsWith("/http/")) {
            String dirName = fn.substring(6);

            if (!isAllowed(ServentManager.Allow.HTML)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            if (!handshakeAuth(request, response, fn, false)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }

            handshakeRemoteFile(response, dirName);

        } else if (fn.startsWith("/html/")) {
            String dirName = fn.substring(1);

            if (!isAllowed(ServentManager.Allow.HTML)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            if (handshakeAuth(request, response, fn, true)) {
                handshakeLocalFile(response, dirName);
            }

        } else if (fn.startsWith("/admin/?")) {
            if (!isAllowed(ServentManager.Allow.HTML)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            log.debug("Admin client");
            handshakeCMD(request, response, fn.substring(8));

        } else if (fn.startsWith("/admin.cgi")) {
            if (!isAllowed(ServentManager.Allow.BROADCAST)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            String pwdArg = request.getParameter("pass");
            String songArg = request.getParameter("song");
            String mountArg = request.getParameter("mount");
            String urlArg = request.getParameter("url");

            if (pwdArg != null && songArg != null) {

                for (Channel channel : channelManager.channels) {

                    if ((channel.status == Channel.Status.BROADCASTING) && (channel.info.contentType == ChannelInfo.ContentType.MP3)) {
                        // if we have a mount point then check for it, otherwise update all channels.
                        if (mountArg != null) {
                            if (channel.mount.equals(mountArg)) {
                                channel = null;
                            }
                        }

                        if (channel != null) {
                            ChannelInfo newInfo = channel.info;
                            newInfo.track.title = songArg;

                            if (urlArg != null) {
                                if (urlArg.length() != 0) {
                                    newInfo.track.contact = urlArg;
                                }
                            }
                            log.debug(String.format("Ch.%d Shoutcast update: %s", channel.index, songArg));
                            channel.updateInfo(newInfo);
                        }
                    }
                }
            }

        } else if (fn.startsWith("/pls/")) {

            if (!((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
                if (!isAllowed(ServentManager.Allow.ALLOW_DIRECT) || !isFiltered(ServFilter.Type.DIRECT.value)) {
                    response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                }
            }

            ChannelInfo info = new ChannelInfo();
            if (serventManager.getChannel(fn.substring(5), info, isPrivate())) {
                handshakePLS(request, response, info, false);
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }

        } else if (fn.startsWith("/stream/")) {

            if (!((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
                if (!isAllowed(ServentManager.Allow.ALLOW_DIRECT) || !isFiltered(ServFilter.Type.DIRECT.value)) {
                    response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                }
            }

            triggerChannel(request, response, fn.substring(8), ChannelInfo.Protocol.HTTP, isPrivate());

        } else if (fn.startsWith("/channel/")) {

            if (!((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
                if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK) || !isFiltered(ServFilter.Type.NETWORK.value)) {
                    response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                }
            }

            triggerChannel(request, response, fn.substring(9), ChannelInfo.Protocol.PCP, false);

        } else {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader("Location", String.format("/%s/index.html", serventManager.htmlPath));
        }
    }

    /** */
    void handshakeHTTP_giv(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }

        GnuID id = new GnuID();
        id.clear();

        String in = request.getRequestURI();
        int idstr = in.indexOf("/");
        if (idstr > 0) {
            id = new GnuID(in.substring(0, idstr + 1));
        }

        String ipstr = request.getRemoteHost();

        if (id.isSet()) {
            // at the moment we don`t really care where the GIV came from, so just give to chan. no. if its waiting.
            Channel ch = channelManager.findChannelByID(id);

            if (ch == null) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }

            if (!ch.acceptGIV(sock))
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);

            log.debug(String.format("Accepted GIV channel %s from: %s", idstr, ipstr));

            sock = null; // release this servent but dont close socket.
        } else {

            if (!serventManager.acceptGIV(sock)) {
                response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            }

            log.debug(String.format("Accepted GIV PCP from: %s", ipstr));
            sock = null; // release this servent but dont close socket.
        }
    }

    /** GnuPacket.PCX_PCP_CONNECT */
    void handshakeHTTP_PCX_PCP_CONNECT(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK) || !isFiltered(ServFilter.Type.NETWORK.value)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }

        processIncomingPCP(request, response, true);
    }

    /** "PEERCAST CONNECT" */
    void handshakeHTTP_peercast_connect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (!isAllowed(ServentManager.Allow.ALLOW_NETWORK) || !isFiltered(ServFilter.Type.NETWORK.value)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }

        log.debug("PEERCAST client");
        processServent(request, response);
    }

    /** "SOURCE" */
    void handshakeHTTP_SOURCE(HttpContext request, HttpServletResponse response, boolean isHttp) throws IOException {
        if (!isAllowed(ServentManager.Allow.BROADCAST)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }

        String in = request.getRequestURI(), mount = null;

        int ps;
        if ((ps = in.indexOf("ICE/1.0")) >= 0) {
            mount = in.substring(7);
            ps = 0;
            log.debug(String.format("ICE 1.0 client to %s", mount != null ? mount : "unknown"));
        } else {
            ps = in.lastIndexOf('/'); // password preceeds
            if (ps < 0) {
                ps = in.length();
            }
            loginPassword = in.substring(7, ps);

            log.debug(String.format("ICY client: %s %s", loginPassword, mount != null ? mount : "unknown"));
        }

        if (mount != null) {
            loginMount = mount;
        }

        handshakeICY(request, response, Channel.SourceType.ICECAST, isHttp);
//      sock = null; // socket is taken over by channel, so don`t close it
    }

    /** servMgr.password */
    void handshakeHTTP_password(HttpContext request, HttpServletResponse response, boolean isHttp) throws IOException {
        if (!isAllowed(ServentManager.Allow.BROADCAST)) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }

        loginPassword = serventManager.password; // pwd already checked

        response.setStatus(0); // TODO "OK2"
        response.setHeader("icy-caps", "11");
        log.debug("ShoutCast client");

        handshakeICY(request, response, Channel.SourceType.SHOUTCAST, isHttp);
//      sock = null; // socket is taken over by channel, so don`t close it
    }

    /** */
    boolean canStream(Channel ch) {
        if (ch == null) {
            return false;
        }

        // TODO !!! ���݂����Y�ݒ� !!!
Debug.println(String.format("bitrate: %b, relay: %b, direct: %b, play: %b, channel: %b", serventManager.bitrateFull(ch.getBitrate()), (type.equals(Type.RELAY) && serventManager.relaysFull()), (type.equals(Type.DIRECT) && serventManager.directFull()), !ch.isPlaying(), ch.isFull()));
        if (!isPrivate()) {
            if (serventManager.bitrateFull(ch.getBitrate()) ||
                (type.equals(Type.RELAY) && serventManager.relaysFull()) ||
                (type.equals(Type.DIRECT) && serventManager.directFull()) ||
                !ch.isPlaying() ||
                ch.isFull()) {

                return false;
            }
        }

        return true;
    }

    /** */
    void handshakeIncoming() throws IOException {
        InputStream is = null;
        OutputStream os = null;

        try {
            setStatus(Status.HANDSHAKE);

            is = sock.getInputStream();
            os = sock.getOutputStream();

            HttpContext requestContext = new HttpContext();
            HttpServletRequestAdapter request = new HttpServletRequestAdapter(requestContext);
            requestContext.setRemoteHost(((InetSocketAddress) sock.getRemoteSocketAddress()).getHostName());
            requestContext.setRemotePort(((InetSocketAddress) sock.getRemoteSocketAddress()).getPort());
            requestContext.setLocalHost(((InetSocketAddress) sock.getLocalSocketAddress()).getHostName());
            requestContext.setLocalPort(((InetSocketAddress) sock.getLocalSocketAddress()).getPort());
            HttpUtil.parseRequestHeader(is, requestContext);

            HttpContext responseContext = new HttpContext();
            responseContext.setRemoteHost(((InetSocketAddress) sock.getRemoteSocketAddress()).getHostName());
            responseContext.setRemotePort(((InetSocketAddress) sock.getRemoteSocketAddress()).getPort());
            responseContext.setLocalHost(((InetSocketAddress) sock.getLocalSocketAddress()).getHostName());
            responseContext.setLocalPort(((InetSocketAddress) sock.getLocalSocketAddress()).getPort());
            responseContext.setOutputStream(os);
            responseContext.setProtocol(requestContext.getProtocol());
            HttpServletResponseAdapter response = new HttpServletResponseAdapter(responseContext);

            String protocol = requestContext.getProtocol().getName();

            log.debug(String.format("Connect from %s '%s'", requestContext.getRemoteHost() + ":" + requestContext.getRemotePort(), protocol));
            if ("RTSP".equalsIgnoreCase(protocol)) {
//              log.debug(String.format("RTSP from %s '%s'", requestContext.getRemoteHost() + ":" + requestContext.getRemotePort(), protocol));
                handshakeRTSP(request, response);
            } else if ("HTTP".equalsIgnoreCase(protocol)) {
//              log.debug(String.format("HTTP from %s '%s'", requestContext.getRemoteHost() + ":" + requestContext.getRemotePort(), protocol));
                handshakeHTTP_get(request, response);
            } else if ("GIV".equalsIgnoreCase(protocol)) {
//              log.debug(String.format("Connect from %s '%s'", requestContext.getRemoteHost() + ":" + requestContext.getRemotePort(), protocol));
                handshakeHTTP_giv(request, response);
            } else if (GnuPacket.PCX_PCP_CONNECT.equalsIgnoreCase(protocol)) {
                handshakeHTTP_PCX_PCP_CONNECT(request, response);
            } else if ("PEERCAST CONNECT".equalsIgnoreCase(protocol)) {
                handshakeHTTP_peercast_connect(request, response);
            } else if (protocol.startsWith("SOURCE")) {
                handshakeHTTP_SOURCE(requestContext, response, false);
            } else if (serventManager.password.equals(protocol)) {
                handshakeHTTP_password(requestContext, response, false);
            } else {
                response.sendError(400);
            }

            if (!response.isCommitted()) {
                response.flushBuffer();
            }
        } catch (Exception e) {
            // TODO response reset
            HttpUtil.printErrorResponse(os, e);
        } finally {
            try {
                os.flush();
Debug.println("==== ONE PROCESS DONE: " + sock.getRemoteSocketAddress());
            } catch (IOException e) {
                e.printStackTrace(System.err);
            }
        }
    }

    /**
     * /stream/
     * /channel/
     * @param url sid?foo=var...
     */
    void triggerChannel(HttpServletRequest request, HttpServletResponse response, String url, ChannelInfo.Protocol proto, boolean relay) throws IOException {

        ChannelInfo info = new ChannelInfo();

        serventManager.getChannel(url, info, relay);

        if (proto.equals(ChannelInfo.Protocol.PCP)) {
            type = Type.RELAY;
        } else {
            type = Type.DIRECT;
        }

        outputProtocol = proto;

        processStream(request, response, false, info);
    }

    /** TODO should move to PlayList */
    void writePLSHeader(OutputStream s, PlayList type) {
        PrintStream ps = new PrintStream(s);
        ps.println(String.valueOf(HttpServletResponse.SC_OK));
        ps.printf("%s %s\n", Peercast.HTTP_HS_SERVER, GnuPacket.PCX_AGENT);

        final String content;
        switch (type) {
        case PLS:
            content = Peercast.MIME_XM3U;
            break;
        case ASX:
            content = Peercast.MIME_ASX;
            break;
        case RAM:
            content = Peercast.MIME_RAM;
            break;
        default:
            content = Peercast.MIME_TEXT;
            break;
        }
        ps.printf("%s %s\n", Peercast.HTTP_HS_CONTENT, content);
        ps.println("Content-Disposition: inline");
        ps.println("Cache-Control: private");
        ps.printf("%s %s\n", Peercast.HTTP_HS_CONNECTION, "close");

        ps.println();
    }

    /** */
    void handshakePLS(HttpServletRequest request, HttpServletResponse response, ChannelInfo info, boolean doneHandshake) throws IOException {
        String url = null;

        BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()));
        if (!doneHandshake) {
            String in = reader.readLine();
            while (in != null) {
            }
        }

        if (getLocalURL(url)) {

            PlayList type;

            if (info.contentType.equals(ChannelInfo.ContentType.WMA) ||
                info.contentType.equals(ChannelInfo.ContentType.WMV)) {
                type = PlayList.ASX;
            } else if (info.contentType.equals(ChannelInfo.ContentType.OGM)) {
                type = PlayList.RAM;
            } else {
                type = PlayList.PLS;
            }

            writePLSHeader(response.getOutputStream(), type);

            type.init(1);
            type.addChannel(url, info);
            type.write(response.getOutputStream());
        }
    }

    /** */
    void handshakePLS(ChannelHitList[] cl, int num, boolean doneHandshake) throws IOException {
        String url = null;

        BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        String in = reader.readLine();
        if (!doneHandshake) {
            while (in != null) {
                ;
            }
        }

        if (getLocalURL(url)) {
            writePLSHeader(sock.getOutputStream(), PlayList.SCPLS);

            PlayList pls = PlayList.SCPLS;
            pls.init(num);

            for (int i = 0; i < num; i++) {
                pls.addChannel(url, cl[i].info);
            }

            pls.write(sock.getOutputStream());
        }
    }

    /** */
    boolean getLocalURL(String str) throws IOException {
        if (sock == null) {
            throw new IOException("Not connected");
        }

        InetSocketAddress h;

        if (((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
            h = (InetSocketAddress) sock.getLocalSocketAddress();
        } else {
            h = serventManager.serverHost;
        }

        h = new InetSocketAddress(h.getAddress(), serventManager.serverHost.getPort());

        String ipStr = h.getHostName();

        str = String.format("http://%s", ipStr);
        return true;
    }

    /**
     * Warning: testing RTSP/RTP stuff below. .. moved over to seperate app now.
     *
     * @throws IOException
     */
    void handshakePOST(HttpServletRequest request, HttpServletResponse response) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(request.getInputStream()));
        String tmp;
        while ((tmp = reader.readLine()) != null) {
            log.debug(String.format("POST: %s", tmp));
        }

        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    }

    /** */
    void handshakeRTSP(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST);
    }

    /** */
    boolean handshakeAuth(HttpServletRequest request, HttpServletResponse response, final String args, boolean local) throws IOException {
        String pass = null;

        String pwd = request.getParameter("pass");

        if (pwd != null && serventManager.password.length() != 0) {
            if (pwd.equals(serventManager.password)) {
                return true;
            }
        }

        Cookie gotCookie;

        Enumeration<?> e = request.getHeaderNames();
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();

            switch (serventManager.authType) {
            case HTTPBASIC:
                if (name.equals("Authorization")) {
                    String value = new String(Base64.decodeBase64(request.getHeader("Basic").getBytes()));
                    int p = value.indexOf(':');
                    String user = value.substring(0, p - 1);
                    pass = value.substring(p + 1);
                }
                break;
            case COOKIE:
                if (name.equals("Cookie")) {
                    String value = request.getHeader(name);
                    log.debug(String.format("Got cookie: %s", request.getHeader(name)));
                    int idp = 0;
                    while ((idp = value.indexOf("id=")) > 0) {
                        idp += 3;
                        gotCookie = new Cookie(value.substring(idp), ((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().getHostName());
                        if (serventManager.cookieList.contains(gotCookie)) {
                            log.debug("Cookie found");
                            cookie = gotCookie;
                            break;
                        }

                    }
                }
                break;
            }
        }

        if (((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().isAnyLocalAddress()) {
            return true;
        }

        switch (serventManager.authType) {
        case HTTPBASIC:

            if (pass.equals(serventManager.password) && serventManager.password.length() != 0) {
                return true;
            }
            break;
        case COOKIE:
            if (serventManager.cookieList.contains(cookie)) {
                return true;
            }
            break;
        }

        if (serventManager.authType == ServentManager.AuthType.HTTPBASIC) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setHeader("WWW-Authenticate", "Basic realm=\"PeerCast Admin\"");
        } else if (serventManager.authType == ServentManager.AuthType.COOKIE) {
            String file = serventManager.htmlPath + "/login.html";
            if (local) {
                handshakeLocalFile(response, file);
            } else {
                handshakeRemoteFile(response, file);
            }
        }

        return false;
    }

    /** */
    void handshakeCMD(HttpServletRequest request, HttpServletResponse response, String cmd) throws IOException {
        String curr;

        String jumpStr;
        String jumpArg = null;
        boolean retHTML = true;

        Document document = Peercast.db.newDocument();

        if (!handshakeAuth(request, response, cmd, true)) {
            return;
        }

        try {
            cmd = request.getParameter("cmd");
            String net = request.getParameter("net");

            if (cmd.equals("redirect")) {
                String j = request.getParameter("url");
                if (j != null) {
                    String url = j;
                    if (!url.startsWith("http://")) {
                        url = "http://" + url;
                    }

                    refreshURL = url;
                    Element html = Peercast.newElement("html");
                    addHead(html);
                    Element body = Peercast.newElement("body");
                    Element h3 = Peercast.newElement("h3");
                    h3.setTextContent("Please wait...");
                    body.appendChild(h3);
                    html.appendChild(body);
                    document.appendChild(html);
                }
            } else {

                if (cmd.equals("viewxml")) {

                    handshakeXML();
                    retHTML = false;
                } else if (cmd.equals("clearlog")) {
                    jumpStr = String.format("/%s/viewlog.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("save")) {

                    Peercast.getInstance().saveSettings();

                    jumpStr = String.format("/%s/settings.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("apply")) {
                    ServFilter currFilter = serventManager.filters.get(0);

                    boolean brRoot = false;
                    boolean getUpd = false;
                    int showLog = 0;
                    int allowServer1 = 0;
                    int allowServer2 = 0;
                    int newPort = serventManager.serverHost.getPort();

                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        // server
                        if (curr.equals("serveractive")) {
                            serventManager.autoServe = Boolean.parseBoolean(request.getParameter(curr));
                        } else if (curr.equals("port")) {
                            newPort = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("icymeta")) {
                            int iv = Integer.parseInt(request.getParameter(curr));
                            if (iv < 0) {
                                iv = 0;
                            } else if (iv > 16384) {
                                iv = 16384;
                            }

                            channelManager.icyMetaInterval = iv;

                        } else if (curr.equals("passnew")) {
                            serventManager.password = request.getParameter(curr);
                        } else if (curr.equals("root")) {
                            serventManager.isRoot = Boolean.parseBoolean(request.getParameter(curr));
                        } else if (curr.equals("brroot")) {
                            brRoot = Boolean.parseBoolean(request.getParameter(curr));
                        } else if (curr.equals("getupd")) {
                            getUpd = Boolean.parseBoolean(request.getParameter(curr));
                        } else if (curr.equals("huint")) {
                            channelManager.setUpdateInterval(Integer.parseInt(request.getParameter(curr)));
                        } else if (curr.equals("forceip")) {
                            serventManager.forceIP = request.getParameter(curr);
                        } else if (curr.equals("htmlPath")) {
                            serventManager.htmlPath = "html/";
                            serventManager.htmlPath = request.getParameter(curr);
                        } else if (curr.equals("djmsg")) {
                            String msg = request.getParameter(curr);
                            channelManager.setBroadcastMessage(msg);
                        } else if (curr.equals("pcmsg")) {
                            serventManager.rootMsg = request.getParameter(curr); // String.T_ESC);
                        } else if (curr.equals("minpgnu")) {
                            serventManager.minGnuIncoming = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("maxpgnu")) {
                            serventManager.maxGnuIncoming = Integer.parseInt(request.getParameter(curr));

                            // connections
                        } else if (curr.equals("maxcin")) {
                            serventManager.maxControl = Integer.parseInt(request.getParameter(curr));

                        } else if (curr.equals("maxup")) {
                            serventManager.maxBitrateOut = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("maxrelays")) {
                            serventManager.setMaxRelays(Integer.parseInt(request.getParameter(curr)));
                        } else if (curr.equals("maxdirect")) {
                            serventManager.maxDirect = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("maxrelaypc")) {
                            channelManager.maxRelaysPerChannel = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.startsWith("filt_")) {
                            String fs = curr.substring(5);
                            {
                                if (fs.startsWith("ip", 2)) { // ip must be first
                                    currFilter = new ServFilter();
                                    currFilter.getMask().equals(request.getParameter(curr));

                                } else if (fs.startsWith("bn")) {
                                    currFilter.flags |= ServFilter.Type.BAN.value;
                                } else if (fs.startsWith("pr")) {
                                    currFilter.flags |= ServFilter.Type.PRIVATE.value;
                                } else if (fs.startsWith("nw")) {
                                    currFilter.flags |= ServFilter.Type.NETWORK.value;
                                } else if (fs.startsWith("di")) {
                                    currFilter.flags |= ServFilter.Type.DIRECT.value;
                                }
                            }

                            // client
                        } else if (curr.equals("clientactive")) {
                            serventManager.autoConnect = Boolean.parseBoolean(request.getParameter(curr));
                        } else if (curr.equals("yp")) {
                            serventManager.rootHost = new String(request.getParameter(curr)); // ESC
                        } else if (curr.equals("deadhitage")) {
                            channelManager.deadHitAge = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("refresh")) {
                            serventManager.refreshHTML = Integer.parseInt(request.getParameter(curr));
                        } else if (curr.equals("auth")) {
                            if (request.getParameter(curr).equals("cookie")) {
                                serventManager.authType = ServentManager.AuthType.COOKIE;
                            } else if (request.getParameter(curr).equals("http")) {
                                serventManager.authType = ServentManager.AuthType.HTTPBASIC;
                            }

                        } else if (curr.equals("expire")) {
                            if (request.getParameter(curr).equals("session")) {
                                serventManager.neverExpire = false;
                            } else if (request.getParameter(curr).equals("never")) {
                                serventManager.neverExpire = true;
                            }
                        } else if (curr.equals("logDebug")) {
                            showLog |= Integer.parseInt(request.getParameter(curr)) != 0 ? (1 << 1) : 0;
                        } else if (curr.equals("logErrors")) {
                            showLog |= Integer.parseInt(request.getParameter(curr)) != 0 ? (1 << 2) : 0;
                        } else if (curr.equals("logNetwork")) {
                            showLog |= Integer.parseInt(request.getParameter(curr)) != 0 ? (1 << 3) : 0;
                        } else if (curr.equals("logChannel")) {
                            showLog |= Integer.parseInt(request.getParameter(curr)) != 0 ? (1 << 4) : 0;

                        } else if (curr.equals("allowHTML1")) {
                            allowServer1 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.HTML.value) : 0;
                        } else if (curr.equals("allowNetwork1")) {
                            allowServer1 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.ALLOW_NETWORK.value) : 0;
                        } else if (curr.equals("allowBroadcast1")) {
                            allowServer1 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.BROADCAST.value) : 0;
                        } else if (curr.equals("allowDirect1")) {
                            allowServer1 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.ALLOW_DIRECT.value) : 0;

                        } else if (curr.equals("allowHTML2")) {
                            allowServer2 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.HTML.value) : 0;
                        } else if (curr.equals("allowBroadcast2")) {
                            allowServer2 |= Integer.parseInt(request.getParameter(curr)) != 0 ? (ServentManager.Allow.BROADCAST.value) : 0;
                        }
                    }

                    serventManager.showLog = showLog;
                    serventManager.allowServer1 = allowServer1;
                    serventManager.allowServer2 = allowServer2;

                    if (serventManager.serverHost.getPort() != newPort) {
                        InetSocketAddress lh = new InetSocketAddress(InetAddress.getLocalHost(), newPort);
                        String ipstr = lh.getHostName();
                        jumpStr = String.format("http://%s/%s/settings.html", ipstr, serventManager.htmlPath);

                        serventManager.serverHost = new InetSocketAddress(serventManager.serverHost.getAddress(), newPort);
                        serventManager.restartServer = true;
                        // html.setRefresh(3);
                        // html.setRefreshURL(jumpStr);
                        // html.startHTML();
                        // html.addHead();
                        // html.startBody();
                        // html.startTagEnd("h1","Please wait...");
                        // html.end();
                        // html.end();

                        // char ipstr[64];
                        // servMgr.serverHost.toStr(ipstr);
                        // sprintf(jumpStr,"/%s/settings.html",ipstr,servMgr.htmlPath);
                        jumpArg = jumpStr;

                    } else {
                        jumpStr = String.format("/%s/settings.html", serventManager.htmlPath);
                        jumpArg = jumpStr;
                    }

                    Peercast.getInstance().saveSettings();

                    Peercast.getInstance().updateSettings();

                    if ((serventManager.isRoot) && (brRoot))
                        serventManager.broadcastRootSettings(getUpd);

                } else if (cmd.equals("fetch")) {

                    ChannelInfo info = new ChannelInfo();
                    String curl = null;

                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        String value = request.getParameter(curr);
                        if (curr.equals("url")) {
                            curl = value; // String.T_ESC);
                        } else if (curr.equals("name")) {
                            info.name = value; // String.T_ESC);
                        } else if (curr.equals("desc")) {
                            info.desc = value; // String.T_ESC);
                        } else if (curr.equals("genre")) {
                            info.genre = value; // String.T_ESC);
                        } else if (curr.equals("contact")) {
                            info.url = value; // String.T_ESC);
                        } else if (curr.equals("bitrate")) {
                            info.bitrate = Integer.parseInt(value);
                        } else if (curr.equals("type")) {
                            info.contentType = ChannelInfo.ContentType.valueOf(value);
                        }

                    }

                    Channel c = channelManager.createChannel(info, null);
                    if (c != null) {
                        c.startURL(curl);
                    }

                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("stopserv")) {

                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("index")) {
                            Servent s = serventManager.findServentByIndex(Integer.parseInt(request.getParameter(curr)));
                            if (s != null) {
                                s.abort();
                            }
                        }
                    }
                    jumpStr = String.format("/%s/connections.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("hitlist")) {

                    Channel[] clist = new Channel[ChannelManager.MAX_CHANNELS];
                    int numChans = 0;
                    boolean stayConnected = request.getParameter("relay") != null;

                    int count = 0;
                    for (ChannelHitList chl : channelManager.channelHitLists) {
                        if (chl.isUsed()) { // TODO CHECK!!!
                            String tmp = request.getParameter(String.format("c%d", count++));

                            if (tmp.equals("1")) {
                                Channel c;
                                if ((c = channelManager.findChannelByID(chl.info.id)) == null) {
                                    c = channelManager.createChannel(chl.info, null);
                                    if (c == null) {
                                        throw new IOException("out of channels");
                                    }
                                    c.stayConnected = stayConnected;
                                    c.startGet();
                                }
                                clist[numChans++] = c;
                            }

                        }
                    }

                    String findArg = request.getParameter("keywords");

                    if (request.getParameter("relay") != null) {
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException e) {
                        }
                        jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                        jumpArg = jumpStr;
                    }
                } else if (cmd.equals("clear")) {
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("hostcache"))
                            serventManager.clearServiceHosts(ServHost.Type.SERVENT);
                        else if (curr.equals("hitlists"))
                            channelManager.clearHitLists();
                        else if (curr.equals("packets")) {
                            Peercast.getInstance().stats.clearRange(Stats.STAT.PACKETSSTART, Stats.STAT.PACKETSEND);
                            serventManager.numVersions = 0;
                        }
                    }

                    jumpStr = String.format("/%s/index.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("upgrade")) {
                    if (serventManager.downloadURL != null) {
                        jumpStr = String.format("/admin?cmd=redirect&url=%s", serventManager.downloadURL);
                        jumpArg = jumpStr;
                    }

                } else if (cmd.equals("chan")) {

                    List<Channel> targetChannels = new ArrayList<>();
                    ChannelInfo info = new ChannelInfo();
                    List<Channel> channels = channelManager.findChannels(info, ChannelManager.MAX_CHANNELS);

                    for (Channel channel : channels) {
                        String tmp = request.getParameter(String.format("c%d=", channel.index));
                        if (tmp.equals("1")) {
                            targetChannels.add(channel);
                        }
                    }

                    boolean delay = false;

                    if (request.getParameter("bump") != null) {
                        for (Channel channel : targetChannels) {
                            channel.bump = true;
                        }
                        delay = true;
                    }

                    if (request.getParameter("keep") != null) {
                        for (Channel channel : targetChannels) {
                            channel.stayConnected = true;
                        }
                        delay = true;
                    }

                    if (request.getParameter("stop") != null) {
                        for (Channel channel : targetChannels) {
                            channel.streaming.cancel(true);
                        }
                        delay = true;
                    }

                    if (delay) {
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException e) {
                        }
                    }

                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("connect")) {

                    for (Servent s : serventManager.servents) {
                        String tmp = request.getParameter(String.format("c%d=", s.serventIndex));
                        if (tmp.equals("1")) {
                            if (request.getParameter("stop") != null) {
                                s.server.stop();
                            }
                        }
                    }
                    jumpStr = String.format("/%s/connections.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("shutdown")) {
                    serventManager.shutdownTimer = 1;

                } else if (cmd.equals("stop")) {
                    GnuID id = new GnuID();
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("id")) {
                            id = new GnuID(request.getParameter(curr));
                        }
                    }

                    Channel c = channelManager.findChannelByID(id);
                    if (c != null) {
                        c.streaming.cancel(true);
                    }

                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException e1) {
                    }
                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("bump")) {
                    GnuID id = new GnuID();
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("id")) {
                            id = new GnuID(request.getParameter(curr));
                        }
                    }

                    Channel c = channelManager.findChannelByID(id);
                    if (c != null) {
                        c.bump = true;
                    }

                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("keep")) {
                    GnuID id = new GnuID();
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("id")) {
                            id = new GnuID(request.getParameter(curr));
                        }
                    }

                    Channel c = channelManager.findChannelByID(id);
                    if (c != null) {
                        c.stayConnected = true;
                    }

                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (cmd.equals("relay")) {
                    ChannelInfo info = new ChannelInfo();
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("id")) {
                            info.id = new GnuID(request.getParameter(curr));
                        }
                    }

                    if (channelManager.findChannelByID(info.id) == null) {

                        ChannelHitList chl = channelManager.findHitList(info);
                        if (chl == null) {
                            throw new IOException("channel not found");
                        }

                        Channel c = channelManager.createChannel(chl.info, null);
                        if (c == null) {
                            throw new IOException("out of channels");
                        }

                        c.stayConnected = true;
                        c.startGet();
                    }

                    jumpStr = String.format("/%s/relays.html", serventManager.htmlPath);
                    jumpArg = jumpStr;

                } else if (net.equals("add")) {

                    GnuID id = new GnuID();
                    id.clear();
                    Enumeration<?> e = request.getParameterNames();
                    while (e.hasMoreElements()) {
                        curr = (String) e.nextElement();
                        if (curr.equals("ip")) {
                            InetSocketAddress h = new InetSocketAddress(request.getParameter(curr), GnuPacket.DEFAULT_PORT);
                            if (serventManager.addOutgoing(h, id, true)) {
                                log.debug(String.format("Added connection: %s", request.getParameter(curr)));
                            }
                        } else if (curr.equals("id")) {
                            id = new GnuID(request.getParameter(curr));
                        }
                    }

                } else if (cmd.equals("logout")) {
                    jumpArg = "/";
                    serventManager.cookieList.remove(cookie);

                } else if (cmd.equals("login")) {
                    GnuID id = new GnuID();
                    id.generate();
                    String idstr = id.toString();

                    cookie.setComment(idstr); // TODO html structure
                    cookie.setValue(((InetSocketAddress) sock.getRemoteSocketAddress()).getAddress().getHostName());
                    serventManager.cookieList.add(cookie);

                    response.setStatus(HttpServletResponse.SC_OK);
                    if (serventManager.neverExpire) {
                        response.setHeader(Peercast.HTTP_HS_SETCOOKIE, String.format("id=%s; path=/; expires=\"Mon, 01-Jan-3000 00:00:00 GMT\";", idstr));
                    } else {
                        response.setHeader(Peercast.HTTP_HS_SETCOOKIE, String.format("id=%s; path=/;", idstr));
                    }
                    response.setHeader("Location", String.format("/%s/index.html", serventManager.htmlPath));

                } else {

                    jumpStr = String.format("/%s/index.html", serventManager.htmlPath);
                    jumpArg = jumpStr;
                }
            }

        } catch (IOException e) {
            Element h1 = Peercast.newElement("h1");
            h1.setTextContent(String.format("ERROR - %s", e.getMessage()));
            log.error(String.format("html: %s", e.getMessage()));
        }

        if (retHTML) {
            if (jumpArg != null) {
                String jmp = new String(jumpArg);
                response.sendRedirect(jmp);
            }
        }
    }

    /** */
    static Element createChannelXML(Channel c) {
        Element n = c.info.createChannelXML();
        n.appendChild(c.createRelayXML(true));
        n.appendChild(c.info.createTrackXML());
        // n.add(c.info.createServentXML());
        return n;
    }

    /** */
    static Element createChannelXML(ChannelHitList chl) {
        Element n = chl.info.createChannelXML();
        n.appendChild(chl.createHitsXML());
        n.appendChild(chl.info.createTrackXML());
        // n.add(chl.info.createServentXML());
        return n;
    }

    /** */
    void handshakeXML() throws IOException {

        Document xml = Peercast.db.newDocument();

        Element root = xml.createElement("peercast");
        xml.appendChild(root);

        Element e = xml.createElement("servent");
        e.setAttribute("uptime", String.valueOf(serventManager.getUptime()));
        root.appendChild(e);

        e = xml.createElement("bandwidth");
        e.setAttribute("out", String.valueOf(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESOUT) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESOUT)));
        e.setAttribute("in", String.valueOf(Peercast.getInstance().stats.getPerSecond(Stats.STAT.BYTESIN) - Peercast.getInstance().stats.getPerSecond(Stats.STAT.LOCALBYTESIN)));
        root.appendChild(e);

        e = xml.createElement("connections");
        e.setAttribute("total", String.valueOf(serventManager.totalConnected()));
        e.setAttribute("relays", String.valueOf(serventManager.numStreams(Type.RELAY, true)));
        e.setAttribute("direct", String.valueOf(serventManager.numStreams(Type.DIRECT, true)));
        root.appendChild(e);

        ChannelInfo info = new ChannelInfo();
        List<Channel> channels = channelManager.findChannels(info, ChannelManager.MAX_CHANNELS);

        Element an = xml.createElement("channels_relayed");
        an.setAttribute("total", String.valueOf(channels.size()));
        root.appendChild(an);
        for (Channel channel : channels) {
            an.appendChild(createChannelXML(channel));
        }

        Element fn = xml.createElement("channels_found");
        an.setAttribute("total", String.valueOf(channelManager.numHitLists()));
        root.appendChild(fn);
        for (ChannelHitList hitList : channelManager.channelHitLists) {
            if (hitList.isUsed()) {
                fn.appendChild(createChannelXML(hitList));
            }
        }

        Element hc = xml.createElement("host_cache");
        for (ServHost sh : serventManager.serviceHosts) {
            if (sh.type != ServHost.Type.NONE) {
                String ipstr = sh.address.getHostName();

                e = xml.createElement("host");
                e.setAttribute("ip", ipstr);
                e.setAttribute("type", sh.type.toString());
                e.setAttribute("time", String.valueOf(sh.time));
                hc.appendChild(e);
            }
        }
        root.appendChild(hc);

        PrintStream ps = new PrintStream(sock.getOutputStream());
        ps.println(HttpServletResponse.SC_OK);
        ps.printf("%s %s\n", Peercast.HTTP_HS_SERVER, GnuPacket.PCX_AGENT);
        ps.printf("%s %s\n", Peercast.HTTP_HS_CONTENT, Peercast.MIME_XML);
        ps.println("Connection: close");

        ps.println();

        PrettyPrinter pp = new PrettyPrinter(sock.getOutputStream());
        pp.print(xml);
    }

    /**
     * Injects response header values into info
     * @param context
     * @param info
     * @param servent
     */
    static void readICYHeader(HttpContext context, ChannelInfo info, Servent servent) {

        Iterator<?> e = context.getHeaders().keySet().iterator();
        while (e.hasNext()) {
            String name = (String) e.next();
//log.debug("name: " + name);

            if (name.equals("x-audiocast-name") || name.equals("icy-name") || name.equals("ice-name")) {
                info.name = context.getHeader(name);

            } else if (name.equals("x-audiocast-url") || name.equals("icy-url") || name.equals("ice-url")) {
                info.url = context.getHeader(name);
            } else if (name.equals("x-audiocast-bitrate") || name.equals("icy-br") || name.equals("ice-bitrate") || name.equals("icy-bitrate")) {
                info.bitrate = Integer.parseInt(context.getHeader(name));
            } else if (name.equals("x-audiocast-genre") || name.equals("ice-genre") || name.equals("icy-genre")) {
                info.genre = context.getHeader(name);

            } else if (name.equals("x-audiocast-description") || name.equals("ice-description")) {
                info.desc = context.getHeader(name);

            } else if (name.equals("authorization")) {
                String value = new String(Base64.decodeBase64(context.getHeader("Basic").getBytes()));
                int p = value.indexOf(':');
                servent.loginPassword = value.substring(p + 1);
            } else if (name.equals(GnuPacket.PCX_HS_CHANNELID)) {
                info.id = new GnuID(context.getHeader(name));
            } else if (name.equals("ice-password")) {
                if (servent.loginPassword != null) {
                    if (context.getHeader(name).length() < 64) {
                        servent.loginPassword = context.getHeader(name);
                    }
                }
            } else if (name.equals("content-type")) {
                String arg = context.getHeader(name);
//log.debug("content-type: value: " + arg);
                if (arg.indexOf(Peercast.MIME_OGG) >= 0) {
                    info.contentType = ChannelInfo.ContentType.OGG;
                } else if (arg.indexOf(Peercast.MIME_XOGG) >= 0) {
                    info.contentType = ChannelInfo.ContentType.OGG;

                } else if (arg.indexOf(Peercast.MIME_MP3) >= 0) {
                    info.contentType = ChannelInfo.ContentType.MP3;
                } else if (arg.indexOf(Peercast.MIME_XMP3) >= 0) {
                    info.contentType = ChannelInfo.ContentType.MP3;

                } else if (arg.indexOf(Peercast.MIME_WMA) >= 0) {
                    info.contentType = ChannelInfo.ContentType.WMA;
                } else if (arg.indexOf(Peercast.MIME_WMV) >= 0) {
                    info.contentType = ChannelInfo.ContentType.WMV;
                } else if (arg.indexOf(Peercast.MIME_ASX) >= 0) {
                    info.contentType = ChannelInfo.ContentType.ASX;

                } else if (arg.indexOf(Peercast.MIME_NSV) >= 0) {
                    info.contentType = ChannelInfo.ContentType.NSV;
                } else if (arg.indexOf(Peercast.MIME_RAW) >= 0) {
                    info.contentType = ChannelInfo.ContentType.RAW;

                } else if (arg.indexOf(Peercast.MIME_MMS) >= 0) {
                    info.srcProtocol = ChannelInfo.Protocol.MMS;
                } else if (arg.indexOf(Peercast.MIME_XPCP) >= 0) {
                    info.srcProtocol = ChannelInfo.Protocol.PCP;
                } else if (arg.indexOf(Peercast.MIME_XPEERCAST) >= 0) {
                    info.srcProtocol = ChannelInfo.Protocol.PEERCAST;

                } else if (arg.indexOf(Peercast.MIME_XSCPLS) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                } else if (arg.indexOf(Peercast.MIME_PLS) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                } else if (arg.indexOf(Peercast.MIME_XPLS) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                } else if (arg.indexOf(Peercast.MIME_M3U) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                } else if (arg.indexOf(Peercast.MIME_MPEGURL) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                } else if (arg.indexOf(Peercast.MIME_TEXT) >= 0) {
                    info.contentType = ChannelInfo.ContentType.PLS;
                }
//log.debug("content-type: " + info.contentType);
            }
        }
    }

    /** */
    void handshakeICY(HttpContext request, HttpServletResponse response, Channel.SourceType type, boolean isHTTP) throws IOException {
        ChannelInfo info = new ChannelInfo();

        // default to mp3 for shoutcast DSP (doesn`t send content-type)
        if (type.equals(Channel.SourceType.SHOUTCAST)) {
            info.contentType = ChannelInfo.ContentType.MP3;
        }

        // log.debug(String.format("ICY %s", http.cmdLine));
        readICYHeader(request, info, this);

        // check password before anything else, if needed
        if (serventManager.password.equals(loginPassword)) {
            if (!InetAddress.getByName(request.getRemoteHost()).isAnyLocalAddress() || loginPassword != null) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }

        // we need a valid IP address before we start
        serventManager.checkFirewall();

        // attach channel ID to name, channel ID is also encoded with IP address
        // to help prevent channel hijacking.

        info.id = channelManager.broadcastID;
        info.id.encode(null, info.name, loginMount, (byte) info.bitrate);

        log.debug(String.format("Incoming source: %s : %s", info.name, info.contentType.name()));

        if (isHTTP) {
            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            response.setStatus(0); // "OK";
        }

        Channel c = channelManager.findChannelByID(info.id);
        if (c != null) {
            log.debug("ICY channel already active, closing old one");
            c.streaming.cancel(true);
        }

        info.comment = channelManager.broadcastMessage;

        c = channelManager.createChannel(info, loginMount);
        if (c == null) {
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }

        c.startICY(sock, type);
    }

    /** */
    void handshakeLocalFile(HttpServletResponse response, String fn) {

        String fileName;

        fileName = Peercast.getInstance().getPath();

        fileName += fn;

        log.debug("HTML client");

        int args = fileName.indexOf("?");
        if (args > 0) {
            fileName = fileName.substring(0, args++);
        }

        if (fileName.contains(".htm")) {
            writeOK(Peercast.MIME_HTML);
            writeTemplate(response, fileName, args);

        } else if (fileName.contains(".css")) {
            writeOK(Peercast.MIME_CSS);
            writeRawFile(response, fileName);
        } else if (fileName.contains(".jpg")) {
            writeOK(Peercast.MIME_JPEG);
            writeRawFile(response, fileName);
        } else if (fileName.contains(".gif")) {
            writeOK(Peercast.MIME_GIF);
            writeRawFile(response, fileName);
        } else if (fileName.contains(".png")) {
            writeOK(Peercast.MIME_PNG);
            writeRawFile(response, fileName);
        }
    }

    /** */
    private void writeRawFile(HttpServletResponse response, String fileName) {
        // TODO File(fileName) -> response.getOutputStream
    }

    /**
     * $foo value, \@bar command
     */
    private void writeTemplate(HttpServletResponse response, String fileName, int args) {
        // TODO read template, replace, output
    }

    /** */
    void handshakeRemoteFile(HttpServletResponse response, final String dirName) throws IOException {

        final String hostName = "www.peercast.org"; // hardwired for "security"

        HttpContext requestContext = new HttpContext(); // rsock
        requestContext.setRemoteHost(hostName);
        requestContext.setRemotePort(80);
        requestContext.setMethod("GET");
        requestContext.setProtocol(new HttpProtocol());
        requestContext.setHeader(Peercast.HTTP_HS_HOST, hostName);
        requestContext.setHeader(Peercast.HTTP_HS_CONNECTION, "close");
        requestContext.setHeader(Peercast.HTTP_HS_ACCEPT, "*/*");

        HttpContext responseContext = HttpUtil.postRequest(requestContext);

        String contentType = responseContext.getHeader("content-type");

        boolean isTemplate = false;
        if (contentType.contains(Peercast.MIME_HTML)) {
            isTemplate = true;
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(Peercast.HTTP_HS_SERVER, GnuPacket.PCX_AGENT);
        response.setHeader(Peercast.HTTP_HS_CACHE, "no-cache");
        response.setHeader(Peercast.HTTP_HS_CONNECTION, "close");
        response.setHeader(Peercast.HTTP_HS_CONTENT, contentType);

        if (isTemplate) {
            Document html = Peercast.db.newDocument();
            Object o = readTemplate(sock.getInputStream());
        } else {
            InputStream is = responseContext.getInputStream();
            OutputStream os = response.getOutputStream();
            byte[] buffer = new byte[8192];
            while (is.available() > 0) {
                int l = is.read(buffer, 0, buffer.length);
                os.write(buffer, 0, l);
            }
        }
    }

    /** */
    Object readTemplate(InputStream inputStream) {
        // TODO inputStream -> response
        return null;
    }

    boolean isConnected() {
        return status == Status.CONNECTED;
    }

    boolean isListening() {
        return status == Status.LISTENING;
    }

    boolean hasSeenPacket(GnuPacket p) {
        return seenIDs.contains(p.id);
    }

    Type type;

    Status status;

    GnuStream gnuStream;

    GnuPacket pack;

    long lastConnect;

    long lastPing;

    long lastPacket;

    String agent;

    List<GnuID> seenIDs;

    GnuID networkID;

    int serventIndex;

    GnuID remoteID;

    GnuID chanID;

    GnuID givID;

    InetServer server;

    String loginPassword;

    String loginMount;

    boolean priorityConnect;

    boolean addMetadata;

    int nsSwitchNum;

    int allow;

    Socket sock;

    Socket pushSock;

    boolean sendHeader;

    int syncPos, streamPos;

    int servPort;

    ChannelInfo.Protocol outputProtocol;

    GnuPacketBuffer outPacketsNorm, outPacketsPri;

    int bytesPerSecond;

    boolean flowControl;

    PCPStream pcpStream;

    Cookie cookie;
}

/* */
