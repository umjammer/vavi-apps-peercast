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
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.http.Cookie;

import org.w3c.dom.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.peercast.core.common.ChannelInfo.ContentType;
import org.peercast.core.common.ChannelInfo.Protocol;

import vavi.util.Debug;
import vavi.util.Singleton;
import vavi.util.win32.WindowsProperties;


/**
 * ServHost.
 * 
 * @version 4-apr-2002
 * @author giles
 */
class ServHost {

    enum Type {
        /** */
        NONE,
        /** */
        STREAM,
        /** */
        CHANNEL,
        /** */
        SERVENT,
        /** */
        TRACKER
    };

    ServHost() {
        address = null;
        time = 0;
        type = Type.NONE;
    }

    ServHost(InetSocketAddress address, Type type, long time) {
        this.address = address;
        this.type = type;
        if (time != 0) {
            this.time = time;
        } else {
            this.time = System.currentTimeMillis();
        }
    }

    Type type;

    InetSocketAddress address;

    long time;
}

/** */
class ServFilter {

    enum Type {
        /** */
        PRIVATE(0x01),
        /** */
        BAN(0x02),
        /** */
        NETWORK(0x04),
        /** */
        DIRECT(0x08);
        int value;
        Type(int value) {
            this.value = value;
        }
    };

    ServFilter() {
        flags = 0;
        mask = new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255 };
    }

    /** */
    boolean writeVariable(OutputStream out, final String var) throws IOException {
        StringBuilder buf = new StringBuilder();

        if (var.equals("network")) {
            buf.append((flags & Type.NETWORK.value) != 0 ? "1" : "0");
        } else if (var.equals("private")) {
            buf.append((flags & Type.PRIVATE.value) != 0 ? "1" : "0");
        } else if (var.equals("direct")) {
            buf.append((flags & Type.DIRECT.value) != 0 ? "1" : "0");
        } else if (var.equals("banned")) {
            buf.append((flags & Type.BAN.value) != 0 ? "1" : "0");
        } else if (var.equals("ip")) {
            buf.append(getMask());
        } else {
            return false;
        }

        out.write(buf.toString().getBytes());
        return true;
    }

    byte[] mask;

    int flags;

    boolean isMemberOf(InetAddress s) {

        if (mask[0] != (byte) 255 && s.getAddress()[0] != mask[0]) {
            return false;
        }
        if (mask[1] != (byte) 255 && s.getAddress()[1] != mask[1]) {
            return false;
        }
        if (mask[2] != (byte) 255 && s.getAddress()[2] != mask[2]) {
            return false;
        }
        if (mask[3] != (byte) 255 && s.getAddress()[3] != mask[3]) {
            return false;
        }
        return true;
    }    

    void setMask(String mask) {
        String[] ip = mask.split("\\.");
        for (int i = 0; i < 4; i++) {
            this.mask[i] = (byte) Integer.parseInt(ip[i]);
        }
    }

    String getMask() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            sb.append(this.mask[i] & 0xff);
            if (i != 3) {
                sb.append('.');
            }
        }
        return sb.toString();
    }
}

/**
 * ServMgr keeps track of Servents.
 */
public class ServentManager extends Singleton {

    /** */
    private static Log log = LogFactory.getLog(ServentManager.class);

    /** */
    static final int MIN_YP_RETRY = 20;

    /** */
    static final int MIN_TRACKER_RETRY = 10;

    /** */
    static final int MIN_RELAY_RETRY = 5;

    /** */
    enum NotifyType {
        /** */
        UPGRADE(0x0001),
        /** */
        PEERCAST(0x0002),
        /** */
        BROADCASTERS(0x0004),
        /** */
        TRACKINFO(0x0008);
        /** */
        int value;
        /** */
        NotifyType(int value) {
            this.value = value;
        }
    }

    /** */
    enum FirewallState {
        /** */
        OFF,
        /** */
        ON,
        /** */
        UNKNOWN
    }

    // max. amount of hosts in cache
    static final int MAX_HOSTCACHE = 100;

    // min. amount of hosts that should be kept in cache
    static final int MIN_HOSTS = 3;

    // max. number of outgoing servents to use
    static final int MAX_OUTGOING = 3;

    // max. number of public incoming servents to use
    static final int MAX_INCOMING = 6;

    // max. number of outgoing servents to try connect
    static final int MAX_TRYOUT = 10;

    // min. amount of connected hosts that should be kept
    static final int MIN_CONNECTED = 3;

    /** */
    static final int MAX_FILTERS = 50;

    /** */
    static final int MAX_VERSIONS = 16;

    // max. seconds preview per channel available (direct connections)
    static final int MAX_PREVIEWTIME = 300;

    // max. seconds wait between previews
    static final int MAX_PREVIEWWAIT = 300;

    /** */
    enum AuthType {
        /** */
        COOKIE,
        /** */
        HTTPBASIC
    }

    /** */
    static enum Allow {
        /** */
        HTML(0x01),
        /** */
        BROADCAST(0x02),
        /** */
        ALLOW_NETWORK(0x04),
        /** */
        ALLOW_DIRECT(0x08),
        /** */
        ALL(0xff);
        /** */
        int value;
        /** */
        Allow(int value) {
            this.value = value;
        }
    }

    /** */
    public ServentManager() {
        clearServiceHosts(ServHost.Type.NONE);
        sessionID.generate();

        setFilterDefaults();
    }

    /** */
    void connectBroadcaster() {
        if (rootHost.length() != 0) {
            if (numUsed(Servent.Type.COUT) == 0) {
                Servent sv = allocServent();
                if (sv != null) {
                    sv.initOutgoing(Servent.Type.COUT);
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException e) {
                    }
                }
            }
        }
    }

    /** */
    void addVersion(int ver) {
        for (int i = 0; i < numVersions; i++) {
            if (clientVersions[i] == ver) {
                clientCounts[i]++;
                return;
            }
        }

        if (numVersions < MAX_VERSIONS) {
            clientVersions[numVersions] = ver;
            clientCounts[numVersions] = 1;
            numVersions++;
        }
    }

    /** */
    void setFilterDefaults() {
        ServFilter filter = new ServFilter();
        filter.setMask("255.255.255.255");
        filter.flags = ServFilter.Type.NETWORK.value | ServFilter.Type.DIRECT.value;
        filters.add(filter);
    }

    /** */
    void setPassiveSearch(int t) {
    }

    /** */
    boolean seenHost(InetSocketAddress h, ServHost.Type type, long time) {
        time = System.currentTimeMillis() - time;

        for (ServHost serviceHost : serviceHosts) {
            if (serviceHost.type == type) {
                if (serviceHost.address.getAddress().equals(h.getAddress())) {
                    if (serviceHost.time >= time) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /** */
    void addHost(InetSocketAddress address, ServHost.Type type, long time) {

        if (address.getAddress().getAddress() == null) {
            return;
        }

        ServHost sh = null;

        for (ServHost serviceHost : serviceHosts) {
            if (serviceHost.type == type) {
                if (serviceHost.address.equals(address)) {
                    sh = serviceHost;
                    break;
                }
            }
        }

        String hostName = address.getHostName();
        if (sh == null) {
            log.debug(String.format("New host: %s - %s", hostName, type.toString()));
        } else {
            log.debug(String.format("Old host: %s - %s", hostName, type.toString()));
        }

        address = null; // make sure dead count is zero
        if (sh == null) {

            // find empty slot
            for (ServHost serviceHost : serviceHosts) {
                if (serviceHost.type == ServHost.Type.NONE) {
                    sh = serviceHost;
                    break;
                }
            }

            // otherwise, find oldest host and replace
            if (sh == null) {
                for (ServHost serviceHost : serviceHosts) {
                    if (serviceHost.type != ServHost.Type.NONE) {
                        if (sh != null) {
                            if (serviceHost.time < sh.time) {
                                sh = serviceHost;
                            }
                        } else {
                            sh = serviceHost;
                        }
                    }
                }
            }
        }

        if (sh != null) {
            sh = new ServHost(address, type, time);
        }
    }

    /** */
    void clearDeadServiceHost(InetSocketAddress address, ServHost.Type type) {
        List<ServHost> tempServiceHosts = new ArrayList<ServHost>(serviceHosts);
        for (ServHost serviceHost : tempServiceHosts) {
            if (serviceHost.type.equals(type) && serviceHost.address.equals(address)) {
                serviceHosts.remove(serviceHost);
            }
        }
    }

    /** */
    void clearServiceHosts(ServHost.Type type) {
        List<ServHost> tempServiceHosts = new ArrayList<ServHost>(serviceHosts);
        for (ServHost serviceHost : tempServiceHosts) {
            if (serviceHost.type.equals(type) || type.equals(ServHost.Type.NONE)) {
                serviceHosts.remove(serviceHost);
            }
        }
    }

    /** */
    int getServiceHostsCount(ServHost.Type type) {
        int count = 0;
        for (ServHost serviceHost : serviceHosts) {
            if (serviceHost.type.equals(type) || type.equals(ServHost.Type.NONE)) {
                count++;
            }
        }
        return count;
    }

    /** */
    int getNewestServents(InetSocketAddress[] addresses, int max, InetSocketAddress rh) {
        int count = 0;
        for (int i = 0; i < max; i++) {
            // find newest host not in list
            ServHost foundServiceHost = null;
            for (ServHost serviceHost : serviceHosts) {
                // find newest servent
                if (serviceHost.type.equals(ServHost.Type.SERVENT)) {
                    if (!(!rh.getAddress().isAnyLocalAddress() && serviceHost.address.getAddress().isAnyLocalAddress())) {
                        // and not in list already
                        boolean found = false;
                        for (int k = 0; k < count; k++) {
                            if (addresses[k].equals(serviceHost.address)) {
                                found = true;
                                break;
                            }
                        }

                        if (!found) {
                            if (foundServiceHost == null) {
                                foundServiceHost = serviceHost;
                            } else {
                                if (serviceHost.time > foundServiceHost.time) {
                                    foundServiceHost = serviceHost;
                                }
                            }
                        }
                    }
                }
            }

            // add to list
            if (foundServiceHost != null) {
                addresses[count++] = foundServiceHost.address;
            }
        }

        return count;
    }

    /** */
    ServHost getOutgoingServent(GnuID netid) throws IOException {
        ServHost host = new ServHost();

        InetSocketAddress lh = new InetSocketAddress(InetAddress.getLocalHost(), 0);

        // find newest host not in list
        ServHost sh = null;
        for (ServHost serviceHost : serviceHosts) {
            ServHost hc = serviceHost;
            // find newest servent not already connected.
            if (hc.type == ServHost.Type.SERVENT) {
                if (!((!lh.getAddress().isAnyLocalAddress() && hc.address.getAddress().isAnyLocalAddress()) || lh.equals(hc.address))) {

                }
            }
        }

        if (sh != null) {
            host = sh;
        }

        return host;
    }

    /** */
    Servent findOldestServent(Servent.Type type, boolean priv) {
        Servent oldest = null;

        for (Servent servant : servents) {
            if (servant.type.equals(type)) {
                if (servant.isOlderThan(oldest)) {
                    if (servant.isPrivate() == priv) {
                        oldest = servant;
                    }
                }
            }
        }
        return oldest;
    }

    /** */
    synchronized Servent findServent(Servent.Type type, InetSocketAddress host, GnuID netid) {
        for (Servent servent : servents) {
            if (servent.type.equals(type)) {
                InetSocketAddress address = servent.getHost();
                if (address.equals(host) && servent.networkID.equals(netid)) {
                    return servent;
                }
            }
        }
        return null;

    }

    /** */
    synchronized Servent findServent(int ip, short port, GnuID netid) {
        for (Servent servent : servents) {
            if (!servent.type.equals(Servent.Type.NONE)) {
                InetSocketAddress address = servent.getHost();
                if (Peercast.byteToInt(address.getAddress().getAddress()) == ip && address.getPort() == port && servent.networkID.equals(netid)) {
                    return servent;
                }
            }
        }
        return null;

    }

    /** */
    Servent findServent(Servent.Type type) {
        for (Servent servent : servents) {
            if (servent.type.equals(type)) {
                return servent;
            }
        }
        return null;
    }

    /** */
    Servent findServentByIndex(int id) {
        int count = 0;
        for (Servent servent : servents) {
            if (count == id) {
                return servent;
            }
            count++;
        }
        return null;
    }

    /** */
    synchronized Servent allocServent() {

        Servent newServent = new Servent(++serventNum);
        servents.add(newServent);

        return newServent;
    }

    /** */
    void closeConnections(Servent.Type type) {
        for (Servent servent : servents) {
            if (servent.isConnected() &&
                servent.type.equals(type)) {
                    // sv.thread.isAlive() = false; // TODO check comment out
            }
        }
    }

    /** */
    int numConnected(Servent.Type type, boolean priv, int uptime) {
        int count = 0;

        long currentTime = System.currentTimeMillis();
        for (Servent servent : servents) {
            if (servent.isConnected() &&
                servent.type.equals(type) &&
                servent.isPrivate() == priv && 
                (currentTime - servent.lastConnect) >= uptime) {
                count++;
            }
        }

        return count;
    }

    /** */
    int numConnected() {
        int count = 0;

        for (Servent servent : servents) {
            if (servent.isConnected()) {
                count++;
            }
        }
        return count;
    }

    /** */
    int numServents() {
        return servents.size();
    }

    /** */
    int numUsed(Servent.Type type) {
        int count = 0;

        for (Servent servent : servents) {
            if (servent.type.equals(type)) {
                count++;
            }
        }
        return count;
    }

    /** */
    int numActiveOnPort(int port) {
        int count = 0;

        for (Servent servent : servents) {
            if (servent.servPort == port) {
                count++;
            }
        }
        return count;
    }

    /** */
    int numActive(Servent.Type type) {
        int count = 0;

        for (Servent servent : servents) {
            if (servent.type.equals(type)) {
                count++;
            }
        }
        return count;
    }

    /** */
    int totalOutput(boolean all) {
        int total = 0;
        for (Servent servent : servents) {
            if (servent.isConnected()) {
                if (all || !servent.isPrivate()) {
                    total += Peercast.getInstance().bytesOutPerSec;
                }
            }
        }

        return total;
    }

    /** */
    int numOutgoing() {
        return servents.size();
    }

    /** */
    boolean seenPacket(GnuPacket packet) {
        for (Servent servent : servents) {
            if (servent.isConnected()) {
                if (servent.seenIDs.contains(packet.id)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** */
    void quit() {
        log.debug("ServMgr is quitting..");

        serverThread.interrupt();

        idleThread.interrupt();

        for (Servent servent : servents) {
            try {
                servent.server.stop();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /** */
    int broadcast(GnuPacket packet, Servent source) {
        int count = 0;
        if (packet.ttl != 0) {
            for (Servent servent : servents) {

                if (servent != source) {
                    if (servent.isConnected() &&
                        servent.type == Servent.Type.PGNU &&
                        !servent.seenIDs.contains(packet.id)) {

                        if (source != null) {
                            if (!source.networkID.equals(servent.networkID)) {
                                continue;
                            }
                        }

                        if (servent.outputPacket(packet, false)) {
                            count++;
                        }
                    }
                }
            }
        }

        log.debug(String.format("broadcast: %s (%d) to %d servents", packet.func, packet.ttl, count));

        return count;
    }

    /** */
    int route(GnuPacket pack, GnuID routeID, Servent src) {
        int count = 0;
        if (pack.ttl != 0) {
            for (Servent servent : servents) {
                if (servent != src) {
                    if (servent.isConnected()) {
                        if (servent.type == Servent.Type.PGNU) {
                            if (!servent.seenIDs.contains(pack.id)) {
                                if (servent.seenIDs.contains(routeID)) {
                                    if (src != null) {
                                        if (!src.networkID.equals(servent.networkID)) {
                                            continue;
                                        }
                                    }

                                    if (servent.outputPacket(pack, true)) {
                                        count++;
                                    }
                                }
                            }
                        }
                    }
                }
            }

        }

        log.debug(String.format("route: %s (%d) to %d servents", pack.func, pack.ttl, count));
        return count;
    }

    /** */
    boolean checkForceIP() throws IOException {
        if (forceIP.length() != 0) {
            int newIP = Peercast.byteToInt(InetAddress.getByName(forceIP).getAddress());
            if (Peercast.byteToInt(serverHost.getAddress().getAddress()) != newIP) {
                serverHost = new InetSocketAddress(InetAddress.getByAddress(Peercast.intToByte(newIP)), serverHost.getPort());
                log.debug(String.format("Server IP changed to %s", serverHost.getHostName()));
                return true;
            }
        }
        return false;
    }

    /** */
    void checkFirewall() throws IOException {
        if (getFirewall().equals(FirewallState.UNKNOWN) && rootHost.length() != 0) {

            log.debug("Checking firewall..");
            InetSocketAddress host;
            host = new InetSocketAddress(rootHost, GnuPacket.DEFAULT_PORT);

            Socket sock = new Socket();
            if (sock == null) {
                throw new IOException("Unable to create socket");
            }
            sock.setSoTimeout(30000);
            sock.connect(host);

            AtomOutputStream atomOut = new AtomOutputStream(sock.getOutputStream());

            atomOut.writeInt(PCPStream.PCP_CONNECT, 1);

            AtomInputStream atomIn = new AtomInputStream(sock.getInputStream());
            Servent.handshakeOutgoingPCP(atomIn, atomOut, (InetSocketAddress) sock.getRemoteSocketAddress(), null, null, true);

            atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT);

            sock.close();
        }
    }

    /** */
    void setFirewall(FirewallState state) {
        if (firewalled != state) {
            log.debug("Firewall is set to " + state);
            firewalled = state;
        }
    }

    /** */
    boolean isFiltered(int fl, InetSocketAddress h) {
        for (ServFilter filter : filters) {
            if ((filter.flags & fl) != 0) {
                if (filter.isMemberOf(h.getAddress())) {
                    return true;
                }
            }
        }

        return false;
    }

    /** */
    void writeServerSettings(WindowsProperties iniFile, int value, String section) {
        iniFile.setProperty(section + "." + "allowHTML", String.valueOf(value & ServentManager.Allow.HTML.value));
        iniFile.setProperty(section + "." + "allowBroadcast", String.valueOf(value & ServentManager.Allow.BROADCAST.value));
        iniFile.setProperty(section + "." + "allowNetwork", String.valueOf(value & ServentManager.Allow.ALLOW_NETWORK.value));
        iniFile.setProperty(section + "." + "allowDirect", String.valueOf(value & ServentManager.Allow.ALLOW_DIRECT.value));
    }

    /** */
    void writeFilterSettings(WindowsProperties iniFile, ServFilter servFilter) {
        iniFile.setProperty("Filter.ip", servFilter.getMask());
        iniFile.setProperty("Filter.private", String.valueOf(servFilter.flags & ServFilter.Type.PRIVATE.value));
        iniFile.setProperty("Filter.ban",     String.valueOf(servFilter.flags & ServFilter.Type.BAN.value));
        iniFile.setProperty("Filter.network", String.valueOf(servFilter.flags & ServFilter.Type.NETWORK.value));
        iniFile.setProperty("Filter.direct",  String.valueOf(servFilter.flags & ServFilter.Type.DIRECT.value));
    }

    /** */
    void writeServHost(WindowsProperties iniFile, ServHost servHost) {

        iniFile.setProperty("Host.type", servHost.type.toString());
        iniFile.setProperty("Host.address", servHost.address.getHostName());
        iniFile.setProperty("Host.time", String.valueOf(servHost.time));
    }

    /** */
    void saveSettings(String fn) {

        ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

        WindowsProperties iniFile = new WindowsProperties();

        log.debug(String.format("Saving settings to:  %s", fn));

        iniFile.setProperty("Server.serverPort", String.valueOf(serverHost.getPort()));
        iniFile.setProperty("Server.autoServe", String.valueOf(autoServe));
        iniFile.setProperty("Server.forceIP", forceIP);
        iniFile.setProperty("Server.isRoot", String.valueOf(isRoot));
        iniFile.setProperty("Server.maxBitrateOut", String.valueOf(maxBitrateOut));
        iniFile.setProperty("Server.maxRelays", String.valueOf(maxRelays));
        iniFile.setProperty("Server.maxDirect", String.valueOf(maxDirect));
        iniFile.setProperty("Server.maxRelaysPerChannel", String.valueOf(channelManager.maxRelaysPerChannel));
        iniFile.setProperty("Server.firewallTimeout", String.valueOf(firewallTimeout));
        iniFile.setProperty("Server.forceNormal", String.valueOf(forceNormal));
        iniFile.setProperty("Server.rootMsg", rootMsg);
        iniFile.setProperty("Server.authType", authType == AuthType.COOKIE ? "cookie" : "http-basic");
        iniFile.setProperty("Server.cookiesExpire", neverExpire == true ? "never" : "session");
        iniFile.setProperty("Server.htmlPath", htmlPath);
        iniFile.setProperty("Server.minPGNUIncoming", String.valueOf(minGnuIncoming));
        iniFile.setProperty("Server.maxPGNUIncoming", String.valueOf(maxGnuIncoming));
        iniFile.setProperty("Server.maxServIn", String.valueOf(maxServIn));

        iniFile.setProperty("Server.networkID", networkID.toString());

        iniFile.setProperty("Broadcast.broadcastMsgInterval", String.valueOf(channelManager.broadcastMsgInterval));
        iniFile.setProperty("Broadcast.broadcastMsg", String.valueOf(channelManager.broadcastMessage));
        iniFile.setProperty("Broadcast.icyMetaInterval", String.valueOf(channelManager.icyMetaInterval));

        iniFile.setProperty("Broadcast.broadcastID", channelManager.broadcastID.toString());
        iniFile.setProperty("Broadcast.hostUpdateInterval", String.valueOf(channelManager.hostUpdateInterval));
        iniFile.setProperty("Broadcast.maxControlConnections", String.valueOf(maxControl));
        iniFile.setProperty("Broadcast.rootHost", rootHost);

        iniFile.setProperty("Client.refreshHTML", String.valueOf(refreshHTML));
        iniFile.setProperty("Client.relayBroadcast", String.valueOf(relayBroadcast));
        iniFile.setProperty("Client.minBroadcastTTL", String.valueOf(channelManager.minBroadcastTTL));
        iniFile.setProperty("Client.maxBroadcastTTL", String.valueOf(channelManager.maxBroadcastTTL));
        iniFile.setProperty("Client.pushTries", String.valueOf(channelManager.pushTries));
        iniFile.setProperty("Client.pushTimeout", String.valueOf(channelManager.pushTimeout));
        iniFile.setProperty("Client.maxPushHops", String.valueOf(channelManager.maxPushHops));
        iniFile.setProperty("Client.autoQuery", String.valueOf(channelManager.autoQuery));
        iniFile.setProperty("Client.queryTTL", String.valueOf(queryTTL));

        iniFile.setProperty("Privacy.password", password);
        iniFile.setProperty("Privacy.maxUptime", String.valueOf(channelManager.maxUptime));

        for (ServFilter filter : filters) {
            writeFilterSettings(iniFile, filter);
        }

        iniFile.setProperty("Notify.PeerCast", String.valueOf(notifyMask & NotifyType.PEERCAST.value));
        iniFile.setProperty("Notify.Broadcasters", String.valueOf(notifyMask & NotifyType.BROADCASTERS.value));
        iniFile.setProperty("Notify.TrackInfo", String.valueOf(notifyMask & NotifyType.TRACKINFO.value));

        writeServerSettings(iniFile, allowServer1, "Server1");

        writeServerSettings(iniFile, allowServer2, "Server2");

        iniFile.setProperty("Debug.logDebug", String.valueOf((showLog & (1 << 1)) != 0));
        iniFile.setProperty("Debug.logErrors", String.valueOf((showLog & (1 << 2)) != 0));
        iniFile.setProperty("Debug.logNetwork", String.valueOf((showLog & (1 << 3)) != 0));
        iniFile.setProperty("Debug.logChannel", String.valueOf((showLog & (1 << 4)) != 0));
        iniFile.setProperty("Debug.pauseLog", String.valueOf(pauseLog));
        iniFile.setProperty("Debug.idleSleepTime", String.valueOf(Peercast.idleSleepTime));

        for (Channel channel : channelManager.channels) {
            if (channel != null && channel.isActive() && channel.stayConnected) {
                iniFile.setProperty("RelayChannel.name", channel.getName());
                iniFile.setProperty("RelayChannel.genre", channel.info.genre);
                if (channel.sourceURL.length() != 0) {
                    iniFile.setProperty("RelayChannel.sourceURL", channel.sourceURL);
                }
                iniFile.setProperty("RelayChannel.sourceProtocol", channel.info.srcProtocol.name());
                iniFile.setProperty("RelayChannel.contentType", channel.info.contentType.name());
                iniFile.setProperty("RelayChannel.bitrate", String.valueOf(channel.info.bitrate));
                iniFile.setProperty("RelayChannel.contactURL", channel.info.url);
                iniFile.setProperty("RelayChannel.id", channel.getIDString());
                iniFile.setProperty("RelayChannel.stayConnected", String.valueOf(channel.stayConnected));

                ChannelHitList chl = channelManager.findHitListByID(channel.info.id);
                if (chl != null) {

                    ChannelHitSearch chs = new ChannelHitSearch();
                    chs.trackersOnly = true;
                    if (chl.pickHits(chs) != 0) {
                        iniFile.setProperty("RelayChannel.tracker", chs.bestHits.get(0).getAddress().getHostName());
                    }
                }
            }
        }

        for (ServHost serviceHost : serviceHosts) {
            if (serviceHost.type != ServHost.Type.NONE) {
                writeServHost(iniFile, serviceHost);
            }
        }

        try {
            iniFile.store(new FileOutputStream(fn), Peercast.class.getName());
        } catch (IOException e) {
            log.error("Unable to open ini file");
        }
    }

    /** */
    int readServerSettings(WindowsProperties iniFile, int value, String section) {
        value = iniFile.getProperty(section + "." + "allowHTML"     , "false").equals("true") ? value | ServentManager.Allow.HTML.value          : value & ~ServentManager.Allow.HTML.value;
        value = iniFile.getProperty(section + "." + "allowDirect"   , "false").equals("true") ? value | ServentManager.Allow.ALLOW_DIRECT.value  : value & ~ServentManager.Allow.ALLOW_DIRECT.value;
        value = iniFile.getProperty(section + "." + "allowNetwork"  , "false").equals("true") ? value | ServentManager.Allow.ALLOW_NETWORK.value : value & ~ServentManager.Allow.ALLOW_NETWORK.value;
        value = iniFile.getProperty(section + "." + "allowBroadcast", "false").equals("true") ? value | ServentManager.Allow.BROADCAST.value     : value & ~ServentManager.Allow.BROADCAST.value;
        return value;
    }

    /** */
    void readFilterSettings(WindowsProperties iniFile, ServFilter servFilter) {

        servFilter.setMask(iniFile.getProperty("Filter.ip", "255.255.255.255"));
        servFilter.flags = (servFilter.flags & ~ServFilter.Type.PRIVATE.value) | (iniFile.getProperty("Filter.private", "false").equals("true") ? ServFilter.Type.PRIVATE.value : 0);
        servFilter.flags = (servFilter.flags & ~ServFilter.Type.BAN.value)     | (iniFile.getProperty("Filter.ban",     "false").equals("true") ? ServFilter.Type.BAN.value :     0);
        servFilter.flags = (servFilter.flags & ~ServFilter.Type.NETWORK.value) | (iniFile.getProperty("Filter.allow",   "false").equals("true") ? ServFilter.Type.NETWORK.value : 0);
        servFilter.flags = (servFilter.flags & ~ServFilter.Type.DIRECT.value)  | (iniFile.getProperty("Filter.direct",  "false").equals("true") ? ServFilter.Type.DIRECT.value :  0);
    }

    /** */
    void loadSettings(String fileName) {
        ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

        WindowsProperties iniFile = new WindowsProperties();

        if (!new File(fileName).exists()) {
            saveSettings(fileName);
            return;
        }

        showLog = 0;

        try {
            iniFile.load(new FileInputStream(fileName));

            // [Server] settings
            serverHost = new InetSocketAddress(InetAddress.getLocalHost(), Integer.parseInt(iniFile.getProperty("Server.serverPort")));
            autoServe = iniFile.getProperty("Server.autoServe", "false").equals("true");
            autoConnect = iniFile.getProperty("Server.autoConnect", "false").equals("true");
            password = iniFile.getProperty("Server.icyPassword", "");
            forceIP = iniFile.getProperty("Server.forceIP", "");
            isRoot = iniFile.getProperty("Server.isRoot", "false").equals("true");
            channelManager.broadcastID = new GnuID(iniFile.getProperty("Broadcast.broadcastID", "00000000000000000000000000000000"));
            htmlPath = iniFile.getProperty("Server.htmlPath", "html/ja");
            maxGnuIncoming = Integer.parseInt(iniFile.getProperty("Server.maxPGNUIncoming", "10"));
            minGnuIncoming = Integer.parseInt(iniFile.getProperty("Server.minPGNUIncoming", "20"));

            maxControl = Integer.parseInt(iniFile.getProperty("Broadcast.maxControlConnections", "3"));

            maxBitrateOut = Integer.parseInt(iniFile.getProperty("Server.maxBitrateOut", "0"));

//          setMaxRelays(Integer.parseInt(iniFile.getProperty("Server.maxStreamsOut", "0"))); // depreciated
            setMaxRelays(Integer.parseInt(iniFile.getProperty("Server.maxRelays", "1")));
            maxDirect = Integer.parseInt(iniFile.getProperty("Server.maxDirect", "0"));

//          channelManager.maxRelaysPerChannel = Integer.parseInt(iniFile.getProperty("Server.maxStreamsPerChannel", "0")); // depreciated
            channelManager.maxRelaysPerChannel = Integer.parseInt(iniFile.getProperty("Server.maxRelaysPerChannel", "0"));

            firewallTimeout = Integer.parseInt(iniFile.getProperty("Server.firewallTimeout", "0")) * 1000;
            forceNormal = iniFile.getProperty("Server.forceNormal", "false").equals("true");
            channelManager.broadcastMsgInterval = Integer.parseInt(iniFile.getProperty("Broadcast.broadcastMsgInterval", "10")) * 1000;
            channelManager.broadcastMessage = iniFile.getProperty("Broadcast.broadcastMsg", "");
            channelManager.hostUpdateInterval = Integer.parseInt(iniFile.getProperty("Broadcast.hostUpdateInterval", "90")) * 1000;
            channelManager.icyMetaInterval = Integer.parseInt(iniFile.getProperty("Broadcast.icyMetaInterval", "8192"));
            maxServIn = Integer.parseInt(iniFile.getProperty("Server.maxServIn", "50"));

            rootMsg = iniFile.getProperty("Server.rootMsg", "");
            networkID = new GnuID(iniFile.getProperty("Server.networkID", "00000000000000000000000000000000"));
            authType = iniFile.getProperty("Server.authType").equals("cookie") ? AuthType.COOKIE : AuthType.HTTPBASIC; // cookie/http-basic 

            neverExpire = iniFile.getProperty("Server.cookiesExpire").equals("never"); // never/session

            // [Privacy] settings
            password = iniFile.getProperty("Privacy.password", "");
            channelManager.maxUptime = Integer.parseInt(iniFile.getProperty("Privacy.maxUptime", "0")) * 1000;

            // [Client] settings
            rootHost = iniFile.getProperty("Broadcast.rootHost", "yp.peercast.org");
            channelManager.deadHitAge = Integer.parseInt(iniFile.getProperty("Client.deadHitAge", "0"));
            tryoutDelay = Integer.parseInt(iniFile.getProperty("Client.tryoutDelay", "0")) * 1000;
            refreshHTML = Integer.parseInt(iniFile.getProperty("Client.refreshHTML", "5")) * 1000;
            relayBroadcast = Integer.parseInt(iniFile.getProperty("Client.relayBroadcast", "30"));
            if (relayBroadcast < 30) {
                relayBroadcast = 30;
            }

            channelManager.minBroadcastTTL = Integer.parseInt(iniFile.getProperty("Client.minBroadcastTTL", "1"));
            channelManager.maxBroadcastTTL = Integer.parseInt(iniFile.getProperty("Client.maxBroadcastTTL", "7"));
            channelManager.pushTimeout = Integer.parseInt(iniFile.getProperty("Client.pushTimeout", "60")) * 1000;
            channelManager.pushTries = Integer.parseInt(iniFile.getProperty("Client.pushTries", "5"));
            channelManager.maxPushHops = Integer.parseInt(iniFile.getProperty("Client.maxPushHops", "60"));
            channelManager.autoQuery = Integer.parseInt(iniFile.getProperty("Client.autoQuery", "0"));
            if (channelManager.autoQuery < 300 && channelManager.autoQuery > 0) {
                channelManager.autoQuery = 300;
            }

            queryTTL = Integer.parseInt(iniFile.getProperty("Client.queryTTL", "7"));

            // debug
            showLog |= iniFile.getProperty("Debug.logDebug", "false").equals("true") ? 1 << 1 : 0;
            showLog |= iniFile.getProperty("Debug.logErrors", "false").equals("true") ? 1 << 2 : 0;
            showLog |= iniFile.getProperty("Debug.logNetwork", "false").equals("true") ? 1 << 3 : 0;
            showLog |= iniFile.getProperty("Debug.logChannel", "false").equals("true") ? 1 << 4 : 0;
            pauseLog = iniFile.getProperty("Debug.pauseLog", "false").equals("true");
            Peercast.idleSleepTime = Integer.parseInt(iniFile.getProperty("Debug.idleSleepTime"));

            allowServer1 = readServerSettings(iniFile, allowServer1, "Server1");
            allowServer2 = readServerSettings(iniFile, allowServer2, "Server2");
            ServFilter filter = new ServFilter();
            readFilterSettings(iniFile, filter);

            filters.add(filter);

            // "[Notify]"
            notifyMask = NotifyType.UPGRADE.value;
            notifyMask |= iniFile.getProperty("Notify.PeerCast",     "true").equals("true") ? NotifyType.PEERCAST.value     : 0;
            notifyMask |= iniFile.getProperty("Notify.Broadcasters", "true").equals("true") ? NotifyType.BROADCASTERS.value : 0;
            notifyMask |= iniFile.getProperty("Notify.TrackInfo",    "true").equals("true") ? NotifyType.TRACKINFO.value    : 0;

            // "[RelayChannel]"
            ChannelInfo info = new ChannelInfo();
            boolean stayConnected = false;
            info.name = iniFile.getProperty("RelayChannel.name");
            info.id = new GnuID(iniFile.getProperty("RelayChannel.id"));
            info.srcProtocol = ChannelInfo.Protocol.valueOf(iniFile.getProperty("RelayChannel.sourceType", Protocol.UNKNOWN.name()));
            info.contentType = ContentType.valueOf(iniFile.getProperty("RelayChannel.contentType", ContentType.UNKNOWN.name()));
            stayConnected = iniFile.getProperty("RelayChannel.stayConnected", "false").equals("true");
            String sourceURL = iniFile.getProperty("RelayChannel.sourceURL");
            info.genre = iniFile.getProperty("RelayChannel.genre");
            info.url = iniFile.getProperty("RelayChannel.contactURL");
            info.bitrate = Integer.parseInt(iniFile.getProperty("RelayChannel.bitrate", "0"));

            ChannelHit hit = new ChannelHit();
            hit.tracker = true;
            hit.setAddress(new InetSocketAddress(iniFile.getProperty("RelayChannel.tracker", "localhost"), GnuPacket.DEFAULT_PORT));
            hit.remoteAddresses[0] = hit.getAddress();
            hit.remoteAddresses[1] = hit.getAddress();
            hit.channelID = info.id;
            hit.receiver = true;
    
            if (info.name != null) {
                channelManager.addHit(hit);

                if (sourceURL == null || sourceURL.length() == 0) {
                    channelManager.createRelay(info, stayConnected);
                } else {
                    Channel channel = channelManager.createChannel(info, null);
                    channel.startURL(sourceURL);
                }
            }

            // "[Host]"
            boolean firewalled = false;
            InetSocketAddress h = new InetSocketAddress(iniFile.getProperty("Host.address", "localhost"), GnuPacket.DEFAULT_PORT);
            ServHost.Type type = ServHost.Type.valueOf(iniFile.getProperty("Host.type", ServHost.Type.NONE.toString()));
            int time = Integer.parseInt(iniFile.getProperty("Host.time", "0"));
            addHost(h, type, time);

        } catch (IOException e) {
Debug.printStackTrace(e);
        }

        if (filters.size() == 0) {
            setFilterDefaults();
        }
    }

    /** */
    int numStreams(GnuID cid, Servent.Type type, boolean all) {
        int count = 0;
        for (Servent servent : servents) {
            if (servent.isConnected()) {
                if (servent.type.equals(type)) {
                    if (servent.chanID.equals(cid)) {
                        if (all || !servent.isPrivate()) {
                            count++;
                        }
                    }
                }
            }
        }
        return count;
    }

    /** */
    int numStreams(Servent.Type type, boolean all) {
        int count = 0;
        for (Servent servent : servents) {
            if (servent.isConnected()) {
                if (servent.type.equals(type)) {
                    if (all || !servent.isPrivate()) {
                        count++;
                    }
                }
            }
        }
        return count;
    }

    /**
     * @param url sid?foo=var... 
     */
    boolean getChannel(String url, ChannelInfo info, boolean relay) {
        ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);
        // remove file extension (only added for winamp)
Debug.println("url: " + url);
        procConnectArgs(url, info);

        Channel channel = channelManager.findChannelByNameID(info);
        if (channel != null) {

            if (!channel.isPlaying()) {
                if (relay) {
                    channel.info.lastPlayStart = 0; // force reconnect
                    channel.info.lastPlayEnd = 0;
                } else {
                    return false;
                }
            }

            info = channel.info; // get updated channel info

            return true;
        } else {
            if (relay) {
                channel = channelManager.findAndRelay(info);
                if (channel != null) {
                    info = channel.info; // get updated channel info
                    return true;
                }
            }
        }

        return false;
    }

    /** */
    int findChannel(ChannelInfo info) {
        return 0;
    }

    /**
     * add outgoing network connection from string (ip:port format)
     */
    boolean addOutgoing(InetSocketAddress address, GnuID netid, boolean pri) {
        return false;
    }

    /** */
    Servent findConnection(Servent.Type type, GnuID sid) {
        for (Servent servent : servents) {
            if (servent.isConnected()) {
                if (servent.type.equals(type)) {
                    if (servent.remoteID.equals(sid)) {
                        return servent;
                    }
                }
            }
        }
        return null;
    }

    /**
     * url からパラメータを取り出して設定します。
     * TODO move to ChanInfo 
     */
    void procConnectArgs(String url, ChannelInfo info) {

        ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

        info.initNameID(url);

        int questionIndex = url.indexOf('?');
        if (questionIndex < 0) {
            return;
        } else {
            url = url.substring(questionIndex + 1);
        }
        
        StringTokenizer st = new StringTokenizer(url, "&");
        while (st.hasMoreTokens()) {
            String pair = st.nextToken();
            String name = null;
            String value = null;
            int equalIndex = pair.indexOf('=');
            if (equalIndex < 0) {
                name = pair;
            } else {
                try {
                    name = URLDecoder.decode(pair.substring(0, equalIndex), "UTF-8");
                    value = URLDecoder.decode(pair.substring(equalIndex + 1), "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    assert false;
                }
            }
log.debug(String.format("cmd: %s, arg: %s", name, value));

            InetSocketAddress address = null;
            int colonIndex = value.indexOf(':');
            if (colonIndex >= 0) {
                String host = value.substring(0, colonIndex);
                int port = Integer.parseInt(value.substring(colonIndex + 1));
                address = new InetSocketAddress(host, port);
            } else {
                address = new InetSocketAddress(value, GnuPacket.DEFAULT_PORT);
            }
//Debug.println("address: " + address);

            if (name.equals("sip")) {
                // sip - add network connection to client with channel

                if (addOutgoing(address, networkID, true)) { // TODO networkID belongs to ServentManager
                    log.debug(String.format("Added connection: %s", address));
                }

            } else if (name.equals("pip")) {
                // pip - add private network connection to client with channel

                if (addOutgoing(address, info.id, true)) { // TODO addOutgoing() belongs to ServentManager
                    log.debug(String.format("Added private connection: %s", address));
                }
            } else if (name.equals("ip")) {
                // ip - add hit

                ChannelHit hit = new ChannelHit();
                hit.setAddress(address);
                hit.remoteAddresses[0] = address;
                hit.remoteAddresses[1] = null;
                hit.channelID = info.id;
                hit.receiver = true;

                channelManager.addHit(hit);
            } else if (name.equals("tip")) {
                // tip - add tracker hit
Debug.println("tip: " + address);
                channelManager.addHit(address, info.id, true);
            }
        }
    }

    /** start point */
    boolean start() throws IOException {
        log.debug("SessionID: " + sessionID);

        checkForceIP();

        serverThread = new Thread(serverProc);
        serverThread.start();

        idleThread = new Thread(idleProc);
        idleThread.start();

        return true;
    }

    /** */
    Runnable clientProc = new Runnable() {
        public void run() {
        }
    };

    /** */
    boolean acceptGIV(Socket sock) {
        for (Servent sv : servents) {
            if (sv.type == Servent.Type.COUT) {
                if (sv.acceptGIV(sock)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** */
    int broadcastPushRequest(ChannelHit hit, InetSocketAddress to, GnuID chanID, Servent.Type type) throws IOException {
        ChannelPacket pack = new ChannelPacket();
        ByteArrayOutputStream pmem = new ByteArrayOutputStream();
        AtomOutputStream atom = new AtomOutputStream(pmem);

        atom.writeParent(PCPStream.PCP_BCST, 7);
        atom.writeByte(PCPStream.PCP_BCST_GROUP, (byte) PCPStream.PCP_BCST_GROUP_ALL);
        atom.writeByte(PCPStream.PCP_BCST_HOPS, (byte) 0);
        atom.writeByte(PCPStream.PCP_BCST_TTL, (byte) 7);
        atom.writeBytes(PCPStream.PCP_BCST_DEST, hit.sessionID.id, 16);
        atom.writeBytes(PCPStream.PCP_BCST_FROM, sessionID.id, 16);
        atom.writeInt(PCPStream.PCP_BCST_VERSION, PCPStream.PCP_CLIENT_VERSION);
        atom.writeParent(PCPStream.PCP_PUSH, 3);
        atom.writeInt(PCPStream.PCP_PUSH_IP, Peercast.byteToInt(to.getAddress().getAddress()));
        atom.writeShort(PCPStream.PCP_PUSH_PORT, (short) to.getPort());
        atom.writeBytes(PCPStream.PCP_PUSH_CHANID, chanID.id, 16);

        pack.data = pmem.toByteArray();
        pack.type = ChannelPacket.Type.PCP;

        GnuID noID = new GnuID();
        noID.clear();

        return broadcastPacket(pack, noID, sessionID, hit.sessionID, type);
    }

    /** */
    void writeRootAtoms(AtomOutputStream atomOut, boolean getUpdate) throws IOException {
        ChannelManager chanMgr = Singleton.getInstance(ChannelManager.class);

        atomOut.writeParent(PCPStream.PCP_ROOT, 5 + (getUpdate ? 1 : 0));
        atomOut.writeInt(PCPStream.PCP_ROOT_UPDINT, (int) (chanMgr.hostUpdateInterval / 1000));
        atomOut.writeString(PCPStream.PCP_ROOT_URL, "download.php");
        atomOut.writeInt(PCPStream.PCP_ROOT_CHECKVER, PCPStream.PCP_CLIENT_VERSION);
        atomOut.writeInt(PCPStream.PCP_ROOT_NEXT, (int) (chanMgr.hostUpdateInterval / 1000));
        atomOut.writeString(PCPStream.PCP_MESG_ASCII, rootMsg);
        if (getUpdate) {
            atomOut.writeParent(PCPStream.PCP_ROOT_UPDATE, 0);
        }
    }

    /** */
    void broadcastRootSettings(boolean getUpdate) throws IOException {
        if (isRoot) {

            ChannelPacket packet = new ChannelPacket();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            AtomOutputStream atomOut = new AtomOutputStream(baos);
            atomOut.writeParent(PCPStream.PCP_BCST, 6);
            atomOut.writeByte(PCPStream.PCP_BCST_GROUP, (byte) PCPStream.PCP_BCST_GROUP_TRACKERS);
            atomOut.writeByte(PCPStream.PCP_BCST_HOPS, (byte) 0);
            atomOut.writeByte(PCPStream.PCP_BCST_TTL, (byte) 7);
            atomOut.writeBytes(PCPStream.PCP_BCST_FROM, sessionID.id, 16);
            atomOut.writeInt(PCPStream.PCP_BCST_VERSION, PCPStream.PCP_CLIENT_VERSION);
            writeRootAtoms(atomOut, getUpdate);

            // mem.len = mem.pos;
            // mem.rewind();

            packet.data = baos.toByteArray();

            GnuID noID = new GnuID();
            noID.clear();

            broadcastPacket(packet, noID, sessionID, noID, Servent.Type.CIN);
        }
    }

    /** */
    int broadcastPacket(ChannelPacket pack, GnuID chanID, GnuID srcID, GnuID destID, Servent.Type type) {
        int cnt = 0;

        for (Servent sv : servents) {
            if (sv.sendPacket(pack, chanID, srcID, destID, type)) {
                cnt++;
            }
        }
        return cnt;
    }

    /** */
    Runnable idleProc = new Runnable() {
        public void run() {

            ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

            int lastPasvFind = 0;
            int lastBroadcast = 0;

            // nothing much to do for the first couple of seconds, so just hang around.
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
            }

            int lastBWcheck = 0;
            int bytesIn = 0, bytesOut = 0;

            long lastBroadcastConnect = 0;
            long lastRootBroadcast = 0;

            long lastForceIPCheck = 0;

            while (true) {
                try {
                    Peercast.getInstance().stats.update();

                    long currentTime = System.currentTimeMillis();

                    if (forceIP.length() != 0) {
                        if ((currentTime - lastForceIPCheck) > 60) {
                            if (checkForceIP()) {
                                GnuID noID = new GnuID();
                                noID.clear();
                                channelManager.broadcastTrackerUpdate(noID, true);
                            }
                            lastForceIPCheck = currentTime;
                        }
                    }

                    if (channelManager.isBroadcasting()) {
                        if ((currentTime - lastBroadcastConnect) > 30) {
                            connectBroadcaster();
                            lastBroadcastConnect = currentTime;
                        }
                    }

                    if (isRoot) {
                        if ((lastIncoming != 0) && ((currentTime - lastIncoming) > 60 * 60)) {
                            Peercast.getInstance().saveSettings();
                            System.exit(0);
                        }

                        if ((currentTime - lastRootBroadcast) > channelManager.hostUpdateInterval) {
                            broadcastRootSettings(true);
                            lastRootBroadcast = currentTime;
                        }
                    }

                    // clear dead hits
                    channelManager.clearDeadHits(true);

                    if (shutdownTimer != 0) {
                        if (--shutdownTimer <= 0) {
                            Peercast.getInstance().saveSettings();
                            System.exit(0);
                        }
                    }

                    try { Thread.sleep(500); } catch (InterruptedException e) {}
                } catch (IOException e) {
log.error(e);
                }
            }
        }
    };

    /** */
    Runnable serverProc = new Runnable() {
        public void run() {

            Servent serv = allocServent();
            Servent serv2 = allocServent();

            int lastLookupTime = 0;

            while (true) {

                if (restartServer) {
                    try {
                        serv.abort();
                        serv2.abort(); // force close
                    } catch (IOException e) {
log.error("restartServer", e);
                    } // force close
                    quit();

                    restartServer = false;
                }

                if (autoServe) {
                    serv.allow = allowServer1;
                    serv2.allow = allowServer2;

                    if (serv.server == null || serv2.server == null) {
log.debug("Starting servers");
                        // forceLookup = true;

                        // if (serverHost.ip != 0)
                        {

                            if (forceNormal) {
                                setFirewall(FirewallState.OFF);
                            } else {
                                setFirewall(FirewallState.UNKNOWN);
                            }

                            if (serv.server == null) {
                                serv.initServer(serverHost.getAddress().getHostName(), serverHost.getPort());
                            }
                            if (serv2.server == null) {
                                serv2.initServer(serverHost.getAddress().getHostName(), serverHost.getPort() + 1);
                            }
                        }
                    }
                } else {
                    // stop server
                    try {
                        serv.abort();
                        serv2.abort(); // force close
                    } catch (IOException e) {
log.error(e);
                    } // force close

                    // cancel incoming connectuions
                    for (Servent s : servents) {
                        if (s.type == Servent.Type.INCOMING) {
                            // s.thread.isAlive() = false;
                        }
                    }

                    setFirewall(FirewallState.ON);
                }

                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }
        }
    };

    /** */
    void setMaxRelays(int max) {
        if (max <= 0)
            max = 1;
        maxRelays = max;
    }

    /** */
    Element createServentXML() {
        Element e = Peercast.newElement("servent");
        e.setAttribute("agent", GnuPacket.PCX_AGENT);
        return e;
    }

    int numConnected(Servent.Type t, int tim /* = 0 */) {
        return numConnected(t, false, tim) + numConnected(t, true, tim);
    }

    int totalConnected() {
        return numConnected();
    }

    FirewallState getFirewall() {
        return firewalled;
    }

    /**
     * @return [msec]
     */
    long getUptime() {
        return System.currentTimeMillis() - startTime;
    }

    boolean isReplyID(GnuID id) {
        return replyIDs.contains(id);
    }

    void addReplyID(GnuID id) {
        replyIDs.add(id);
    }

    boolean needHosts() {
        return false;
    }

    boolean needConnections() {
        return numConnected(Servent.Type.PGNU, false, 60) < minGnuIncoming;
    }

    boolean tryFull() {
        return false;
    }

    boolean pubInOver() {
        return numConnected(Servent.Type.PGNU, false, 0) > maxGnuIncoming;
    }

    boolean pubInFull() {
        return numConnected(Servent.Type.PGNU, false, 0) >= maxGnuIncoming;
    }

    boolean outUsedFull() {
        return false;
    }

    boolean outOver() {
        return false;
    }

    boolean controlInFull() {
        return numConnected(Servent.Type.CIN, false, 0) >= maxControl;
    }

    boolean outFull() {
        return false;
    }

    boolean relaysFull() {
        return numStreams(Servent.Type.RELAY, false) >= maxRelays;
    }

    boolean directFull() {
        return numStreams(Servent.Type.DIRECT, false) >= maxDirect;
    }

    boolean bitrateFull(int br) {
        return maxBitrateOut != 0 ? (Peercast.BYTES_TO_KBPS(totalOutput(false)) + br) > maxBitrateOut : false;
    }

    /** */
    boolean writeVariable(OutputStream out, final String var) throws IOException {
        String buf = null;

        if (var.equals("version")) {
            buf = GnuPacket.PCX_VERSTRING;
        } else if (var.equals("uptime")) {
            buf = Peercast.getFromStopwatch((int) (getUptime() / 1000));
        } else if (var.equals("numRelays")) {
            buf = String.format("%d", numStreams(Servent.Type.RELAY, true));
        } else if (var.equals("numDirect")) {
            buf = String.format("%d", numStreams(Servent.Type.DIRECT, true));
        } else if (var.equals("totalConnected")) {
            buf = String.format("%d", totalConnected());
        } else if (var.equals("numServHosts")) {
            buf = String.format("%d", getServiceHostsCount(ServHost.Type.SERVENT));
        } else if (var.equals("numServents")) {
            buf = String.format("%d", numServents());
        } else if (var.equals("serverPort")) {
            buf = String.format("%d", serverHost.getPort());
        } else if (var.equals("serverIP")) {
            buf = serverHost.getHostName();
        } else if (var.equals("ypAddress")) {
            buf = rootHost;
        } else if (var.equals("password")) {
            buf = password;
        } else if (var.equals("isFirewalled")) {
            buf = String.format("%d", getFirewall() == FirewallState.ON ? 1 : 0);
        } else if (var.equals("firewallKnown")) {
            buf = String.format("%d", getFirewall() == FirewallState.UNKNOWN ? 0 : 1);
        } else if (var.equals("rootMsg")) {
            buf = rootMsg;
        } else if (var.equals("isRoot")) {
            buf = String.format("%d", isRoot ? 1 : 0);
        } else if (var.equals("refreshHTML")) {
            buf = String.format("%d", refreshHTML != 0 ? refreshHTML : 0x0fffffff);
        } else if (var.equals("maxRelays")) {
            buf = String.format("%d", maxRelays);
        } else if (var.equals("maxDirect")) {
            buf = String.format("%d", maxDirect);
        } else if (var.equals("maxBitrateOut")) {
            buf = String.format("%d", maxBitrateOut);
        } else if (var.equals("maxControlsIn")) {
            buf = String.format("%d", maxControl);
        } else if (var.equals("numFilters")) {
            buf = String.format("%d", filters.size() + 1);
        } else if (var.equals("maxPGNUIn")) {
            buf = String.format("%d", maxGnuIncoming);
        } else if (var.equals("minPGNUIn")) {
            buf = String.format("%d", minGnuIncoming);
        } else if (var.equals("numActive1")) {
            buf = String.format("%d", numActiveOnPort(serverHost.getPort()));
        } else if (var.equals("numActive2")) {
            buf = String.format("%d", numActiveOnPort(serverHost.getPort() + 1));
        } else if (var.equals("numPGNU")) {
            buf = String.format("%d", numConnected(Servent.Type.PGNU, false, 0));
        } else if (var.equals("numCIN")) {
            buf = String.format("%d", numConnected(Servent.Type.CIN, false, 0));
        } else if (var.equals("numCOUT")) {
            buf = String.format("%d", numConnected(Servent.Type.COUT, false, 0));
        } else if (var.equals("numIncoming")) {
            buf = String.format("%d", numActive(Servent.Type.INCOMING));

        } else if (var.equals("serverPort1")) {
            buf = String.format("%d", serverHost.getPort());
        } else if (var.equals("serverLocalIP")) {
            InetSocketAddress lh = new InetSocketAddress(InetAddress.getLocalHost(), 0);
            String ipStr;
            ipStr = lh.getHostName();
            buf = ipStr;
        } else if (var.equals("upgradeURL")) {
            buf = downloadURL;
        } else if (var.equals("serverPort2")) {
            buf = String.format("%d", serverHost.getPort() + 1);
        } else if (var.startsWith("allow.")) {
            if (var.equals("allow.HTML1")) {
                buf = (allowServer1 & ServentManager.Allow.HTML.value) != 0 ? "1" : "0";
            } else if (var.equals("allow.HTML2")) {
                buf = (allowServer2 & ServentManager.Allow.HTML.value) != 0 ? "1" : "0";
            } else if (var.equals("allow.broadcasting1")) {
                buf = (allowServer1 & ServentManager.Allow.BROADCAST.value) != 0 ? "1" : "0";
            } else if (var.equals("allow.broadcasting2")) {
                buf = (allowServer2 & ServentManager.Allow.BROADCAST.value) != 0 ? "1" : "0";
            } else if (var.equals("allow.network1")) {
                buf = (allowServer1 & ServentManager.Allow.ALLOW_NETWORK.value) != 0 ? "1" : "0";
            } else if (var.equals("allow.direct1")) {
                buf = (allowServer1 & ServentManager.Allow.ALLOW_DIRECT.value) != 0 ? "1" : "0";
            }
        } else if (var.startsWith("auth.")) {
            if (var.equals("auth.useCookies")) {
                buf = authType == AuthType.COOKIE ? "1" : "0";
            } else if (var.equals("auth.useHTTP")) {
                buf = authType == AuthType.HTTPBASIC ? "1" : "0";
            } else if (var.equals("auth.useSessionCookies")) {
                buf = neverExpire == false ? "1" : "0";
            }
        } else if (var.startsWith("log.")) {
            if (var.equals("log.debug")) {
                buf = (showLog & (1 << 1)) != 0 ? "1" : "0";
            } else if (var.equals("log.errors")) {
                buf= (showLog & (1 << 2)) != 0 ? "1" : "0";
            } else if (var.equals("log.gnet")) {
                buf = (showLog & (1 << 3)) != 0 ? "1" : "0";
            } else if (var.equals("log.channel")) {
                buf = (showLog & (1 << 4)) != 0 ? "1" : "0";
            } else {
                return false;
            }
        } else if (var.equals("test")) {
            DataOutputStream dos = new DataOutputStream(out);
            dos.writeUTF("\u304b");
            dos.writeUTF("\u304d");
            dos.writeUTF("\u304f");
            dos.writeUTF("\u3051");
            dos.writeUTF("\u3053");

            dos.writeUTF("\u0041");
            dos.writeUTF("\u0042");
            dos.writeUTF("\u0043");
            dos.writeUTF("\u0044");

            dos.writeByte('a');
            dos.writeByte('b');
            dos.writeByte('c');
            dos.writeByte('d');
            return true;

        } else {
            return false;
        }

        out.write(buf.getBytes()); // TODO encoding?
        return true;
    }

    Thread serverThread, idleThread;

    List<Servent> servents = new ArrayList<Servent>();

    List<ServHost> serviceHosts = new ArrayList<ServHost>();

    @Deprecated
    String password = "";

    boolean allowGnutella = false;

    int maxBitrateOut = 0;

    int maxControl = 3;

    int maxRelays = 1;

    int maxDirect = 0;

    int minGnuIncoming = 10;

    int maxGnuIncoming = 20;

    int maxServIn = 50;

    boolean isRoot = false;

    int totalStreams = 0;

    InetSocketAddress serverHost = new InetSocketAddress("127.0.0.1", GnuPacket.DEFAULT_PORT);

    String rootHost = "yp.peercast.org";

    String downloadURL = "";

    String rootMsg = "";

    String forceIP = "";

    String connectHost = "connect1.peercast.org";

    GnuID networkID = new GnuID();

    /** [msec] */
    long firewallTimeout = 30 * 1000;

    int showLog = 0;

    int shutdownTimer = 0;

    boolean pauseLog = false;

    boolean forceNormal = false;

    boolean useFlowControl = true;

    long lastIncoming = 0;

    boolean restartServer = false;

    boolean allowDirect = true;

    boolean autoConnect = true;

    boolean forceLookup = true;

    boolean autoServe = true;

    int queryTTL = 7;

    int allowServer1 = ServentManager.Allow.ALL.value;

    int allowServer2 = ServentManager.Allow.BROADCAST.value;

    /** [msec] */
    long startTime = System.currentTimeMillis();

    /** [msec] */
    long tryoutDelay = 10 * 1000;

    /** [msec] */
    int refreshHTML = 5 * 1000;

    int relayBroadcast;

    int notifyMask = 0xffff;

    List<GnuID> replyIDs = new ArrayList<GnuID>(500);

    GnuID sessionID = new GnuID();

    List<ServFilter> filters = new ArrayList<ServFilter>();

    List<Cookie> cookieList = new ArrayList<Cookie>();

    // cookieList.
    boolean neverExpire;

    AuthType authType = AuthType.COOKIE;

    String htmlPath = "html/en";

    int[] clientVersions = new int[MAX_VERSIONS];

    int[] clientCounts = new int[MAX_VERSIONS];

    int numVersions = 0;

    int serventNum = 0;

    private FirewallState firewalled = FirewallState.UNKNOWN;
}

/* */
