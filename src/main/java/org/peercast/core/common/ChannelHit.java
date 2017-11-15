/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.w3c.dom.Element;

import vavi.util.Debug;
import vavi.util.Singleton;


/**
 * ChanHit.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelHit implements Comparable<ChannelHit> {
    /** */
    private ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    /** */
    Element createXML() {
        // IP

        Element e = Peercast.newElement("host");
        e.setAttribute("ip", address.getHostName());
        e.setAttribute("hops", String.valueOf(numHops));
        e.setAttribute("listeners", String.valueOf(numListeners));
        e.setAttribute("relays", String.valueOf(numRelays));
        e.setAttribute("uptime", String.valueOf(upTime));
        e.setAttribute("push", firewalled ? "1" : "0");
        e.setAttribute("relay", relay ? "1" : "0");
        e.setAttribute("direct", direct ? "1" : "0");
        e.setAttribute("cin", cin ? "1" : "0");
        e.setAttribute("stable", stable ? "1" : "0");
        e.setAttribute("agent", agentStr);
        e.setAttribute("version", String.valueOf(version));
        e.setAttribute("update", String.valueOf(System.currentTimeMillis() - time));
        e.setAttribute("tracker", String.valueOf(tracker));

        return e;
    }

    /** */
    void pickNearestIP(InetSocketAddress address) {
        for (int i = 0; i < 2; i++) {
            if (address.getAddress().isAnyLocalAddress() == remoteAddresses[i].getAddress().isAnyLocalAddress() ||
                address.getAddress().isLinkLocalAddress() == remoteAddresses[i].getAddress().isLinkLocalAddress() ||
                address.getAddress().isLoopbackAddress() == remoteAddresses[i].getAddress().isLoopbackAddress()) {
                this.address = remoteAddresses[i];
Debug.println("address: " + address + ": " + hashCode());
                break;
            }
        }
    }

    /** */
    ChannelHit() {
        init();
    }

    /** */
    void init() {
//new Exception("*** address cleared: " + address).printStackTrace();
//Debug.println("*** address cleared: " + address);
        address = null;

        remoteAddresses[0] = null;
        remoteAddresses[1] = null;

        numListeners = 0;
        numRelays = 0;

        dead = tracker = firewalled = stable = yp = false;
        receiver = cin = direct = relay = true;

        direct = false;
        numHops = 0;
        time = upTime = 0;
        agentStr = "";
        lastContact = 0;

        version = 0;

        sessionID = new GnuID();
        sessionID.clear();
        channelID = new GnuID();
        channelID.clear();
    }

    /** */
    void initLocal(int numl, int numr, int i, long uptm, boolean connected) throws IOException {
        init();
        firewalled = (serventManager.getFirewall() != ServentManager.FirewallState.OFF);
        numListeners = numl;
        numRelays = numr;
        upTime = uptm;
        stable = serventManager.totalStreams > 0;
        agentStr = GnuPacket.PCX_AGENT;
        sessionID = serventManager.sessionID;
        receiver = connected;

        direct = !serventManager.directFull();
        relay = !serventManager.relaysFull();
        cin = !serventManager.controlInFull();

        address = serventManager.serverHost;
Debug.println("address: " + address + ": @" + hashCode());

        if (firewalled) {
            remoteAddresses[0] = new InetSocketAddress(address.getAddress(), 0);
        } else {
            remoteAddresses[0] = new InetSocketAddress(address.getAddress(), address.getPort());
        }
        remoteAddresses[1] = new InetSocketAddress(InetAddress.getLocalHost(), address.getPort());
    }

    /** */
    void writeAtoms(AtomOutputStream atomOut, boolean tryHost, GnuID chanID) throws IOException {
        boolean addChan = chanID.isSet();

        if (tryHost) {
            atomOut.writeParent(PCPStream.PCP_HOST, 5 + (addChan ? 1 : 0));
            if (addChan) {
                atomOut.writeBytes(PCPStream.PCP_HOST_CHANID, chanID.id, 16);
            }
            atomOut.writeInt(PCPStream.PCP_HOST_IP, Peercast.byteToInt(remoteAddresses[0].getAddress().getAddress()));
            atomOut.writeShort(PCPStream.PCP_HOST_PORT, (short) remoteAddresses[0].getPort());
            atomOut.writeInt(PCPStream.PCP_HOST_IP, Peercast.byteToInt(remoteAddresses[1].getAddress().getAddress()));
            atomOut.writeShort(PCPStream.PCP_HOST_PORT, (short) remoteAddresses[1].getPort());
            atomOut.writeByte(PCPStream.PCP_HOST_TRACKER, (byte) (tracker ? 1 : 0));
        } else {
            atomOut.writeParent(PCPStream.PCP_HOST, 15 + (addChan ? 1 : 0));
            if (addChan) {
                atomOut.writeBytes(PCPStream.PCP_HOST_CHANID, chanID.id, 16);
            }
            atomOut.writeBytes(PCPStream.PCP_HOST_ID, sessionID.id, 16);
            atomOut.writeInt(PCPStream.PCP_HOST_IP, Peercast.byteToInt(remoteAddresses[0].getAddress().getAddress()));
            atomOut.writeShort(PCPStream.PCP_HOST_PORT, (short) remoteAddresses[0].getPort());
            atomOut.writeInt(PCPStream.PCP_HOST_IP, Peercast.byteToInt(remoteAddresses[1].getAddress().getAddress()));
            atomOut.writeShort(PCPStream.PCP_HOST_PORT, (short) remoteAddresses[1].getPort());
            atomOut.writeInt(PCPStream.PCP_HOST_NUML, numListeners);
            atomOut.writeInt(PCPStream.PCP_HOST_NUMR, numRelays);
            atomOut.writeInt(PCPStream.PCP_HOST_UPTIME, (int) (upTime / 1000));
            atomOut.writeInt(PCPStream.PCP_HOST_VERSION, PCPStream.PCP_CLIENT_VERSION);

            // depreciated
            atomOut.writeString(PCPStream.PCP_HOST_AGENT, agentStr);
            atomOut.writeByte(PCPStream.PCP_HOST_BUSY, (byte) (!relay ? 1 : 0));
            atomOut.writeByte(PCPStream.PCP_HOST_PUSH, (byte) (firewalled ? 1 : 0));
            atomOut.writeByte(PCPStream.PCP_HOST_RECV, (byte) (receiver ? 1 : 0));
            atomOut.writeByte(PCPStream.PCP_HOST_TRACKER, (byte) (tracker ? 1 : 0));

            int fl1 = 0;
            if (receiver) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_RECV;
            }
            if (relay) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_RELAY;
            }
            if (direct) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_DIRECT;
            }
            if (cin) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_CIN;
            }
            if (tracker) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_TRACKER;
            }
            if (firewalled) {
                fl1 |= PCPStream.PCP_HOST_FLAGS1_PUSH;
            }

            atomOut.writeByte(PCPStream.PCP_HOST_FLAGS1, (byte) fl1);
        }
    }

    /** */
    boolean writeVariable(OutputStream out, final String var) {
        String buf;

        if (var.equals("rhost0")) {
            buf = remoteAddresses[0].getHostName();
        } else if (var.equals("rhost1")) {
            buf= remoteAddresses[1].getHostName();
        } else if (var.equals("numHops")) {
            buf = String.format("%d", numHops);
        } else if (var.equals("numListeners")) {
            buf = String.format("%d", numListeners);
        } else if (var.equals("numRelays")) {
            buf = String.format("%d", numRelays);
        } else if (var.equals("uptime")) {
            buf = Peercast.getFromStopwatch((int) (upTime / 1000));
        } else if (var.equals("update")) {
            buf = Peercast.getFromStopwatch((int) ((System.currentTimeMillis() - time) / 1000));
        } else if (var.equals("isFirewalled")) {
            buf = String.format("%d", firewalled ? 1 : 0);
        } else if (var.equals("agent")) {
            buf = agentStr;
        } else {
            return false;
        }

        PrintStream ps = new PrintStream(out);
        ps.print(buf);
        return true;
    }

    public int compareTo(ChannelHit c2) {
        return (int) (this.time - c2.time);
    }

    /** */
    private InetSocketAddress address;

    /** */
    public InetSocketAddress getAddress() {
        return address;
    }

    /** */
    public void setAddress(InetSocketAddress address) {
if (address == null) {
 new Exception("*** DUMMY *** address: " + address + ": " + hashCode()).printStackTrace();
}
        this.address = address;
    }

    /** 0: local, 2: wan */
    InetSocketAddress[] remoteAddresses = new InetSocketAddress[2];

    int numListeners, numRelays, numHops;

    /** [nsec] */
    long time;

    /** [nsec] */
    long upTime;

    /** [nsec] */
    long lastContact;

    int hitID;

    String agentStr;

    GnuID sessionID, channelID;

    int version;

    boolean firewalled = true;
    boolean stable = true;
    boolean tracker = true;
    boolean receiver = true;
    boolean yp = true;
    boolean dead = true;
    boolean direct = true;
    boolean relay = true;
    boolean cin = true;
}

/* */
