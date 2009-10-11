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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.util.Singleton;


/**
 * ChannelStream.
 *
 * @version 12-mar-2004
 * @author giles
 */
abstract class ChannelStream {
    private static Log log = LogFactory.getLog(ChannelStream.class);

    /** */
    private ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    private ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

    ChannelStream() {
        numListeners = 0;
        numRelays = 0;
        isPlaying = false;
        fwState = 0;
        lastUpdate = 0;
    }

    /** */
    void updateStatus(Channel channel) throws IOException {
        ChannelPacket pack = getStatus(channel);
        if (pack != null) {
            if (!channel.isBroadcasting()) {
                GnuID noID = new GnuID();
                noID.clear();
                int cnt = channelManager.broadcastPacketUp(pack, channel.info.id, serventManager.sessionID, noID);
                log.debug(String.format("Sent channel status update to %d clients", cnt));
            }
        }
    }

    /** */
    private ChannelPacket getStatus(Channel channel) throws IOException {
        long ctime = System.currentTimeMillis();

        ChannelHitList chl = channelManager.findHitListByID(channel.info.id);

        if (chl == null) {
            return null;
        }

        int newLocalListeners = channel.localListeners();
        int newLocalRelays = channel.localRelays();

        if (((numListeners != newLocalListeners) ||
             (numRelays != newLocalRelays) ||
             (channel.isPlaying() != isPlaying) ||
             (serventManager.getFirewall().ordinal() != fwState) ||
             (((ctime - lastUpdate) > channelManager.hostUpdateInterval) && channelManager.hostUpdateInterval != 0)) && ((ctime - lastUpdate) > 10)) {

            numListeners = newLocalListeners;
            numRelays = newLocalRelays;
            isPlaying = channel.isPlaying();
            fwState = serventManager.getFirewall().ordinal();
            lastUpdate = ctime;

            ChannelHit hit = new ChannelHit();

            hit.initLocal(numListeners, numRelays, channel.info.numSkips, channel.info.getUptime(), isPlaying);
            hit.tracker = channel.isBroadcasting();

            ByteArrayOutputStream pmem = new ByteArrayOutputStream();
            AtomOutputStream atom = new AtomOutputStream(pmem);

            GnuID noID = new GnuID();
            noID.clear();

            atom.writeParent(PCPStream.PCP_BCST, 7);
            atom.writeByte(PCPStream.PCP_BCST_GROUP, (byte) PCPStream.PCP_BCST_GROUP_TRACKERS);
            atom.writeByte(PCPStream.PCP_BCST_HOPS, (byte) 0);
            atom.writeByte(PCPStream.PCP_BCST_TTL, (byte) 7);
            atom.writeBytes(PCPStream.PCP_BCST_FROM, serventManager.sessionID.id, 16);
            atom.writeInt(PCPStream.PCP_BCST_VERSION, PCPStream.PCP_CLIENT_VERSION);
            atom.writeBytes(PCPStream.PCP_BCST_CHANID, channel.info.id.id, 16);
            hit.writeAtoms(atom, false, noID);

            ChannelPacket packet = new ChannelPacket();
            packet.data = pmem.toByteArray();
            packet.type = ChannelPacket.Type.PCP;
            return packet;
        } else {
            return null;
        }
    }

    /** */
    boolean sendPacket(ChannelPacket packet, GnuID id) {
        return false;
    }

    /** */
    void flush(OutputStream os) throws IOException {
    }

    /** */
    abstract int readHeader(InputStream is, Channel channel) throws IOException;

    /** */
    abstract int readPacket(InputStream is, Channel channel) throws IOException;

    /** */
    abstract int readEnd(InputStream is, Channel channel) throws IOException;

    /** */
    protected int numRelays;

    /** */
    protected int numListeners;

    /** */
    protected boolean isPlaying;

    /** */
    protected int fwState;

    /** */
    protected long lastUpdate;
}

/* */
