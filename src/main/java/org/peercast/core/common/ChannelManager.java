/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import static java.lang.System.getLogger;


/**
 * ChannelManager.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
public class ChannelManager {

    private static final Logger logger = getLogger(ChannelManager.class.getName());

    /** */
    private final ServentManager serventManager = Peercast.serventManager;

    /** */
    static final int MAX_CHANNELS = 8;

    /** */
    static final int MAX_HITLISTS = 200;

    // must be at least smaller than ChanPacket data len (ie. about half)
    static final int MAX_METAINT = 8192;

    public ChannelManager() {
        broadcastID.generate();
    }

    /** */
    void startSearch(ChannelInfo info) {
        searchInfo = info;
        clearHitLists();
        numFinds = 0;
        lastHit = 0;
        // lastSearch = 0;
        searchActive = true;
    }

    /** */
    void quit() {
        logger.log(Level.DEBUG, "ChanMgr is quitting..");
        for (Channel channel : channels) {
            if (!channel.streaming.isCancelled()) {
                channel.streaming.cancel(true);
            }
        }
    }

    /** */
    Channel findChannelByNameID(ChannelInfo info) {
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.info.matchNameID(info)) {
                    return channel;
                }
            }
        }
        return null;
    }

    /**
     * @param name case insensitive
     */
    Channel findChannelByName(String name) {
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.info.name.equalsIgnoreCase(name)) {
                    return channel;
                }
            }
        }
        return null;
    }

    /** */
    Channel findChannelByIndex(int index) {
        return channels.get(index);
    }

    /** */
    Channel findChannelByMount(String mount) {
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.mount.equals(mount)) {
                    return channel;
                }
            }
        }
        return null;
    }

    /** */
    Channel findChannelByID(GnuID id) {
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.info.id.equals(id)) {
                    return channel;
                }
            }
        }
        return null;
    }

    /** */
    List<Channel> findChannels(ChannelInfo info, int max) {
        List<Channel> result = new ArrayList<>();
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.info.match(info)) {
                    result.add(channel);
                    if (result.size() >= max) {
                        break;
                    }
                }
            }
        }
        return result;
    }

    /** */
    List<Channel> findChannelsByStatus(int max, Channel.Status status) {
        List<Channel> result = new ArrayList<>();
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.status == status) {
                    result.add(channel);
                    if (result.size() >= max) {
                        break;
                    }
                }
            }
        }
        return result;
    }

    /** */
    Channel createRelay(ChannelInfo info, boolean stayConnected) {
        Channel channel = createChannel(info, null);
        channel.stayConnected = stayConnected;
        channel.startGet();
        return channel;
    }

    /** */
    Channel findAndRelay(ChannelInfo info) {
        logger.log(Level.DEBUG, String.format("Searching for: %s (%s)", info.id.toString(), info.name));
        Peercast.getInstance().notifyMessage(ServentManager.NotifyType.PEERCAST, "Finding channel... : " + info.id);

        Channel channel = findChannelByNameID(info);

        if (channel == null) {
            channel = createChannel(info, null);
            if (channel != null) {
                channel.setStatus(Channel.Status.SEARCHING);
                channel.startGet();
            }
        }

        for (int i = 0; i < 600; i++) { // search for 1 minute.

            channel = findChannelByNameID(info);

            if (channel == null) {
                Peercast.getInstance().notifyMessage(ServentManager.NotifyType.PEERCAST, "Channel not found");
                return null;
            }

            if (channel.isPlaying() && (channel.info.contentType != ChannelInfo.ContentType.UNKNOWN)) {
                break;
            }

            if (channel.isError()) {
                Peercast.getInstance().notifyMessage(ServentManager.NotifyType.PEERCAST, "Channel error");
                return null;
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
        }

        if (channel.isPlaying() && (channel.info.contentType != ChannelInfo.ContentType.UNKNOWN)) {
            return channel;
        }

        return null;
    }

    /** */
    boolean writeVariable(OutputStream out, String var, int index) {
        String buf;
        switch (var) {
            case "numHitLists" -> buf = String.format("%d", numHitLists());
            case "numChannels" -> buf = String.format("%d", numChannels());
            case "djMessage" -> buf = broadcastMessage;
            case "icyMetaInterval" -> buf = String.format("%d", icyMetaInterval);
            case "maxRelaysPerChannel" -> buf = String.format("%d", maxRelaysPerChannel);
            case "hostUpdateInterval" -> buf = String.format("%d", hostUpdateInterval);
            default -> {
                return false;
            }
        }

        PrintStream ps = new PrintStream(out);
        ps.print(buf);
        return true;
    }

    /** */
    void broadcastTrackerUpdate(GnuID svID, boolean force) throws IOException {
        for (Channel channel : channels) {
            if (channel.isActive() && channel.isBroadcasting()) {
                channel.broadcastTrackerUpdate(svID, force);
            }
        }
    }

    /** */
    int broadcastPacketUp(ChannelPacket pack, GnuID chanID, GnuID srcID, GnuID destID) {
        int count = 0;

        for (Channel channel : channels) {
            if (channel.sendPacketUp(pack, chanID, srcID, destID)) {
                count++;
            }
        }

        return count;
    }

    /** */
    void broadcastRelays(Servent serv, int minTTL, int maxTTL) throws IOException {
        // if ((servMgr.getFirewall() == ServMgr.FW_OFF) || servMgr.serverHost.localIP())
        {

            InetSocketAddress serverAdress = serventManager.serverHost;
            boolean push = serventManager.getFirewall() != ServentManager.FirewallState.OFF;
            boolean busy = (serventManager.pubInFull() && ServentManager.outFull()) || serventManager.relaysFull();
            boolean stable = serventManager.totalStreams > 0;

            GnuPacket hit = null;

            int numChans = 0;

            for (Channel channel : channels) {

                if (channel.isPlaying()) {

                    boolean tracker = channel.isBroadcasting();

                    long ttl = (channel.info.getUptime() / serventManager.relayBroadcast); // 1 hop per N seconds

                    if (ttl < minTTL) {
                        ttl = minTTL;
                    }

                    if (ttl > maxTTL) {
                        ttl = maxTTL;
                    }

                    try {
                        hit = new GnuPacket(serverAdress, channel, null, push, busy, stable, tracker, ttl);
                        int numOut = 0;
                        numChans++;
                        if (serv != null) {
                            serv.outputPacket(hit, false);
                            numOut++;
                        }

                        logger.log(Level.DEBUG, String.format("Sent ch.%d to %d servents, TTL %d", channel.index, numOut, ttl));
                    } catch (Exception e) {
                        logger.log(Level.ERROR, e.getMessage(), e);
                    }
                }
            }
        }
    }

    /** */
    void setUpdateInterval(int interval) {
        hostUpdateInterval = interval;
    }

    /**
     * message check
     */
    void setBroadcastMessage(String message) throws IOException {
        if (!message.equals(broadcastMessage)) {
            broadcastMessage = message;

            for (Channel channel : channels) {
                if (channel.isActive() && channel.isBroadcasting()) {
                    ChannelInfo newInfo = channel.info;
                    newInfo.comment = broadcastMessage;
                    channel.updateInfo(newInfo);
                }
            }
        }
    }

    /** */
    void clearHitLists() {
        for (ChannelHitList hitList : channelHitLists) {
            Peercast.getInstance().delChannel(hitList.info);
            hitList.init();
        }
    }

    /** */
    synchronized Channel createChannel(ChannelInfo info, String mount) {

        Channel newChannel = new Channel();

        for (Channel channel : channels) {
            if (!channel.isPlaying()) {
                channel.streaming.cancel(true);
            }
        }

        newChannel.info = info;
        newChannel.info.lastPlayStart = 0;
        newChannel.info.lastPlayEnd = 0;
        newChannel.info.status = ChannelInfo.Status.UNKNOWN;
        if (mount != null) {
            newChannel.mount = mount;
        }
        newChannel.index = channels.size() + 1;
        newChannel.setStatus(Channel.Status.WAIT);
        newChannel.type = Channel.Type.ALLOCATED;
        newChannel.info.createdTime = System.currentTimeMillis();

        logger.log(Level.DEBUG, String.format("New channel (%d) created", newChannel.index));

        channels.add(newChannel);

        return newChannel;
    }

    /** */
    int pickHits(ChannelHitSearch chs) {
        for (ChannelHitList hitList : channelHitLists) {
            if (hitList.isUsed()) {
                if (hitList.pickHits(chs) != 0) {
//                  hitList.info.id; // TODO ignore ???
                    return 1;
                }
            }
        }
        return 0;
    }

    /** */
    int numHitLists() {
        int num = 0;
        for (ChannelHitList hitList : channelHitLists) {
            if (hitList.isUsed()) {
                num++;
            }
        }
        return num;
    }

    /**
     * info ���� ChanHitList ��쐬�� channelHitLists �ɒǉB���
     *
     * @return �ǉB��ꂽ ChanHitList
     */
    ChannelHitList addHitList(ChannelInfo info) {
        ChannelHitList chl = null;

        for (ChannelHitList hitList : channelHitLists) {
            if (!hitList.isUsed()) {
                logger.log(Level.DEBUG, String.format("Created new hitlist: %s", info.id));
                chl = hitList;
                break;
            }
        }

        if (chl != null) {
            chl.used = true;
            chl.info = info;
            chl.info.createdTime = System.currentTimeMillis();
            Peercast.getInstance().addChannel(chl.info);
        } else {
            chl = new ChannelHitList();
            logger.log(Level.DEBUG, String.format("Created new hitlist: %s", info.id));
            chl.used = true;
            chl.info = info;
            chl.info.createdTime = System.currentTimeMillis();
            Peercast.getInstance().addChannel(chl.info);
            channelHitLists.add(chl);
        }

        return chl;
    }

    /** */
    void clearDeadHits(boolean clearTrackers) {
        long interval; // [msec]

        if (serventManager.isRoot) {
            interval = 1200; // mainly for old 0.119 clients
        } else {
            interval = hostUpdateInterval + 30 * 1000;
        }

        for (ChannelHitList hitList : channelHitLists) {
            if (hitList.isUsed()) {
                if (hitList.clearDeadHits(interval, clearTrackers) == 0) {
                    if (!isBroadcasting(hitList.info.id)) {
                        if (findChannelByID(hitList.info.id) == null) {
                            logger.log(Level.DEBUG, "Deleting hitlist");
                            Peercast.getInstance().delChannel(hitList.info);
                            hitList.init();
                        }
                    }
                }
            }
        }
    }

    /** */
    boolean isBroadcasting(GnuID id) {
        Channel channel = findChannelByID(id);
        if (channel != null) {
            return channel.isBroadcasting();
        }

        return false;
    }

    /** */
    boolean isBroadcasting() {
        for (Channel channel : channels) {
            if (channel.isActive()) {
                if (channel.isBroadcasting()) {
                    return true;
                }
            }
        }
        return false;
    }

    /** */
    int numChannels() {
        int total = 0;
        for (Channel channel : channels) {
            if (channel.isActive()) {
                total++;
            }
        }
        return total;
    }

    /** */
    void deadHit(ChannelHit hit) {
        ChannelHitList chl = findHitListByID(hit.channelID);
        if (chl != null) {
            chl.deadHit(hit);
        }
    }

    /** */
    void delHit(ChannelHit hit) {
        ChannelHitList chl = findHitListByID(hit.channelID);
        if (chl != null) {
            chl.deleteHit(hit);
        }
    }

    /** */
    void addHit(InetSocketAddress address, GnuID id, boolean tracker) {
        ChannelHit hit = new ChannelHit();
        logger.log(Level.TRACE, "address: " + address);
        hit.setAddress(address);
        hit.remoteAddresses[0] = address;
        hit.remoteAddresses[1] = null;
        hit.tracker = tracker;
        hit.receiver = true;
        hit.channelID = id;
        addHit(hit);
    }

    /** */
    ChannelHit addHit(ChannelHit hit) {
        if (searchActive) {
            lastHit = System.currentTimeMillis();
        }

        ChannelHitList hitList = findHitListByID(hit.channelID);

        if (hitList == null) {
            ChannelInfo info = new ChannelInfo();
            info.id = hit.channelID;
            hitList = addHitList(info);
        }

        return hitList.addHit(hit);
    }

    /** */
    class ChannelInfoFinder extends Thread {

        ChannelInfo info;

        boolean keep;

        @Override
        public void run() {
            try {
                Channel channel = findChannelByNameID(info);

                currFindAndPlayChannel = info.id;

                if (channel == null) {
                    channel = findAndRelay(info);
                }

                if (channel != null) {
                    // check that a different channel hasn't be selected already.
                    if (currFindAndPlayChannel.equals(channel.info.id)) {
                        playChannel(channel.info);
                    }

                    if (this.keep) {
                        channel.stayConnected = this.keep;
                    }
                }
            } catch (Exception e) {
                logger.log(Level.ERROR, "ChannelInfoFinder", e);
            }
        }
    }

    /** */
    void findAndPlayChannel(ChannelInfo info, boolean keep) {
        ChannelInfoFinder cfi = new ChannelInfoFinder();
        cfi.info = info;
        cfi.keep = keep;
        cfi.start();
    }

    /** */
    static final String player = "/Applications/foobar2000.app/Contents/MacOS/foobar2000";

    /** */
    void playChannel(ChannelInfo info) throws IOException {

        String filename;

        String string = String.format("http://localhost:%d", serventManager.serverHost.getPort());

        PlayList playList;

        ProcessBuilder pb = new ProcessBuilder();
        if (info.contentType.equals(ChannelInfo.ContentType.WMA) || info.contentType.equals(ChannelInfo.ContentType.WMV)) {
            playList = PlayList.ASX;
            // WMP seems to have a bug where it doesn`t re-read asx files if they have the same name
            // so we prepend the channel id to make it unique - NOTE: should be deleted afterwards.
            filename = String.format("%s/%s.asx", Peercast.getInstance().getPath(), info.id.toString());
        } else if (info.contentType.equals(ChannelInfo.ContentType.OGM)) {
            playList = PlayList.RAM;
            filename = String.format("%s/play.ram", Peercast.getInstance().getPath());

        } else {
            playList = PlayList.SCPLS;
            filename = String.format("%s/play.pls", Peercast.getInstance().getPath());
        }

        playList.init(1);
        playList.addChannel(string, info);

        logger.log(Level.DEBUG, String.format("Writing %s", filename));
        FileOutputStream file;
        file = new FileOutputStream(filename);
        playList.write(file);
        file.close();

        logger.log(Level.DEBUG, String.format("Executing: %s", filename));
        pb.command(player, filename);
        pb.start();
    }

    /** */
    ChannelHitList findHitList(ChannelInfo info) {
        for (ChannelHitList hitlist : channelHitLists) {
            if (hitlist.isUsed()) {
                if (hitlist.info.matchNameID(info)) {
                    return hitlist;
                }
            }
        }
        return null;
    }

    /** */
    ChannelHitList findHitListByID(GnuID id) {
        for (ChannelHitList hitlist : channelHitLists) {
            if (hitlist.isUsed()) {
                if (hitlist.info.id.equals(id)) {
                    return hitlist;
                }
            }
        }
        return null;
    }

    List<Channel> channels = new ArrayList<>();

    List<ChannelHitList> channelHitLists = new ArrayList<>();

    GnuID broadcastID = new GnuID();

    ChannelInfo searchInfo = new ChannelInfo();

    int numFinds;

    String broadcastMessage = "";

    /** [msec] */
    long broadcastMsgInterval = 10 * 1000;

    /** [msec] */
    long lastHit;

    int lastQuery = 0;

    /** [msec] */
    long maxUptime;

    boolean searchActive;

    int deadHitAge = 600;

    int icyMetaInterval = 8192;

    int maxRelaysPerChannel = 0;

    int minBroadcastTTL = 1;

    int maxBroadcastTTL = 7;
    // 1 minute [msec]
    long pushTimeout = 60 * 1000;
    // max 8 hops away
    int maxPushHops = 8;

    int pushTries = 5;

    int autoQuery = 0;
    /** [msec] */
    long prefetchTime = 10 * 1000;

    /** [msec] */
    long lastYPConnect = 0;

    int icyIndex = 0;

    /** 180s [msec] */
    long hostUpdateInterval = 180 * 1000;

    /** 5s [msec] */
    long bufferTime = 5 * 1000;

    GnuID currFindAndPlayChannel;
}
