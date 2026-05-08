/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;

import static java.lang.System.getLogger;


/**
 * PerrcastSource.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class PeercastSource extends ChannelSource {

    private static final Logger logger = getLogger(PeercastSource.class.getName());

    private final ServentManager serventManager = Peercast.serventManager;

    private final ChannelManager channelManager = Peercast.channelManager;

    @Override
    void stream(Channel channel) throws IOException {
        int numYPTries = 0;
        while (true) {
            ChannelHitList chl = null;

            channel.sourceHost.init();

            channel.setStatus(Channel.Status.SEARCHING);
            logger.log(Level.DEBUG, String.format("Ch.%d searching for hit..", channel.index));
            do {
                if (channel.pushSock != null) {
                    logger.log(Level.TRACE, "use push socket: @" + channel.pushSock);
                    channel.sock = channel.pushSock;
                    channel.pushSock = null;
                    channel.sourceHost.setAddress((InetSocketAddress) channel.sock.getRemoteSocketAddress()); // TODO remote?
                    break;
                }

                chl = channelManager.findHitList(channel.info);
                if (chl != null) {
                    ChannelHitSearch chs = new ChannelHitSearch();

                    // find local hit
                    chs.init();
                    chs.matchHost = serventManager.serverHost;
                    chs.waitDelay = ServentManager.MIN_RELAY_RETRY;
                    chs.excludeID = serventManager.sessionID;
                    if (chl.pickHits(chs) != 0) {
                        channel.sourceHost = chs.bestHits.get(0);
                        logger.log(Level.TRACE, "source host: local: " + channel.sourceHost.getAddress());
                    }

                    // else find global hit
                    if (channel.sourceHost.getAddress() == null) {
                        chs.init();
                        chs.waitDelay = ServentManager.MIN_RELAY_RETRY;
                        chs.excludeID = serventManager.sessionID;
                        if (chl.pickHits(chs) != 0) {
                            channel.sourceHost = chs.bestHits.get(0);
                            logger.log(Level.TRACE, "source host: global: " + channel.sourceHost.getAddress());
                        }
                    }

                    // else find local tracker
                    if (channel.sourceHost.getAddress() == null) {
                        chs.init();
                        chs.matchHost = serventManager.serverHost;
                        chs.waitDelay = ServentManager.MIN_TRACKER_RETRY;
                        chs.excludeID = serventManager.sessionID;
                        chs.trackersOnly = true;
                        if (chl.pickHits(chs) != 0) {
                            channel.sourceHost = chs.bestHits.get(0);
                            logger.log(Level.TRACE, "source host: local tracker: " + channel.sourceHost.getAddress());
                        }
                    }

                    // else find global tracker
                    if (channel.sourceHost.getAddress() == null) {
                        chs.init();
                        chs.waitDelay = ServentManager.MIN_TRACKER_RETRY;
                        chs.excludeID = serventManager.sessionID;
                        chs.trackersOnly = true;
                        if (chl.pickHits(chs) != 0) {
                            channel.sourceHost = chs.bestHits.get(0);
                            logger.log(Level.TRACE, "source host: global tracker: " + channel.sourceHost.getAddress());
                        }
                    }

                }

                // no trackers found so contact YP
                if (channel.sourceHost.getAddress() == null) {
                    if (serventManager.rootHost.isEmpty()) {
                        break;
                    }

                    if (numYPTries >= 3) {
                        break;
                    }

                    long currentTime = System.currentTimeMillis();
                    if ((currentTime - channelManager.lastYPConnect) > ServentManager.MIN_YP_RETRY) {
                        channel.sourceHost.setAddress(new InetSocketAddress(serventManager.rootHost, GnuPacket.DEFAULT_PORT));
                        channel.sourceHost.yp = true;
                        channelManager.lastYPConnect = currentTime;
                    }
                }

                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }

            } while (channel.sourceHost.getAddress() == null);

            if (channel.sourceHost.getAddress() == null) {
                logger.log(Level.ERROR, String.format("Ch.%d giving up", channel.index));
                break;
            }

            if (channel.sourceHost.yp) {
                numYPTries++;
                logger.log(Level.DEBUG, String.format("Ch.%d contacting YP, try %d", channel.index, numYPTries));
            } else {
                logger.log(Level.DEBUG, String.format("Ch.%d found hit", channel.index));
                numYPTries = 0;
            }

            if (channel.sourceHost.getAddress() != null) {
//                boolean isTrusted = channel.sourceHost.tracker | channel.sourceHost.yp;

//                if (channel.sourceHost.tracker) {
//                    Peercast.getInstance().notifyMessage(ServentManager.NotifyType.PEERCAST, "Contacting tracker, please wait...");
//                }

                String ipstr = channel.sourceHost.getAddress().getHostName();

                String type = "";
                if (channel.sourceHost.tracker) {
                    type = "(tracker)";
                } else if (channel.sourceHost.yp) {
                    type = "(YP)";
                }

                int error = -1;
                try {
                    channel.setStatus(Channel.Status.CONNECTING);

                    if (channel.sock == null) {
                        logger.log(Level.DEBUG, String.format("Ch.%d connecting to %s %s", channel.index, ipstr, type));
                        logger.log(Level.TRACE, "address: " + channel.sourceHost.getAddress() + ": @" + channel.sourceHost.hashCode());
                        channel.connectFetch();
                    }

                    error = channel.handshakeFetch();
                    if (error != 0) {
                        throw new IOException("Handshake error: " + error);
                    }

                    channel.sourceStream = channel.createSource();

                    error = channel.readStream(channel.sock.getInputStream(), channel.sourceStream);
                    if (error != 0) {
                        throw new IOException("Stream error");
                    }

                    error = 0; // no errors, closing normally.
                    channel.setStatus(Channel.Status.CLOSING);

                    logger.log(Level.DEBUG, String.format("Ch.%d closed normally", channel.index));

                } catch (IOException e) {
                    channel.setStatus(Channel.Status.ERROR);
                    logger.log(Level.ERROR, String.format("Ch.%d to %s %s : %s (%d)", channel.index, ipstr, type, e.getMessage(), error));
                    if (!channel.sourceHost.tracker || (error != 503 && channel.sourceHost.tracker)) {
                        channelManager.deadHit(channel.sourceHost);
                    }
                }

                // broadcast quit to any connected downstream servents
                {
                    ChannelPacket pack = new ChannelPacket();
                    ByteArrayOutputStream mem = new ByteArrayOutputStream();
                    AtomOutputStream atomOut = new AtomOutputStream(mem);
                    atomOut.writeInt(PCPStream.PCP_QUIT, PCPStream.PCP_ERROR_QUIT + PCPStream.PCP_ERROR_OFFAIR);
                    pack.data = mem.toByteArray();
                    pack.type = ChannelPacket.Type.PCP;
                    GnuID noID = new GnuID();
                    noID.clear();
                    serventManager.broadcastPacket(pack, channel.info.id, channel.remoteID, noID, Servent.Type.RELAY);
                }

                if (channel.sourceStream != null) {
                    try {
                        if (error == 0) {
                            channel.sourceStream.updateStatus(channel);
                            channel.sourceStream.flush(channel.sock.getOutputStream());
                        }
                    } catch (IOException e) {
                        logger.log(Level.TRACE, e);
                    }
//                    ChannelStream cs = channel.sourceStream;
//                    cs.sourceStream = null;
//                    cs.kill();
                }

                if (channel.sock != null) {
                    channel.sock.close();
                    channel.sock = null;
                }

                if (error == 404) {
                    logger.log(Level.ERROR, String.format("Ch.%d not found", channel.index));
                    return;
                }

            }

            channel.lastIdleTime = System.currentTimeMillis();
            channel.setStatus(Channel.Status.IDLE);
            while (channel.checkIdle() && !channel.streaming.isCancelled()) {
                try {
                    Thread.sleep(Peercast.idleSleepTime);
                } catch (InterruptedException e) {
                }
            }

            if (channel.streaming.isCancelled()) {
                break;
            }

            channel.setStatus(Channel.Status.SEARCHING);

            try {
                Thread.sleep(Peercast.idleSleepTime);
            } catch (InterruptedException e) {
            }
        }
    }
}
