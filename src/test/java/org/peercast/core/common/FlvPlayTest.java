/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.peercast.core.common.ServentManager.NotifyType;

import static java.lang.System.getLogger;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


/**
 * Relays an FLV channel listed on a YP and shows it with ffplay.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2026-11-12 nsano initial version <br>
 */
class FlvPlayTest {

    private static final Logger logger = getLogger(FlvPlayTest.class.getName());

    static final String FFPLAY = "/opt/homebrew/bin/ffplay";

    /** play time [ms] */
    static final long PLAY_TIME = Long.getLong("peercast.playTime", 30_000);

    /** 0.0 ~ 1.0 */
    static final float VOLUME = Float.parseFloat(System.getProperty("vavi.test.volume", "0.2"));

    static boolean hasFfplay() {
        return new java.io.File(FFPLAY).canExecute();
    }

    record Candidate(String name, String id, String tip, String type, int listeners) {}

    static List<Candidate> fetchYP(String indexUrl) {
        List<Candidate> list = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(URI.create(indexUrl).toURL().openStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] p = line.split("<>", -1);
                if (p.length > 9 && !p[1].matches("0+") && !p[2].isEmpty()) {
                    int listeners;
                    try { listeners = Integer.parseInt(p[6]); } catch (NumberFormatException e) { listeners = -1; }
                    list.add(new Candidate(p[0], p[1], p[2], p[9], listeners));
                }
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "YP failed: " + indexUrl + ": " + e);
        }
        return list;
    }

    @Test
    @EnabledIf("hasFfplay")
    void testPlayFlv() throws Exception {
        Peercast.idleSleepTime = 10;
        Peercast.iniFileName = "peercast.ini";
        Peercast.instance = new Peercast() {
            @Override void notifyMessage(NotifyType type, String string) { logger.log(Level.DEBUG, "notify: " + type + ": " + string); }
            @Override void delChannel(ChannelInfo info) {}
            @Override void addChannel(ChannelInfo info) {}
            @Override void channelStart(ChannelInfo info) {}
            @Override void channelStop(ChannelInfo info) {}
            @Override void channelUpdate(ChannelInfo info) {}
            @Override void updateSettings() {}
        };
        Peercast.getInstance().init();

        List<Candidate> candidates = fetchYP("http://bayonet.ddo.jp/sp/index.txt");
        candidates.removeIf(c -> !c.type.equals("FLV"));
        // popular ones first, they are more likely to accept relays
        candidates.sort((a, b) -> Integer.compare(b.listeners, a.listeners));
        logger.log(Level.INFO, "candidates: " + candidates.size());

        boolean played = false;
        for (Candidate c : candidates) {
            logger.log(Level.INFO, "Trying: " + c.name + " " + c.id + " @" + c.tip);
            ChannelInfo chanInfo = new ChannelInfo();
            Peercast.serventManager.procConnectArgs(c.id + "?tip=" + c.tip, chanInfo);
            Channel channel = Peercast.channelManager.createRelay(chanInfo, true); // we read the buffer directly, so we are not counted as a listener

            long start = System.currentTimeMillis();
            while ((!channel.isPlaying() || channel.headPack.data == null || channel.headPack.data.length == 0)
                    && !channel.isError() && System.currentTimeMillis() - start < 60_000) {
                Thread.sleep(500);
            }
            if (!channel.isPlaying() || channel.headPack.data == null) {
                logger.log(Level.INFO, "failed: " + channel.status);
                channel.setStatus(Channel.Status.CLOSING);
                continue;
            }

            logger.log(Level.INFO, "Receiving! head: " + channel.headPack.data.length + " bytes, launching ffplay, volume: " + VOLUME);
            Process ffplay = new ProcessBuilder(FFPLAY, "-hide_banner", "-loglevel", "warning",
                    "-volume", String.valueOf(Math.round(Math.max(0, Math.min(1, VOLUME)) * 100)),
                    "-window_title", "PeerCast(Java): " + c.name, "-")
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start();
            long written = 0;
            String dump = System.getProperty("peercast.dump"); // optional: also save the received stream
            try (OutputStream fos = dump != null ? new java.io.FileOutputStream(dump) : OutputStream.nullOutputStream();
                 OutputStream pipe = ffplay.getOutputStream();
                 OutputStream os = new OutputStream() {
                     @Override public void write(int b) throws IOException { pipe.write(b); fos.write(b); }
                     @Override public void write(byte[] b, int o, int l) throws IOException { pipe.write(b, o, l); fos.write(b, o, l); }
                 }) {
                ChannelPacket head = channel.headPack;
                os.write(head.data);
                written += head.data.length;
                int streamPos = head.pos + head.data.length;
                int streamIndex = channel.streamIndex;
                start = System.currentTimeMillis();
                long lastData = start;
                while (System.currentTimeMillis() - start < PLAY_TIME && ffplay.isAlive() && channel.isPlaying()) {
                    if (streamIndex != channel.streamIndex) { // stream restarted
                        streamIndex = channel.streamIndex;
                        streamPos = channel.headPack.pos;
                    }
                    ChannelPacket p = channel.rawData.findPacket(streamPos);
                    if (p != null && p.data != null && (p.type == ChannelPacket.Type.DATA || p.type == ChannelPacket.Type.HEAD)) {
                        os.write(p.data);
                        written += p.data.length;
                        streamPos = p.pos + p.data.length;
                        lastData = System.currentTimeMillis();
                    } else if (System.currentTimeMillis() - lastData > 10_000) {
                        logger.log(Level.INFO, "stalled, no data for 10s: want " + streamPos + ", buffer " + channel.rawData.getOldestPos() + ".." + channel.rawData.getLatestPos() + ", channel.streamPos " + channel.streamPos + ", status " + channel.status);
                        break;
                    } else {
                        Thread.sleep(20);
                    }
                }
            } catch (IOException e) {
                logger.log(Level.INFO, "ffplay pipe closed: " + e.getMessage());
            }
            logger.log(Level.INFO, "fed ffplay " + written + " bytes");
            ffplay.destroy();
            channel.setStatus(Channel.Status.CLOSING);
            if (written > 100_000) {
                played = true;
                break;
            }
        }

        try {
            Peercast.getInstance().quit();
        } catch (Exception e) {
            logger.log(Level.WARNING, "quit: " + e);
        }
        assumeTrue(played, "no FLV channel could be played");
    }
}
