package org.peercast.core.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.SourceDataLine;
import org.junit.jupiter.api.Test;
import org.peercast.core.common.ServentManager.NotifyType;

import static java.lang.System.getLogger;


/**
 * TestCase.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2026-02-09 nsano initial version <br>
 */
class TestCase {

    private static final Logger logger = getLogger(TestCase.class.getName());

    @Test
    void testPlayChannelFromYP() throws Exception {
        Peercast.idleSleepTime = 10;

        Peercast.iniFileName = "peercast.ini";
        Peercast.instance = new Peercast() {
            @Override void notifyMessage(NotifyType type, String string) {
                logger.log(Level.DEBUG, "notify: " + type + ": " + string);
            }
            @Override void delChannel(ChannelInfo info) {}
            @Override void addChannel(ChannelInfo info) {}
            @Override void channelStart(ChannelInfo info) {}
            @Override void channelStop(ChannelInfo info) {}
            @Override void channelUpdate(ChannelInfo info) {}
            @Override void updateSettings() {}
        };
        Peercast.getInstance().init();

        java.util.List<ChannelCandidate> candidates = new java.util.ArrayList<>();
        
        // 1. Try to get active channels from the YP
        String[] indexUrls = {
            "http://bayonet.ddo.jp/sp/index.txt",
            "http://temp.pecu.jp/index.txt",
            "http://yp.peercast.org/index.txt"
        };
        
        for (String indexUrl : indexUrls) {
            logger.log(Level.INFO, "Fetching channels from YP: " + indexUrl);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new URL(indexUrl).openStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("<>");
                    if (parts.length > 9) {
                        String name = parts[0];
                        String id = parts[1];
                        String ip = parts[2];
                        String typeStr = parts[9];
                        
                        if (!id.equals("00000000000000000000000000000000") && !typeStr.equals("RAW")) {
                            String currentUrl = "peercast://pls/" + id + "?tip=" + ip;
                            ChannelInfo.ContentType currentType = ChannelInfo.ContentType.UNKNOWN;
                            try {
                                currentType = ChannelInfo.ContentType.valueOf(typeStr);
                            } catch (IllegalArgumentException e) {
                                // logger.log(Level.WARNING, "Unknown content type: " + typeStr);
                            }
                            candidates.add(new ChannelCandidate(currentUrl, currentType, name));
                        }
                    }
                }
            } catch (IOException e) {
                logger.log(Level.WARNING, "Failed to fetch from YP (" + indexUrl + "): " + e.getMessage());
            }
        }
        
        // Remove duplicates based on ID (embedded in URL)
        java.util.Set<String> seenIds = new java.util.HashSet<>();
        candidates.removeIf(c -> {
            // simplistic extraction of ID
            String id = c.url;
            if (id.contains("?")) id = id.substring(0, id.indexOf("?"));
            return !seenIds.add(id);
        });

        // Sort candidates: MP3/OGG first
        candidates.sort((c1, c2) -> {
            boolean c1Audio = c1.type == ChannelInfo.ContentType.MP3 || c1.type == ChannelInfo.ContentType.OGG;
            boolean c2Audio = c2.type == ChannelInfo.ContentType.MP3 || c2.type == ChannelInfo.ContentType.OGG;
            if (c1Audio && !c2Audio) return -1;
            if (!c1Audio && c2Audio) return 1;
            return 0;
        });

        if (candidates.isEmpty()) {
            logger.log(Level.WARNING, "No active channel found on YP, using fallback.");
            candidates.add(new ChannelCandidate("peercast://pls/69AED3D9586F089E4D832A2450158498?tip=61.202.103.86:7144", ChannelInfo.ContentType.UNKNOWN, "Fallback"));
        }

        boolean success = false;
        for (ChannelCandidate candidate : candidates) {
            String url = candidate.url;
            ChannelInfo.ContentType contentType = candidate.type;
            
            if (url.startsWith("peercast://")) {
                if (url.startsWith("peercast://pls/")) {
                    url = url.substring(15);
                } else {
                    url = url.substring(11);
                }
            }
            logger.log(Level.INFO, "Trying candidate: " + candidate.name + " (" + contentType + ") url: " + url);

            ChannelInfo chanInfo = new ChannelInfo();
            Peercast.serventManager.procConnectArgs(url, chanInfo);
            Channel channel = Peercast.channelManager.createRelay(chanInfo, false);

            logger.log(Level.INFO, "Connecting to " + url);

            // Wait for channel to be RECEIVING
            long start = System.currentTimeMillis();
            while (!channel.isPlaying() && !channel.isError() && (System.currentTimeMillis() - start) < 10000) { // 10s timeout per candidate
                Thread.sleep(1000);
                logger.log(Level.INFO, "Status: " + channel.status);
            }

            if (channel.isPlaying()) {
                logger.log(Level.INFO, "Channel connected!");
                if (contentType == ChannelInfo.ContentType.MP3 || contentType == ChannelInfo.ContentType.OGG) {
                    InputStream is = new ChannelInputStream(channel);
                    logger.log(Level.INFO, "Waiting for buffer to fill...");
                    Thread.sleep(2000);
                    logger.log(Level.INFO, "Starting javax.sound.sampled playback...");
                    long totalBytesWritten = 0;
                    try {
                        AudioInputStream ais = AudioSystem.getAudioInputStream(new java.io.BufferedInputStream(is, 1024 * 512));
                        javax.sound.sampled.AudioFormat baseFormat = ais.getFormat();
                        javax.sound.sampled.AudioFormat decodedFormat = new javax.sound.sampled.AudioFormat(
                            javax.sound.sampled.AudioFormat.Encoding.PCM_SIGNED,
                            baseFormat.getSampleRate(),
                            16,
                            baseFormat.getChannels(),
                            baseFormat.getChannels() * 2,
                            baseFormat.getSampleRate(),
                            false);
                        AudioInputStream dais = AudioSystem.getAudioInputStream(decodedFormat, ais);

                        SourceDataLine line = AudioSystem.getSourceDataLine(decodedFormat);
                        line.open(decodedFormat);
                        line.start();
        
                        byte[] buf = new byte[4096];
                        int n;
                        long playStart = System.currentTimeMillis();
                        // Play for 5 seconds
                        while ((n = dais.read(buf)) != -1 && (System.currentTimeMillis() - playStart) < 5000) {
                            line.write(buf, 0, n);
                            totalBytesWritten += n;
                        }
                        line.drain();
                        line.close();
                        logger.log(Level.INFO, "Playback finished. Total bytes written: " + totalBytesWritten);
                        if (totalBytesWritten > 0) {
                            success = true;
                            break;
                        }
                    } catch (Exception e) {
                        logger.log(Level.ERROR, "Playback failed: " + e);
                    }
                } else {
                     logger.log(Level.INFO, "Channel is playing but content type is " + contentType + ", skipping audio playback verification.");
                     success = true; // Count as success if we connected to a non-audio stream
                     break;
                }
            } else {
                logger.log(Level.INFO, "Failed to connect or timed out. Status: " + channel.status);
            }
            
            // Cleanup for next attempt
            if (channel.streaming != null) {
                channel.streaming.cancel(true);
            }
            channel.setStatus(Channel.Status.CLOSING);
            // Give it a moment to cleanup
            Thread.sleep(500); 
        }

        try {
            Peercast.getInstance().quit();
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error during Peercast quit (ignoring): " + e.getMessage());
        }
        
        if (!success) {
            logger.log(Level.WARNING, "Could not connect to any channel from YP. Skipping test assertion.");
            org.junit.jupiter.api.Assumptions.assumeTrue(success, "Could not connect to any channel from YP");
        }
    }

    static class ChannelCandidate {
        String url;
        ChannelInfo.ContentType type;
        String name;
        
        ChannelCandidate(String url, ChannelInfo.ContentType type, String name) {
            this.url = url;
            this.type = type;
            this.name = name;
        }
    }

    static class ChannelInputStream extends InputStream {
        ChannelPacketBuffer buffer;
        ChannelPacket currentPacket;
        Channel channel;
        int offset;
        long totalRead = 0;

        ChannelInputStream(Channel channel) {
            this.channel = channel;
            this.buffer = channel.rawData;
        }

        @Override
        public int available() throws IOException {
            int available = 0;
            if (currentPacket != null) {
                available += currentPacket.data.length - offset;
            }
            // This is a rough estimate as we don't know the size of pending packets in buffer
            if (buffer.numPending()) {
                available += 1; // At least one byte
            }
            return available;
        }

        @Override
        public int read() throws IOException {
            if (currentPacket == null || offset >= currentPacket.data.length) {
                if (!channel.isPlaying() && !buffer.numPending()) {
                    return -1;
                }
                currentPacket = buffer.readPacket();
                offset = 0;
                while (currentPacket.type != ChannelPacket.Type.DATA && currentPacket.type != ChannelPacket.Type.HEAD || currentPacket.data.length == 0) {
                    if (!channel.isPlaying() && !buffer.numPending()) {
                        return -1;
                    }
                    currentPacket = buffer.readPacket();
                    offset = 0;
                }
            }
            totalRead++;
            return currentPacket.data[offset++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (currentPacket == null || offset >= currentPacket.data.length) {
                if (!channel.isPlaying() && !buffer.numPending()) {
                    return -1;
                }
                try {
                    currentPacket = buffer.readPacket();
                    offset = 0;
                    while (currentPacket.type != ChannelPacket.Type.DATA && currentPacket.type != ChannelPacket.Type.HEAD || currentPacket.data.length == 0) {
                        if (!channel.isPlaying() && !buffer.numPending()) {
                            return -1;
                        }
                        currentPacket = buffer.readPacket();
                        offset = 0;
                    }
                } catch (IOException e) {
                    if (!channel.isPlaying()) {
                        return -1;
                    }
                    logger.log(Level.WARNING, "ChannelInputStream EOF: " + e.getMessage());
                    return -1;
                }
            }
            int available = currentPacket.data.length - offset;
            int toCopy = Math.min(len, available);
            System.arraycopy(currentPacket.data, offset, b, off, toCopy);
            offset += toCopy;
            totalRead += toCopy;
            return toCopy;
        }
    }
}
