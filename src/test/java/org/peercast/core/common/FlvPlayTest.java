/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.GraphicsEnvironment;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.SourceDataLine;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.peercast.core.common.ServentManager.NotifyType;

import static java.lang.System.getLogger;
import static org.junit.jupiter.api.Assumptions.assumeTrue;


/**
 * Relays FLV channels listed on a YP and shows them in a Swing window.
 * <p>
 * keys: ^N next channel, ^P previous channel
 * <p>
 * system properties
 * <ul>
 *  <li>vavi.test.volume ... 0.0 ~ 1.0</li>
 *  <li>peercast.playTime ... [ms] session length, 0 means until the window is closed</li>
 *  <li>peercast.dump ... file to save the stream of the current channel</li>
 * </ul>
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2026-11-12 nsano initial version <br>
 */
class FlvPlayTest {

    private static final Logger logger = getLogger(FlvPlayTest.class.getName());

    static final String FFMPEG = "/opt/homebrew/bin/ffmpeg";

    /** session length [ms], 0 means until the window is closed */
    static final long PLAY_TIME = Long.getLong("peercast.playTime", 30_000);

    /** 0.0 ~ 1.0 */
    static final float VOLUME = Float.parseFloat(System.getProperty("vavi.test.volume", "0.2"));

    static final int W = 960, H = 540;

    static boolean canPlay() {
        return new File(FFMPEG).canExecute() && !GraphicsEnvironment.isHeadless();
    }

    record Candidate(String name, String id, String tip, String type, int listeners, String detail) {}

    static List<Candidate> fetchYP(String indexUrl) {
        List<Candidate> list = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(URI.create(indexUrl).toURL().openStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] p = line.split("<>", -1);
                if (p.length > 9 && !p[1].matches("0+") && !p[2].isEmpty()) {
                    int listeners;
                    try { listeners = Integer.parseInt(p[6]); } catch (NumberFormatException e) { listeners = -1; }
                    list.add(new Candidate(p[0], p[1], p[2], p[9], listeners, p[5].replace("&lt;", "<").replace("&gt;", ">")));
                }
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "YP failed: " + indexUrl + ": " + e);
        }
        return list;
    }

    /** stops a relay created with stayConnected */
    static void stopChannel(Channel channel) {
        channel.stayConnected = false;
        if (channel.streaming != null) {
            channel.streaming.cancel(true);
        }
        try {
            Socket sock = channel.sock;
            if (sock != null) {
                sock.close();
            }
        } catch (IOException e) {
            logger.log(Level.DEBUG, e);
        }
        channel.setStatus(Channel.Status.CLOSING);
    }

    @Test
    @EnabledIf("canPlay")
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
        assumeTrue(!candidates.isEmpty(), "no FLV channel on the YP");

        Player player = new Player(candidates);
        player.tune(0, +1);
        if (PLAY_TIME > 0) {
            player.closed.await(PLAY_TIME, TimeUnit.MILLISECONDS);
        } else {
            player.closed.await();
        }
        player.close();

        try {
            Peercast.getInstance().quit();
        } catch (Exception e) {
            logger.log(Level.WARNING, "quit: " + e);
        }
        assumeTrue(player.totalBytes.get() > 100_000, "no FLV channel could be played");
    }

    /** a Swing window, ffmpeg decodes the stream into raw video and pcm */
    static class Player {

        final List<Candidate> candidates;
        final JFrame frame = new JFrame();
        final BufferedImage image = new BufferedImage(W, H, BufferedImage.TYPE_3BYTE_BGR);
        final JComponent canvas;
        final CountDownLatch closed = new CountDownLatch(1);
        final ExecutorService switcher = Executors.newSingleThreadExecutor();
        /** incremented on every key press, older tuning jobs give up */
        final AtomicInteger generation = new AtomicInteger();
        final AtomicLong totalBytes = new AtomicLong();

        volatile Session current;
        volatile int index;
        volatile String status = "";

        Player(List<Candidate> candidates) {
            this.candidates = candidates;

            canvas = new JComponent() {
                @Override protected void paintComponent(Graphics g) {
                    synchronized (image) {
                        g.drawImage(image, 0, 0, getWidth(), getHeight(), null);
                    }
                    Candidate c = candidates.get(index);
                    String line1 = String.format("[%d/%d] %s - %s", index + 1, candidates.size(), c.name, c.detail);
                    String line2 = status + "    ^P prev / ^N next";
                    g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
                    for (int i = 0; i < 2; i++) { // outlined text
                        g.setColor(i == 0 ? Color.black : Color.white);
                        int d = i == 0 ? 1 : 0;
                        g.drawString(line1, 10 + d, 22 + d);
                        g.drawString(line2, 10 + d, 42 + d);
                    }
                }
            };
            canvas.setPreferredSize(new Dimension(W, H));

            JComponent root = frame.getRootPane();
            bind(root, KeyEvent.VK_N, "next", () -> tune(index + 1, +1));
            bind(root, KeyEvent.VK_P, "prev", () -> tune(index - 1, -1));

            frame.setTitle("PeerCast(Java)");
            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            frame.addWindowListener(new WindowAdapter() {
                @Override public void windowClosed(WindowEvent e) { closed.countDown(); }
            });
            frame.getContentPane().add(canvas);
            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
            frame.toFront();
        }

        private static void bind(JComponent c, int key, String name, Runnable r) {
            c.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(key, InputEvent.CTRL_DOWN_MASK), name);
            c.getActionMap().put(name, new AbstractAction() {
                @Override public void actionPerformed(ActionEvent e) { r.run(); }
            });
        }

        void setStatus(String status) {
            this.status = status;
            logger.log(Level.INFO, status);
            canvas.repaint();
        }

        /** starts from {@code start}, skips unplayable channels in {@code dir} direction */
        void tune(int start, int dir) {
            int gen = generation.incrementAndGet();
            int n = candidates.size();
            index = Math.floorMod(start, n);
            canvas.repaint();
            switcher.submit(() -> {
                BooleanSupplier cancelled = () -> generation.get() != gen;
                if (current != null) {
                    current.close();
                    current = null;
                }
                for (int k = 0; k < n && !cancelled.getAsBoolean(); k++) {
                    int i = Math.floorMod(start + k * dir, n);
                    index = i;
                    Candidate c = candidates.get(i);
                    setStatus("connecting: " + c.name);
                    Session s = Session.open(this, c, cancelled);
                    if (s != null) {
                        if (cancelled.getAsBoolean()) {
                            s.close();
                        } else {
                            current = s;
                            setStatus("playing");
                        }
                        return;
                    }
                }
                if (!cancelled.getAsBoolean()) {
                    setStatus("no playable channel");
                }
            });
        }

        void onStall(Session s) {
            if (s == current) {
                setStatus("stalled, next channel");
                tune(index + 1, +1);
            }
        }

        void close() {
            generation.incrementAndGet();
            switcher.shutdownNow();
            if (current != null) {
                current.close();
            }
            SwingUtilities.invokeLater(frame::dispose);
        }
    }

    /** one channel being played */
    static class Session {

        final Player player;
        final Channel channel;
        final Process ffmpeg;
        final ServerSocket audioServer;
        volatile boolean running = true;
        volatile SourceDataLine line;

        private Session(Player player, Channel channel, Process ffmpeg, ServerSocket audioServer) {
            this.player = player;
            this.channel = channel;
            this.ffmpeg = ffmpeg;
            this.audioServer = audioServer;
        }

        /** @return null when the channel could not be received */
        static Session open(Player player, Candidate c, BooleanSupplier cancelled) {
            logger.log(Level.INFO, "Trying: " + c.name + " " + c.id + " @" + c.tip);
            ChannelInfo chanInfo = new ChannelInfo();
            Peercast.serventManager.procConnectArgs(c.id + "?tip=" + c.tip, chanInfo);
            Channel channel = Peercast.channelManager.createRelay(chanInfo, true); // we read the buffer directly, so we are not counted as a listener

            try {
                long start = System.currentTimeMillis();
                while ((!channel.isPlaying() || channel.headPack.data == null || channel.headPack.data.length == 0)
                        && !channel.isError() && !cancelled.getAsBoolean() && System.currentTimeMillis() - start < 60_000) {
                    Thread.sleep(200);
                }
                if (!channel.isPlaying() || channel.headPack.data == null || cancelled.getAsBoolean()) {
                    logger.log(Level.INFO, "failed: " + channel.status);
                    stopChannel(channel);
                    return null;
                }

                ServerSocket audioServer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                Process ffmpeg = new ProcessBuilder(FFMPEG, "-hide_banner", "-loglevel", "error",
                        "-re", "-i", "pipe:0",
                        "-map", "0:v:0",
                        "-vf", String.format("scale=%1$d:%2$d:force_original_aspect_ratio=decrease,pad=%1$d:%2$d:(ow-iw)/2:(oh-ih)/2", W, H),
                        "-pix_fmt", "bgr24", "-f", "rawvideo", "pipe:1",
                        "-map", "0:a:0?",
                        "-af", "volume=" + Math.max(0, Math.min(1, VOLUME)),
                        "-ac", "2", "-ar", "48000", "-f", "s16le",
                        "tcp://127.0.0.1:" + audioServer.getLocalPort())
                        .redirectError(ProcessBuilder.Redirect.INHERIT)
                        .start();
                Session s = new Session(player, channel, ffmpeg, audioServer);
                s.start(c);
                return s;
            } catch (Exception e) {
                logger.log(Level.WARNING, "open: " + e);
                stopChannel(channel);
                return null;
            }
        }

        private void start(Candidate c) {
            daemon("pump-" + c.name, this::pump);
            daemon("video-" + c.name, this::video);
            daemon("audio-" + c.name, this::audio);
        }

        private static void daemon(String name, Runnable r) {
            Thread t = new Thread(r, name);
            t.setDaemon(true);
            t.start();
        }

        /** channel buffer -> ffmpeg stdin */
        private void pump() {
            String dump = System.getProperty("peercast.dump");
            try (OutputStream fos = dump != null ? new FileOutputStream(dump) : OutputStream.nullOutputStream();
                 OutputStream os = ffmpeg.getOutputStream()) {
                ChannelPacket head = channel.headPack;
                os.write(head.data);
                fos.write(head.data);
                int streamPos = head.pos + head.data.length;
                int streamIndex = channel.streamIndex;
                long lastData = System.currentTimeMillis();
                while (running && ffmpeg.isAlive()) {
                    if (streamIndex != channel.streamIndex) { // stream restarted
                        streamIndex = channel.streamIndex;
                        streamPos = channel.headPack.pos;
                    }
                    ChannelPacket p = channel.rawData.findPacket(streamPos);
                    if (p != null && p.data != null && (p.type == ChannelPacket.Type.DATA || p.type == ChannelPacket.Type.HEAD)) {
                        os.write(p.data);
                        fos.write(p.data);
                        player.totalBytes.addAndGet(p.data.length);
                        streamPos = p.pos + p.data.length;
                        lastData = System.currentTimeMillis();
                    } else if (System.currentTimeMillis() - lastData > 10_000) {
                        logger.log(Level.INFO, "stalled, no data for 10s: " + channel.status);
                        player.onStall(this);
                        break;
                    } else {
                        Thread.sleep(20);
                    }
                }
            } catch (IOException | InterruptedException e) {
                if (running) logger.log(Level.INFO, "pump: " + e);
            }
        }

        /** ffmpeg stdout (raw bgr24) -> window */
        private void video() {
            byte[] buf = new byte[W * H * 3];
            byte[] dst = ((DataBufferByte) player.image.getRaster().getDataBuffer()).getData();
            try (InputStream is = ffmpeg.getInputStream()) {
                while (running && is.readNBytes(buf, 0, buf.length) == buf.length) {
                    if (player.current != this) continue; // not (or no longer) the channel on screen
                    synchronized (player.image) {
                        System.arraycopy(buf, 0, dst, 0, buf.length);
                    }
                    player.canvas.repaint();
                }
            } catch (IOException e) {
                if (running) logger.log(Level.INFO, "video: " + e);
            }
        }

        /** ffmpeg tcp (pcm s16le) -> javax.sound */
        private void audio() {
            try {
                audioServer.setSoTimeout(30_000); // no audio track, ffmpeg never connects
                try (Socket s = audioServer.accept(); InputStream is = s.getInputStream()) {
                    AudioFormat format = new AudioFormat(48000, 16, 2, true, false);
                    line = AudioSystem.getSourceDataLine(format);
                    line.open(format, 48000 * 4 / 4); // 250ms
                    line.start();
                    byte[] buf = new byte[4096];
                    int n;
                    while (running && (n = is.read(buf)) > 0) {
                        line.write(buf, 0, n);
                    }
                }
            } catch (Exception e) {
                if (running) logger.log(Level.INFO, "audio: " + e);
            } finally {
                if (line != null) line.close();
            }
        }

        void close() {
            running = false;
            stopChannel(channel);
            ffmpeg.destroy();
            try {
                audioServer.close();
            } catch (IOException e) {
                logger.log(Level.DEBUG, e);
            }
            SourceDataLine l = line;
            if (l != null) {
                l.stop();
                l.flush();
            }
        }
    }
}
