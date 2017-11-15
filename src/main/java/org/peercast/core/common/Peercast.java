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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.peercast.core.common.ServentManager.NotifyType;

import vavi.net.http.HttpUtil;
import vavi.util.Debug;
import vavi.util.Singleton;
import vavix.util.screenscrape.Scraper;
import vavix.util.screenscrape.SimpleURLScraper;
import vavix.util.screenscrape.StringSimpleXPathScraper;


/**
 * This is the interface from the application to the core.
 */
abstract class Peercast {

    static Log log = LogFactory.getLog(Peercast.class);

    private static ServentManager serventManager = Singleton.getInstance(ServentManager.class);

    private static ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

    static String iniFileName;

    static Peercast instance;

    final String getPath() {
        return ".";
    }

    final String getIniFilename() {
        return iniFileName;
    }

    private Peercast() {
        isQuitting = false;
    }

    static Peercast getInstance() {
        return instance;
    }

    /** start point */
    void init() throws IOException {

        if (getIniFilename() != null) {
            serventManager.loadSettings(getIniFilename());
        }

        serventManager.start();
    }

    /** */
    void setNotifyMask(int mask) {
        serventManager.notifyMask = mask;
    }

    /** */
    int getNotifyMask() {
        return serventManager.notifyMask;
    }

    /** */
    void setAutoConnect(boolean on) {
        serventManager.autoConnect = on;
    }

    /** */
    boolean getAutoConnect() {
        return serventManager.autoConnect;
    }

    /** */
    void setMaxOutput(int kbps) {
        serventManager.maxBitrateOut = kbps;
    }

    /** */
    int getMaxOutput() {
        return serventManager.maxBitrateOut;
    }

    /** */
    void setMaxRelays(int max) {
        serventManager.setMaxRelays(max);
    }

    /** */
    int getMaxRelays() {
        return serventManager.maxRelays;
    }

    /** */
    void setActive(boolean on) {
        serventManager.autoConnect = on;
        serventManager.autoServe = on;
    }

    /** */
    boolean getActive() {
        return serventManager.autoConnect && serventManager.autoServe;
    }

    /** */
    void saveSettings() {
        serventManager.saveSettings(getIniFilename());
    }

    /** */
    void quit() {
        isQuitting = true;
        channelManager.quit();
        serventManager.quit();
    }

    /** */
    void setServerPort(int port) {
        serventManager.serverHost = new InetSocketAddress(serventManager.serverHost.getAddress(), port);
        serventManager.restartServer = true;
    }

    /** */
    int getServerPort() {
        return serventManager.serverHost.getPort();
    }

    /** */
    void setServerPassword(final String password) {
        serventManager.password = password;
    }

    /** */
    final String getServerPassword() {
        return serventManager.password;
    }

    /** */
    void callLocalURL(String url) throws IOException {
        Runtime.getRuntime().exec("IExplorer " + new URL("http", "localhost", serventManager.serverHost.getPort(), url).toString());
    }

    /** */
    abstract void notifyMessage(NotifyType type, String string);

    /** */
    abstract void delChannel(ChannelInfo info);

    /** */
    abstract void addChannel(ChannelInfo info);

    /** */
    abstract void channelStart(ChannelInfo info);

    /** */
    abstract void channelStop(ChannelInfo info);

    /** */
    abstract void channelUpdate(ChannelInfo info);

    /** */
    abstract void updateSettings();

    boolean isQuitting;

//    static final String RTSP_SC_OK = "RTSP/1.0 200 OK";

//    static final String HTTP_PROTO1 = "HTTP/1.";
//    static final String RTSP_PROTO1 = "RTSP/1.";

    static final String HTTP_HS_SERVER = "server";
    static final String HTTP_HS_AGENT = "user-agent";
    static final String HTTP_HS_CONTENT = "content-type";
    static final String HTTP_HS_CACHE = "cache-control";
    static final String HTTP_HS_CONNECTION = "connection";
    static final String HTTP_HS_SETCOOKIE = "set-cookie";
    static final String HTTP_HS_COOKIE = "cookie";
    static final String HTTP_HS_HOST = "host";
    static final String HTTP_HS_ACCEPT = "accept";
    static final String HTTP_HS_LENGTH = "content-length";

    static final String MIME_MP3 = "audio/mpeg";
    static final String MIME_XMP3 = "audio/x-mpeg";
    static final String MIME_OGG = "application/ogg";
    static final String MIME_XOGG = "application/x-ogg";
    static final String MIME_MOV = "video/quicktime";
    static final String MIME_MPG = "video/mpeg";
    static final String MIME_NSV = "video/nsv";
    static final String MIME_ASF = "video/x-ms-asf";
    static final String MIME_ASX = "video/x-ms-asf"; // same as ASF
    static final String MIME_MMS = "application/x-mms-framed";
    static final String MIME_RAM = "audio/x-pn-realaudio";
    static final String MIME_WMA = "audio/x-ms-wma";
    static final String MIME_WMV = "video/x-ms-wmv";
    static final String MIME_HTML = "text/html";
    static final String MIME_XML = "text/xml";
    static final String MIME_CSS = "text/css";
    static final String MIME_TEXT = "text/plain";
    static final String MIME_PLS = "audio/mpegurl";
    static final String MIME_XPLS = "audio/x-mpegurl";
    static final String MIME_XSCPLS = "audio/x-scpls";
    static final String MIME_SDP = "application/sdp";
    static final String MIME_M3U = "audio/m3u";
    static final String MIME_MPEGURL = "audio/mpegurl";
    static final String MIME_XM3U = "audio/x-mpegurl";
    static final String MIME_XPEERCAST = "application/x-peercast";
    static final String MIME_XPCP = "application/x-peercast-pcp";
    static final String MIME_RAW = "application/binary";
    static final String MIME_JPEG = "image/jpeg";
    static final String MIME_GIF = "image/gif";
    static final String MIME_PNG = "image/png";

    // ----

    static DocumentBuilder db;

    static {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try {
            db = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            log.error(e);
        }
    }

    /** */
    public static Attr newAttribute(String name) {
        Document document = db.newDocument();
        return document.createAttribute(name);
    }

    /** */
    public static Element newElement(String name) {
        Document document = db.newDocument();
        return document.createElement(name);
    }

    // ----

    Stats stats = new Stats();

    static int idleSleepTime = 10 * 1000;

    int bytesOutPerSec;

    int bytesInPerSec;

    int totalBytesIn;

    int totalBytesOut;

    long lastPlayTime;

    /**
     * @param t [sec]
     */
    static String getFromStopwatch(int t) {
        int sec, min, hour, day;

        sec = t % 60;
        min = (t / 60) % 60;
        hour = (t / 3600) % 24;
        day = (t / 86400);

        if (day != 0) {
            return String.format("%d day, %d hour", day, hour);
        } else if (hour != 0) {
            return String.format("%d hour, %d min", hour, min);
        } else if (min != 0) {
            return String.format("%d min, %d sec", min, sec);
        } else if (sec != 0) {
            return String.format("%d sec", sec);
        } else {
            return "-";
        }
    }

    // ---- common ----

    /** */
    static int byteToInt(byte[] ip) {
        return ByteBuffer.wrap(ip).asIntBuffer().get();
    }

    /** */
    static byte[] intToByte(int ip) {
        byte[] tmp = new byte[4];
        ByteBuffer.wrap(tmp).asIntBuffer().put(ip);
        return tmp;
    }

    static float BYTES_TO_KBPS(int n) {
        return (n * 8.0f) / 1024.0f;
    }

//    /** TODO calc ip to int */
//    static int strToID(String str) {
//        return str.charAt(0);
//    }

    //----

    /** */
    public static void main(String[] args) throws Exception {

        Peercast.iniFileName = "peercast.ini";

        if (args.length > 2) {
            if (args[1].equals("-inifile")) {
                Peercast.iniFileName = args[2];
            }
        }

        instance = new Peercast() {
            @Override
            void notifyMessage(NotifyType type, String string) {
                System.err.println("notify: " + type + ": " + string + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void delChannel(ChannelInfo info) {
                System.err.println("delete: " + info.id + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void addChannel(ChannelInfo info) {
                System.err.println("add: " + info.id + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void channelStart(ChannelInfo info) {
                System.err.println("start: " + info.id + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void channelStop(ChannelInfo info) {
                System.err.println("stop: " + info.id + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void channelUpdate(ChannelInfo info) {
//new Exception("*** UPDATE ***").printStackTrace(System.err);
                System.err.println("update: " + info.id + " <- " + Debug.getCallerMethod(2));
            }
            @Override
            void updateSettings() {
                System.err.println("setting: " + " <- " + Debug.getCallerMethod(2));
            }
        };
        instance.init();

        HttpUtil.setEncoding("MS932");

        String urlString = "http://yp.peercast.org/";
        // tr[7] index 2 ~ ranking
        int number = (int) (Math.random() * 4 + 4);
Debug.println("number: " + number);
        String xpath = String.format("/html/body/div/table/tr/td/div[2]/table/tr[%d]/td[2]/a/@href", number);

        Scraper<URL, String> scraper = new SimpleURLScraper<>(new StringSimpleXPathScraper(xpath));
        String url = scraper.scrape(new URL(urlString));
//      String url = "peercast://pls/69AED3D9586F089E4D832A2450158498?tip=61.202.103.86:7144";
Debug.println("url: " + url);
        if (url.startsWith("peercast://")) {
            if (url.startsWith("peercast://pls/")) {
                url = url.substring(11 + 4);
            } else {
                url = url.substring(11);
            }
        }

        ChannelInfo chanInfo = new ChannelInfo();
        serventManager.procConnectArgs(url, chanInfo);
        channelManager.findAndPlayChannel(chanInfo, false);

        while (!instance.isQuitting) {
            Thread.sleep(1000);
        }

        instance.saveSettings();
        instance.quit();
    }
}

/** */
