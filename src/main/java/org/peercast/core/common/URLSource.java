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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.peercast.core.common.ChannelInfo.ContentType;

import static java.lang.System.getLogger;


/**
 * URLSource.
 *
 * @author giles
 * @version 20-feb-2004
 */
class URLSource extends ChannelSource {

    private static final Logger logger = getLogger(URLSource.class.getName());

    private final ChannelManager channelManager = Peercast.channelManager;

    /** */
    URLSource(String url) {
        baseurl = url;
    }

    @Override
    void stream(Channel ch) {

        String url = null;
        while (!ch.streaming.isCancelled() && !Peercast.getInstance().isQuitting) {
            if (url == null || url.isEmpty()) {
                url = baseurl;
            }

            url = streamURL(ch, url);
        }

    }

    @Override
    int getSourceRate() {
        if (inputStream != null) {
            return Peercast.getInstance().bytesInPerSec;
        } else {
            return 0;
        }
    }

    /** */
    String streamURL(Channel channel, String url) {
        String nextURL = null;

        if (Peercast.getInstance().isQuitting || channel.streaming.isCancelled()) {
            return nextURL;
        }

        String urlTmp;
        urlTmp = url;

        String fileName = urlTmp;

        PlayList playList = null;
        ChannelStream source = null;

        logger.log(Level.DEBUG, String.format("Fetch URL=%s", fileName));

        try {

            // get the source protocol
            if (fileName.toLowerCase().startsWith("http://") || fileName.toLowerCase().startsWith("https://")) {
                channel.info.srcProtocol = ChannelInfo.Protocol.HTTP;
                if (fileName.toLowerCase().startsWith("http://")) {
                    fileName = fileName.substring(7);
                } else {
                    fileName = fileName.substring(8);
                }
            } else if (fileName.toLowerCase().startsWith("mms://")) {
                channel.info.srcProtocol = ChannelInfo.Protocol.MMS;
                fileName = fileName.substring(6);
            } else if (fileName.toLowerCase().startsWith("pcp://")) {
                channel.info.srcProtocol = ChannelInfo.Protocol.PCP;
                fileName = fileName.substring(6);
            } else if (fileName.toLowerCase().startsWith("file://")) {
                channel.info.srcProtocol = ChannelInfo.Protocol.FILE;
                fileName = fileName.substring(7);
            } else {
                channel.info.srcProtocol = ChannelInfo.Protocol.FILE;
            }

            // default to mp3 for shoutcast servers
            if (channel.info.contentType.equals(ChannelInfo.ContentType.PLS)) {
                channel.info.contentType = ChannelInfo.ContentType.MP3;
            }

            channel.setStatus(Channel.Status.CONNECTING);

            if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.HTTP) ||
                    channel.info.srcProtocol.equals(ChannelInfo.Protocol.PCP) ||
                    channel.info.srcProtocol.equals(ChannelInfo.Protocol.MMS)) {

                if (channel.info.contentType.equals(ChannelInfo.ContentType.WMA) ||
                        channel.info.contentType.equals(ChannelInfo.ContentType.WMV)) {
                    channel.info.srcProtocol = ChannelInfo.Protocol.MMS;
                }

                logger.log(Level.DEBUG, "Channel source is " + channel.info.srcProtocol);

                // Reconstruct full URL for HttpURLConnection
                String protocol = "http";
                if (url.toLowerCase().startsWith("https://")) {
                    protocol = "https";
                }
                String fullUrl = protocol + "://" + fileName;
                
                URL urlObj = new URL(fullUrl);
                HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(10000);

                conn.setRequestProperty(Peercast.HTTP_HS_HOST, urlObj.getHost());
                conn.setRequestProperty(Peercast.HTTP_HS_CONNECTION, "close");
                conn.setRequestProperty(Peercast.HTTP_HS_ACCEPT, "*/*");

                if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.MMS)) {
                    conn.setRequestProperty(Peercast.HTTP_HS_AGENT, "NSPlayer/4.1.0.3856");
                    conn.setRequestProperty("Pragma", "no-cache,rate=1.000000,request-context=1");
                    conn.setRequestProperty("Pragma", "xPlayStrm=1");
                    conn.setRequestProperty("Pragma", "xClientGUID={c77e7400-738a-11d2-9add-0020af0a3278}");
                    conn.setRequestProperty("Pragma", "stream-switch-count=2");
                    conn.setRequestProperty("Pragma", "stream-switch-entry=ffff:1:0 ffff:2:0");
                } else if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.HTTP)) {
                    conn.setRequestProperty(Peercast.HTTP_HS_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
                    conn.setRequestProperty("Icy-MetaData", "1");
                } else {
                    conn.setRequestProperty(Peercast.HTTP_HS_AGENT, GnuPacket.PCX_AGENT);
                    conn.setRequestProperty(GnuPacket.PCX_HS_PCP, "1");
                    conn.setRequestProperty("Icy-MetaData", "1");
                }

                int responseCode = conn.getResponseCode();
                logger.log(Level.DEBUG, String.format("Fetch HTTP: %d", responseCode));

                // Process headers
                // Note: HttpURLConnection header keys can be null (for status line) or case-insensitive
                for (Map.Entry<String, List<String>> header : conn.getHeaderFields().entrySet()) {
                    if (header.getKey() == null) continue;
                    
                    String key = header.getKey().toLowerCase();
                    String value = header.getValue().get(0); // Take first value

                    // Ideally we should use Servent.readICYHeader logic but it takes HttpContext
                    // We can manually map or just handle key headers here

                    switch (key) {
                        case "icy-metaint" -> channel.icyMetaInterval = Integer.parseInt(value);
                        case "location" -> nextURL = value;
                        case "content-type" -> {
                            if (value.indexOf(Peercast.MIME_XSCPLS) > 0) {
                                playList = PlayList.SCPLS;
                            } else if (value.indexOf(Peercast.MIME_PLS) > 0) {
                                playList = PlayList.PLS;
                            } else if (value.indexOf(Peercast.MIME_XPLS) > 0) {
                                playList = PlayList.PLS;
                            } else if (value.indexOf(Peercast.MIME_M3U) > 0) {
                                playList = PlayList.PLS;
                            } else if (value.indexOf(Peercast.MIME_TEXT) > 0) {
                                playList = PlayList.PLS;
                            } else if (value.indexOf(Peercast.MIME_ASX) > 0) {
                                playList = PlayList.ASX;
                            } else if (value.indexOf(Peercast.MIME_MMS) > 0) {
                                channel.info.srcProtocol = ChannelInfo.Protocol.MMS;
                            }
                            if (playList != null) playList.init(1000);
                        }
                    }
                    
                    // Simple mapping for channel info update (simplified)
                    if (key.equals("icy-name")) channel.info.name = value;
                    if (key.equals("icy-genre")) channel.info.genre = value;
                    if (key.equals("icy-url")) channel.info.url = value;
                }

                if (nextURL != null && !nextURL.isEmpty() && responseCode == 302) {
                    logger.log(Level.DEBUG, String.format("Ch.%d redirect: %s", channel.index, nextURL));
                    return nextURL;
                }

                if (responseCode != 200) {
                    logger.log(Level.ERROR, "HTTP response: " + responseCode);
                    throw new IOException("Bad HTTP connect: " + responseCode);
                }

                inputStream = conn.getInputStream();

            } else if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.FILE)) {

                logger.log(Level.DEBUG, "Channel source is FILE");

                inputStream = new FileInputStream(fileName);

                ChannelInfo.ContentType fileType = ChannelInfo.ContentType.UNKNOWN;
                // if filetype is unknown, try and figure it out from file extension.
                {
                    int ext = fileName.indexOf('.');
                    if (ext > 0) {

                        fileType = ContentType.valueOf(fileName.substring(ext + 1));
                    }
                }

                if (channel.info.bitrate != 0) {
                    channel.readDelay = true;
                }

                if (fileType == ChannelInfo.ContentType.PLS) {
                    playList = PlayList.PLS;
                    playList.init(1000);
                } else if (fileType == ChannelInfo.ContentType.ASX) {
                    playList = PlayList.ASX;
                    playList.init(1000);
                } else {
                    channel.info.contentType = fileType;
                }

            } else {
                throw new IOException("Unsupported URL");
            }


            if (playList != null) {

                logger.log(Level.DEBUG, String.format("Ch.%d is Playlist", channel.index));

                playList.read(inputStream);

                inputStream.close();
                inputStream = null;

                int urlNum = 0;

                logger.log(Level.DEBUG, String.format("Playlist: %d URLs", playList.numURLs));
                while (!channel.streaming.isCancelled() && playList.numURLs != 0 && !Peercast.getInstance().isQuitting) {
                    if (url.isEmpty()) {
                        url = playList.urls[urlNum % playList.numURLs];
                        urlNum++;
                    }
                    url = streamURL(channel, url);
                }

            } else {

                // if we didn`t get a channel id from the source, then create our own (its an original broadcast)
                if (!channel.info.id.isSet()) {
                    channel.info.id = channelManager.broadcastID;
                    channel.info.id.encode(null, channel.info.name, null, (byte) channel.info.bitrate);
                }

                if (channel.info.contentType.equals(ChannelInfo.ContentType.ASX)) {
                    channel.info.contentType = ChannelInfo.ContentType.WMV;
                }

                channel.setStatus(Channel.Status.BROADCASTING);

                if (channel.sock != null) {
                    channel.sock.setSoTimeout(60);    // use longer read timeout
                }

                source = channel.createSource();

                channel.readStream(inputStream, source);

                inputStream.close();
            }

        } catch (IOException e) {
            logger.log(Level.ERROR, e.getMessage(), e);
            channel.setStatus(Channel.Status.ERROR);
            logger.log(Level.ERROR, String.format("Ch.%d error: %s", channel.index, e.getMessage()));
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ie) {
            }
        }


        channel.setStatus(Channel.Status.CLOSING);
        if (inputStream != null) {
            inputStream = null;
        }

        return nextURL;
    }

    /** */
    InputStream inputStream;

    /** */
    String baseurl;
}
