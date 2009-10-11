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
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.peercast.core.common.ChannelInfo.ContentType;

import vavi.net.http.HttpContext;
import vavi.net.http.HttpProtocol;
import vavi.net.http.HttpUtil;
import vavi.util.Singleton;


/**
 * URLSource.
 *
 * @version 20-feb-2004
 * @author giles
 */
class URLSource extends ChannelSource {

    /** */
    static Log log = LogFactory.getLog(URLSource.class);

    private ChannelManager channelManager = Singleton.getInstance(ChannelManager.class);

    /** */
    URLSource(final String url) {
        baseurl = url;
    }

    /** */
    void stream(Channel ch) {

        String url = null;
        while (!ch.streaming.isCancelled() && !Peercast.getInstance().isQuitting) {
            if (url == null || url.length() == 0) {
                url = baseurl;
            }

            url = streamURL(ch, url);
        }

    }

    /** */
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

log.debug(String.format("Fetch URL=%s", fileName));

        try {

            // get the source protocol
            if (fileName.toLowerCase().startsWith("http://")) {
                channel.info.srcProtocol = ChannelInfo.Protocol.HTTP;
                fileName = fileName.substring(7);
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
                channel.info.srcProtocol.equals(ChannelInfo.Protocol.PCP)  ||
                channel.info.srcProtocol.equals(ChannelInfo.Protocol.MMS)) {

                if (channel.info.contentType.equals(ChannelInfo.ContentType.WMA) ||
                    channel.info.contentType.equals(ChannelInfo.ContentType.WMV)) {
                    channel.info.srcProtocol = ChannelInfo.Protocol.MMS;
                }

log.debug("Channel source is HTTP");

                String dir = null;
                int p = fileName.indexOf("/");
                if (p > 0) {
                    dir = fileName.substring(0, p - 1);
                    fileName = fileName.substring(p, fileName.length());
                }

log.debug(String.format("Fetch Host=%s", fileName));
if (dir != null) {
 log.debug(String.format("Fetch Dir=%s", dir));
}

                HttpContext request = new HttpContext();

                request.setMethod("GET");
                request.setRemoteHost(fileName);
                request.setRemotePort(80);
                request.setRequestURI(dir != null ? String.valueOf(dir) : "");
                request.setProtocol(new HttpProtocol());
                request.setHeader(Peercast.HTTP_HS_HOST, fileName);
                request.setHeader(Peercast.HTTP_HS_CONNECTION, "close");
                request.setHeader(Peercast.HTTP_HS_ACCEPT, "*/*");

                if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.MMS)) {
                    request.setHeader(Peercast.HTTP_HS_AGENT, "NSPlayer/4.1.0.3856");
                    request.setHeader("Pragma", "no-cache,rate=1.000000,request-context=1");
//                  request.setHeader("Pragma", "no-cache,rate=1.000000,stream-time=0,stream-offset=4294967295:4294967295,request-context=22605256,max-duration=0");
                    request.setHeader("Pragma", "xPlayStrm=1");
                    request.setHeader("Pragma", "xClientGUID={c77e7400-738a-11d2-9add-0020af0a3278}");
                    request.setHeader("Pragma", "stream-switch-count=2");
                    request.setHeader("Pragma", "stream-switch-entry=ffff:1:0 ffff:2:0");
                } else {
                    request.setHeader(Peercast.HTTP_HS_AGENT, GnuPacket.PCX_AGENT);
                    request.setHeader(GnuPacket.PCX_HS_PCP, "1");
                    request.setHeader("Icy-MetaData", "1");        // fix by ravon
                }

                HttpContext response = HttpUtil.postRequest(request);
log.debug(String.format("Fetch HTTP: %d", response.getStatus()));

//                String name = channel.info.name;

                for (Map.Entry<String, String> header : response.getHeaders().entrySet()) {

                    ChannelInfo tmpInfo = channel.info;
                    Servent.readICYHeader(response, channel.info, null);

                    if (tmpInfo.name.length() != 0) {
                        channel.info.name = tmpInfo.name;
                    }
                    if (tmpInfo.genre.length() != 0) {
                        channel.info.genre = tmpInfo.genre;
                    }
                    if (tmpInfo.url.length() != 0) {
                        channel.info.url = tmpInfo.url;
                    }

                    if (header.getKey().equals("icy-metaint")) {
                        channel.icyMetaInterval = Integer.parseInt(header.getValue());
                    } else if (header.getKey().equals("location")) {
                        nextURL = header.getValue();
                    } else if (header.getKey().equals("content-type")) {
                        if (header.getValue().indexOf(Peercast.MIME_XSCPLS) > 0) {
                            playList = PlayList.SCPLS;
                        } else if (header.getValue().indexOf(Peercast.MIME_PLS) > 0) {
                            playList = PlayList.PLS;
                        } else if (header.getValue().indexOf(Peercast.MIME_XPLS) > 0) {
                            playList = PlayList.PLS;
                        } else if (header.getValue().indexOf(Peercast.MIME_M3U) > 0) {
                            playList = PlayList.PLS;
                        } else if (header.getValue().indexOf(Peercast.MIME_TEXT) > 0) {
                            playList = PlayList.PLS;
                        } else if (header.getValue().indexOf(Peercast.MIME_ASX) > 0) {
                            playList = PlayList.ASX;
                        } else if (header.getValue().indexOf(Peercast.MIME_MMS) > 0) {
                            channel.info.srcProtocol = ChannelInfo.Protocol.MMS;
                        }
                        playList.init(1000);
                    }

                }

                if (nextURL.length() != 0 && response.getStatus() == 302) {
                    log.debug(String.format("Ch.%d redirect: %s", channel.index, nextURL));
                    return nextURL;
                }

                if (response.getStatus() != 200) {
                    log.error("HTTP response: " + response.getStatus());
                    throw new IOException("Bad HTTP connect");
                }

                inputStream = response.getInputStream();

            } else if (channel.info.srcProtocol.equals(ChannelInfo.Protocol.FILE)) {

                log.debug("Channel source is FILE");

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

                log.debug(String.format("Ch.%d is Playlist", channel.index));

                playList.read(inputStream);

                inputStream.close();
                inputStream = null;

                int urlNum = 0;

                log.debug(String.format("Playlist: %d URLs", playList.numURLs));
                while (!channel.streaming.isCancelled() && playList.numURLs != 0 && !Peercast.getInstance().isQuitting) {
                    if (url.length() == 0) {
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

                channel.sock.setSoTimeout(60);    // use longer read timeout

                source = channel.createSource();

                channel.readStream(inputStream, source);

                inputStream.close();
            }

        } catch (IOException e) {
e.printStackTrace();
            channel.setStatus(Channel.Status.ERROR);
            log.error(String.format("Ch.%d error: %s", channel.index, e.getMessage()));
            try { Thread.sleep(1000); } catch (InterruptedException ie) {}
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

/* */
