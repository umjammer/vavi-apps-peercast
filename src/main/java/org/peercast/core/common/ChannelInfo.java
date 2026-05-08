/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import org.w3c.dom.Element;

import static java.lang.System.getLogger;


/**
 * ChanInfo.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelInfo {

    private static final Logger logger = getLogger(ChannelInfo.class.getName());

    /** */
    private final ChannelManager channelManager = Peercast.channelManager;

    /** */
    enum ContentType {
        /** */
        UNKNOWN("") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },

        /** */
        RAW("") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },
        /** */
        MP3(".mp3") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is MP3 - meta: %d", channel.index, channel.icyMetaInterval));
                return new MP3Stream();
            }
        },
        /** */
        OGG(".ogg") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is OGG", channel.index));
                return new OGGStream();
            }
        },
        /** */
        OGM(".ogg") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is OGG", channel.index));
                return new OGGStream();
            }
        },
        /** */
        MOV(".mov") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },
        /** */
        MPG("") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },
        /** */
        NSV(".nsv") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is NSV", channel.index));
                return new NSVStream();
            }
        },

        /** */
        WMA(".wma") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                throw new IllegalArgumentException(String.format("Ch.%d is WMA/WMV - but not MMS", channel.index));
            }
        },
        /** */
        WMV(".wmv") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                throw new IllegalArgumentException(String.format("Ch.%d is WMA/WMV - but not MMS", channel.index));
            }
        },

        /** */
        PLS("") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },
        /** */
        ASX("") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        },
        /** */
        FLV(".flv") {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Raw", channel.index));
                return new RawStream();
            }
        };

        ContentType(String extention) {
            this.extention = extention;
        }

        final String extention;

        /** */
        String getExtention() {
            return extention;
        }

        /** @throws IllegalArgumentException  */
        abstract ChannelStream getChannelStream(Channel channel);
    }

    enum Protocol {
        /** */
        UNKNOWN {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                return channel.info.contentType.getChannelStream(channel);
            }
        },
        /** */
        PEERCAST {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is Peercast", channel.index));
                return new PeercastStream();
            }
        },
        /** */
        HTTP {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                return channel.info.contentType.getChannelStream(channel);
            }
        },
        /** */
        FILE {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                return channel.info.contentType.getChannelStream(channel);
            }
        },
        /** */
        MMS {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is MMS", channel.index));
                return new MMSStream();
            }
        },
        /** */
        PCP {
            @Override
            ChannelStream getChannelStream(Channel channel) {
                logger.log(Level.DEBUG, String.format("Ch.%d is PCP", channel.index));
                return new PCPStream(channel.remoteID);
            }
        };

        /** @throws IllegalArgumentException  */
        abstract ChannelStream getChannelStream(Channel channel);
    }

    /** */
    enum Status {
        /** */
        UNKNOWN,
        /** */
        PLAY
    }

    ChannelInfo() {
        init();
    }

    boolean isActive() {
        return id.isSet();
    }

    /** */
    boolean matchNameID(ChannelInfo info) {
        if (info.id.isSet()) {
            if (id.equals(info.id)) {
                return true;
            }
        }

        if (info.name != null && !info.name.isEmpty()) {
            if (name != null && name.contains(info.name)) {
                return true;
            }
        }

        return false;
    }

    /** */
    boolean match(ChannelInfo info) {
        boolean matchAny = true;

        if (!info.status.equals(ChannelInfo.Status.UNKNOWN)) {
            if (status != info.status) {
                return false;
            }
        }

        if (info.bitrate != 0) {
            if (bitrate == info.bitrate) {
                return true;
            }
            matchAny = false;
        }

        if (info.id.isSet()) {
            if (id.equals(info.id)) {
                return true;
            }
            matchAny = false;
        }

        if (!info.contentType.equals(ChannelInfo.ContentType.UNKNOWN)) {
            if (contentType == info.contentType) {
                return true;
            }
            matchAny = false;
        }

        if (!info.name.isEmpty()) {
            if (name.contains(info.name)) {
                return true;
            }
            matchAny = false;
        }

        if (!info.genre.isEmpty()) {
            if (genre.contains(info.genre)) {
                return true;
            }
            matchAny = false;
        }

        return matchAny;
    }

    /** */
    boolean update(ChannelInfo info) {
        boolean changed = false;

        // check valid id
        if (!info.id.isSet()) {
            return false;
        }

        // only update from chaninfo that has full name etc..
        if (info.name == null || info.name.isEmpty()) {
            return false;
        }

        // check valid broadcaster key
        if (bcID.isSet()) {
            if (!bcID.equals(info.bcID)) {
                logger.log(Level.ERROR, "ChanInfo BC key not valid");
                return false;
            }
        }

        bcID = info.bcID;

        if (bitrate != info.bitrate) {
            bitrate = info.bitrate;
            changed = true;
        }

        if (contentType != info.contentType) {
            contentType = info.contentType;
            changed = true;
        }

        if (name == null || !name.equals(info.name)) {
            name = info.name;
            changed = true;
        }

        if (comment == null || !comment.equals(info.comment)) {
            comment = info.comment;
            changed = true;
        }

        if (genre == null || !genre.equals(info.genre)) {
            genre = info.genre;
            changed = true;
        }

        if (url == null || !url.equals(info.url)) {
            url = info.url;
            changed = true;
        }

        if (track.update(info.track)) {
            changed = true;
        }

        return changed;
    }

    /**
     * @param idString "23450ABCDEF1..." 32 �����܂ł�����͂��Ȃ��A���̌�؂�̂�
     */
    void initNameID(String idString) {
        init();
        id = new GnuID(idString);
        if (!id.isSet()) {
            name = idString;
        }
        logger.log(Level.TRACE, "id: " + id + ", " + name);
    }

    /** */
    void init() {
        status = Status.UNKNOWN;
        name = null;
        bitrate = 0;
        contentType = ContentType.UNKNOWN;
        srcProtocol = Protocol.UNKNOWN;
        id = new GnuID(); // TODO ���ʂȋC��...
        id.clear();
        url = null;
        genre = null;
        comment = null;
        track = new TrackInfo(); // TODO ���ʂȋC��...
        lastPlayStart = 0;
        lastPlayEnd = 0;
        numSkips = 0;
        bcID = new GnuID(); // TODO ���ʂȋC��...
        bcID.clear();
        createdTime = 0;
    }

    /** */
    void readTrackXML(Element n) {
        track.clear();
        track.title = readXMLString(n, "title");
        track.contact = readXMLString(n, "contact");
        track.artist = readXMLString(n, "artist");
        track.album = readXMLString(n, "album");
        track.genre = readXMLString(n, "genre");
    }

    /** */
    long getUptime() {
        // calculate uptime and cap if requested by settings.
        long upt;
        upt = lastPlayStart != 0 ? (System.currentTimeMillis() - lastPlayStart) : 0;
        if (channelManager.maxUptime != 0) {
            if (upt > channelManager.maxUptime) {
                upt = channelManager.maxUptime;
            }
        }
        return upt;
    }

    /** */
    long getAge() {
        return System.currentTimeMillis() - createdTime;
    }

    /** */
    void readTrackAtoms(AtomInputStream atomIn, int childCount) throws IOException {
        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();
            if (id.equals(PCPStream.PCP_CHAN_TRACK_TITLE)) {
                track.title = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_TRACK_CREATOR)) {
                track.artist = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_TRACK_URL)) {
                track.contact = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_TRACK_ALBUM)) {
                track.album = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else {
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }
    }

    /** */
    void readInfoAtoms(AtomInputStream atomIn, int childCount) throws IOException {
        for (int i = 0; i < childCount; i++) {
            ID4 id = atomIn.read();
            if (id.equals(PCPStream.PCP_CHAN_INFO_NAME)) {
                name = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_BITRATE)) {
                bitrate = atomIn.readInt();
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_GENRE)) {
                genre = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_URL)) {
                url = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_DESC)) {
                desc = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_COMMENT)) {
                comment = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
            } else if (id.equals(PCPStream.PCP_CHAN_INFO_TYPE)) {
                String type = null;
                type = atomIn.readString(atomIn.dataLength, atomIn.dataLength);
                int p = type.indexOf((char) 0x00);
                if (p > 0) {
                    type = type.substring(0, p); // TODO readString need to deal asciiz?
                }
                contentType = ContentType.valueOf(type);
            } else {
                atomIn.skip(atomIn.childCount, atomIn.dataLength);
            }
        }
    }

    /** */
    void writeInfoAtoms(AtomOutputStream atomOut) throws IOException {
        atomOut.writeParent(PCPStream.PCP_CHAN_INFO, 7);
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_NAME, name != null ? name : "");
        atomOut.writeInt(PCPStream.PCP_CHAN_INFO_BITRATE, bitrate);
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_GENRE, genre != null ? genre : "");
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_URL, url != null ? url : "");
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_DESC, desc != null ? desc : "");
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_COMMENT, comment != null ? comment : "");
        atomOut.writeString(PCPStream.PCP_CHAN_INFO_TYPE, contentType.toString());
    }

    /** */
    void writeTrackAtoms(AtomOutputStream atomOut) throws IOException {
        atomOut.writeParent(PCPStream.PCP_CHAN_TRACK, 4);
        atomOut.writeString(PCPStream.PCP_CHAN_TRACK_TITLE, track.title != null ? track.title : "");
        atomOut.writeString(PCPStream.PCP_CHAN_TRACK_CREATOR, track.artist != null ? track.artist : "");
        atomOut.writeString(PCPStream.PCP_CHAN_TRACK_URL, track.contact != null ? track.contact : "");
        atomOut.writeString(PCPStream.PCP_CHAN_TRACK_ALBUM, track.album != null ? track.album : "");
    }

    /** */
    Element createChannelXML() {
        Element e = Peercast.newElement("channel");
        e.setAttribute("name", name);
        e.setAttribute("id", id.toString());
        e.setAttribute("bitrate", String.valueOf(bitrate));
        e.setAttribute("type", contentType.toString());
        e.setAttribute("genre", genre);
        e.setAttribute("desc", desc);
        e.setAttribute("url", url);
        e.setAttribute("uptime", String.valueOf(getUptime()));
        e.setAttribute("comment", comment);
        e.setAttribute("skips", String.valueOf(numSkips));
        e.setAttribute("age", String.valueOf(getAge()));
        return e;
    }

    /** */
    Element createQueryXML() {
        Element e = Peercast.newElement("channel");
        e.setAttribute("name", name);
        e.setAttribute("genre", genre);
        e.setAttribute("id", id.toString());
        return e;
    }

    /** */
    Element createRelayChannelXML() {
        String idStr = id.toString();
        Element e = Peercast.newElement("channel");
        e.setAttribute("id", idStr);
        e.setAttribute("uptime", String.valueOf(getUptime()));
        e.setAttribute("skips", String.valueOf(numSkips));
        e.setAttribute("age", String.valueOf(getAge()));
        return e;
    }

    /** */
    Element createTrackXML() {
        Element e = Peercast.newElement("track");
        e.setAttribute("title", track.title);
        e.setAttribute("artist", track.artist);
        e.setAttribute("album", track.album);
        e.setAttribute("genre", track.genre);
        e.setAttribute("contact", track.contact);
        return e;
    }

    /** */
    void init(Element n) {
        init();

        updateFromXML(n);
    }

    /** */
    void updateFromXML(Element n) {
        String typeStr = null, idStr = null;

        name = readXMLString(n, "name");
        genre = readXMLString(n, "genre");
        url = readXMLString(n, "url");
        desc = readXMLString(n, "desc");

        int br = Integer.parseInt(n.getAttribute("bitrate"));
        if (br > 0) {
            bitrate = br;
        }

        typeStr = readXMLString(n, "type");
        if (!typeStr.isEmpty()) {
            contentType = ContentType.valueOf(typeStr);
        }

        idStr = readXMLString(n, "id");
        if (!idStr.isEmpty()) {
            id = new GnuID(idStr);
        }

        comment = readXMLString(n, "comment");

        Element tn = (Element) n.getElementsByTagName("track").item(0);
        if (tn != null) {
            readTrackXML(tn);
        }
    }

    /** */
    void init(String n, GnuID cid, ContentType tp, int br) {
        init();

        name = n;
        bitrate = br;
        contentType = tp;
        id = cid;
    }

    /** */
    void init(String fn) {
        init();

        if (fn != null) {
            name = fn;
        }
    }

    /** */
    private static String readXMLString(Element n, String arg) {
        return n.getAttribute(arg);
    }

    String name;

    GnuID id, bcID;

    int bitrate;

    ContentType contentType;

    Protocol srcProtocol;

    /** [msec] */
    long lastPlayStart;

    /** [msec] */
    long lastPlayEnd;

    int numSkips;

    /** [msec] */
    long createdTime;

    Status status;

    TrackInfo track;

    String desc, genre, url, comment;
}
