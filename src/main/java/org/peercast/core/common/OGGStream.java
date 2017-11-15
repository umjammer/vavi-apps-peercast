//
// (c) 2002-3 peercast.org
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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * OggSubStream.
 *
 * @version 28-may-2003
 * @author giles
 */
abstract class OggSubStream {
    OggSubStream() {
        maxHeaders = 0;
        serialNo = 0;
        bitrate = 0;
    }

    boolean needHeader() {
        return maxHeaders != 0 && (pack.numPackets < maxHeaders);
    }

    void eos() {
        maxHeaders = 0;
        serialNo = 0;
    }

    void bos(int ser) {
        maxHeaders = 3;
        pack.numPackets = 0;
        pack.packetSizes[0] = 0;
        pack.bodyLen = 0;
        serialNo = ser;
        bitrate = 0;
    }

    boolean isActive() {
        return serialNo != 0;
    }

    /** */
    void readHeader(Channel ch, OGGPage ogg) throws IOException {
        if ((pack.bodyLen + ogg.bodyLen) >= OGGPacket.MAX_BODYLEN) {
            throw new IOException("OGG packet too big");
        }

        if (ch.headPack.data.length + (ogg.bodyLen + ogg.headLen) >= ChannelMeta.MAX_DATALEN) {
            throw new IOException("OGG packet too big for headMeta");
        }

        // copy complete packet into head packet
        System.arraycopy(ogg.data, 0, ch.headPack.data, ch.headPack.data.length, ogg.headLen + ogg.bodyLen);

        // add body to packet
        System.arraycopy(ogg.data, ogg.headLen, pack.body, pack.bodyLen, ogg.bodyLen);
        pack.bodyLen += ogg.bodyLen;

        pack.addLacing(ogg);

        if (pack.numPackets >= maxHeaders) {
            procHeaders(ch);
        }
    }

    /** */
    abstract void procHeaders(Channel ch) throws IOException;

    int bitrate;

    OGGPacket pack;

    int maxHeaders;

    int serialNo;
}


/**
 * OggVorbisSubStream.
 */
class OggVorbisSubStream extends OggSubStream {

    private Log log = LogFactory.getLog(OggVorbisSubStream.class);

    OggVorbisSubStream() {
        samplerate = 0;
    }

    /** */
    void procHeaders(Channel ch) throws IOException {
        int packPtr = 0;

        for (int i = 0; i < pack.numPackets; i++) {
            ByteArrayInputStream vin = new ByteArrayInputStream(pack.body); // pack.packetSizes[i]
            vin.skip(packPtr);

            packPtr += pack.packetSizes[i];

            byte[] id = new byte[8];

            vin.read(id, 0, 7);
            id[7] = 0;

            switch (id[0]) {
            case 1: // ident
                log.debug(String.format("OGG Vorbis Header: Ident (%d bytes)", vin.available()));
                readIdent(vin, ch.info);
                break;
            case 3: // comment
            {
                log.debug(String.format("OGG Vorbis Header: Comment (%d bytes)", vin.available()));
                ChannelInfo newInfo = ch.info;
                readComment(vin, newInfo);
                ch.updateInfo(newInfo);
            }
                break;
            case 5: // setup
                log.debug(String.format("OGG Vorbis Header: Setup (%d bytes)", vin.available()));
                // readSetup(vin);
                break;
            default:
                throw new IOException("Unknown Vorbis packet header type");
            }
        }

    }

    /** */
    double getTime(OGGPage ogg) {
        return (double) ogg.granPos / (double) samplerate;
    }

    /** */
    void readIdent(InputStream in, ChannelInfo info) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        int ver = dis.readInt();
        int chans = dis.readByte();
        samplerate = dis.readInt();
        int brMax = dis.readInt();
        int brNom = dis.readInt();
        int brLow = dis.readInt();

        dis.readByte(); // skip blocksize 0+1

        log.debug(String.format("OGG Vorbis Ident: ver=%d, chans=%d, rate=%d, brMax=%d, brNom=%d, brLow=%d", ver, chans, samplerate, brMax, brNom, brLow));

        bitrate = brNom / 1000;

        byte frame = dis.readByte(); // framing bit
        if (frame == 0) {
            throw new IOException("Bad Indent frame");
        }
    }

    /** */
    void readSetup(InputStream in) throws IOException {
        // skip everything in packet
        int cnt = 0;
        while (in.available() > 0) {
            cnt++;
            in.read();
        }

        log.debug(String.format("Read %d bytes of Vorbis Setup", cnt));
    }

    /** */
    void readComment(InputStream in, ChannelInfo info) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        int vLen = dis.readInt(); // vendor len

        in.skip(vLen);

        byte[] argBuf = new byte[8192];

        info.track.clear();

        int cLen = dis.readInt(); // comment len
        for (int i = 0; i < cLen; i++) {
            int l = dis.readInt();
            if (l > argBuf.length) {
                throw new IOException("Comment string too long");
            }
            in.read(argBuf, 0, l);
            String arg = new String(argBuf, 0, l);
            log.debug(String.format("OGG Comment: %s", argBuf));

            int p;
            if ((p = arg.indexOf("ARTIST=")) > 0) {
                info.track.artist = new String(argBuf, p, p + 7);

            } else if ((p = arg.indexOf("TITLE=")) > 0) {
                info.track.title = new String(argBuf, p, p + 6);

            } else if ((p = arg.indexOf("GENRE=")) > 0) {
                info.track.genre = new String(argBuf, p, p + 6);

            } else if ((p = arg.indexOf("CONTACT=")) > 0) {
                info.track.contact = new String(argBuf, p, p + 8);

            } else if ((p = arg.indexOf("ALBUM=")) > 0) {
                info.track.album = new String(argBuf, p, p + 6);
            }
        }

        byte frame = dis.readByte(); // framing bit
        if (frame == 0) {
            throw new IOException("Bad Comment frame");
        }
    }

    int samplerate;
}


/**
 * OggTheoraSubStream.
 */
class OggTheoraSubStream extends OggSubStream {
    private Log log = LogFactory.getLog(OggTheoraSubStream.class);

    OggTheoraSubStream() {
        granposShift = 0;
        frameTime = 0;
    }

    /** */
    double getTime(OGGPage ogg) {
        long iframe = ogg.granPos >> granposShift;
        long pframe = ogg.granPos - (iframe << granposShift);

        return (iframe + pframe) * frameTime;
    }

    /** */
    void readInfo(InputStream in, ChannelInfo info) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        int verMaj = dis.read();
        int verMin = dis.read();
        int verSub = dis.read();
log.debug(verMaj + ", " + verMin + ", " + verSub);
        int encWidth = dis.readShort() << 4;
        int encHeight = dis.readShort() << 4;

        // 24 + 24 + 8 + 8;
        dis.readByte();
        dis.readByte();
        dis.readByte();

        dis.readByte();
        dis.readByte();
        dis.readByte();

        dis.readByte();

        dis.readByte();

        int fpsNum = dis.readInt();
        int fpsDen = dis.readInt();

        float fps = (float) fpsNum / (float) fpsDen;
        frameTime = (double) fpsDen / (double) fpsNum;

        // 24 + 24 + 8
        dis.readByte();
        dis.readByte();
        dis.readByte();

        dis.readByte();
        dis.readByte();
        dis.readByte();

        dis.readByte();

        int l = dis.readByte();
        int m = dis.readByte();
        int h = dis.readByte();
        bitrate = ((l << 16) | (m << 8) | h) / 1000;
        int quality = dis.readByte() & 0x3f; // 6bits

        granposShift = dis.readByte() & 0x1f; // 5bits

        log.debug(String.format("OGG Theora Info: %dx%dx%.1ffps %dkbps %dQ %dG", encWidth, encHeight, fps, bitrate, quality, granposShift));
    }

    /** */
    void procHeaders(Channel ch) throws IOException {
        int packPtr = 0;

        for (int i = 0; i < pack.numPackets; i++) {
            ByteArrayInputStream vin = new ByteArrayInputStream(pack.body); // [packPtr], pack.packetSizes[i]
            vin.skip(packPtr);

            packPtr += pack.packetSizes[i];

            byte[] id = new byte[8];

            vin.read(id, 0, 7);
            id[7] = 0;

            switch (id[0] & 0xff) {
            case 128: // info
                log.debug(String.format("OGG Theora Header: Info (%d bytes)", vin.available()));
                readInfo(vin, ch.info);
                break;
            default:
                log.debug(String.format("OGG Theora Header: Unknown %d (%d bytes)", id[0] & 0xff, vin.available()));
                break;
            }

        }

    }

    int granposShift;

    double frameTime;
}


/** */
class OGGStream extends ChannelStream {

    private Log log = LogFactory.getLog(OGGStream.class);

    OGGStream() {
    }

    static int test = 0;

    /** */
    int readHeader(InputStream is, Channel channel) throws IOException {
        test = 0;
        return 0;
    }

    /** */
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readPacket(InputStream is, Channel channel) throws IOException {
        OGGPage ogg = new OGGPage();
        ChannelPacket pack = null;

        ogg.read(is);

        if (ogg.isBOS()) {

            if (ogg.detectVorbis()) {
                vorbis.bos(ogg.getSerialNo());
            }
            if (ogg.detectTheora()) {
                theora.bos(ogg.getSerialNo());
            }
        }

        if (ogg.isEOS()) {

            if (ogg.getSerialNo() == vorbis.serialNo) {
                log.debug("Vorbis stream: EOS");
                vorbis.eos();
            }
            if (ogg.getSerialNo() == theora.serialNo) {
                log.debug("Theora stream: EOS");
                theora.eos();
            }
        }

        if (vorbis.needHeader() || theora.needHeader()) {

            if (ogg.getSerialNo() == vorbis.serialNo) {
                vorbis.readHeader(channel, ogg);
            } else if (ogg.getSerialNo() == theora.serialNo) {
                theora.readHeader(channel, ogg);
            } else {
                throw new IOException("Bad OGG serial no.");
            }

            if (!vorbis.needHeader() && !theora.needHeader()) {

                channel.info.bitrate = 0;

                if (vorbis.isActive()) {
                    channel.info.bitrate += vorbis.bitrate;
                }

                if (theora.isActive()) {
                    channel.info.bitrate += theora.bitrate;
                    channel.info.contentType = ChannelInfo.ContentType.OGM;
                }

                channel.headPack.type = ChannelPacket.Type.HEAD;
                channel.headPack.pos = channel.streamPos;

                channel.startTime = System.currentTimeMillis(); // TODO DTime?

                channel.streamPos += channel.headPack.data.length;

                channel.newPacket(channel.headPack);
                log.debug(String.format("Got %d bytes of headers", channel.headPack.data.length));
            }

        } else {

            pack = new ChannelPacket(ChannelPacket.Type.DATA, ogg.data, ogg.headLen + ogg.bodyLen, channel.streamPos);
            channel.newPacket(pack);

            channel.streamPos += pack.data.length;

            if (theora.isActive()) {
                if (ogg.getSerialNo() == theora.serialNo) {
                    channel.sleepUntil(theora.getTime(ogg));
                }
            } else if (vorbis.isActive()) {
                if (ogg.getSerialNo() == vorbis.serialNo) {
                    channel.sleepUntil(vorbis.getTime(ogg));
                }
            }

        }
        return 0;
    }

    OggVorbisSubStream vorbis;

    OggTheoraSubStream theora;
}
