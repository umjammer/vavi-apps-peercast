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
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * MMSStream.
 * 
 * @version 28-may-2003
 * @author giles
 */
class MMSStream extends ChannelStream {

    static final Log log = LogFactory.getLog(MMSStream.class);

    /** */
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readHeader(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    /** */
    int readPacket(InputStream is, Channel channel) throws IOException {
        ASFChunk chunk = new ASFChunk();

        chunk.read(is);

        switch (chunk.type) {
        case 0x4824: // asf header
        {
            ByteArrayOutputStream mem = new ByteArrayOutputStream();

            chunk.write(mem);

            ByteArrayInputStream asfm = new ByteArrayInputStream(chunk.data);
            ASFObject asfHead = new ASFObject();
            asfHead.readHead(asfm);

            ASFInfo asf = parseASFHeader(asfm);
            log.debug(String.format("ASF Info: pnum=%d, psize=%d, br=%d", asf.numPackets, asf.packetSize, asf.bitrate));
            for (int i = 0; i < ASFInfo.MAX_STREAMS; i++) {
                ASFStream s = asf.streams[i];
                if (s.id != 0) {
                    log.debug(String.format("ASF Stream %d : %s, br=%d", s.id, s.getTypeName(), s.bitrate));
                }
            }

            channel.info.bitrate = asf.bitrate / 1000;

            channel.headPack.data = mem.toByteArray();
            channel.headPack.type = ChannelPacket.Type.HEAD;
            channel.headPack.pos = channel.streamPos;
            channel.newPacket(channel.headPack);

            channel.streamPos += channel.headPack.data.length;

            break;
        }
        case 0x4424: // asf data
        {
            ChannelPacket pack = new ChannelPacket();

            ByteArrayOutputStream mem = new ByteArrayOutputStream();

            chunk.write(mem);

            pack.data = mem.toByteArray();
            pack.type = ChannelPacket.Type.DATA;
            pack.pos = channel.streamPos;

            channel.newPacket(pack);
            channel.streamPos += pack.data.length;

            break;
        }
        default:
            throw new IOException("Unknown ASF chunk");
        }

        return 0;
    }

    /** */
    ASFInfo parseASFHeader(InputStream in) {
        ASFInfo asf = new ASFInfo();

        try {
            DataInputStream dis = new DataInputStream(in);
            int numHeaders = dis.readInt();

            dis.readByte();
            dis.readByte();

            log.debug(String.format("ASF Headers: %d", numHeaders));
            for (int i = 0; i < numHeaders; i++) {

                ASFObject obj = new ASFObject();

                int l = obj.readHead(in);
                obj.readData(in, l);

                ByteArrayInputStream data = new ByteArrayInputStream(obj.data);
                DataInputStream dataIn = new DataInputStream(data);

                switch (obj.type) {
                case T_FILE_PROP: {
                    dataIn.skip(32);

                    int dpLo = dataIn.readInt();
                    int dpHi = dataIn.readInt();
                    log.debug("lo: " + dpLo + ", hi: " + dpHi);
                    data.skip(24);

                    dataIn.readLong();
                    // data.writeLong(1); // flags = broadcast, not seekable

                    int min = dataIn.readInt();
                    int max = dataIn.readInt();
                    int br = dataIn.readInt();

                    if (min != max) {
                        throw new IOException("ASF packetsizes (min/max) must match");
                    }

                    asf.packetSize = max;
                    asf.bitrate = br;
                    asf.numPackets = dpLo;
                    break;
                }
                case T_STREAM_BITRATE: {
                    int cnt = dataIn.readShort();
                    for (int j = 0; j < cnt; j++) {
                        int id = dataIn.readShort();
                        int bitrate = dataIn.readInt();
                        if (id < ASFInfo.MAX_STREAMS) {
                            asf.streams[id].bitrate = bitrate;
                        }
                    }
                    break;
                }
                case T_STREAM_PROP: {
                    ASFStream s = new ASFStream();
                    s.read(data);
                    asf.streams[s.id].id = s.id;
                    asf.streams[s.id].type = s.type;
                    break;
                }
                }

            }
        } catch (IOException e) {
            log.error(String.format("ASF: %s", e.getMessage()));
        }

        return asf;
    }
}

/* */
