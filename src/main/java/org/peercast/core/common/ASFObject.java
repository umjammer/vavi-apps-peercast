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

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * ASFObject.
 * 
 * @version 10-apr-2003
 * @author giles
 */
class ASFObject {

    Log log = LogFactory.getLog(ASFObject.class);

    enum TYPE {
        T_UNKNOWN,
        T_HEAD_OBJECT,
        T_DATA_OBJECT,
        T_FILE_PROP,
        T_STREAM_PROP,
        T_STREAM_BITRATE
    }

    int getTotalLen() {
        return 24 + dataLen;
    }

    int readHead(InputStream in) throws IOException {
        DataInputStream dis = new DataInputStream(in);
        id.read(dis);

        lenLo = dis.readInt();
        lenHi = dis.readInt();

        type = TYPE.T_UNKNOWN;
        if (id == MSID.headObjID) {
            type = TYPE.T_HEAD_OBJECT;
        } else if (id == MSID.dataObjID) {
            type = TYPE.T_DATA_OBJECT;
        } else if (id == MSID.filePropObjID) {
            type = TYPE.T_FILE_PROP;
        } else if (id == MSID.streamPropObjID) {
            type = TYPE.T_STREAM_PROP;
        } else if (id == MSID.streamBitrateObjID) {
            type = TYPE.T_STREAM_BITRATE;
        }
        String str = id.toString();
        log.debug(String.format("ASF: %s (%s)= %d : %d\n", str, getTypeName(), lenLo, lenHi));

        dataLen = 0;

        return lenLo - 24;
    }

    void readData(InputStream in, int len) throws IOException {
        dataLen = len;

        if (dataLen > data.length || lenHi > 0) {
            throw new IOException("ASF object too big");
        }

        in.read(data, 0, dataLen);
    }

    void write(DataOutputStream out) throws IOException {
        id.write(out);
        out.writeLong(lenLo);
        out.writeLong(lenHi);
        if (dataLen > 0) {
            out.write(data, 0, dataLen);
        }
    }

    final String getTypeName() {
        switch (type) {
        case T_HEAD_OBJECT:
            return "ASF_Header_Object";
        case T_DATA_OBJECT:
            return "ASF_Data_Object";
        case T_FILE_PROP:
            return "ASF_File_Properties_Object";
        case T_STREAM_PROP:
            return "ASF_Stream_Properties_Object";
        case T_STREAM_BITRATE:
            return "ASF_Stream_Bitrate_Properties_Object";
        default:
            return "Unknown_Object";
        }
    }

    byte[] data = new byte[8192];

    MSID id;

    int lenLo, lenHi, dataLen;

    TYPE type;
}

/* */
