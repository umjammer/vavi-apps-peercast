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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;


/**
 * ID4. 
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050814 nsano initial version <br>
 */
class ID4 {

    private byte[] cv = new byte[4];

    ID4() {
    }

    ID4(int i) {
        ByteBuffer.wrap(cv).asIntBuffer().put(i);
    }

    ID4(final String id) {
        for (int i = 0; i < id.length(); i++) {
            cv[i] = (byte) id.charAt(i);
        }
    }

    void clear() {
        Arrays.fill(cv, (byte) 0);
    }

    /** Compares as integer value. */
    boolean equals(ID4 id) {
        return ByteBuffer.wrap(cv).asIntBuffer().get() == ByteBuffer.wrap(id.cv).asIntBuffer().get();
    }

    /** not 0 as integer value */
    final boolean isSet() {
        return ByteBuffer.wrap(cv).asIntBuffer().get() != 0;
    }

    /** as integer value */
    final int getValue() {
        return ByteBuffer.wrap(cv).asIntBuffer().get();
    }

    public String toString() {
        return new String(cv, 0, 4);
    }

    byte[] getData() {
        return cv;
    }

    /** */
    public static ID4 read(InputStream in) throws IOException {
        ID4 id = new ID4();
        int r = in.read(id.cv, 0, 4);
        if (r != 4) {
            throw new EOFException();
        }
        return id;
    }
}

/* */
