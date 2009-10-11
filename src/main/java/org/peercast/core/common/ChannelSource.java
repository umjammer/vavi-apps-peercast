/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.IOException;


/**
 * ChannleSource. 
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
abstract class ChannelSource {

    int getSourceRate() {
        return 0;
    }

    /** */
    abstract void stream(Channel channel) throws IOException;
}

/* */
