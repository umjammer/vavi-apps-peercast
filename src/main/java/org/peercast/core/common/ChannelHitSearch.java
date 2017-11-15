/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;


/**
 * ChanHitSearch.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelHitSearch {

    /** */
    static final int MAX_RESULTS = 8;

    /** */
    ChannelHitSearch() {
        init();
    }

    /** */
    void init() {
        matchHost = null;
        waitDelay = 0;
        useFirewalled = false;
        trackersOnly = false;
        useBusyRelays = true;
        useBusyControls = true;
        excludeID = new GnuID();
    }

    /** */
    List<ChannelHit> bestHits = new ArrayList<>();

    /** */
    InetSocketAddress matchHost;

    /** */
    int waitDelay;

    /** */
    boolean useFirewalled;

    /** */
    boolean trackersOnly;

    /** */
    boolean useBusyRelays, useBusyControls;

    /** */
    GnuID excludeID;
}

/* */
