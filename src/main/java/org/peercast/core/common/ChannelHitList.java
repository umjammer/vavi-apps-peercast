/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Element;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.util.Singleton;


/**
 * ChanHitList.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class ChannelHitList {
    /** */
    private static Log log = LogFactory.getLog(ChannelHitList.class);

    /** */
    Element createHitsXML() {
        Element hn = Peercast.newElement("hits");
        hn.setAttribute("listeners", String.valueOf(numListeners()));
        hn.setAttribute("hosts", String.valueOf(numHits()));
        hn.setAttribute("firewalled", String.valueOf(numFirewalled()));
        hn.setAttribute("closest", String.valueOf(closestHit()));
        hn.setAttribute("furthest", String.valueOf(furthestHit()));
        hn.setAttribute("newest", String.valueOf(System.currentTimeMillis() - newestHit()));

        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                hn.appendChild(hit.createXML());
            }
        }

        return hn;
    }

    boolean isUsed() {
        return used;
    }

    /** */
    void init() {
        info.init();
        lastHitTime = 0;
        used = false;
    }

    /** */
    int getTotalListeners() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                count += hit.numListeners;
            }
        }
        return count;
    }

    /** */
    int getTotalRelays() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                count += hit.numRelays;
            }
        }
        return count;
    }

    /** */
    int getTotalFirewalled() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                if (hit.firewalled) {
                    count++;
                }
            }
        }
        return count;
    }

    /** */
    int contactTrackers(boolean connected, int numl, int nums, int uptm) {
        return 0;
    }

    /** */
    ChannelHit addHit(ChannelHit newHit) {
//new Exception().printStackTrace(System.err);
log.debug(String.format("Add hit: %s , %s : %s", newHit.remoteAddresses[0], newHit.remoteAddresses[1], newHit.sessionID));

        // dont add our own hits
        final ServentManager serventManager = Singleton.getInstance(ServentManager.class);
        if (serventManager.sessionID.equals(newHit.sessionID)) {
            return null;
        }

        lastHitTime = System.currentTimeMillis();
        newHit.time = lastHitTime;

        for (ChannelHit hit : hits) {
//Debug.println("hit: " + hit.getAddress() + ", " + hit.remoteAddresses[0] + ", " + hit.sessionID);
            if (hit.remoteAddresses[0] != null && hit.remoteAddresses[0].equals(newHit.remoteAddresses[0])) {
                if (hit.remoteAddresses[1] == null || hit.remoteAddresses[1].equals(newHit.remoteAddresses[1])) {
                    if (!hit.dead) {
                        hits.set(hits.indexOf(hit), newHit);
                    }
                    return newHit;
                }
            }
        }

        // clear hits with same session ID (IP may have changed)
        if (newHit.sessionID.isSet()) {
            for (ChannelHit hit : hits) {
                if (hit.getAddress() != null) {
                    if (hit.sessionID.equals(newHit.sessionID)) {
                        hit.init();
                    }
                }
            }
        }

        for (ChannelHit hit : hits) {
            if (hit.getAddress() == null) {
                hits.set(hits.indexOf(hit), newHit);
                newHit.channelID = info.id;
                return newHit;
            }
        }

        hits.add(newHit);

        return newHit;
    }

    /**
     * @param timeout [nsec]
     */
    int clearDeadHits(long timeout, boolean clearTrackers) {
        int count = 0;
        long currentTime = System.currentTimeMillis();
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                if (hit.dead || ((currentTime - hit.time) > timeout) && (clearTrackers || (!clearTrackers & !hit.tracker))) {
                    hit.init();
                } else {
                    count++;
                }
            }
        }
        return count;
    }

    /** */
    void deadHit(ChannelHit targetHit) {
        log.debug(String.format("Dead hit: %s , %s", targetHit.remoteAddresses[0], targetHit.remoteAddresses[1]));

        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                if (hit.remoteAddresses[0].equals(targetHit.remoteAddresses[0]) && ((hit.remoteAddresses[1] == null && targetHit.remoteAddresses[1] == null) || hit.remoteAddresses[1].equals(targetHit.remoteAddresses[1]))) {
                    hit.dead = true;
log.debug(String.format("*** Dead hit: %s , %s", hit.remoteAddresses[0], hit.remoteAddresses[1]));
                }
            }
        }
    }

    /** */
    void deleteHit(ChannelHit targetHit) {
        log.debug(String.format("Del hit: %s , %s", targetHit.remoteAddresses[0], targetHit.remoteAddresses[1]));

        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null) {
                if (hit.remoteAddresses[0].equals(targetHit.remoteAddresses[0]) && ((hit.remoteAddresses[1] == null && targetHit.remoteAddresses[1] == null) || hit.remoteAddresses[1].equals(targetHit.remoteAddresses[1]))) {
                    hit.init();
log.debug(String.format("*** Del hit: %s , %s", hit.remoteAddresses[0], hit.remoteAddresses[1]));
                }
            }
        }
    }

    /** */
    int numHits() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                count++;
            }
        }

        return count;
    }

    /** */
    int numListeners() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                count += hit.numListeners;
            }
        }

        return count;
    }

    /** */
    int numTrackers() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if ((hit.getAddress() != null && !hit.dead) && hit.tracker) {
                count++;
            }
        }

        return count;
    }

    /** */
    int numFirewalled() {
        int count = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                count += hit.firewalled ? 1 : 0;
            }
        }

        return count;
    }

    /** */
    int closestHit() {
        int hops = 10000;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                if (hit.numHops < hops) {
                    hops = hit.numHops;
                }
            }
        }

        return hops;
    }

    /** */
    int furthestHit() {
        int hops = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                if (hit.numHops > hops) {
                    hops = hit.numHops;
                }
            }
        }

        return hops;
    }

    /** */
    long newestHit() {
        long time = 0;
        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                if (hit.time > time) {
                    time = hit.time;
                }
            }
        }

        return time;
    }

    /** */
    int pickHits(ChannelHitSearch chs) {
        ChannelHit best = new ChannelHit(), bestP = null;
        best.numHops = 255;
        best.time = 0;

        long currentTime = System.currentTimeMillis();

        for (ChannelHit hit : hits) {
            if (hit.getAddress() != null && !hit.dead) {
                if (!chs.excludeID.equals(hit.sessionID)) {
                    if (chs.waitDelay == 0 || (currentTime - hit.lastContact) >= chs.waitDelay) {
                        if ((hit.numHops < best.numHops)) { // (c.time>=best.time))
                            if (hit.relay || (!hit.relay && chs.useBusyRelays)) {
                                if (hit.cin || (!hit.cin && chs.useBusyControls)) {

                                    if (chs.trackersOnly && hit.tracker) {
                                        if (chs.matchHost != null) {
                                            if (hit.remoteAddresses[0].getAddress().equals(chs.matchHost.getAddress()) && hit.remoteAddresses[1] != null) {
                                                bestP = hit;
                                                best = hit;
                                                best.setAddress(best.remoteAddresses[1]); // use lan ip
                                            }
                                        } else if (hit.firewalled == chs.useFirewalled) {
                                            bestP = hit;
                                            best = hit;
                                            best.setAddress(best.remoteAddresses[0]); // use wan ip
                                        }
                                    } else if (!chs.trackersOnly && !hit.tracker) {
                                        if (chs.matchHost != null) {
                                            if (hit.remoteAddresses[0].getAddress().equals(chs.matchHost.getAddress()) && hit.remoteAddresses[1] != null) {
                                                bestP = hit;
                                                best = hit;
                                                best.setAddress(best.remoteAddresses[1]); // use lan ip
                                            }
                                        } else if (hit.firewalled == chs.useFirewalled) {
                                            bestP = hit;
                                            best = hit;
                                            best.setAddress(best.remoteAddresses[0]); // use wan ip
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (bestP != null) {
            if (chs.bestHits.size() < ChannelHitSearch.MAX_RESULTS) {
                if (chs.waitDelay != 0) {
                    bestP.lastContact = currentTime;
                }
                chs.bestHits.add(best);
                return 1;
            }

        }

        return 0;
    }

    boolean used;

    ChannelInfo info;

    List<ChannelHit> hits = new ArrayList<ChannelHit>() /* {
        public boolean add(ChanHit o) {
            if (o.remoteAddresses[0] == null) {
new Exception("*** DUMMY *** : " + o.getAddress()).printStackTrace();
            }
log.debug("add: " + o.getAddress() + ", " + o.remoteAddresses[0] + ": " + o.sessionID);
            return super.add(o);
        }
        public ChanHit set(int i, ChanHit o) {
            if (o.remoteAddresses[0] == null) {
new Exception("*** DUMMY *** : " + o.getAddress()).printStackTrace();
            }
log.debug("set: " + o.getAddress() + ", " + o.remoteAddresses[0] + ": " + o.sessionID);
            return super.set(i, o);
        }
    } */;

    long lastHitTime;

    int index;
}

/* */
