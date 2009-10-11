/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

/**
 * TrackInfo.
 * 
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class TrackInfo {
    void clear() {
        contact = "";
        title = "";
        artist = "";
        album = "";
        genre = "";
    }

    /** */
    boolean update(TrackInfo inf) {
        boolean changed = false;

        if (contact == null || !contact.equals(inf.contact)) {
            contact = inf.contact;
            changed = true;
        }

        if (title == null || !title.equals(inf.title)) {
            title = inf.title;
            changed = true;
        }

        if (artist == null || !artist.equals(inf.artist)) {
            artist = inf.artist;
            changed = true;
        }

        if (album == null || !album.equals(inf.album)) {
            album = inf.album;
            changed = true;
        }

        if (genre == null || !genre.equals(inf.genre)) {
            genre = inf.genre;
            changed = true;
        }

        return changed;
    }

    String contact, title, artist, album, genre;
}

/* */
