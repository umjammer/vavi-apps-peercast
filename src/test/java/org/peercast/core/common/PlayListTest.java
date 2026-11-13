/*
 * Copyright (c) 2026 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * PlayListTest.
 *
 * @author <a href="mailto:umjammer@gmail.com">Naohide Sano</a> (nsano)
 * @version 0.00 2026-11-12 nsano initial version <br>
 */
class PlayListTest {

    static final String EVIL = "<script>alert(1)</script>\"\r\nX-Injected: 1";

    static String write(PlayList type, ChannelInfo info) {
        type.init(1);
        type.addChannel("http://localhost:7144", info);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        type.write(out);
        return out.toString(StandardCharsets.UTF_8);
    }

    @Test
    void testUnsafeNameIsRejected() {
        ChannelInfo info = new ChannelInfo();
        info.name = EVIL;
        for (PlayList type : new PlayList[] {PlayList.PLS, PlayList.SCPLS, PlayList.ASX, PlayList.RAM}) {
            type.init(1);
            assertFalse(type.addChannel("http://localhost:7144", info), type.toString());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            type.write(out);
            String s = out.toString(StandardCharsets.UTF_8);
            assertFalse(s.contains("<script>"), type + ": " + s);
            assertFalse(s.contains("X-Injected"), type + ": " + s);
        }
    }

    @Test
    void testSafeNameIsKept() {
        ChannelInfo info = new ChannelInfo();
        info.name = "%E3%81%82-ch_1.x~";
        String s = write(PlayList.PLS, info);
        assertTrue(s.contains("/stream/%E3%81%82-ch_1.x~"), s);
    }

    @Test
    void testIdIsUsedWhenSet() {
        ChannelInfo info = new ChannelInfo();
        info.name = EVIL;
        info.id = new GnuID("F5D7BABEBC6B4E10254BE4AACCAF7846");
        String s = write(PlayList.PLS, info);
        assertTrue(s.contains("/stream/F5D7BABEBC6B4E10254BE4AACCAF7846"), s);
    }

    @Test
    void testXxeIsRejected() {
        String xml = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>";
        assertThrows(SAXException.class, () -> Peercast.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8))));
    }
}
