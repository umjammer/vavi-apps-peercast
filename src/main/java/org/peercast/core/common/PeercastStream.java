/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


/**
 * PeercastStream.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
class PeercastStream extends ChannelStream {

    private final ChannelManager chanMgr = Peercast.channelManager;

    private Document parseMetaXmlSecurely(ByteArrayInputStream mem) throws IOException, SAXException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(mem);
    }

    @Override
    int readHeader(InputStream is, Channel channel) throws IOException {
        byte[] tp = new byte[4];
        int l = is.read(tp, 0, 4);
        if (!Arrays.equals(tp, "PCST".getBytes())) {
            throw new IOException("Not PeerCast stream");
        }
        return l;
    }

    @Override
    int readEnd(InputStream is, Channel channel) throws IOException {
        return 0;
    }

    @Override
    int readPacket(InputStream is, Channel channel) throws IOException {
        ChannelPacket pack = new ChannelPacket();

        pack.readPeercast(is);

        ByteArrayInputStream mem = new ByteArrayInputStream(pack.data);

        switch (pack.type) {
            case HEAD:
                // update sync pos
                channel.headPack = pack;
                pack.pos = channel.streamPos;
                channel.newPacket(pack);
                channel.streamPos += pack.data.length;
                break;
            case DATA:
                pack.pos = channel.streamPos;
                channel.newPacket(pack);
                channel.streamPos += pack.data.length;
                break;
            case META:
                channel.insertMeta.fromMem(pack.data, pack.data.length);
                if (pack.data.length != 0) {
                    Document xml;
                    try {
                        xml = parseMetaXmlSecurely(mem);
                    } catch (SAXException | ParserConfigurationException e) {
                        throw new IOException(e);
                    }
                    Element n = (Element) xml.getElementsByTagName("channel").item(0);
                    if (n != null) {
                        ChannelInfo newInfo = channel.info;
                        newInfo.updateFromXML(n);
                        ChannelHitList chl = chanMgr.findHitList(channel.info);
                        if (chl != null) {
                            newInfo.updateFromXML(n);
                        }
                        channel.updateInfo(newInfo);
                    }
                }
                break;
        }
        return 0;
    }
}
