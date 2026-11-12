/*
 * Copyright (c) 2005 by Naohide Sano, All rights reserved.
 *
 * Programmed by Naohide Sano
 */

package org.peercast.core.common;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import static java.lang.System.getLogger;


/**
 * PlayList.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
enum PlayList {

    /** */
    T_NONE {
        @Override
        void write(OutputStream out) {
            throw new UnsupportedOperationException();
        }

        @Override
        void read(InputStream in) throws IOException {
            throw new UnsupportedOperationException();
        }
    },
    /** */
    SCPLS {
        @Override
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            ps.println("[playlist]");
            ps.println();
            ps.printf("NumberOfEntries=%d\n", numURLs);

            for (int i = 0; i < numURLs; i++) {
                ps.printf("File%d=%s\n", i + 1, urls[i]);
                ps.printf("Title%d=%s\n", i + 1, titles[i]);
                ps.printf("Length%d=-1\n", i + 1);
            }
            ps.println("Version=2");
        }

        @Override
        void read(InputStream in) throws IOException {
            String tmp;
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            while ((tmp = reader.readLine()) != null) {
                if (tmp.toLowerCase().startsWith("file")) {
                    int p = tmp.indexOf('=');
                    if (p != 0) {
                        addURL(tmp.substring(p + 1), "");
                    }
                }
            }
        }
    },
    /** */
    PLS {
        @Override
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            for (int i = 0; i < numURLs; i++) {
                ps.printf("%s\n", urls[i]);
                logger.log(Level.TRACE, "player's url: " + urls[i]);
            }
        }

        @Override
        void read(InputStream in) throws IOException {
            String tmp;
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            while ((tmp = reader.readLine()) != null) {
                if (tmp.charAt(0) != '#') {
                    addURL(tmp, "");
                }
            }
        }
    },
    /** */
    ASX {
        @Override
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            ps.println("<ASX Version=\"3.0\">");
            for (int i = 0; i < numURLs; i++) {
                ps.println("<ENTRY>");
                ps.printf("<REF href = \"%s\" />\n", escapeXml(urls[i]));
                ps.println("</ENTRY>");
            }
            ps.println("</ASX>");
        }

        @Override
        void read(InputStream in) throws IOException {
            logger.log(Level.DEBUG, "Reading ASX");

            Document xml;
            try {
                xml = Peercast.newDocumentBuilder().parse(in);
            } catch (SAXException | ParserConfigurationException e) {
                throw new IllegalStateException(e);
            } // TODO: eof is NOT handled properly in sockets - always get error at end

            NodeList nodeList = xml.getChildNodes();
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if ("entry".equalsIgnoreCase(node.getNodeName())) {
                    NodeList nodeList2 = node.getChildNodes();
                    for (int j = 0; j < nodeList2.getLength(); j++) {
                        node = nodeList.item(j);
                        if ("ref".equalsIgnoreCase(node.getNodeName())) {
                            String hr = ((Element) node).getAttribute("href");
                            if (hr.isEmpty()) {
                                addURL(hr, "");
//logger.log(Level.DEBUG, "asx url %s".formatted(hr));
                            }
                        }
                    }
                }
            }
        }
    },
    RAM {
        @Override
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            for (int i = 0; i < numURLs; i++) {
                ps.printf("%s", urls[i]);
            }
        }

        @Override
        void read(InputStream in) throws IOException {
            throw new UnsupportedOperationException();
        }
    };

    private static final Logger logger = getLogger(PlayList.class.getName());

    /** */
    abstract void write(OutputStream out);

    /** keep pls regardless of errors (eof isn`t handled properly in sockets) */
    abstract void read(InputStream in) throws IOException;

    void init(int max) {
        maxURLs = max;
        numURLs = 0;
        urls = new String[max];
        titles = new String[max];
    }

    void addURL(String url, String tit) {
        if (numURLs < maxURLs) {
            urls[numURLs] = singleLine(url);
            titles[numURLs] = singleLine(tit);
            numURLs++;
        }
    }

    /** */
    void addChannel(String path, ChannelInfo info) {

        // the name may come from a request path or the network, never write it raw
        String nid = info.id.isSet() ? info.id.toString() : URLEncoder.encode(String.valueOf(info.name), StandardCharsets.UTF_8);

        String url = String.format("%s/stream/%s%s", path, nid, info.contentType.extention);
        addURL(url, info.name);
    }

    /** a playlist entry is one line, drops line breaks and other control characters */
    static String singleLine(String s) {
        return s == null ? null : s.replaceAll("\\p{Cntrl}", "");
    }

    /** for xml attribute values */
    static String escapeXml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;");
    }

    int numURLs, maxURLs;

    String[] urls, titles;
}
