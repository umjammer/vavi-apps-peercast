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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.xml.sax.SAXException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import vavi.util.Debug;


/**
 * PlayList.
 *
 * @author <a href="mailto:vavivavi@yahoo.co.jp">Naohide Sano</a> (nsano)
 * @version 0.00 050811 nsano initial version <br>
 */
enum PlayList {

    /** */
    T_NONE {
        void write(OutputStream out) {
            throw new UnsupportedOperationException();
        }
        void read(InputStream in) throws IOException {
            throw new UnsupportedOperationException();
        }
    },
    /** */
    SCPLS {
        /** */
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            ps.println("[playlist]");
            ps.println("");
            ps.printf("NumberOfEntries=%d\n", numURLs);

            for (int i = 0; i < numURLs; i++) {
                ps.printf("File%d=%s\n", i + 1, urls[i]);
                ps.printf("Title%d=%s\n", i + 1, titles[i]);
                ps.printf("Length%d=-1\n", i + 1);
            }
            ps.println("Version=2");
        }

        /** */
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
        /** */
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            for (int i = 0; i < numURLs; i++) {
                ps.printf("%s\n", urls[i]);
Debug.println("player's url: " + urls[i]);
            }
        }

        /** */
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
        /** */
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            ps.println("<ASX Version=\"3.0\">");
            for (int i = 0; i < numURLs; i++) {
                ps.println("<ENTRY>");
                ps.printf("<REF href = \"%s\" />\n", urls[i]);
                ps.println("</ENTRY>");
            }
            ps.println("</ASX>");
        }

        /** */
        void read(InputStream in) throws IOException {
            log.debug("Reading ASX");

            Document xml;
            try {
                xml = Peercast.db.parse(in);
            } catch (SAXException e) {
                throw (RuntimeException) new IllegalStateException().initCause(e);
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
                            if (hr != null) {
                                addURL(hr, "");
                                // log.debug("asx url %s",hr);
                            }
                        }
                    }
                }
            }
        }
    },
    RAM {
        /** */
        void write(OutputStream out) {
            PrintStream ps = new PrintStream(out);
            for (int i = 0; i < numURLs; i++) {
                ps.printf("%s", urls[i]);
            }
        }
        void read(InputStream in) throws IOException {
            throw new UnsupportedOperationException();
        }
    };

    static Log log = LogFactory.getLog(PlayList.class);

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

    void addURL(final String url, final String tit) {
        if (numURLs < maxURLs) {
            urls[numURLs] = url;
            titles[numURLs] = tit;
            numURLs++;
        }
    }

    /** */
    void addChannel(final String path, ChannelInfo info) {

        String idStr = info.id.toString();
        String nid = info.id.isSet() ? idStr : info.name;

        String url = String.format("%s/stream/%s%s", path, nid, info.contentType.extention);
        addURL(url, info.name);
    }

    int numURLs, maxURLs;

    String[] urls, titles;
}

/* */
