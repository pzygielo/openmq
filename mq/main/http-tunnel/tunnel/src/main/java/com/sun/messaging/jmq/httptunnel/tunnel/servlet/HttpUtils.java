/*
 * Copyright (c) 1997, 2020 Oracle and/or its affiliates and others.
 * Copyright 2021, 2022 Contributors to the Eclipse Foundation
 *
 * All rights reserved.
 * Copyright 2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sun.messaging.jmq.httptunnel.tunnel.servlet;

import java.util.Hashtable;
import java.util.StringTokenizer;

@SuppressWarnings("JdkObsolete")
class HttpUtils {
    private HttpUtils() {
    }

    /**
     * Parses a query string passed from the client to the server and builds a <code>HashTable</code> object with key-value
     * pairs. The query string should be in the form of a string packaged by the GET or POST method, that is, it should have
     * key-value pairs in the form <i>key=value</i>, with each pair separated from the next by a &amp; character.
     *
     * <p>
     * A key can appear more than once in the query string with different values. However, the key appears only once in the
     * hashtable, with its value being an array of strings containing the multiple values sent by the query string.
     * 
     * <p>
     * The keys and values in the hashtable are stored in their decoded form, so any + characters are converted to spaces,
     * and characters sent in hexadecimal notation (like <i>%xx</i>) are converted to ASCII characters.
     *
     * @param s a string containing the query to be parsed
     *
     * @return a <code>HashTable</code> object built from the parsed key-value pairs
     *
     * @exception IllegalArgumentException if the query string is invalid
     */
    static Hashtable<String, String[]> parseQueryString(String s) {

        String valArray[] = null;

        if (s == null) {
            throw new IllegalArgumentException();
        }

        Hashtable<String, String[]> ht = new Hashtable<>();
        StringBuilder sb = new StringBuilder();
        StringTokenizer st = new StringTokenizer(s, "&");
        while (st.hasMoreTokens()) {
            String pair = st.nextToken();
            int pos = pair.indexOf('=');
            if (pos == -1) {
                // XXX
                // should give more detail about the illegal argument
                throw new IllegalArgumentException();
            }
            String key = parseName(pair.substring(0, pos), sb);
            String val = parseName(pair.substring(pos + 1, pair.length()), sb);
            if (ht.containsKey(key)) {
                String oldVals[] = ht.get(key);
                valArray = new String[oldVals.length + 1];
                System.arraycopy(oldVals, 0, valArray, 0, oldVals.length);
                valArray[oldVals.length] = val;
            } else {
                valArray = new String[1];
                valArray[0] = val;
            }
            ht.put(key, valArray);
        }

        return ht;
    }

    /*
     * Parse a name in the query string.
     */
    private static String parseName(String s, StringBuilder sb) {
        sb.setLength(0);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
            case '+':
                sb.append(' ');
                break;
            case '%':
                try {
                    sb.append((char) Integer.parseInt(s.substring(i + 1, i + 3), 16));
                    i += 2;
                } catch (NumberFormatException e) {
                    // XXX
                    // need to be more specific about illegal arg
                    throw new IllegalArgumentException();
                } catch (StringIndexOutOfBoundsException e) {
                    String rest = s.substring(i);
                    sb.append(rest);
                    if (rest.length() == 2) {
                        i++;
                    }
                }

                break;
            default:
                sb.append(c);
                break;
            }
        }

        return sb.toString();
    }
}
