/*
 * Copyright (c) 2000, 2017 Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2021 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */

package com.sun.messaging.jmq.jmsserver.auth.ldap;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.sun.messaging.jmq.jmsserver.Globals;
import com.sun.messaging.jmq.util.log.Logger;

public abstract class TrustSSLSocketFactory extends SSLSocketFactory {

    // private Logger logger = Globals.getLogger();

    public static SocketFactory getDefault() {

        try {

            return getTrustSocketFactory();

        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Globals.getLogger().log(Logger.ERROR, e.getMessage(), e);
        }

        return null;
    }

    private static SSLSocketFactory getTrustSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {

        SSLContext ctx = SSLContext.getInstance("TLS");
        TrustManager[] tm = new TrustManager[1];
        tm[0] = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String type) {
                return;
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String type) {
                return;
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };

        ctx.init(null, tm, null);
        return ctx.getSocketFactory();
    }
}
