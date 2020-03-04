/*
 * Copyright (c) 2000, 2017 Oracle and/or its affiliates. All rights reserved.
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

/*
 * @(#)ConnectionClosedEvent.java	1.4 07/02/07
 */

package com.sun.messaging.jms.notification;

import com.sun.messaging.jms.Connection;
import com.sun.messaging.jmq.jmsclient.resources.ClientResources;

import javax.jms.JMSException;

/**
 * MQ Connection closed Event. This event is generated by MQ and delivered to an application (if the connection event
 * listener is set) when a connection is closed by MQ.
 */
public class ConnectionClosedEvent extends ConnectionEvent {

    /**
     * 
     */
    private static final long serialVersionUID = 7020602592556706912L;

    // if there is any exception that caused the connection to be closed,
    // it is set to this event.
    private JMSException exception = null;

    /**
     * Connection closed event code - admin requested shutdown
     */
    public static final String CONNECTION_CLOSED_SHUTDOWN = ClientResources.E_CONNECTION_CLOSED_SHUTDOWN;

    /**
     * Connection closed event code - admin requested restart
     */
    public static final String CONNECTION_CLOSED_RESTART = ClientResources.E_CONNECTION_CLOSED_RESTART;

    /**
     * Connection closed event code - server error, e.g. out of memory.
     */
    public static final String CONNECTION_CLOSED_ERROR = ClientResources.E_CONNECTION_CLOSED_ERROR;

    /**
     * Connection closed event code - admin killed connection.
     */
    public static final String CONNECTION_CLOSED_KILL = ClientResources.E_CONNECTION_CLOSED_KILL;

    /**
     * Connection closed event code - broker crash.
     */
    public static final String CONNECTION_CLOSED_BROKER_DOWN = ClientResources.E_CONNECTION_CLOSED_BROKER_DOWN;

    /**
     * Connection closed event code - broker is not responsive.
     */
    public static final String CONNECTION_CLOSED_NON_RESPONSIVE = ClientResources.E_CONNECTION_CLOSED_NON_RESPONSIVE;

    /**
     * The above event codes are for events originated from the broker. Broker notifies MQ client runtime that the
     * connection is closed.
     *
     * This event code is to represent that the MQ client runtime detects the connection to the broker is broken. This could
     * be a network problem or broker crashed.
     */
    public static final String CONNECTION_CLOSED_LOST_CONNECTION = ClientResources.E_CONNECTION_CLOSED_LOST_CONNECTION;

    /**
     * Construct a connection closed event.
     *
     * @param conn the connection that the event is associated with. MQ may automatically reconnect to the same broker or a
     * different broker depends on the client runtime configuration.
     * @param evCode the event code that represents this event object.
     * @param evMessage the event message that describes this event object.
     * @param jmse the JMSException that caused this event.
     */
    public ConnectionClosedEvent(Connection conn, String evCode, String evMessage, JMSException jmse) {

        super(conn, evCode, evMessage);

        this.exception = jmse;
    }

    /**
     * Get the JMSException that caused the connection to be closed.
     *
     * @return the JMSException that caused the connection to be closed. return null if no JMSException associated with this
     * event. Such as connection closed caused by admin requested shutdown.
     */
    public JMSException getJMSException() {
        return exception;
    }

}
