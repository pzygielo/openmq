/*
 * Copyright (c) 2000, 2020 Oracle and/or its affiliates. All rights reserved.
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

package com.sun.messaging.jmq.jmsclient;

import jakarta.jms.*;

/**
 * A client uses a QueueSender to send messages to a queue.
 *
 * <P>
 * Normally the Queue is specified when a QueueSender is created and in this case, attempting to use the methods for an
 * unidentified QueueSender will throws an UnsupportedOperationException.
 *
 * <P>
 * In the case that the QueueSender with an unidentified Queue is created, the methods that assume the Queue has been
 * identified throw an UnsupportedOperationException.
 *
 * @see jakarta.jms.MessageProducer
 * @see jakarta.jms.QueueSession#createSender(Queue)
 */

public class QueueSenderImpl extends MessageProducerImpl implements QueueSender {

    private Queue queue = null;

    public QueueSenderImpl(SessionImpl session, Queue queue) throws JMSException {
        super(session, queue);
        this.queue = queue;
    }

    /**
     * Get the queue associated with this queue sender.
     *
     * @return the queue
     *
     * @exception JMSException if JMS fails to get queue for this queue sender due to some internal error.
     */
    @Override
    public Queue getQueue() throws JMSException {
        checkState();
        return queue;
    }

    /**
     * Send a message to a queue for an unidentified message producer. Use the QueueSender's default delivery mode,
     * timeToLive and priority.
     *
     * <P>
     * Typically a JMS message producer is assigned a queue at creation time; however, JMS also supports unidentified
     * message producers which require that the queue be supplied on every message send.
     *
     * @param queue the queue that this message should be sent to
     * @param message the message to be sent
     *
     * @exception JMSException if JMS fails to send the message due to some internal error.
     * @exception MessageFormatException if invalid message specified
     * @exception InvalidDestinationException if a client uses this method with an invalid queue.
     */
    @Override
    public void send(Queue queue, Message message) throws JMSException {

        super.send(queue, message);

    }

    /**
     * Send a message to a queue for an unidentified message producer, specifying delivery mode, priority and time to live.
     *
     * <P>
     * Typically a JMS message producer is assigned a queue at creation time; however, JMS also supports unidentified
     * message producers which require that the queue be supplied on every message send.
     *
     * @param queue the queue that this message should be sent to
     * @param message the message to be sent
     * @param deliveryMode the delivery mode to use
     * @param priority the priority for this message
     * @param timeToLive the message's lifetime (in milliseconds).
     *
     * @exception JMSException if JMS fails to send the message due to some internal error.
     * @exception MessageFormatException if invalid message specified
     * @exception InvalidDestinationException if a client uses this method with an invalid queue.
     */

    @Override
    public void send(Queue queue, Message message, int deliveryMode, int priority, long timeToLive) throws JMSException {

        super.send(queue, message, deliveryMode, priority, timeToLive);

    }

}
