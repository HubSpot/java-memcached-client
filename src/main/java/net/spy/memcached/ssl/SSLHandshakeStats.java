/**
 * Copyright (C) 2006-2009 Dustin Sallings
 * Copyright (C) 2009-2011 Couchbase, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALING
 * IN THE SOFTWARE.
 */

package net.spy.memcached.ssl;

import java.net.SocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A simple statistics tracker for SSL handshakes.
 * This class is thread-safe and can be used to monitor SSL handshake
 * attempts, successes, and failures.
 */
public class SSLHandshakeStats {
    
    private final AtomicInteger totalHandshakes = new AtomicInteger(0);
    private final AtomicInteger successfulHandshakes = new AtomicInteger(0);
    private final AtomicInteger failedHandshakes = new AtomicInteger(0);
    private final Map<SocketAddress, NodeStats> nodeStats = new ConcurrentHashMap<>();
    
    /**
     * Statistics for a specific node.
     */
    public static class NodeStats {
        private final SocketAddress address;
        private final AtomicInteger attempts = new AtomicInteger(0);
        private final AtomicInteger successes = new AtomicInteger(0);
        private final AtomicInteger failures = new AtomicInteger(0);
        private final AtomicLong lastAttemptTimestamp = new AtomicLong(0);
        private final AtomicLong lastSuccessTimestamp = new AtomicLong(0);
        private final AtomicLong lastFailureTimestamp = new AtomicLong(0);
        private volatile Throwable lastException = null;
        
        /**
         * Create statistics for a node.
         * 
         * @param address the socket address of the node
         */
        public NodeStats(SocketAddress address) {
            this.address = address;
        }
        
        /**
         * Record a handshake attempt.
         */
        public void recordAttempt() {
            attempts.incrementAndGet();
            lastAttemptTimestamp.set(System.currentTimeMillis());
        }
        
        /**
         * Record a handshake success.
         */
        public void recordSuccess() {
            successes.incrementAndGet();
            lastSuccessTimestamp.set(System.currentTimeMillis());
        }
        
        /**
         * Record a handshake failure.
         */
        public void recordFailure() {
            failures.incrementAndGet();
            lastFailureTimestamp.set(System.currentTimeMillis());
        }
        
        /**
         * Record a handshake failure with the exception that caused it.
         * 
         * @param e the exception that caused the failure
         */
        public void recordFailure(Throwable e) {
            recordFailure();
            this.lastException = e;
        }
        
        /**
         * Get the last exception that caused a handshake failure.
         * 
         * @return the last exception, or null if no exceptions have been recorded
         */
        public Throwable getLastException() {
            return lastException;
        }
        
        /**
         * Get the node's socket address.
         * 
         * @return the socket address
         */
        public SocketAddress getAddress() {
            return address;
        }
        
        /**
         * Get the number of handshake attempts.
         * 
         * @return the number of attempts
         */
        public int getAttempts() {
            return attempts.get();
        }
        
        /**
         * Get the number of successful handshakes.
         * 
         * @return the number of successes
         */
        public int getSuccesses() {
            return successes.get();
        }
        
        /**
         * Get the number of failed handshakes.
         * 
         * @return the number of failures
         */
        public int getFailures() {
            return failures.get();
        }
        
        /**
         * Get the timestamp of the last handshake attempt.
         * 
         * @return the timestamp in milliseconds
         */
        public long getLastAttemptTimestamp() {
            return lastAttemptTimestamp.get();
        }
        
        /**
         * Get the timestamp of the last successful handshake.
         * 
         * @return the timestamp in milliseconds
         */
        public long getLastSuccessTimestamp() {
            return lastSuccessTimestamp.get();
        }
        
        /**
         * Get the timestamp of the last failed handshake.
         * 
         * @return the timestamp in milliseconds
         */
        public long getLastFailureTimestamp() {
            return lastFailureTimestamp.get();
        }
        
        @Override
        public String toString() {
            return "NodeStats{" +
                "address=" + address +
                ", attempts=" + attempts +
                ", successes=" + successes +
                ", failures=" + failures +
                '}';
        }
    }
    
    /**
     * Record a handshake attempt for a node.
     * 
     * @param address the socket address of the node
     * @return the updated node statistics
     */
    public NodeStats recordAttempt(SocketAddress address) {
        totalHandshakes.incrementAndGet();
        NodeStats stats = getOrCreateNodeStats(address);
        stats.recordAttempt();
        return stats;
    }
    
    /**
     * Record a successful handshake for a node.
     * 
     * @param address the socket address of the node
     * @return the updated node statistics
     */
    public NodeStats recordSuccess(SocketAddress address) {
        successfulHandshakes.incrementAndGet();
        NodeStats stats = getOrCreateNodeStats(address);
        stats.recordSuccess();
        return stats;
    }
    
    /**
     * Record a failed handshake for a node.
     * 
     * @param address the socket address of the node
     * @return the updated node statistics
     */
    public NodeStats recordFailure(SocketAddress address) {
        failedHandshakes.incrementAndGet();
        NodeStats stats = getOrCreateNodeStats(address);
        stats.recordFailure();
        return stats;
    }
    
    /**
     * Record a failed handshake for a node.
     * 
     * @param address the socket address of the node
     * @param e the exception that caused the failure
     * @return the updated node statistics
     */
    public NodeStats recordFailure(SocketAddress address, Throwable e) {
        failedHandshakes.incrementAndGet();
        NodeStats stats = getOrCreateNodeStats(address);
        stats.recordFailure(e);
        return stats;
    }
    
    /**
     * Get statistics for a specific node.
     * 
     * @param address the socket address of the node
     * @return the node statistics, or null if no statistics exist for the node
     */
    public NodeStats getNodeStats(SocketAddress address) {
        return nodeStats.get(address);
    }
    
    /**
     * Get or create statistics for a specific node.
     * 
     * @param address the socket address of the node
     * @return the node statistics
     */
    private NodeStats getOrCreateNodeStats(SocketAddress address) {
        return nodeStats.computeIfAbsent(address, NodeStats::new);
    }
    
    /**
     * Get all node statistics.
     * 
     * @return a map of socket addresses to node statistics
     */
    public Map<SocketAddress, NodeStats> getAllNodeStats() {
        return nodeStats;
    }
    
    /**
     * Get the total number of handshake attempts.
     * 
     * @return the total number of attempts
     */
    public int getTotalHandshakes() {
        return totalHandshakes.get();
    }
    
    /**
     * Get the total number of successful handshakes.
     * 
     * @return the total number of successes
     */
    public int getSuccessfulHandshakes() {
        return successfulHandshakes.get();
    }
    
    /**
     * Get the total number of failed handshakes.
     * 
     * @return the total number of failures
     */
    public int getFailedHandshakes() {
        return failedHandshakes.get();
    }
    
    /**
     * Reset all statistics.
     */
    public void reset() {
        totalHandshakes.set(0);
        successfulHandshakes.set(0);
        failedHandshakes.set(0);
        nodeStats.clear();
    }
    
    @Override
    public String toString() {
        return "SSLHandshakeStats{" +
            "totalHandshakes=" + totalHandshakes +
            ", successfulHandshakes=" + successfulHandshakes +
            ", failedHandshakes=" + failedHandshakes +
            ", nodeStats=" + nodeStats +
            '}';
    }
} 