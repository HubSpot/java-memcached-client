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

import java.util.HashMap;
import java.util.Map;
import net.spy.memcached.MemcachedConnection;
import net.spy.memcached.MemcachedNode;
import net.spy.memcached.compat.SpyObject;

/**
 * This will manage SSL connections and retries for MemcachedClient.
 * Similar to AuthThreadMonitor, this ensures no more than one SSLThread
 * will exist for a given MemcachedNode.
 */
public class SSLThreadMonitor extends SpyObject {

  private final Map<Object, SSLThread> nodeMap;
  private final int maxRetryCount;
  private final int retryDelayMillis;
  private SSLConnectionCallback callback;

  /**
   * Create an SSL Thread Monitor with default settings.
   */
  public SSLThreadMonitor() {
    this(5, 1000); // Default: 5 retries, 1 second between attempts
  }

  /**
   * Create an SSL Thread Monitor with custom retry settings.
   * 
   * @param maxRetryCount maximum number of SSL connection retries
   * @param retryDelayMillis delay between retry attempts in milliseconds
   */
  public SSLThreadMonitor(int maxRetryCount, int retryDelayMillis) {
    nodeMap = new HashMap<Object, SSLThread>();
    this.maxRetryCount = maxRetryCount;
    this.retryDelayMillis = retryDelayMillis;
  }

  /**
   * Set the callback for SSL connection events.
   * 
   * @param callback the callback to use
   */
  public void setCallback(SSLConnectionCallback callback) {
    this.callback = callback;
  }

  /**
   * Start SSL handshake for a connection.
   * This is typically used by a MemcachedNode after a connection
   * has been established to initiate the SSL handshake.
   *
   * If an old, but not yet completed SSL handshake exists, this will stop it
   * in order to create a new handshake attempt.
   *
   * @param conn the memcached connection
   * @param node the node to secure
   */
  public synchronized void secureConnection(MemcachedConnection conn, 
      MemcachedNode node) {
    interruptOldSSL(node);
    SSLThread newSSLThread = new SSLThread(node, maxRetryCount, retryDelayMillis);
    nodeMap.put(node, newSSLThread);
    newSSLThread.start();
  }

  /**
   * Interrupt all pending {@link SSLThread}s.
   *
   * While shutting down a connection, if there are any {@link SSLThread}s
   * running, terminate them so that the java process can exit gracefully.
   */
  public synchronized void interruptAllPendingSSL() {
    for (SSLThread toStop : nodeMap.values()) {
      if (toStop.isAlive()) {
        getLogger().warn("Connection shutdown in progress - interrupting "
          + "SSL handshake thread.");
        toStop.interrupt();
      }
    }
  }

  private void interruptOldSSL(MemcachedNode nodeToStop) {
    SSLThread toStop = nodeMap.get(nodeToStop);
    if (toStop != null) {
      if (toStop.isAlive()) {
        getLogger().warn(
            "Incomplete SSL handshake interrupted for node " + nodeToStop);
        toStop.interrupt();
      }
      nodeMap.remove(nodeToStop);
    }
  }

  /**
   * Thread that handles SSL connection setup and retries.
   */
  private class SSLThread extends Thread {
    private final MemcachedNode node;
    private final int maxRetries;
    private final int retryDelay;
    private int attemptCount;

    public SSLThread(MemcachedNode n, int maxRetries, int retryDelay) {
      super("SSLThread for " + n.getSocketAddress().toString());
      node = n;
      this.maxRetries = maxRetries;
      this.retryDelay = retryDelay;
      attemptCount = 0;
      setDaemon(true);
    }

    @Override
    public void run() {
      try {
        while (attemptCount < maxRetries && !Thread.interrupted()) {
          attemptCount++;
          getLogger().info("SSL handshake attempt %d/%d for %s", 
              attemptCount, maxRetries, node);
          
          try {
            // Attempt the SSL handshake
            boolean success = attemptSSLHandshake();
            
            if (success) {
              getLogger().info("SSL handshake succeeded for %s", node);
              // Handshake successful, remove from map and exit
              synchronized (SSLThreadMonitor.this) {
                nodeMap.remove(node);
                if (callback != null) {
                  callback.onHandshakeSuccess(node);
                }
              }
              return;
            } else if (attemptCount >= maxRetries) {
              getLogger().warn("SSL handshake failed after %d attempts for %s", 
                  attemptCount, node);
              // Use the callback to handle failure
              if (callback != null) {
                callback.onHandshakeFailure(node);
              }
              return;
            }
            
            // Wait before retrying
            Thread.sleep(retryDelay);
          } catch (Exception e) {
            getLogger().warn("Exception during SSL handshake for %s: %s", 
                node, e.getMessage());
            
            if (attemptCount >= maxRetries) {
              getLogger().warn("SSL handshake failed after %d attempts for %s", 
                  attemptCount, node);
              if (callback != null) {
                callback.onHandshakeFailure(node);
              }
              return;
            }
            
            // Wait before retrying
            Thread.sleep(retryDelay);
          }
        }
      } catch (InterruptedException e) {
        getLogger().debug("SSL handshake thread interrupted for %s", node);
      } finally {
        synchronized (SSLThreadMonitor.this) {
          nodeMap.remove(node);
        }
      }
    }
    
    private boolean attemptSSLHandshake() {
      try {
        return node.executeTlsHandshake();
      } catch (Exception e) {
        getLogger().warn("Exception during SSL handshake: %s", e.getMessage());
        return false;
      }
    }
  }

  /**
   * Returns Map of SSLThread for testing.
   * It should not be accessed from anywhere else.
   * @return map of node to SSL threads
   */
  protected Map<Object, SSLThread> getNodeMap() {
    return nodeMap;
  }
} 