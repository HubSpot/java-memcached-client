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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import net.spy.memcached.MemcachedConnection;
import net.spy.memcached.MemcachedNode;
import net.spy.memcached.compat.SpyObject;

/**
 * Exception class to store details about SSL handshake failures.
 */
class SSLHandshakeException extends Exception {
  private static final long serialVersionUID = -7784967329863361921L;
  private final SocketAddress socketAddress;
  private final int attemptNumber;
  
  public SSLHandshakeException(SocketAddress socketAddress, int attemptNumber, String message, Throwable cause) {
    super(message, cause);
    this.socketAddress = socketAddress;
    this.attemptNumber = attemptNumber;
  }
  
  public SocketAddress getSocketAddress() {
    return socketAddress;
  }
  
  public int getAttemptNumber() {
    return attemptNumber;
  }
}

/**
 * This will manage SSL connections and retries for MemcachedClient.
 * Similar to AuthThreadMonitor, this ensures no more than one SSLThread
 * will exist for a given MemcachedNode.
 */
public class SSLThreadMonitor extends SpyObject {

  private final Map<Object, SSLThread> nodeMap;
  private int maxRetryCount;
  private int retryDelayMillis;
  private SSLConnectionCallback callback;
  private volatile boolean shuttingDown = false;
  
  // Keep track of nodes that are currently in handshake process
  private final Set<MemcachedNode> nodesInHandshake = 
      Collections.newSetFromMap(new ConcurrentHashMap<MemcachedNode, Boolean>());

  /**
   * Statistics for SSL handshakes.
   * This can be accessed to monitor handshake attempts, successes, and failures.
   */
  private final SSLHandshakeStats stats = new SSLHandshakeStats();
  
  /**
   * Get the SSL handshake statistics.
   * 
   * @return the SSL handshake statistics
   */
  public SSLHandshakeStats getStats() {
    return stats;
  }

  /**
   * Get the current attempt count for a node.
   * 
   * @param node the node to check
   * @return the current attempt count from statistics
   */
  public int getAttemptCount(MemcachedNode node) {
    SSLHandshakeStats.NodeStats nodeStats = stats.getNodeStats(node.getSocketAddress());
    return nodeStats != null ? nodeStats.getAttempts() : 0;
  }

  /**
   * Get the current attempt count for a node.
   * 
   * @param node the node to check
   * @return the current attempt count from the running SSL thread, or 0 if no thread exists
   */
  public int getCurrentAttemptCount(MemcachedNode node) {
    synchronized (this) {
      SSLThread thread = nodeMap.get(node);
      return thread != null ? thread.attemptCounter.get() : 0;
    }
  }

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
   * Set monitor in shutdown state.
   * This prevents new connections from being attempted.
   */
  public void setShuttingDown() {
    shuttingDown = true;
  }

  /**
   * Check if monitor is in shutdown state.
   * 
   * @return true if the monitor is shutting down
   */
  public boolean isShuttingDown() {
    return shuttingDown;
  }

  /**
   * Check if a node is currently in SSL handshake process.
   * 
   * @param node the node to check
   * @return true if the node is currently in handshake process
   */
  public boolean isHandshaking(MemcachedNode node) {
    return nodesInHandshake.contains(node);
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
    // Don't start new handshakes if we're shutting down
    if (shuttingDown) {
      getLogger().info("Skipping SSL handshake attempt for %s - shutdown in progress", node);
      return;
    }
    
    // Mark this node as in handshake process
    nodesInHandshake.add(node);
    
    interruptOldSSL(node);
    SSLThread newSSLThread = new SSLThread(node);
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
    shuttingDown = true;
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
    final AtomicInteger attemptCounter = new AtomicInteger(0);

    public SSLThread(MemcachedNode n) {
      super("SSLThread for " + n.getSocketAddress().toString());
      node = n;
      setDaemon(true);
    }

    @Override
    public void run() {
      try {
        while (attemptCounter.incrementAndGet() <= maxRetryCount) {
          int currentAttempt = attemptCounter.get();
          if (Thread.interrupted() || shuttingDown) {
            break;
          }
          
          // Record attempt in stats
          stats.recordAttempt(node.getSocketAddress());
          
          getLogger().info("SSL handshake attempt %d/%d for %s", 
              currentAttempt, maxRetryCount, node);
          
          try {
            // Attempt the SSL handshake
            boolean success = attemptSSLHandshake();
            
            if (success) {
              getLogger().info("SSL handshake succeeded for %s", node);
              stats.recordSuccess(node.getSocketAddress());
              notifySuccess();
              return;
            }
            
            if (currentAttempt >= maxRetryCount || shuttingDown) {
              getLogger().warn("SSL handshake failed after %d attempts for %s", 
                  currentAttempt, node);
              stats.recordFailure(node.getSocketAddress());
              notifyFailure();
              return;
            }
            
            // Wait before retrying
            if (!shuttingDown) {
              Thread.sleep(retryDelayMillis);
            }
          } catch (Exception e) {
            getLogger().warn("Exception during SSL handshake for %s: %s", 
                node, e.getMessage());
            getLogger().debug("SSL handshake failure details for %s", node, e);
            stats.recordFailure(node.getSocketAddress(), e);
            
            if (currentAttempt >= maxRetryCount || shuttingDown) {
              getLogger().warn("SSL handshake failed after %d attempts for %s", 
                  currentAttempt, node);
              notifyFailure();
              return;
            }
            
            // Wait before retrying if not shutting down
            if (!shuttingDown) {
              Thread.sleep(retryDelayMillis);
            }
          }
        }
      } catch (InterruptedException e) {
        getLogger().debug("SSL handshake thread interrupted for %s", node);
      } finally {
        cleanupThread();
      }
    }
    
    private boolean attemptSSLHandshake() {
      try {
        if (shuttingDown || node.getChannel() == null) {
          return false;
        }
        return node.executeTlsHandshake();
      } catch (Exception e) {
        getLogger().warn("Exception during SSL handshake: %s", e.getMessage());
        getLogger().debug("SSL handshake exception details", e);
        stats.recordFailure(node.getSocketAddress(), e);
        return false;
      }
    }
    
    private void notifySuccess() {
      synchronized (SSLThreadMonitor.this) {
        nodeMap.remove(node);
        nodesInHandshake.remove(node);
        if (callback != null && !shuttingDown) {
          callback.onHandshakeSuccess(node);
        }
      }
    }
    
    private void notifyFailure() {
      synchronized (SSLThreadMonitor.this) {
        if (callback != null && !shuttingDown) {
          callback.onHandshakeFailure(node);
        }
      }
    }
    
    private void cleanupThread() {
      synchronized (SSLThreadMonitor.this) {
        nodeMap.remove(node);
        nodesInHandshake.remove(node);
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

  /**
   * Set SSL handshake retry parameters.
   * 
   * @param retryCount the maximum number of retries
   * @param delayMillis the delay between retries in milliseconds
   */
  public void setRetryParameters(int retryCount, int delayMillis) {
    if (retryCount < 1) {
      throw new IllegalArgumentException("Retry count must be at least 1");
    }
    if (delayMillis < 0) {
      throw new IllegalArgumentException("Delay must be non-negative");
    }
    
    synchronized(this) {
      // Only allow setting these if no handshakes are in progress
      if (!nodesInHandshake.isEmpty()) {
        throw new IllegalStateException("Cannot change retry parameters while handshakes are in progress");
      }
      
      this.maxRetryCount = retryCount;
      this.retryDelayMillis = delayMillis;
    }
  }
  
  /**
   * Get diagnostics information about current SSL handshakes.
   * 
   * @return a map of nodes to their current handshake attempt counts
   */
  public Map<MemcachedNode, Integer> getHandshakeDiagnostics() {
    Map<MemcachedNode, Integer> result = new HashMap<>();
    
    synchronized(this) {
      for (Map.Entry<Object, SSLThread> entry : nodeMap.entrySet()) {
        if (entry.getKey() instanceof MemcachedNode) {
          MemcachedNode node = (MemcachedNode) entry.getKey();
          SSLThread thread = entry.getValue();
          result.put(node, thread.attemptCounter.get());
        }
      }
    }
    
    return result;
  }

  /**
   * Get detailed information about SSL handshake failures for a specific node.
   * 
   * @param node the node to get failure information for
   * @return a string containing detailed failure information, or null if no failures have been recorded
   */
  public String getDetailedFailureInfo(MemcachedNode node) {
    SSLHandshakeStats.NodeStats nodeStats = stats.getNodeStats(node.getSocketAddress());
    if (nodeStats == null) {
      return null;
    }
    
    Throwable lastException = nodeStats.getLastException();
    if (lastException == null) {
      return null;
    }
    
    StringBuilder sb = new StringBuilder();
    sb.append("SSL handshake failures for node: ").append(node).append("\n");
    sb.append("Attempts: ").append(nodeStats.getAttempts()).append("\n");
    sb.append("Failures: ").append(nodeStats.getFailures()).append("\n");
    sb.append("Last exception: ").append(lastException.getClass().getName())
      .append(": ").append(lastException.getMessage()).append("\n");
    
    // Add stack trace
    StackTraceElement[] stackTrace = lastException.getStackTrace();
    for (StackTraceElement element : stackTrace) {
      sb.append("  at ").append(element.toString()).append("\n");
    }
    
    // Add cause if present
    Throwable cause = lastException.getCause();
    if (cause != null) {
      sb.append("Caused by: ").append(cause.getClass().getName())
        .append(": ").append(cause.getMessage()).append("\n");
      
      StackTraceElement[] causeTrace = cause.getStackTrace();
      for (StackTraceElement element : causeTrace) {
        sb.append("  at ").append(element.toString()).append("\n");
      }
    }
    
    return sb.toString();
  }
} 