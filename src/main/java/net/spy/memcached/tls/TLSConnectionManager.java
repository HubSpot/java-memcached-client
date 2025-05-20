package net.spy.memcached.tls;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import net.spy.memcached.ConnectionFactory;
import net.spy.memcached.compat.log.Logger;
import net.spy.memcached.compat.log.LoggerFactory;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);

    // Buffer pool for reusing direct buffers
    private static final Map<Integer, List<ByteBuffer>> BUFFER_POOL = new ConcurrentHashMap<>();

    // Cipher suite that does not encrypt data
    private static final String[] NULL_CIPHER_SUITE = {"eNULL", "NULL"};
    
    // Per-instance configuration values
    private final int maxPoolSizePerCapacity;
    private final int maxBufferSize;

    private final SSLContext sslContext;
    private SSLEngine sslEngine;

    public static final int WRAP_STATUS_BUFFER_UNDERFLOW = -1;
    public static final int WRAP_STATUS_BUFFER_OVERFLOW = -2;

    private SSLSession currentSession;

    private ByteBuffer appOutBuffer; // Holds the data we are preparing to send out
    private ByteBuffer appInBuffer; // Holds the data we have received and unwrapped
    private ByteBuffer networkOutBuffer; // Holds the data we are sending across the wire
    private ByteBuffer networkInBuffer; // Holds the data we have received from the wire

    private CountDownLatch handshakeSuccessful;

    /**
     * Create a new TLS Connection Manager.
     * 
     * @param sslContext the SSLContext to use
     * @param connectionFactory the connection factory providing buffer configuration
     */
    public TLSConnectionManager(SSLContext sslContext, ConnectionFactory connectionFactory) {
        this.sslContext = sslContext;
        this.handshakeSuccessful = new CountDownLatch(1);
        
        // Set buffer pool configuration from connection factory
        this.maxBufferSize = connectionFactory.getTLSMaxBufferSize();
        this.maxPoolSizePerCapacity = connectionFactory.getTLSMaxPoolSizePerCapacity();
    }

    private void initSslEngine() {
        ensureSslEngineInitialized(true);
    }

    private void ensureSslEngineInitialized(boolean forceReset) {
        // We are the client, not the server
        if (sslEngine != null) {
            if (forceReset) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Resetting SSL Engine");
                }
                closeSslEngine();
            } else {
                return;
            }
        }
        sslEngine = sslContext.createSSLEngine();
        SSLParameters sslParameters = sslEngine.getSSLParameters();
        sslParameters.setCipherSuites(NULL_CIPHER_SUITE);
        sslEngine.setUseClientMode(true);
        sslEngine.setSSLParameters(sslParameters);
    }

    private void releaseBufferToPool(ByteBuffer buffer) {
        if (buffer == null || !buffer.isDirect()) {
            return;
        }
        
        int capacity = buffer.capacity();
        if (capacity > maxBufferSize) {
            // Too large, don't pool it
            buffer = null;
            return;
        }
        
        // Clear and reset the buffer for reuse
        buffer.clear();
        
        // Add to pool if there's space
        List<ByteBuffer> bufferList = BUFFER_POOL.computeIfAbsent(capacity, k -> new ArrayList<>());
        synchronized (bufferList) {
            if (bufferList.size() < maxPoolSizePerCapacity) {
                bufferList.add(buffer);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Added buffer of size %d to pool, pool size: %d", capacity, bufferList.size());
                }
            }
        }
    }

    private ByteBuffer getBufferFromPool(int capacity) {
        List<ByteBuffer> bufferList = BUFFER_POOL.get(capacity);
        if (bufferList != null) {
            synchronized (bufferList) {
                if (!bufferList.isEmpty()) {
                    ByteBuffer buffer = bufferList.remove(bufferList.size() - 1);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Reused buffer of size %d from pool, pool size: %d", capacity, bufferList.size());
                    }
                    return buffer;
                }
            }
        }
        // No buffer available in pool, allocate a new one
        return ByteBuffer.allocateDirect(capacity);
    }

    private void cleanupBuffers() {
        if (appOutBuffer != null) {
            releaseBufferToPool(appOutBuffer);
            appOutBuffer = null;
        }
        if (appInBuffer != null) {
            releaseBufferToPool(appInBuffer);
            appInBuffer = null;
        }
        if (networkOutBuffer != null) {
            releaseBufferToPool(networkOutBuffer);
            networkOutBuffer = null;
        }
        if (networkInBuffer != null) {
            releaseBufferToPool(networkInBuffer);
            networkInBuffer = null;
        }
    }

    private void initBuffers(SSLSession session) {
        // Clean up any existing buffers first
        cleanupBuffers();
        
        int appBufferSize = session.getApplicationBufferSize();
        int netBufferSize = session.getPacketBufferSize();
        
        appOutBuffer = getBufferFromPool(appBufferSize);
        appInBuffer = getBufferFromPool(appBufferSize);
        networkOutBuffer = getBufferFromPool(netBufferSize);
        networkInBuffer = getBufferFromPool(netBufferSize);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initialized buffers: appOut=%d, appIn=%d, netOut=%d, netIn=%d bytes",
                      appOutBuffer.capacity(), appInBuffer.capacity(), 
                      networkOutBuffer.capacity(), networkInBuffer.capacity());
        }
    }

    public boolean doHandshake(SocketChannel socketChannel) throws IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("%s - Beginning handshake.", socketChannel.getRemoteAddress());
        }

        try {
            initSslEngine();
            sslEngine.beginHandshake();
            currentSession = sslEngine.getSession();
            initBuffers(currentSession);

            HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            if (LOG.isDebugEnabled()) {
                LOG.info("%s - Handshake status: %s", socketChannel.getRemoteAddress(), handshakeStatus.name());
            }
            while (!Thread.currentThread().isInterrupted()
              && handshakeStatus != HandshakeStatus.FINISHED
              && handshakeStatus != HandshakeStatus.NOT_HANDSHAKING) {

                switch (handshakeStatus) {
                    case NEED_TASK:
                        // we need to finish these tasks for the handshake to continue
                        List<Runnable> tasks = new ArrayList<>();
                        Runnable currentTask = sslEngine.getDelegatedTask();
                        while(currentTask != null) {
                            tasks.add(currentTask);
                            currentTask = sslEngine.getDelegatedTask();
                        }
                        for (Runnable task : tasks) {
                            task.run();
                        }
                        break;
                    case NEED_WRAP:
                        // We're about to send something to the server, but it needs to be wrapped first
                        networkOutBuffer.clear();
                        SSLEngineResult wrapResult = sslEngine.wrap(appOutBuffer, networkOutBuffer);
                        handleHandshakeWrapResult(socketChannel, wrapResult);
                        break;
                    case NEED_UNWRAP:
                        // We need to receive a message from the server, but it needs to be unwrapped first
                        if (socketChannel.read(networkInBuffer) < 0) {
                            // The message hit the end of the stream
                            if (sslEngine.isInboundDone() && sslEngine.isOutboundDone()) {
                                // SSL Engine closed before handshake could complete
                                return false;
                            }
                            // We're done with the handshake, signal that we aren't going to be sending or receiving any more data
                            try {
                                sslEngine.closeInbound();
                            } catch (SSLException e) {
                                if (LOG.isDebugEnabled()) {
                                    // This doesn't seem to be critical, but it could be nice to know about
                                    LOG.warn("%s - tried to close inbound traffic but has not received a TLS close notification yet due to end of stream.", socketChannel.getRemoteAddress(), e);
                                }
                            }
                            sslEngine.closeOutbound();
                            break;
                        }
                        networkInBuffer.flip();
                        SSLEngineResult unwrapResult = sslEngine.unwrap(networkInBuffer, appInBuffer);
                        networkInBuffer.compact(); // Leaves any unread bytes while creating more room in the buffer
                        if (unwrapResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                            return false; // Server closed session before handshake completed
                        }
                        handleHandshakeUnwrapResult(socketChannel, unwrapResult);
                        break;
                    case NEED_UNWRAP_AGAIN:
                        throw new UnsupportedOperationException("DTLS not supported");
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
                }

                handshakeStatus = sslEngine.getHandshakeStatus();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("%s - Handshake status: %s", socketChannel.getRemoteAddress(), handshakeStatus.name());
                }
            }

            // If we were interrupted, get out
            if (Thread.currentThread().isInterrupted()) {
                this.close();
                throw new InterruptedException("Thread interrupted while completing SSL Handshake");
            }


        } catch (SSLException | InterruptedException e) {
            throw new RuntimeException("Caught exception during SSL Handshake", e);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("%s - Handshake complete.", socketChannel.getRemoteAddress());
        }
        handshakeSuccessful.countDown();
        return true;
    }

    /**
     * Uses the keys stored in the SSLEngine to encrypt bytes to send to the server
     * @param appOutBuffer The buffer containing the unencrypted data to send. Should be at least sslEngine.getApplicationBufferSize() in length.
     * @param networkOutBuffer The buffer to write to, should be at least sslEngine.getPacketBuffer() in length
     * @return If the wrap succeeds, the number of bytes produced by the wrap.
     *         If a Buffer Overflow happened, TLSConnectionManager.WRAP_STATUS_BUFFER_OVERFLOW
     *         If a Buffer Underflow happened, TLSConnectionManager.WRAP_STATUS_BUFFER_UNDERFLOW
     * @throws SSLException from the call to SSLEngine::wrap if any occurred
     */
    public int wrapBufferForSend(ByteBuffer appOutBuffer, ByteBuffer networkOutBuffer) throws SSLException {
        SSLEngineResult wrap = sslEngine.wrap(appOutBuffer, networkOutBuffer);
        switch (wrap.getStatus()) {
            case BUFFER_UNDERFLOW:
                return WRAP_STATUS_BUFFER_UNDERFLOW;
            case BUFFER_OVERFLOW:
                return WRAP_STATUS_BUFFER_OVERFLOW;
            case OK:
                return wrap.bytesProduced();
            case CLOSED:
                throw new RuntimeException(sslEngine.getPeerHost() + " - TLS Connection is closed");
            default:
                // This might get hit if the Status enum ever gets expanded, but for now, we should not hit this. Case
                // required to make the Java compiler happy.
                throw new IllegalStateException("Invalid SSL status: " + wrap.getStatus());
        }
    }

    public UnwrapResult unwrapReceivedBuffer (ByteBuffer networkInBuffer) throws IOException {
        appInBuffer.clear();
        while(!Thread.currentThread().isInterrupted()) {
            SSLEngineResult unwrapResult = sslEngine.unwrap(networkInBuffer, appInBuffer);
            switch (unwrapResult.getStatus()) {
                case BUFFER_OVERFLOW:
                    // Application buffer is too small, set it to the correct size
                    enlargeBuffer(appInBuffer, sslEngine.getSession().getApplicationBufferSize());
                    break;
                case BUFFER_UNDERFLOW:
                    // We aren't done reading the response yet
                    return new UnwrapResult(null, unwrapResult);
                case OK:
                    appInBuffer.flip();
                    return new UnwrapResult(appInBuffer, unwrapResult);
                case CLOSED:
                    this.close();
                    throw new IOException(sslEngine.getPeerHost() + " - TLS Connection is closed");
                default:
                    // This might get hit if the Status enum ever gets expanded, but for now, we should not hit this. Case
                    // required to make the Java compiler happy.
                    throw new IllegalStateException("Invalid SSL status: " + unwrapResult.getStatus());
            }
        }
        throw new RuntimeException(sslEngine.getPeerHost() + " - Interrupted while unwrapping read buffer");
    }

    @Override
    public void close() throws IOException {
        cleanupBuffers();
        closeSslEngine();
    }

    private void closeSslEngine() {
        if (sslEngine != null) {
            sslEngine.setEnableSessionCreation(false);
            sslEngine.closeOutbound();
            try {
                sslEngine.closeInbound();
            } catch (SSLException e) {
                if (LOG.isDebugEnabled()) {
                    // This doesn't seem to be critical, but it could be nice to know about
                    LOG.warn("Tried to close inbound traffic but has not received a TLS close notification yet due to end of stream.", e);
                }
            }
            sslEngine = null;
        }
    }

    private void handleHandshakeWrapResult(SocketChannel socketChannel, SSLEngineResult result) throws SSLException {
        switch (result.getStatus()) {
            case BUFFER_UNDERFLOW:
                // We should not get here
                throw new SSLException("Buffer underflow occurred after wrap");
            case BUFFER_OVERFLOW:
                // If networkOutBuffer is too small to contain the response
                networkOutBuffer = enlargeBuffer(networkOutBuffer, sslEngine.getSession().getPacketBufferSize());
                // Try again with new larger buffer
                break;
            case OK:
                sendNetworkBuffer(socketChannel);
                break;
            case CLOSED:
                // We need to tell the server we're closing
                sendNetworkBuffer(socketChannel);
                // The next status will be NEED_UNWRAP and we'll need to pre-emptively clear the input network data
                networkInBuffer.clear();
                break;
        }
    }

    private void handleHandshakeUnwrapResult(SocketChannel socketChannel, SSLEngineResult result) throws SSLException {
        switch (result.getStatus()) {
            case BUFFER_UNDERFLOW:
                // If the network buffer is too small
                networkInBuffer = enlargeBuffer(networkInBuffer, sslEngine.getSession().getPacketBufferSize());
                break;
            case BUFFER_OVERFLOW:
                // if networkInBuffer is larger than appInBuffer
                appInBuffer = enlargeBuffer(appInBuffer, sslEngine.getSession().getApplicationBufferSize());
                // try again with larger buffer
                break;
            case OK:
            case CLOSED:
                break;
        }
    }

    public ByteBuffer allocateAppBuffer() {
        return allocateAppBuffer(0);
    }

    public ByteBuffer allocateAppBuffer(int suggestedSize) {
        ensureSslEngineInitialized(false);
        int requiredSize = Math.max(sslEngine.getSession().getApplicationBufferSize(), suggestedSize);
        return getBufferFromPool(requiredSize);
    }

    public ByteBuffer allocateNetworkBuffer() {
        ensureSslEngineInitialized(false);
        return getBufferFromPool(sslEngine.getSession().getPacketBufferSize());
    }

    public ByteBuffer allocateNetworkBuffer(int suggestedSize) {
        ensureSslEngineInitialized(false);
        int requiredSize = Math.max(sslEngine.getSession().getPacketBufferSize(), suggestedSize);
        return getBufferFromPool(requiredSize);
    }

    private ByteBuffer enlargeBuffer(ByteBuffer oldBuffer, int suggestedCapacity) {
        // Cap buffer size to prevent excessive memory usage
        int newCapacity;
        if (suggestedCapacity > oldBuffer.capacity()) {
            newCapacity = Math.min(suggestedCapacity, maxBufferSize);
        } else {
            // If the suggested capacity is still too small, double the size (with max limit)
            newCapacity = Math.min(oldBuffer.capacity() * 2, maxBufferSize);
        }

        ByteBuffer newBuffer = getBufferFromPool(newCapacity);
        
        // Copy any remaining data from the old buffer to the new one
        oldBuffer.flip();
        newBuffer.put(oldBuffer);
        
        // Release the old buffer back to the pool
        releaseBufferToPool(oldBuffer);
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Enlarged buffer from %d to %d bytes", oldBuffer.capacity(), newBuffer.capacity());
        }
        
        return newBuffer;
    }

    private void sendNetworkBuffer(SocketChannel socketChannel) throws SSLException {
        networkOutBuffer.flip(); // Change from reading to writing
        // Send data over the wire
        while(networkOutBuffer.hasRemaining()) {
            try {
                socketChannel.write(networkOutBuffer);
            } catch (IOException e) {
                throw new SSLException("Failed to write wrapped buffer.", e);
            }
        }
    }

    public static class UnwrapResult {
        private final ByteBuffer dataBuffer;
        private final SSLEngineResult result;

        private UnwrapResult(ByteBuffer dataBuffer, SSLEngineResult result) {
            this.dataBuffer = dataBuffer;
            this.result = result;
        }

        public ByteBuffer getDataBuffer() {
            return dataBuffer;
        }

        public SSLEngineResult getResult() {
            return result;
        }
    }

    public boolean wasHandshakeSuccessful() {
        return handshakeSuccessful.getCount() == 0;
    }

    public boolean awaitHandshake(long msToWait) throws InterruptedException {
        return handshakeSuccessful.await(msToWait, TimeUnit.MILLISECONDS);
    }

    public void resetHandshakeStatus() {
        handshakeSuccessful = new CountDownLatch(1);
    }

    // Static cleanup method to release all pooled buffers 
    public static void releaseAllPooledBuffers() {
        BUFFER_POOL.clear();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Released all pooled buffers");
        }
    }
}
