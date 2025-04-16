package net.spy.memcached.tls;

import java.io.Closeable;
import java.io.IOException;
import java.lang.management.BufferPoolMXBean;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import net.spy.memcached.compat.log.Logger;
import net.spy.memcached.compat.log.LoggerFactory;

public class TLSConnectionManager implements Closeable {

    private static final Logger LOG = LoggerFactory.getLogger(TLSConnectionManager.class);
    private static final AtomicLong totalDirectMemoryUsed = new AtomicLong(0);
    
    // Get the direct buffer pool MX bean for accurate native memory tracking
    private static final BufferPoolMXBean directBufferPool = ManagementFactory.getPlatformMXBeans(BufferPoolMXBean.class)
        .stream()
        .filter(pool -> pool.getName().equals("direct"))
        .findFirst()
        .orElse(null);

    private static void logNativeMemoryStats(String operation, ByteBuffer buffer) {
        if (buffer != null && buffer.isDirect()) {
            long bufferSize = buffer.capacity();
            totalDirectMemoryUsed.addAndGet(bufferSize);
            
            if (directBufferPool != null) {
                LOG.info("%s - Native memory stats: current buffer: %s bytes, total count: %s, total capacity: %s bytes, memory used: %s bytes",
                    operation,
                    bufferSize,
                    directBufferPool.getCount(),
                    directBufferPool.getTotalCapacity(),
                    directBufferPool.getMemoryUsed());
            } else {
                // Fallback if MXBean not available
                LOG.info("%s - Direct memory: current buffer: %s bytes, total allocated: %s bytes",
                    operation, bufferSize, totalDirectMemoryUsed.get());
            }
        }
    }

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

    public TLSConnectionManager(SSLContext sslContext) {
        this.sslContext = sslContext;
        this.handshakeSuccessful = new CountDownLatch(1);
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
        sslEngine.setUseClientMode(true);
    }

    private void initBuffers(SSLSession session) {
        appOutBuffer = allocateAppBuffer();
        appInBuffer = allocateAppBuffer();
        networkOutBuffer = allocateNetworkBuffer();
        networkInBuffer = allocateNetworkBuffer();
        
        LOG.info("Initialized buffers - appOutBuffer: %s bytes, appInBuffer: %s bytes, networkOutBuffer: %s bytes, networkInBuffer: %s bytes",
            appOutBuffer.capacity(), appInBuffer.capacity(), networkOutBuffer.capacity(), networkInBuffer.capacity());
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
        LOG.info("Wrapping buffer - appOutBuffer: %s bytes (position: %s, remaining: %s), networkOutBuffer: %s bytes (position: %s, remaining: %s)",
            appOutBuffer.capacity(), appOutBuffer.position(), appOutBuffer.remaining(),
            networkOutBuffer.capacity(), networkOutBuffer.position(), networkOutBuffer.remaining());
            
        SSLEngineResult wrap = sslEngine.wrap(appOutBuffer, networkOutBuffer);
        
        LOG.info("Wrap result - bytesConsumed: %s, bytesProduced: %s, status: %s",
            wrap.bytesConsumed(), wrap.bytesProduced(), wrap.getStatus());
            
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

    public UnwrapResult unwrapReceivedBuffer(ByteBuffer networkInBuffer) throws IOException {
        appInBuffer.clear();
        LOG.info("Unwrapping buffer - networkInBuffer: %s bytes (position: %s, remaining: %s), appInBuffer: %s bytes",
            networkInBuffer.capacity(), networkInBuffer.position(), networkInBuffer.remaining(),
            appInBuffer.capacity());
            
        while(!Thread.currentThread().isInterrupted()) {
            SSLEngineResult unwrapResult = sslEngine.unwrap(networkInBuffer, appInBuffer);
            LOG.info("Unwrap result - bytesConsumed: %s, bytesProduced: %s, status: %s",
                unwrapResult.bytesConsumed(), unwrapResult.bytesProduced(), unwrapResult.getStatus());
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
        long freedMemory = 0;
        if (appOutBuffer != null && appOutBuffer.isDirect()) {
            freedMemory += appOutBuffer.capacity();
            totalDirectMemoryUsed.addAndGet(-appOutBuffer.capacity());
            LOG.info("Freed appOutBuffer memory: %s bytes", appOutBuffer.capacity());
        }
        if (appInBuffer != null && appInBuffer.isDirect()) {
            freedMemory += appInBuffer.capacity();
            totalDirectMemoryUsed.addAndGet(-appInBuffer.capacity());
            LOG.info("Freed appInBuffer memory: %s bytes", appInBuffer.capacity());
        }
        if (networkOutBuffer != null && networkOutBuffer.isDirect()) {
            freedMemory += networkOutBuffer.capacity();
            totalDirectMemoryUsed.addAndGet(-networkOutBuffer.capacity());
            LOG.info("Freed networkOutBuffer memory: %s bytes", networkOutBuffer.capacity());
        }
        if (networkInBuffer != null && networkInBuffer.isDirect()) {
            freedMemory += networkInBuffer.capacity();
            totalDirectMemoryUsed.addAndGet(-networkInBuffer.capacity());
            LOG.info("Freed networkInBuffer memory: %s bytes", networkInBuffer.capacity());
        }
        
        if (directBufferPool != null) {
            LOG.info("Closing TLS connection - total memory freed: %s bytes, direct buffer count: %s, total capacity: %s bytes, memory used: %s bytes",
                freedMemory,
                directBufferPool.getCount(),
                directBufferPool.getTotalCapacity(),
                directBufferPool.getMemoryUsed());
        } else {
            LOG.info("Closing TLS connection - total memory freed: %s bytes, final total direct memory used: %s bytes",
                freedMemory, totalDirectMemoryUsed.get());
        }
        closeSslEngine();
    }

    private void closeSslEngine() {
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

    private void handleHandshakeWrapResult(SocketChannel socketChannel, SSLEngineResult result) throws SSLException {
        LOG.info("Handling handshake wrap result - status: %s, bytesConsumed: %s, bytesProduced: %s",
            result.getStatus(), result.bytesConsumed(), result.bytesProduced());
            
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
        LOG.info("Handling handshake unwrap result - status: %s, bytesConsumed: %s, bytesProduced: %s",
            result.getStatus(), result.bytesConsumed(), result.bytesProduced());
            
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
        ByteBuffer buffer = ByteBuffer.allocateDirect(requiredSize);
        LOG.info("Allocated application buffer - requested: %s bytes, actual: %s bytes",
            suggestedSize, buffer.capacity());
        logNativeMemoryStats("App buffer allocation", buffer);
        return buffer;
    }

    public ByteBuffer allocateNetworkBuffer() {
        return ByteBuffer.allocateDirect(0);
    }

    public ByteBuffer allocateNetworkBuffer(int suggestedSize) {
        ensureSslEngineInitialized(false);
        int requiredSize = Math.max(sslEngine.getSession().getPacketBufferSize(), suggestedSize);
        ByteBuffer buffer = ByteBuffer.allocateDirect(requiredSize);
        LOG.info("Allocated network buffer - requested: %s bytes, actual: %s bytes",
            suggestedSize, buffer.capacity());
        logNativeMemoryStats("Network buffer allocation", buffer);
        return buffer;
    }

    private void sendNetworkBuffer(SocketChannel socketChannel) throws SSLException {
        networkOutBuffer.flip(); // Change from reading to writing
        LOG.info("Sending network buffer - capacity: %s bytes, position: %s, remaining: %s",
            networkOutBuffer.capacity(), networkOutBuffer.position(), networkOutBuffer.remaining());
            
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

    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int suggestedCapacity) {
        int oldCapacity = buffer.capacity();
        ByteBuffer newBuffer;
        
        if (suggestedCapacity > buffer.capacity()) {
            newBuffer = ByteBuffer.allocateDirect(suggestedCapacity);
            LOG.info("Enlarging buffer from %s to %s bytes (suggested capacity)",
                oldCapacity, suggestedCapacity);
        } else {
            // If the suggested capacity is still too small, double the size
            int newCapacity = buffer.capacity() * 2;
            newBuffer = ByteBuffer.allocateDirect(newCapacity);
            LOG.info("Enlarging buffer from %s to %s bytes (doubled capacity)",
                oldCapacity, newCapacity);
        }
        
        if (buffer.isDirect()) {
            totalDirectMemoryUsed.addAndGet(-oldCapacity);
            if (directBufferPool != null) {
                LOG.info("Freed buffer memory: %s bytes, current direct buffer count: %s, memory used: %s bytes",
                    oldCapacity, directBufferPool.getCount(), directBufferPool.getMemoryUsed());
            } else {
                LOG.info("Freed buffer memory: %s bytes, remaining total: %s bytes",
                    oldCapacity, totalDirectMemoryUsed.get());
            }
        }
        logNativeMemoryStats("Buffer enlarged", newBuffer);
        return newBuffer;
    }
}
