package net.spy.memcached.ops;

import java.io.IOException;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLException;

import net.spy.memcached.MemcachedNode;
import net.spy.memcached.tls.TLSConnectionManager;

public class TLSWrappedOperation implements Operation {

  private final Operation delegate;
  private ByteBuffer wrappedBuffer;

  public TLSWrappedOperation(Operation op) {
    this.delegate = op;
  }

  @Override
  public boolean isCancelled() {
    return delegate.isCancelled();
  }

  @Override
  public boolean hasErrored() {
    return delegate.hasErrored();
  }

  @Override
  public OperationException getException() {
    return delegate.getException();
  }

  @Override
  public OperationCallback getCallback() {
    return delegate.getCallback();
  }

  @Override
  public void cancel() {
    delegate.cancel();
  }

  @Override
  public OperationState getState() {
    return delegate.getState();
  }

  @Override
  public ByteBuffer getBuffer() {
    return wrappedBuffer;
  }

  @Override
  public void writing() {
    delegate.writing();
  }

  @Override
  public void writeComplete() {
    delegate.writeComplete();
  }

  @Override
  public void initialize() {
    delegate.initialize();
  }

  @Override
  public void readFromBuffer(ByteBuffer data) throws IOException {
    delegate.readFromBuffer(data);
  }

  @Override
  public void handleRead(ByteBuffer data) {
    delegate.handleRead(data);
  }

  @Override
  public MemcachedNode getHandlingNode() {
    return delegate.getHandlingNode();
  }

  @Override
  public void setHandlingNode(MemcachedNode to) {
    delegate.setHandlingNode(to);
  }

  @Override
  public void timeOut() {
    delegate.timeOut();
  }

  @Override
  public boolean isTimedOut() {
    return delegate.isTimedOut();
  }

  @Override
  public boolean isTimedOut(long ttlMillis) {
    return delegate.isTimedOut(ttlMillis);
  }

  @Override
  public boolean isTimedOutUnsent() {
    return delegate.isTimedOutUnsent();
  }

  @Override
  public long getWriteCompleteTimestamp() {
    return delegate.getWriteCompleteTimestamp();
  }

  @Override
  public byte[] getErrorMsg() {
    return delegate.getErrorMsg();
  }

  @Override
  public void addClone(Operation op) {
    delegate.addClone(op);
  }

  @Override
  public int getCloneCount() {
    return delegate.getCloneCount();
  }

  @Override
  public void setCloneCount(int count) {
    delegate.setCloneCount(count);
  }

  public void wrapBufferForTls(TLSConnectionManager tlsConnectionManager) throws SSLException {
    this.wrappedBuffer = tlsConnectionManager.allocateNetworkBuffer(delegate.getBuffer().capacity());
    tlsConnectionManager.wrapBufferForSend(delegate.getBuffer(), wrappedBuffer);
  }

  public void resetTlsConnection() {
    if (wrappedBuffer != null) {
      wrappedBuffer = null;
    }
  }

  public boolean requiresWrapping() {
    return wrappedBuffer == null;
  }
}
