/**
 * Copyright (C) 2006-2009 Dustin Sallings
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

package net.spy.memcached.protocol.binary;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;

import junit.framework.TestCase;

import net.spy.memcached.OperationFactory;
import net.spy.memcached.ops.GetOperation;
import net.spy.memcached.ops.OperationException;
import net.spy.memcached.ops.OperationStatus;
import net.spy.memcached.ops.StatusCode;

import static net.spy.memcached.protocol.binary.OperationImpl.decodeInt;
import static net.spy.memcached.protocol.binary.OperationImpl.decodeLong;
import static net.spy.memcached.protocol.binary.OperationImpl.decodeUnsignedInt;

/**
 * Test operation stuff.
 */
public class OperatonTest extends TestCase {

  public void testIntegerDecode() {
    assertEquals(129, decodeInt(new byte[] { 0, 0, 0, (byte) 0x81 }, 0));
    assertEquals(129 * 256, decodeInt(new byte[] { 0, 0, (byte) 0x81, 0 }, 0));
    assertEquals(129 * 256 * 256,
        decodeInt(new byte[] { 0, (byte) 0x81, 0, 0 }, 0));
    assertEquals(129 * 256 * 256 * 256,
        decodeInt(new byte[] { (byte) 0x81, 0, 0, 0 }, 0));
  }

  public void testUnsignedIntegerDecode() {
    assertEquals(129, decodeUnsignedInt(new byte[] { 0, 0, 0, (byte) 0x81 },
        0));
    assertEquals(129 * 256,
        decodeUnsignedInt(new byte[] { 0, 0, (byte) 0x81, 0 }, 0));
    assertEquals(129 * 256 * 256,
        decodeUnsignedInt(new byte[] { 0, (byte) 0x81, 0, 0 }, 0));
    assertEquals(129L * 256L * 256L * 256L,
        decodeUnsignedInt(new byte[] { (byte) 0x81, 0, 0, 0 }, 0));
  }

  public void testLongDecode() {
    assertEquals(4294967296L,
        decodeLong(new byte[]{0, 0, 0, 1, 0, 0, 0, 0}, 0));
    assertEquals(1L,
        decodeLong(new byte[]{0, 0, 0, 0, 0, 0, 0, 1}, 0));
  }

  public void testOperationStatusString() {
    String s = String.valueOf(OperationImpl.STATUS_OK);
    assertEquals("{OperationStatus success=true:  OK}", s);
  }

  public void testInvalidMagicRaisesException() {
    byte[] header = new byte[24];
    header[0] = (byte) 0x45;
    header[8] = (byte) 0x6F;
    header[9] = (byte) 0x20;
    header[10] = (byte) 0x6D;
    header[11] = (byte) 0x61;

    AtomicReference<OperationStatus> received = new AtomicReference<>();
    GetOperation op = newGetOperation(received);

    IOException thrown = null;
    try {
      op.readFromBuffer(ByteBuffer.wrap(header));
    } catch (IOException e) {
      thrown = e;
    }

    assertNotNull("Expected IOException for invalid magic byte", thrown);
    assertTrue(thrown instanceof OperationException);
    assertTrue(thrown.getMessage().contains("Invalid magic byte"));
    assertNotNull(received.get());
    assertFalse(received.get().isSuccess());
    assertEquals(StatusCode.ERR_INTERNAL, received.get().getStatusCode());
  }

  public void testMismatchedResponseCmdRaisesException() {
    byte[] header = new byte[24];
    header[0] = (byte) 0x81;
    header[1] = (byte) 0x7A;

    AtomicReference<OperationStatus> received = new AtomicReference<>();
    GetOperation op = newGetOperation(received);

    IOException thrown = null;
    try {
      op.readFromBuffer(ByteBuffer.wrap(header));
    } catch (IOException e) {
      thrown = e;
    }

    assertNotNull("Expected IOException for mismatched response command", thrown);
    assertTrue(thrown instanceof OperationException);
    assertTrue(thrown.getMessage().contains("Unexpected response command"));
    assertEquals(StatusCode.ERR_INTERNAL, received.get().getStatusCode());
  }

  public void testInvalidOpaqueRaisesException() {
    byte[] header = new byte[24];
    header[0] = (byte) 0x81;
    header[1] = (byte) 0x00;
    header[12] = (byte) 0x7F;
    header[13] = (byte) 0xFF;
    header[14] = (byte) 0xFF;
    header[15] = (byte) 0xFE;

    AtomicReference<OperationStatus> received = new AtomicReference<>();
    GetOperation op = newGetOperation(received);

    IOException thrown = null;
    try {
      op.readFromBuffer(ByteBuffer.wrap(header));
    } catch (IOException e) {
      thrown = e;
    }

    assertNotNull("Expected IOException for invalid opaque", thrown);
    assertTrue(thrown instanceof OperationException);
    assertTrue(thrown.getMessage().contains("Opaque is not valid"));
    assertEquals(StatusCode.ERR_INTERNAL, received.get().getStatusCode());
  }

  private static GetOperation newGetOperation(
      final AtomicReference<OperationStatus> received) {
    OperationFactory opFact = new BinaryOperationFactory();
    return opFact.get("key", new GetOperation.Callback() {
      public void receivedStatus(OperationStatus s) {
        received.set(s);
      }

      public void gotData(String k, int flags, byte[] data) {
      }

      public void complete() {
      }
    });
  }
}
