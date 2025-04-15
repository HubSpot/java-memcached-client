package net.spy.memcached.compat;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;

public class BufferUtils {
    public static void clean(ByteBuffer buffer) {
        if (buffer == null || !buffer.isDirect()) return;
        try {
            Method cleanerMethod = buffer.getClass().getMethod("cleaner");
            cleanerMethod.setAccessible(true);
            Object cleaner = cleanerMethod.invoke(buffer);
            if (cleaner != null) {
                Method cleanMethod = cleaner.getClass().getMethod("clean");
                cleanMethod.invoke(cleaner);
            }
        } catch (Exception e) {
            // Log or ignore; best effort
        }
    }
} 