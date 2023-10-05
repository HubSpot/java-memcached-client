package net.spy.memcached.protocol.ascii;

import net.spy.memcached.ops.LruCrawlerOperation;
import net.spy.memcached.ops.OperationState;
import net.spy.memcached.ops.OperationStatus;
import net.spy.memcached.ops.StatusCode;

import java.nio.ByteBuffer;

public class LruCrawlerOperationImpl extends OperationImpl implements LruCrawlerOperation {

    private static final OperationStatus END = new OperationStatus(true, "END", StatusCode.SUCCESS);
    private final byte[] msg;
    private final LruCrawlerOperation.Callback callback;

    public LruCrawlerOperationImpl(String arg, LruCrawlerOperation.Callback callback){
        super(callback);
        this.callback = callback;
        if (arg == null){
            throw new RuntimeException("Arg to lru_crawler cannot be null");
        }

        msg = ("lru_crawler " + arg + "\r\n").getBytes();
    }

    @Override
    public void initialize() {
        setBuffer(ByteBuffer.wrap(msg));
    }

    @Override
    public void handleLine(String line) {
        if(line.equals("END")) {
            callback.receivedStatus(END);
            transitionState(OperationState.COMPLETE);
        } else {
            String[] parts = line.split(" ", 7);
            assert parts.length == 7;
            callback.gotCacheEntry(splitField(parts[0], String.class),
                    splitField(parts[1], Long.class),
                    splitField(parts[2], Long.class),
                    splitField(parts[3], Long.class),
                    splitField(parts[4], Boolean.class),
                    splitField(parts[5], Integer.class),
                    splitField(parts[6], Long.class));
        }
    }

    private <T> T splitField(String field, Class<T> clazz){
        return clazz.cast(field.split("=")[1]);
    }

    @Override
    protected void wasCancelled() {callback.receivedStatus(CANCELLED);}
}
