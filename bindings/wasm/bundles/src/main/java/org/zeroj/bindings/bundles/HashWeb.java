package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.hash.HashAdapter;
public final class HashWeb {
    public static void main(String[] args) { WebBridge.start(Map.of("hash",new HashAdapter())); }
}
