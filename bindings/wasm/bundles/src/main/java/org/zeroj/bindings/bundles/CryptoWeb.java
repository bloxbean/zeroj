package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.pedersen.PedersenAdapter;
import org.zeroj.bindings.bbs.BbsAdapter;
public final class CryptoWeb {
    public static void main(String[] args) {
        WebBridge.start(Map.of("pedersen",new PedersenAdapter(),"bbs",new BbsAdapter()));
    }
}
