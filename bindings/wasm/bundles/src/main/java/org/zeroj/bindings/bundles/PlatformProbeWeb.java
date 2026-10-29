package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.common.WebBridge;
/** Test-only runtime fingerprint probe, excluded from consumer bundle descriptors. */
public final class PlatformProbeWeb {
    public static void main(String[] args) {
        WebBridge.start(Map.of("probe", (operation, arguments, session) -> {
            if (operation.equals("entropy")) {
                Boundary.fields(arguments,"length");
                byte[] bytes=new byte[Boundary.integer(arguments,"length",0,131073)];
                session.random().nextBytes(bytes);
                return Boundary.object().put("bytes",Boundary.hex(bytes));
            }
            return Boundary.object()
                .put("osName",System.getProperty("os.name"))
                .put("vmName",System.getProperty("java.vm.name"))
                .put("imageCode",System.getProperty("org.graalvm.nativeimage.imagecode"))
                .put("runtime",System.getProperty("java.runtime.name"));
        }));
    }
}
