package org.zeroj.bindings.common;

import org.graalvm.webimage.api.JS;
import org.graalvm.webimage.api.JSString;
import java.util.Map;
import java.util.function.Function;

public final class WebBridge {
    private WebBridge() {}
    @JS.Coerce
    @JS("return globalThis.ZEROJ_EXPERIMENTAL_SECRETS === true;")
    private static native boolean experimentalSecrets();
    @JS(args={"handler"}, value="""
        globalThis.zerojCall = handler;
        if (globalThis.zerojReady) globalThis.zerojReady();
        """)
    private static native void export(Function<JSString,JSString> handler);
    public static void start(Map<String, Adapter> adapters) {
        BrowserRandom.install();
        BindingSession session = new BindingSession(adapters,experimentalSecrets());
        export(value -> JSString.of(session.call(value.asString())));
    }
}
