package org.zeroj.bindings.bundles;

import java.util.Map;
import java.util.function.Function;
import java.math.BigInteger;
import org.graalvm.webimage.api.JS;
import org.graalvm.webimage.api.JSString;
import org.zeroj.api.SecureRandoms;
import org.zeroj.bbs.BbsService;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;

/** Negative test only: intentionally omit the WebCrypto provider. Never a consumer profile. */
public final class UnprotectedWeb {
    @JS(args={"handler"},value="globalThis.zerojCall=handler;globalThis.zerojReady();")
    private static native void export(Function<JSString,JSString> handler);
    public static void main(String[] args) {
        var session=new BindingSession(Map.of("unprotected",(op,n,s)->{
            try { switch(op) {
                case "random" -> SecureRandoms.create().nextBytes(new byte[16]);
                case "bbs" -> BbsService.pureJava();
                case "pedersen" -> G1Pedersen.pureJava().commitScalar(BigInteger.ONE,BigInteger.ONE);
                default -> throw Boundary.invalid();
            } } catch (ExceptionInInitializerError e) {
                if(e.getCause() instanceof java.security.ProviderException)
                    throw new org.zeroj.bindings.common.BindingException("RANDOMNESS_UNAVAILABLE");
                throw e;
            }
            return Boundary.object().put("unexpectedSuccess",true);
        }),true);
        export(value->JSString.of(session.call(value.asString())));
    }
}
