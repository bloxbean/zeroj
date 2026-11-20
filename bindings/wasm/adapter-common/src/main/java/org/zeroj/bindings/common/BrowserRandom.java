package org.zeroj.bindings.common;

import org.graalvm.webimage.api.JS;
import org.zeroj.api.SecureRandoms;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

/** JCA bridge for the pinned Web Image toolchain. Installed even when WebCrypto is absent, so no weak fallback exists. */
final class BrowserRandom {
    static final String NAME = "ZerojWebCrypto";
    @JS.Coerce
    @JS(args={"n"}, value="""
        try {
          if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') return null;
          let result = '';
          for (let offset = 0; offset < n; offset += 65536) {
            const bytes = new Uint8Array(Math.min(65536, n - offset));
            globalThis.crypto.getRandomValues(bytes);
            for (const b of bytes) result += b.toString(16).padStart(2, '0');
            bytes.fill(0);
          }
          return result;
        } catch (_) { return null; }
        """)
    private static native String entropy(int n);
    static void install() {
        Security.insertProviderAt(new WebProvider(), 1);
        if (!SecureRandoms.create().getProvider().getName().equals(NAME))
            throw new ProviderException("Safe randomness provider unavailable");
    }
    static final class WebProvider extends Provider implements SecureRandoms.WebImageEntropyProvider {
        WebProvider() {
            super(NAME,"1.0","Browser WebCrypto; fail closed");
            putService(new Service(this,"SecureRandom","WebCrypto",Spi.class.getName(),null,null) {
                @Override public Object newInstance(Object ignored) { return new Spi(); }
            });
        }
    }
    static final class Spi extends SecureRandomSpi {
        @Override protected void engineSetSeed(byte[] ignored) { }
        @Override protected void engineNextBytes(byte[] bytes) {
            String hex = entropy(bytes.length);
            if (hex == null || hex.length() != bytes.length * 2) {
                Arrays.fill(bytes,(byte)0);
                throw new ProviderException("WebCrypto entropy unavailable");
            }
            byte[] fresh = HexFormat.of().parseHex(hex);
            try { System.arraycopy(fresh,0,bytes,0,bytes.length); }
            finally { Arrays.fill(fresh,(byte)0); }
        }
        @Override protected byte[] engineGenerateSeed(int length) {
            byte[] b = new byte[length]; engineNextBytes(b); return b;
        }
    }
}
