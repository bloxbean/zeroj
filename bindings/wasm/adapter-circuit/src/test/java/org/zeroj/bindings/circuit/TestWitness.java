package org.zeroj.bindings.circuit;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.HexFormat;
final class TestWitness {
    static String digest(BigInteger[] values) {
        try {
            var md=MessageDigest.getInstance("SHA-256");
            for(var value:values) {
                var be=value.toByteArray();var fixed=new byte[32];int n=Math.min(32,be.length);
                System.arraycopy(be,be.length-n,fixed,32-n,n);md.update(fixed);
            }
            return HexFormat.of().formatHex(md.digest());
        } catch(java.security.NoSuchAlgorithmException e) {throw new IllegalStateException(e);}
    }
}
