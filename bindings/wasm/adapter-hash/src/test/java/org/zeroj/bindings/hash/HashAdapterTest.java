package org.zeroj.bindings.hash;
import org.junit.jupiter.api.Test;
import org.zeroj.bindings.common.*;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
class HashAdapterTest {
    private final BindingSession s = new BindingSession(Map.of("hash",new HashAdapter()),false);
    private String digest(String op,String arguments) {
        var result = Boundary.parse(s.call("{\"apiVersion\":1,\"capability\":\"hash\",\"operation\":\""+op+"\",\"arguments\":"+arguments+"}"));
        assertTrue(result.get("ok").booleanValue(),result.toString());
        return result.get("value").get("digest").textValue();
    }
    @Test void standardVectors() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                digest("sha256","{\"data\":\"616263\"}"));
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                digest("sha512","{\"data\":\"616263\"}"));
        assertEquals("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
                digest("blake2b","{\"data\":\"616263\",\"outputBytes\":32}"));
        assertEquals("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                digest("blake2b","{\"data\":\"616263\",\"outputBytes\":64}"));
    }
}
