package org.zeroj.bindings.common;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class BoundaryTest {
    private final BindingSession session = new BindingSession(Map.of("test",(op,args,s)->{
        Boundary.fields(args,"scalar","bytes");
        return Boundary.object().put("scalar",Boundary.scalar(args,"scalar",BigInteger.valueOf(19)).toString())
                .put("bytes",Boundary.hex(Boundary.bytes(args,"bytes",1,2)));
    }),false);
    private String call(String args) {
        return session.call("{\"apiVersion\":1,\"capability\":\"test\",\"operation\":\"run\",\"arguments\":"+args+"}");
    }
    @Test void canonicalScalarAndByteContract() {
        assertTrue(Boundary.parse(call("{\"scalar\":\"18\",\"bytes\":\"00ff\"}")).get("ok").booleanValue());
        for (String scalar : new String[]{"19","-1","01","+1"," 1","1.0","1e0"})
            assertFalse(Boundary.parse(call("{\"scalar\":\""+scalar+"\",\"bytes\":\"00\"}")).get("ok").booleanValue());
        for (String bytes : new String[]{"0","FF","gg","","000000"})
            assertFalse(Boundary.parse(call("{\"scalar\":\"1\",\"bytes\":\""+bytes+"\"}")).get("ok").booleanValue());
    }
    @Test void rejectsDuplicateTrailingUnknownAndLargeInput() {
        assertThrows(BindingException.class,()->Boundary.parse("{\"x\":1,\"x\":2}"));
        assertThrows(BindingException.class,()->Boundary.parse("{}{}"));
        assertThrows(BindingException.class,()->Boundary.parse(" ".repeat(Boundary.MAX_REQUEST_CHARS+1)));
        assertFalse(Boundary.parse(call("{\"scalar\":\"1\",\"bytes\":\"00\",\"secret\":\"do not echo\"}")).get("ok").booleanValue());
        assertFalse(call("{}").contains("Exception"));
    }
    @Test void secretOptInAndTypedHandles() {
        assertEquals("EXPERIMENTAL_SECRETS_DISABLED",assertThrows(BindingException.class,session::requireSecrets).code());
        String handle = session.retain(BigInteger.TEN);
        assertEquals(BigInteger.TEN,session.get(handle,BigInteger.class));
        assertThrows(BindingException.class,()->session.get(handle,String.class));
        assertThrows(BindingException.class,()->session.get("foreign",BigInteger.class));
    }
    @Test void integerDoesNotTruncateOrOverflow() {
        for(String value:new String[]{"1.5","2147483648","\"1\""})
            assertThrows(BindingException.class,()->Boundary.integer(Boundary.parse("{\"n\":"+value+"}"),"n",0,5));
    }
}
