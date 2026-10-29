package org.zeroj.api;
import org.junit.jupiter.api.Test;
import java.security.ProviderException;
import static org.junit.jupiter.api.Assertions.*;
class SecureRandomsTest {
    @Test void ordinaryJvmAndWebImageWeakDefault() {
        String original=System.getProperty("os.name");
        try {
            System.setProperty("os.name","Browser");
            assertThrows(ProviderException.class,SecureRandoms::create);
            System.setProperty("os.name","ZerojJvmTest");
            assertNotNull(SecureRandoms.create());
        } finally {
            if(original==null) System.clearProperty("os.name"); else System.setProperty("os.name",original);
        }
    }
}
