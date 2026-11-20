package org.zeroj.crypto.groth16;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ZkeyImporterLimitsTest {
    private byte[] fixture() throws IOException {
        try(var in=getClass().getResourceAsStream("/test-circuits/cubic-bls381/cubic.zkey")) { return in.readAllBytes(); }
    }
    @Test void tighterLimitsPreserveValidImportAndRejectBeforeLargeAllocation() throws Exception {
        byte[] bytes=fixture();byte[] hash=MessageDigest.getInstance("SHA-256").digest(bytes);
        var normal=ZkeyImporterBLS381.importZkeyFull(bytes,hash);
        var bounded=ZkeyImporterBLS381.importZkeyFull(bytes,hash,new ZkeyImporterBLS381.Limits(bytes.length,4096,4096,16384));
        assertEquals(normal.constraints(),bounded.constraints());assertEquals(normal.numWires(),bounded.numWires());
        assertThrows(IOException.class,()->ZkeyImporterBLS381.importZkeyFull(bytes,hash,new ZkeyImporterBLS381.Limits(bytes.length-1,4096,4096,16384)));
        assertThrows(IOException.class,()->ZkeyImporterBLS381.importZkeyFull(bytes,hash,new ZkeyImporterBLS381.Limits(bytes.length,2,4096,16384)));
        assertThrows(IOException.class,()->ZkeyImporterBLS381.importZkeyFull(bytes,hash,new ZkeyImporterBLS381.Limits(bytes.length,4096,4096,0)));
        // A small hostile file claiming a huge FFT domain must fail before allocating its maps.
        ByteBuffer b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);b.position(12);
        while(b.remaining()>12){int id=b.getInt();int length=Math.toIntExact(b.getLong());int start=b.position();
            if(id==2){b.putInt(start+4+48+4+32+8,1<<24);break;}b.position(start+length);}
        byte[] changedHash=MessageDigest.getInstance("SHA-256").digest(bytes);
        var error=assertThrows(IOException.class,()->ZkeyImporterBLS381.importZkeyFull(bytes,changedHash,new ZkeyImporterBLS381.Limits(bytes.length,4096,4096,16384)));
        assertTrue(error.getMessage().contains("caller resource limits"));
    }
    @Test void callerCannotRelaxDefaults() {
        assertThrows(IllegalArgumentException.class,()->new ZkeyImporterBLS381.Limits(Integer.MAX_VALUE,4096,4096,16384));
        assertThrows(IllegalArgumentException.class,()->new ZkeyImporterBLS381.Limits(100,1,4096,16384));
        assertThrows(IllegalArgumentException.class,()->new ZkeyImporterBLS381.Limits(100,2,3,16384));
        assertThrows(IllegalArgumentException.class,()->new ZkeyImporterBLS381.Limits(100,2,4,-1));
    }
}
