package org.zeroj.bindings.notes;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import org.zeroj.bindings.common.*;
import org.zeroj.circuit.lib.jubjub.*;

/** Delivery only: ownership, registry admission, spends and nullifiers remain application policy. */
public final class NotesAdapter implements Adapter {
    private record ViewingKey(NoteViewingKey key) implements AutoCloseable {
        @Override public void close() { key.destroy(); }
    }
    @Override public JsonNode invoke(String op, JsonNode a, BindingSession s) {
        s.requireSecrets();
        return switch(op) {
            case "generateViewingKey", "restoreViewingKey" -> {
                Boundary.fields(a,op.equals("generateViewingKey")?new String[]{}:new String[]{"secret"});
                byte[] secret=op.equals("restoreViewingKey")?Boundary.bytes(a,"secret",32,32):null;
                try {
                    var key=secret==null?NoteViewingKey.generate(s.random()):NoteViewingKey.restore(secret);
                    yield Boundary.object().put("handle",s.retain(new ViewingKey(key))).put("readerKey",Boundary.hex(key.readerKey().encode()));
                } finally {if(secret!=null)Arrays.fill(secret,(byte)0);}
            }
            case "exportViewingKey" -> {
                Boundary.fields(a,"key");byte[] bytes=key(a,s).exportSecret();
                try {yield Boundary.object().put("secret",Boundary.hex(bytes));}finally{Arrays.fill(bytes,(byte)0);}
            }
            case "createOpening", "restoreOpening" -> {
                Boundary.fields(a,op.equals("createOpening")?new String[]{"value"}:new String[]{"value","blinding"});
                var value=Boundary.scalar(a,"value",BigInteger.ONE.shiftLeft(64));
                var opening=op.equals("createOpening")?NoteOpening.random(value,s.random()):
                        NoteOpening.of(value,Boundary.scalar(a,"blinding",JubjubCurve.SUBGROUP_ORDER));
                var point=opening.commitment();
                yield Boundary.object().put("handle",s.retain(opening)).put("commitment",Boundary.hex(point.toBytes()))
                        .put("u",point.affineU().toString()).put("v",point.affineV().toString());
            }
            case "exportOpening" -> {
                Boundary.fields(a,"opening");var opening=s.get(Boundary.text(a,"opening"),NoteOpening.class);
                yield Boundary.object().put("value",opening.value().toString()).put("blinding",opening.blinding().toString());
            }
            case "seal" -> {
                Boundary.fields(a,"opening","readers");JsonNode readers=a.get("readers");
                if(readers==null||!readers.isArray()||readers.isEmpty()||readers.size()>32)throw Boundary.invalid();
                var keys=new ArrayList<NoteReaderKey>();
                for(var reader:readers) keys.add(NoteReaderKey.decode(Boundary.bytes(Boundary.object().set("key",reader),"key",32,32)));
                var opening=s.get(Boundary.text(a,"opening"),NoteOpening.class);
                var out=Boundary.object();var deliveries=out.putArray("deliveries");
                ConfidentialNotes.seal(opening,keys,s.random()).forEach(bytes->deliveries.add(Boundary.hex(bytes)));yield out;
            }
            case "open" -> {
                Boundary.fields(a,"key","delivery","u","v");
                var result=NoteScanner.of(key(a,s)).open(Boundary.bytes(a,"delivery",0,4096),
                        Boundary.scalar(a,"u",JubjubCurve.BASE_FIELD_PRIME),Boundary.scalar(a,"v",JubjubCurve.BASE_FIELD_PRIME));
                if(result.isEmpty())yield Boundary.object().put("opened",false);
                var opening=result.get();yield Boundary.object().put("opened",true).put("opening",s.retain(opening));
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }
    private static NoteViewingKey key(JsonNode a, BindingSession s) {return s.get(Boundary.text(a,"key"),ViewingKey.class).key;}
}
