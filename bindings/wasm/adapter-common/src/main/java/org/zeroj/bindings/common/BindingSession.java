package org.zeroj.bindings.common;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.ProviderException;
import java.security.SecureRandom;
import org.zeroj.api.SecureRandoms;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** One session per worker. Handles preserve local provenance; they are not exportable evidence. */
public final class BindingSession {
    private final Map<String, Adapter> adapters;
    private final Map<String, Object> handles = new HashMap<>();
    private final boolean experimentalSecrets;
    private long nextHandle;
    public BindingSession(Map<String, Adapter> adapters, boolean experimentalSecrets) {
        this.adapters = Map.copyOf(adapters);
        this.experimentalSecrets = experimentalSecrets;
    }
    public String call(String input) {
        try {
            JsonNode n = Boundary.parse(input);
            Boundary.fields(n, "apiVersion", "capability", "operation", "arguments");
            if (Boundary.integer(n, "apiVersion", 1, 1) != 1) throw Boundary.invalid();
            String capability = Boundary.text(n,"capability"), operation = Boundary.text(n,"operation");
            JsonNode args = n.get("arguments");
            if (!args.isObject()) throw Boundary.invalid();
            JsonNode result;
            if (capability.equals("runtime")) {
                result = switch (operation) {
                    case "info" -> {
                        Boundary.fields(args);
                        var info = Boundary.object().put("apiVersion",1)
                                .put("experimentalSecrets",experimentalSecrets);
                        var list = info.putArray("capabilities");
                        adapters.keySet().stream().sorted().forEach(list::add);
                        yield info;
                    }
                    case "release" -> {
                        Boundary.fields(args,"handle");
                        Object removed = handles.remove(Boundary.text(args,"handle"));
                        if (removed instanceof AutoCloseable closeable) {
                            try { closeable.close(); } catch (Exception e) { throw new BindingException("RELEASE_FAILED"); }
                        }
                        yield Boundary.object().put("released",removed != null);
                    }
                    default -> throw new BindingException("UNSUPPORTED_OPERATION");
                };
            } else {
                Adapter adapter = adapters.get(capability);
                if (adapter == null) throw new BindingException("UNSUPPORTED_CAPABILITY");
                result = adapter.invoke(operation,args,this);
            }
            return Boundary.object().put("ok",true).set("value",result).toString();
        } catch (RuntimeException e) {
            String code = e instanceof BindingException b ? b.code()
                    : e instanceof ProviderException ? "RANDOMNESS_UNAVAILABLE" : "INVALID_REQUEST";
            return Boundary.object().put("ok",false)
                    .set("error",Boundary.object().put("code",code)).toString();
        }
    }
    public void requireSecrets() {
        if (!experimentalSecrets) throw new BindingException("EXPERIMENTAL_SECRETS_DISABLED");
        byte[] probe = new byte[16];
        try { SecureRandoms.create().nextBytes(probe); }
        finally { Arrays.fill(probe,(byte)0); }
    }
    public SecureRandom random() { requireSecrets(); return SecureRandoms.create(); }
    public String retain(Object value) {
        if (handles.size() >= 256) throw new BindingException("HANDLE_LIMIT");
        String id = "h" + (++nextHandle);
        handles.put(id,value);
        return id;
    }
    public <T> T get(String id, Class<T> type) {
        Object value = handles.get(id);
        if (!type.isInstance(value)) throw new BindingException("INVALID_HANDLE");
        return type.cast(value);
    }
}
