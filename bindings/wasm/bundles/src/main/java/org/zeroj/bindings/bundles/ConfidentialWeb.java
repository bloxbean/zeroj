package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.elgamal.ElGamalAdapter;
import org.zeroj.bindings.threshold.ThresholdAdapter;
import org.zeroj.bindings.notes.NotesAdapter;
public final class ConfidentialWeb {
    public static void main(String[] args) { WebBridge.start(Map.of("elgamal",new ElGamalAdapter(),
            "threshold",new ThresholdAdapter(),"confidential-notes",new NotesAdapter())); }
}
