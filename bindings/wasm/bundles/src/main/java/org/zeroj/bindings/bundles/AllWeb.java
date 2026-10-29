package org.zeroj.bindings.bundles;
import java.util.Map;
import org.zeroj.bindings.common.WebBridge;
import org.zeroj.bindings.hash.HashAdapter;
import org.zeroj.bindings.pedersen.PedersenAdapter;
import org.zeroj.bindings.bbs.BbsAdapter;
import org.zeroj.bindings.groth16.CubicCircuit;
import org.zeroj.bindings.groth16.Groth16ProverAdapter;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;
import org.zeroj.bindings.elgamal.ElGamalAdapter;
import org.zeroj.bindings.threshold.ThresholdAdapter;
import org.zeroj.bindings.notes.NotesAdapter;
/** Optional shared image for apps using many capabilities; never imported by the runtime. */
public final class AllWeb {
    public static void main(String[] args) {
        var cubic=new CubicCircuit();
        WebBridge.start(Map.of("hash",new HashAdapter(),"pedersen",new PedersenAdapter(),"bbs",new BbsAdapter(),
                "groth16-verifier",new Groth16VerifierAdapter(),"groth16-prover",new Groth16ProverAdapter(Map.of(cubic.id(),cubic)),
                "elgamal",new ElGamalAdapter(),"threshold",new ThresholdAdapter(),"confidential-notes",new NotesAdapter()));
    }
}
