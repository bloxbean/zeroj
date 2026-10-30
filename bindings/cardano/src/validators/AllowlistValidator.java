package org.zeroj.bindings.cardano;

import java.math.BigInteger;
import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

/** Local demonstration: reusable membership + explicit signed claim, not a nullifier protocol. */
@SpendingValidator
public class AllowlistValidator {
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static BigInteger approvedRoot;
    @Param static byte[] authorizedSigner;

    record Claim(BigInteger action,byte[] piA,byte[] piB,byte[] piC) {}
    @Entrypoint public static boolean validate(PlutusData datum,Claim claim,ScriptContext ctx) {
        if (!claim.action().equals(BigInteger.ONE)) return false;
        boolean signed=false;
        for(var signer:ctx.txInfo().signatories())
            signed=signed||Builtins.equalsByteString(signer.hash(),authorizedSigner);
        if (!signed) return false;
        PlutusData inputs=Builtins.unListData(datum);
        if (Builtins.nullList(inputs)) return false;
        BigInteger root=Builtins.asInteger(Builtins.headList(inputs));
        if (!root.equals(approvedRoot)||!Builtins.nullList(Builtins.tailList(inputs))) return false;
        return Groth16BLS12381Lib.verify(datum,claim.piA(),claim.piB(),claim.piC(),
                vkAlpha,vkBeta,vkGamma,vkDelta,vkIc);
    }
}
