package org.zeroj.bindings.circuit;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.BitSet;
import java.util.List;
import org.zeroj.bindings.common.Boundary;

/** Read-only census of existing R1CS wire references. Does not compact or change a relation. */
public final class MerkleWireCensus {
    public static void main(String[] args)throws Exception {
        var rows=Boundary.JSON.createArrayNode();
        for(int depth:new int[]{1,2,8,16,32}){
            var c=new CompiledGraph(MerkleFixtures.circuit(depth).constraintGraph());var used=new BitSet(c.numWires());
            used.set(0,c.numPublic()+1); // The constant/public ABI must be retained even if unused.
            long entries=0;
            for(var constraint:c.constraints())for(var terms:List.of(constraint.a(),constraint.b(),constraint.c())){
                entries+=terms.size();for(var entry:terms.entrySet())if(entry.getValue().signum()!=0)used.set(entry.getKey());
            }
            int unused=c.numWires()-used.cardinality();
            rows.addObject().put("depth",depth).put("wires",c.numWires()).put("constraints",c.constraints().size())
                    .put("retainedWiresIncludingPublic",used.cardinality()).put("unreferencedWires",unused).put("r1csTermEntries",entries)
                    .put("potentialQueryBytesRemoved",unused*480L);
        }
        Path out=Path.of(args[0]);Files.createDirectories(out.getParent());Files.writeString(out,rows.toPrettyString());System.out.println(rows.toPrettyString());
    }
}
