package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(
        name = "annotation-batch-threshold-matrix",
        nameTemplate = "annotation-batch-threshold-matrix-{rows}x{cols}",
        version = 1)
public class AnnotatedBatchThresholdMatrix {
    private final int rows;
    private final int cols;

    public AnnotatedBatchThresholdMatrix(
            @CircuitParam("rows") int rows,
            @CircuitParam("cols") int cols) {
        this.rows = rows;
        this.cols = cols;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public @UInt(bits = 16)
            @FixedSize(param = "cols")
            ZkArray<ZkUInt> columnMaximums,
            @Secret @UInt(bits = 16)
            @FixedSize(param = "rows", innerParam = "cols")
            ZkArray<ZkArray<ZkUInt>> measurements) {
        ZkBool ok = measurements.get(0).get(0).lte(columnMaximums.get(0));
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < cols; col++) {
                if (row != 0 || col != 0) {
                    ok = ok.and(measurements.get(row).get(col).lte(columnMaximums.get(col)));
                }
            }
        }
        return ok;
    }
}
