package org.zeroj.blst.ffm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 M8: GraalVM native image needs every FFM downcall shape registered at build time
 * ({@code reachability-metadata.json}, {@code foreign.downcalls}); a missing one fails only at run
 * time inside the image. This test binds every handle and requires the metadata to list exactly the
 * shapes the binding uses.
 */
class NativeImageForeignMetadataTest {

    @Test
    void foreignMetadataListsExactlyTheBoundDowncallShapes() throws Exception {
        // Force every binding class to bind its handles.
        Class.forName(BlstCurve.class.getName());
        Class.forName(BlstG1Msm.class.getName());
        Class.forName(BlstG2Msm.class.getName());

        Set<String> bound = new HashSet<>();
        for (FunctionDescriptor d : BlstFfm.BOUND_DESCRIPTORS) {
            List<String> params = new ArrayList<>();
            for (MemoryLayout l : d.argumentLayouts()) params.add(name(l));
            bound.add(d.returnLayout().map(NativeImageForeignMetadataTest::name).orElse("void") + params);
        }

        Set<String> declared = new HashSet<>();
        try (InputStream in = BlstFfm.class.getResourceAsStream(
                "/META-INF/native-image/org.zeroj/zeroj-blst/reachability-metadata.json")) {
            assertNotNull(in);
            for (JsonNode d : new ObjectMapper().readTree(in).get("foreign").get("downcalls")) {
                List<String> params = new ArrayList<>();
                d.get("parameterTypes").forEach(p -> params.add(p.asText()));
                declared.add(d.get("returnType").asText() + params);
            }
        }
        assertEquals(bound, declared);
    }

    private static String name(MemoryLayout layout) {
        if (layout.equals(ValueLayout.JAVA_INT)) return "jint";
        if (layout.equals(ValueLayout.JAVA_LONG)) return "jlong";
        if (layout.equals(ValueLayout.JAVA_BOOLEAN)) return "jboolean";
        if (layout.equals(ValueLayout.ADDRESS)) return "void*";
        throw new AssertionError("unmapped layout " + layout);
    }
}
