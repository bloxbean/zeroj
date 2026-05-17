package com.bloxbean.cardano.zeroj.circuit.annotation.processor;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.TypeElement;
import java.util.Set;

/**
 * Service-registered annotation processor placeholder for circuit annotation
 * code generation.
 *
 * <p>Functional processing is introduced in Phase 4. Until then, this processor
 * deliberately claims no annotations and performs no source generation.</p>
 */
public final class CircuitAnnotationProcessor extends AbstractProcessor {

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Set.of();
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latest();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        return false;
    }
}
