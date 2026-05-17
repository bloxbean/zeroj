package com.bloxbean.cardano.zeroj.circuit.annotation.processor;

import org.junit.jupiter.api.Test;

import javax.annotation.processing.Processor;
import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CircuitAnnotationProcessorTest {

    @Test
    void processorIsServiceRegistered() {
        var processors = ServiceLoader.load(Processor.class);
        assertTrue(processors.stream()
                        .map(ServiceLoader.Provider::type)
                        .anyMatch(CircuitAnnotationProcessor.class::equals),
                "CircuitAnnotationProcessor should be discoverable via ServiceLoader");
    }
}
