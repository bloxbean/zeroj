package com.bloxbean.cardano.zeroj.circuit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a Java class as a ZeroJ circuit source for annotation processing.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.SOURCE)
public @interface ZKCircuit {
    String name() default "";
    String nameTemplate() default "";
    int version() default 1;
}
