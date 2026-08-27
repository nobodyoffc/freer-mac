package com.fasterxml.jackson.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Stub. FC-AJDK's data classes are annotated for Jackson, but nothing
 * on the paths this generator compiles reads the annotation — Gson does
 * the serialising. Declaring it here keeps the Jackson jar off the
 * classpath instead of pulling a serializer in to satisfy one marker.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
public @interface JsonIgnoreProperties {
    boolean ignoreUnknown() default false;
    String[] value() default {};
}
