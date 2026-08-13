package androidx.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Stub of the AndroidX annotation so FC-AJDK sources compile on a plain JVM. */
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.METHOD, ElementType.PARAMETER, ElementType.FIELD, ElementType.LOCAL_VARIABLE,
         ElementType.ANNOTATION_TYPE, ElementType.PACKAGE, ElementType.TYPE_USE})
public @interface Nullable {}
