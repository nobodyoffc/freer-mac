package com.fc.fc_ajdk.utils;

/**
 * JVM stub shadowing FC-AJDK's own TimberLogger, which pulls in
 * `android.util.Log` and Timber's Tree hierarchy. It sits first on the
 * javac sourcepath so the real one is never compiled. Vector
 * generation is a batch job — log output is noise, so every call is a
 * no-op.
 */
public class TimberLogger {
    public static void init(String tag) {}
    public static void configureLogging(boolean filterGms) {}

    public static void v(String message) {}
    public static void d(String message) {}
    public static void i(String message) {}
    public static void w(String message) {}
    public static void e(String message) {}

    public static void v(String tag, String message, Object... args) {}
    public static void d(String tag, String message, Object... args) {}
    public static void i(String tag, String message, Object... args) {}
    public static void w(String tag, String message, Object... args) {}
    public static void e(String tag, String message, Object... args) {}
    public static void d(String tag, Throwable t, String message, Object... args) {}
    public static void w(String tag, Throwable t, String message, Object... args) {}
    public static void e(String tag, Throwable t, String message, Object... args) {}
}
