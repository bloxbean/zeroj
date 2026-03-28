package com.bloxbean.cardano.zeroj.ingestion;

import java.io.IOException;
import java.io.Writer;
import java.util.List;
import java.util.Map;

/**
 * Exports audit log entries as newline-delimited JSON (NDJSON).
 *
 * <p>Uses manual string building (no reflection or Jackson) for GraalVM native-image compatibility.</p>
 */
public final class AuditExporter {

    private AuditExporter() {}

    /**
     * Export entries as NDJSON to a writer.
     */
    public static void export(List<AuditLog.AuditEntry> entries, Writer writer) throws IOException {
        for (var entry : entries) {
            writer.write(toJson(entry));
            writer.write('\n');
        }
        writer.flush();
    }

    /**
     * Export entries as a single NDJSON string.
     */
    public static String exportToString(List<AuditLog.AuditEntry> entries) {
        var sb = new StringBuilder();
        for (var entry : entries) {
            sb.append(toJson(entry)).append('\n');
        }
        return sb.toString();
    }

    /**
     * Convert a single audit entry to a JSON string.
     */
    public static String toJson(AuditLog.AuditEntry entry) {
        var sb = new StringBuilder("{");
        appendString(sb, "timestamp", entry.timestamp().toString());
        sb.append(',');
        appendString(sb, "appId", entry.appId());
        sb.append(',');
        appendString(sb, "submitterId", entry.submitterId());
        sb.append(',');
        appendStringNullable(sb, "circuitId", entry.circuitId());
        sb.append(',');
        appendStringNullable(sb, "circuitVersion", entry.circuitVersion());
        sb.append(',');
        sb.append("\"sequence\":").append(entry.sequence());
        sb.append(',');
        sb.append("\"accepted\":").append(entry.accepted());
        sb.append(',');
        appendString(sb, "stage", entry.stage().name());
        sb.append(',');
        appendStringNullable(sb, "rejectionReason",
                entry.rejectionReason() != null ? entry.rejectionReason().name() : null);
        sb.append(',');
        appendStringNullable(sb, "message", entry.message());
        sb.append(',');
        appendStringNullable(sb, "eventType", entry.eventType());
        sb.append(',');
        appendContext(sb, entry.context());
        sb.append('}');
        return sb.toString();
    }

    private static void appendString(StringBuilder sb, String key, String value) {
        sb.append('"').append(key).append("\":\"").append(escapeJson(value)).append('"');
    }

    private static void appendStringNullable(StringBuilder sb, String key, String value) {
        sb.append('"').append(key).append("\":");
        if (value == null) {
            sb.append("null");
        } else {
            sb.append('"').append(escapeJson(value)).append('"');
        }
    }

    private static void appendContext(StringBuilder sb, Map<String, String> context) {
        sb.append("\"context\":{");
        if (context != null && !context.isEmpty()) {
            boolean first = true;
            for (var e : context.entrySet()) {
                if (!first) sb.append(',');
                appendString(sb, e.getKey(), e.getValue());
                first = false;
            }
        }
        sb.append('}');
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        var sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
