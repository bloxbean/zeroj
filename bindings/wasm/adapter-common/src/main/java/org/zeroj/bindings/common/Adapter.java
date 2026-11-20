package org.zeroj.bindings.common;

import com.fasterxml.jackson.databind.JsonNode;

@FunctionalInterface
public interface Adapter {
    JsonNode invoke(String operation, JsonNode arguments, BindingSession session);
}
