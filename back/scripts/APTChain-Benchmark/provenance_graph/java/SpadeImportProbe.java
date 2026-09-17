import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import spade.core.AbstractEdge;
import spade.core.AbstractVertex;
import spade.core.Graph;

/** Count and validate an EvidenceForge graph through SPADE's official JSON reporter. */
public final class SpadeImportProbe {
    private static boolean isType(Map<String, String> nodeTypes, String id, String type) {
        return type.equals(nodeTypes.get(id));
    }

    private static boolean validDirection(
            String eventType,
            String source,
            String target,
            Map<String, String> nodeTypes) {
        boolean sourceActor = isType(nodeTypes, source, "Subject")
                || isType(nodeTypes, source, "Host");
        boolean targetActor = isType(nodeTypes, target, "Subject")
                || isType(nodeTypes, target, "Host");
        if ("EVENT_EXECUTE".equals(eventType)) {
            return sourceActor && isType(nodeTypes, target, "Subject");
        }
        if ("EVENT_READ".equals(eventType) || "EVENT_LOADLIBRARY".equals(eventType)) {
            return isType(nodeTypes, source, "FileObject")
                    && targetActor;
        }
        if ("EVENT_WRITE".equals(eventType) || "EVENT_CREATE_OBJECT".equals(eventType)) {
            return sourceActor
                    && isType(nodeTypes, target, "FileObject");
        }
        if ("EVENT_REGISTRY_MODIFY".equals(eventType)) {
            return sourceActor
                    && isType(nodeTypes, target, "RegistryKeyObject");
        }
        if ("EVENT_CONNECT".equals(eventType)) {
            boolean sourceFlow = isType(nodeTypes, source, "NetFlowObject");
            boolean targetFlow = isType(nodeTypes, target, "NetFlowObject");
            return (sourceActor && targetFlow) || (sourceFlow && targetActor);
        }
        return true;
    }

    private static String mapToJson(Map<String, Integer> values) {
        StringBuilder output = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Integer> entry : values.entrySet()) {
            if (!first) {
                output.append(',');
            }
            first = false;
            output.append('"').append(entry.getKey()).append("\":").append(entry.getValue());
        }
        return output.append('}').toString();
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("usage: SpadeImportProbe <spade.jsonl>");
        }
        Graph graph = Graph.importGraphFromJSONFile(arguments[0]);
        Map<String, String> nodeTypes = new HashMap<>();
        for (AbstractVertex vertex : graph.vertexSet()) {
            nodeTypes.put(vertex.id(), vertex.getAnnotation("cdm.type"));
        }

        Map<String, Integer> edgeTypes = new TreeMap<>();
        Map<String, Integer> directionChecks = new TreeMap<>();
        for (AbstractEdge edge : graph.edgeSet()) {
            String eventType = edge.getAnnotation("cdm.type");
            edgeTypes.put(eventType, edgeTypes.getOrDefault(eventType, 0) + 1);
            String source = edge.getChildVertex().id();
            String target = edge.getParentVertex().id();
            if (validDirection(eventType, source, target, nodeTypes)) {
                directionChecks.put(eventType, directionChecks.getOrDefault(eventType, 0) + 1);
            }
        }

        System.out.println(
                "{\"nodes\":" + graph.vertexSet().size()
                + ",\"edges\":" + graph.edgeSet().size()
                + ",\"edges_by_type\":" + mapToJson(edgeTypes)
                + ",\"valid_direction_by_type\":" + mapToJson(directionChecks)
                + "}");
    }
}
