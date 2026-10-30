package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.zeroj.circuit.ConstraintGraph;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.Gate;
import org.zeroj.circuit.Variable;

/** Experimental, canonical BLS12-381 graph format governed by ADR-0064. */
public final class GraphCodec {
    public static final String COMPILER = "zeroj-r1cs-bls12381-v1";
    public static final int MAX_CHARS = 16 * 1024 * 1024;
    public static final int MAX_WIRES = 200_000;
    public static final int MAX_GATES = 200_000;
    public static final int MAX_TERMS = 1_000_000;
    public static final BigInteger FR = FieldConfig.BLS12_381.prime();
    public static final ObjectMapper JSON = new ObjectMapper();
    static {
        JSON.getFactory().setStreamReadConstraints(StreamReadConstraints.builder()
                .maxNestingDepth(12).maxStringLength(128).maxNumberLength(8).build());
        JSON.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
        JSON.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
    private GraphCodec() {}
    public static IllegalArgumentException invalid() { return new IllegalArgumentException("INVALID_GRAPH"); }
    public static String hash(String text) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    public static BigInteger scalar(String text) {
        if (text == null || text.length() > 77 || !text.matches("0|[1-9][0-9]*")) throw invalid();
        BigInteger v = new BigInteger(text);
        if (v.compareTo(FR) >= 0) throw invalid();
        return v;
    }
    private static String name(JsonNode value) {
        if (value == null || !value.isTextual() || !value.textValue().matches("[A-Za-z_][A-Za-z0-9_-]{0,95}")) throw invalid();
        return value.textValue();
    }
    private static int number(JsonNode value, int min, int max) {
        if (value == null || !value.isIntegralNumber() || !value.canConvertToInt()) throw invalid();
        int n = value.intValue(); if (n < min || n > max) throw invalid(); return n;
    }
    private static void arity(JsonNode node, int length) {
        if (!node.isArray() || node.size() != length) throw invalid();
    }
    private static void exact(JsonNode node, String... fields) {
        if (!node.isObject() || node.size() != fields.length) throw invalid();
        var allowed = Set.of(fields);
        node.fieldNames().forEachRemaining(k -> { if (!allowed.contains(k)) throw invalid(); });
    }
    private static BigInteger coefficient(JsonNode value) {
        if (value == null || !value.isTextual()) throw invalid(); return scalar(value.textValue());
    }
    public static ConstraintGraph decode(String input) {
        if (input == null || input.length() > MAX_CHARS) throw invalid();
        final JsonNode root;
        try { root = JSON.readTree(input); } catch (java.io.IOException e) { throw invalid(); }
        if (root == null) throw invalid();
        exact(root,"format","version","compiler","field","name","public","secret","wires","gates");
        if (!root.path("format").asText().equals("zeroj-graph")
                || number(root.get("version"),1,1) != 1
                || !root.path("compiler").asText().equals(COMPILER)
                || !root.path("field").asText().equals("bls12-381-fr")) throw invalid();
        String graphName = name(root.get("name"));
        int count = number(root.get("wires"),1,MAX_WIRES);
        JsonNode pub = root.get("public"), sec = root.get("secret"), nodes = root.get("gates");
        if (!pub.isArray() || !sec.isArray() || pub.size()+sec.size()>4096
                || 1+pub.size()+sec.size()>count || !nodes.isArray() || nodes.size()>MAX_GATES) throw invalid();
        Variable[] wires = new Variable[count];
        boolean[] defined = new boolean[count];
        wires[0] = new Variable(0,"ONE"); defined[0] = true;
        List<Variable> publicInputs = new ArrayList<>(), secretInputs = new ArrayList<>(), intermediates = new ArrayList<>();
        var names = new HashSet<String>();
        int next=1;
        for (JsonNode list : List.of(pub,sec)) for (JsonNode item : list) {
            String n=name(item); if (!names.add(n)) throw invalid();
            wires[next]=new Variable(next,n); defined[next]=true;
            (list==pub?publicInputs:secretInputs).add(wires[next++]);
        }
        int firstIntermediate=next;
        for (;next<count;next++) { wires[next]=Variable.intermediate(next); intermediates.add(wires[next]); }
        var gates = new ArrayList<Gate>(nodes.size());
        int totalTerms=0;
        if (nodes.isEmpty() || !nodes.get(0).toString().equals("[\"c\",0,\"1\"]")) throw invalid();
        for (JsonNode node : nodes) {
            if (!node.isArray() || node.size()<2 || !node.get(0).isTextual()) throw invalid();
            String op=node.get(0).textValue(); Gate gate;
            switch (op) {
                case "c" -> { arity(node,3);
                    var out=gates.isEmpty()?wires[0]:output(node.get(1),wires,defined,firstIntermediate);
                    gate=new Gate.Const(out,coefficient(node.get(2))); defined[out.id()]=true; }
                case "a", "m" -> { arity(node,4); var out=output(node.get(1),wires,defined,firstIntermediate);
                    var left=read(node.get(2),wires,defined); var right=read(node.get(3),wires,defined);
                    gate=op.equals("a")?new Gate.Add(out,left,right):new Gate.Mul(out,left,right); defined[out.id()]=true; }
                case "e" -> { arity(node,3); gate=new Gate.AssertEq(read(node.get(1),wires,defined),read(node.get(2),wires,defined)); }
                case "b" -> { arity(node,2); gate=new Gate.AssertBoolean(read(node.get(1),wires,defined)); }
                case "l" -> { arity(node,3); var out=output(node.get(1),wires,defined,firstIntermediate);
                    var terms=node.get(2); if (!terms.isArray() || terms.size()>4096 || (totalTerms+=terms.size())>MAX_TERMS) throw invalid();
                    var list=new ArrayList<Gate.Term>(terms.size());
                    for (var term:terms) { arity(term,2); list.add(new Gate.Term(coefficient(term.get(1)),read(term.get(0),wires,defined))); }
                    gate=new Gate.LinComb(out,List.copyOf(list)); defined[out.id()]=true; }
                case "h" -> { arity(node,4); var out=output(node.get(1),wires,defined,firstIntermediate);
                    if (!node.get(2).isTextual()) throw invalid();
                    Gate.HintType type;
                    type=switch(node.get(2).textValue()) {
                        case "INVERSE" -> Gate.HintType.INVERSE;
                        case "IS_ZERO_RESULT" -> Gate.HintType.IS_ZERO_RESULT;
                        case "IS_ZERO_INVERSE" -> Gate.HintType.IS_ZERO_INVERSE;
                        default -> throw invalid();
                    };
                    gate=new Gate.Hint(out,type,read(node.get(3),wires,defined)); defined[out.id()]=true; }
                case "d" -> { arity(node,4); var inputWire=read(node.get(2),wires,defined);
                    int bits=number(node.get(3),1,253); var outs=node.get(1); arity(outs,bits);
                    var outputs=new Variable[bits];
                    for (int i=0;i<bits;i++) { outputs[i]=output(outs.get(i),wires,defined,firstIntermediate); defined[outputs[i].id()]=true; }
                    gate=new Gate.BitDecompose(outputs,inputWire,bits); }
                default -> throw invalid();
            }
            gates.add(gate);
        }
        for (boolean assigned:defined) if (!assigned) throw invalid();
        var graph=new ConstraintGraph(graphName,gates,wires[0],publicInputs,secretInputs,intermediates,count,FieldConfig.BLS12_381);
        if (!encode(graph).equals(input)) throw invalid(); // one canonical spelling, including field order
        return graph;
    }
    private static Variable read(JsonNode node, Variable[] wires, boolean[] defined) {
        int id=number(node,0,wires.length-1); if (!defined[id]) throw invalid(); return wires[id];
    }
    private static Variable output(JsonNode node, Variable[] wires, boolean[] defined, int first) {
        int id=number(node,first,wires.length-1); if (defined[id]) throw invalid(); return wires[id];
    }
    public static String encode(ConstraintGraph graph) {
        graph.requireCompatibleField(FieldConfig.BLS12_381);
        if (graph.numWires()>MAX_WIRES || graph.gates().size()>MAX_GATES) throw invalid();
        var root=JSON.createObjectNode();
        root.put("format","zeroj-graph").put("version",1).put("compiler",COMPILER).put("field","bls12-381-fr").put("name",graph.name());
        var pub=root.putArray("public"); graph.publicInputs().forEach(v->pub.add(v.name()));
        var sec=root.putArray("secret"); graph.secretInputs().forEach(v->sec.add(v.name()));
        root.put("wires",graph.numWires()); var nodes=root.putArray("gates");
        for (var gate:graph.gates()) {
            ArrayNode n=nodes.addArray();
            switch(gate) {
                case Gate.Const(var out,var value) -> n.add("c").add(out.id()).add(value.mod(FR).toString());
                case Gate.Add(var out,var left,var right) -> n.add("a").add(out.id()).add(left.id()).add(right.id());
                case Gate.Mul(var out,var left,var right) -> n.add("m").add(out.id()).add(left.id()).add(right.id());
                case Gate.AssertEq(var left,var right) -> n.add("e").add(left.id()).add(right.id());
                case Gate.AssertBoolean(var v) -> n.add("b").add(v.id());
                case Gate.LinComb(var out,var terms) -> { n.add("l").add(out.id()); var list=n.addArray();
                    for (var t:terms) list.addArray().add(t.variable().id()).add(t.coefficient().mod(FR).toString()); }
                case Gate.Hint(var out,var kind,var in) -> n.add("h").add(out.id()).add(kind.name()).add(in.id());
                case Gate.BitDecompose(var outs,var in,int bits) -> { n.add("d"); var ids=n.addArray();
                    for(var v:outs) ids.add(v.id()); n.add(in.id()).add(bits); }
                default -> throw invalid();
            }
        }
        String encoded=root.toString(); if(encoded.length()>MAX_CHARS) throw invalid(); return encoded;
    }
}
