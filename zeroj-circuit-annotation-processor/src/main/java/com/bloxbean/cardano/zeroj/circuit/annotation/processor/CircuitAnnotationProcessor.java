package com.bloxbean.cardano.zeroj.circuit.annotation.processor;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FieldElement;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Order;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.FilerException;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.Modifier;
import javax.lang.model.element.NestingKind;
import javax.lang.model.element.PackageElement;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.Diagnostic;
import javax.tools.JavaFileObject;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Annotation processor that generates Phase 4 circuit companions.
 */
public final class CircuitAnnotationProcessor extends AbstractProcessor {
    private static final String ANNOTATION_PKG = "com.bloxbean.cardano.zeroj.circuit.annotation.";
    private static final String ZK_BOOL = ANNOTATION_PKG + "ZkBool";
    private static final String ZK_BITS = ANNOTATION_PKG + "ZkBits";
    private static final String ZK_BYTES = ANNOTATION_PKG + "ZkBytes";
    private static final String ZK_FIELD = ANNOTATION_PKG + "ZkField";
    private static final String ZK_UINT = ANNOTATION_PKG + "ZkUInt";
    private static final String ZK_ARRAY = ANNOTATION_PKG + "ZkArray";
    private static final String ZK_CONTEXT = ANNOTATION_PKG + "ZkContext";

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Set.of(ZKCircuit.class.getCanonicalName());
    }

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latestSupported();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnv) {
        for (Element element : roundEnv.getElementsAnnotatedWith(ZKCircuit.class)) {
            if (element.getKind() != ElementKind.CLASS) {
                error(element, "@ZKCircuit can only be applied to classes");
                continue;
            }
            try {
                generate((TypeElement) element);
            } catch (GenerationException e) {
                error(e.element(), e.getMessage());
            } catch (IOException e) {
                error(element, "Failed to generate circuit companion: " + e.getMessage());
            }
        }
        return true;
    }

    private void generate(TypeElement sourceType) throws IOException {
        if (sourceType.getNestingKind() != NestingKind.TOP_LEVEL) {
            throw new GenerationException(sourceType,
                    "Nested @ZKCircuit classes are not supported in Phase 4");
        }

        List<ExecutableElement> proveMethods = sourceType.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.METHOD)
                .map(ExecutableElement.class::cast)
                .filter(m -> m.getAnnotation(Prove.class) != null)
                .toList();
        if (proveMethods.size() != 1) {
            throw new GenerationException(sourceType, "@ZKCircuit classes must declare exactly one @Prove method");
        }

        ExecutableElement proveMethod = proveMethods.get(0);
        if (proveMethod.getModifiers().contains(Modifier.PRIVATE)) {
            throw new GenerationException(proveMethod,
                    "@Prove method must be visible to generated code");
        }
        validateReturnType(proveMethod);

        List<CircuitParamModel> circuitParams = circuitParams(sourceType, proveMethod);
        Map<String, CircuitParamModel> circuitParamMap = circuitParams.stream()
                .collect(Collectors.toMap(CircuitParamModel::name, p -> p));

        List<InputModel> inputs = inputs(sourceType, proveMethod, circuitParamMap);
        validateInputNames(inputs);

        String packageName = packageName(sourceType);
        String sourceSimpleName = sourceType.getSimpleName().toString();
        String generatedSimpleName = sourceSimpleName + "Circuit";
        String generatedName = packageName.isEmpty()
                ? generatedSimpleName
                : packageName + "." + generatedSimpleName;

        String source = render(sourceType, packageName, sourceSimpleName, generatedSimpleName,
                proveMethod, circuitParams, inputs);
        try {
            JavaFileObject file = processingEnv.getFiler().createSourceFile(generatedName, sourceType);
            try (Writer writer = file.openWriter()) {
                writer.write(source);
            }
        } catch (FilerException ignored) {
            // Another round may have already created this file.
        }
    }

    private List<CircuitParamModel> circuitParams(TypeElement sourceType, ExecutableElement proveMethod) {
        List<ExecutableElement> constructors = sourceType.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.CONSTRUCTOR)
                .map(ExecutableElement.class::cast)
                .filter(c -> c.getParameters().stream().anyMatch(p -> p.getAnnotation(CircuitParam.class) != null))
                .toList();

        if (constructors.size() > 1) {
            throw new GenerationException(sourceType,
                    "Only one constructor with @CircuitParam parameters is supported in Phase 4");
        }
        if (constructors.isEmpty()) {
            if (!proveMethod.getModifiers().contains(Modifier.STATIC)) {
                requireVisibleNoArgConstructor(sourceType);
            }
            return List.of();
        }

        ExecutableElement constructor = constructors.get(0);
        if (!proveMethod.getModifiers().contains(Modifier.STATIC)
                && constructor.getModifiers().contains(Modifier.PRIVATE)) {
            throw new GenerationException(constructor, "@CircuitParam constructor must be visible to generated code");
        }

        List<CircuitParamModel> params = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (VariableElement parameter : constructor.getParameters()) {
            CircuitParam annotation = parameter.getAnnotation(CircuitParam.class);
            if (annotation == null) {
                throw new GenerationException(parameter,
                        "All parameters in a @CircuitParam constructor must be annotated with @CircuitParam");
            }
            String name = annotation.value().isBlank()
                    ? parameter.getSimpleName().toString()
                    : annotation.value();
            if (!isSimpleName(name)) {
                throw new GenerationException(parameter,
                        "@CircuitParam name must match [A-Za-z_][A-Za-z0-9_]*");
            }
            if (!names.add(name)) {
                throw new GenerationException(parameter, "Duplicate @CircuitParam name: " + name);
            }
            if (!isSupportedCircuitParamType(parameter.asType())) {
                throw new GenerationException(parameter,
                        "@CircuitParam type must be a primitive or boxed integral/boolean/char type, "
                                + "String, BigInteger, or enum");
            }
            params.add(new CircuitParamModel(name, parameter.getSimpleName().toString(),
                    parameter.asType().toString(), isIntegerCircuitParam(parameter.asType())));
        }
        return params;
    }

    private void requireVisibleNoArgConstructor(TypeElement sourceType) {
        List<ExecutableElement> constructors = sourceType.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.CONSTRUCTOR)
                .map(ExecutableElement.class::cast)
                .toList();
        if (constructors.isEmpty()) {
            return;
        }
        boolean hasVisibleNoArg = constructors.stream()
                .anyMatch(c -> c.getParameters().isEmpty() && !c.getModifiers().contains(Modifier.PRIVATE));
        if (!hasVisibleNoArg) {
            throw new GenerationException(sourceType,
                    "A visible no-arg constructor is required unless the circuit uses a @CircuitParam constructor");
        }
    }

    private List<InputModel> inputs(TypeElement sourceType, ExecutableElement proveMethod,
                                    Map<String, CircuitParamModel> circuitParams) {
        List<InputModel> fieldInputs = sourceType.getEnclosedElements().stream()
                .filter(e -> e.getKind() == ElementKind.FIELD)
                .map(VariableElement.class::cast)
                .filter(f -> f.getAnnotation(Public.class) != null || f.getAnnotation(Secret.class) != null)
                .map(f -> fieldInput(f, circuitParams))
                .toList();

        List<InputModel> parameterInputs = new ArrayList<>();
        for (VariableElement parameter : proveMethod.getParameters()) {
            if (parameter.getAnnotation(CircuitParam.class) != null) {
                throw new GenerationException(parameter,
                        "@CircuitParam is only supported on constructors in Phase 4");
            }
            if (isType(parameter.asType(), ZK_CONTEXT)) {
                if (parameter.getAnnotation(Public.class) != null || parameter.getAnnotation(Secret.class) != null) {
                    throw new GenerationException(parameter, "ZkContext parameters cannot be @Public or @Secret");
                }
                continue;
            }
            if (parameter.getAnnotation(Public.class) != null || parameter.getAnnotation(Secret.class) != null) {
                parameterInputs.add(parameterInput(parameter, circuitParams));
            }
        }

        if (!fieldInputs.isEmpty() && proveMethod.getModifiers().contains(Modifier.STATIC)) {
            throw new GenerationException(proveMethod,
                    "Static @Prove methods must use parameter-style symbolic inputs in Phase 4");
        }

        if (!fieldInputs.isEmpty() && !parameterInputs.isEmpty()) {
            throw new GenerationException(proveMethod,
                    "Mixing field-style and parameter-style symbolic inputs is not supported in Phase 4");
        }

        List<InputModel> inputs = fieldInputs.isEmpty() ? parameterInputs : fieldInputs;
        if (inputs.isEmpty()) {
            throw new GenerationException(proveMethod, "@Prove method or fields must declare at least one symbolic input");
        }
        return orderInputs(inputs);
    }

    private InputModel fieldInput(VariableElement field, Map<String, CircuitParamModel> circuitParams) {
        if (field.getModifiers().contains(Modifier.PRIVATE)) {
            throw new GenerationException(field, "Private symbolic input fields are not supported in Phase 4");
        }
        if (field.getModifiers().contains(Modifier.FINAL)) {
            throw new GenerationException(field, "Final symbolic input fields are not supported");
        }
        return input(field, true, circuitParams);
    }

    private InputModel parameterInput(VariableElement parameter, Map<String, CircuitParamModel> circuitParams) {
        return input(parameter, false, circuitParams);
    }

    private InputModel input(VariableElement element, boolean fieldStyle,
                             Map<String, CircuitParamModel> circuitParams) {
        Public publicAnnotation = element.getAnnotation(Public.class);
        Secret secretAnnotation = element.getAnnotation(Secret.class);
        if ((publicAnnotation == null) == (secretAnnotation == null)) {
            throw new GenerationException(element, "Exactly one of @Public or @Secret is required");
        }

        Visibility visibility = publicAnnotation != null ? Visibility.PUBLIC : Visibility.SECRET;
        String explicitName = publicAnnotation != null ? publicAnnotation.name() : secretAnnotation.name();
        String javaName = element.getSimpleName().toString();
        ValueKind valueKind = valueKind(element);
        String baseName = explicitName.isBlank()
                ? (valueKind == ValueKind.ARRAY ? singularize(javaName) : javaName)
                : explicitName;

        UInt uint = element.getAnnotation(UInt.class);
        if ((valueKind == ValueKind.UINT || isArrayOf(element.asType(), ZK_UINT)) && uint == null) {
            throw new GenerationException(element, "ZkUInt symbolic inputs require @UInt(bits = ...)");
        }
        if (uint != null && valueKind != ValueKind.UINT && !isArrayOf(element.asType(), ZK_UINT)) {
            throw new GenerationException(element, "@UInt can only be used with ZkUInt or ZkArray<ZkUInt>");
        }
        if (element.getAnnotation(FieldElement.class) != null && valueKind != ValueKind.FIELD) {
            throw new GenerationException(element, "@FieldElement can only be used with ZkField");
        }

        FixedSize fixedSize = element.getAnnotation(FixedSize.class);
        SizeModel size = null;
        if (isFixedVector(valueKind)) {
            if (fixedSize == null) {
                throw new GenerationException(element,
                        typeLabel(valueKind) + " symbolic inputs require @FixedSize");
            }
            size = sizeModel(element, fixedSize, circuitParams);
        } else if (fixedSize != null) {
            throw new GenerationException(element, "@FixedSize can only be used with ZkArray, ZkBits, or ZkBytes");
        }

        Integer order = null;
        Order orderAnnotation = element.getAnnotation(Order.class);
        if (orderAnnotation != null) {
            if (!fieldStyle) {
                throw new GenerationException(element, "@Order is only supported on fields");
            }
            if (orderAnnotation.value() < 0) {
                throw new GenerationException(element, "@Order must be non-negative");
            }
            order = orderAnnotation.value();
        }

        int bits = uint == null ? -1 : uint.bits();
        if (bits != -1 && (bits <= 0 || bits > ZkUInt.MAX_BITS)) {
            throw new GenerationException(element,
                    "@UInt bits must be in [1, " + ZkUInt.MAX_BITS + "]");
        }

        return new InputModel(javaName, baseName, constName(baseName), visibility, valueKind,
                elementType(element.asType()), bits, size, order, fieldStyle);
    }

    private SizeModel sizeModel(VariableElement element, FixedSize fixedSize,
                                Map<String, CircuitParamModel> circuitParams) {
        boolean hasLiteral = fixedSize.value() >= 0;
        boolean hasParam = !fixedSize.param().isBlank();
        if (hasLiteral == hasParam) {
            throw new GenerationException(element,
                    "@FixedSize requires exactly one of value or param");
        }
        if (hasLiteral) {
            if (fixedSize.value() <= 0) {
                throw new GenerationException(element, "@FixedSize value must be positive");
            }
            return new SizeModel(Integer.toString(fixedSize.value()), false, "");
        }

        CircuitParamModel param = circuitParams.get(fixedSize.param());
        if (param == null || !param.intLike()) {
            throw new GenerationException(element,
                    "@FixedSize(param = \"" + fixedSize.param()
                            + "\") must reference an integer @CircuitParam");
        }
        return new SizeModel(param.javaName(), true, param.name());
    }

    private List<InputModel> orderInputs(List<InputModel> inputs) {
        for (Visibility visibility : Visibility.values()) {
            Set<Integer> orders = new HashSet<>();
            for (InputModel input : inputs) {
                if (input.visibility() == visibility && input.order() != null && !orders.add(input.order())) {
                    throw new GenerationException(null,
                            "Duplicate @Order value " + input.order() + " for " + visibility.label() + " inputs");
                }
            }
        }

        Comparator<InputModel> comparator = Comparator
                .comparing(InputModel::visibility)
                .thenComparing(i -> i.order() == null ? 1 : 0)
                .thenComparing(i -> i.order() == null ? Integer.MAX_VALUE : i.order());
        return inputs.stream().sorted(comparator).toList();
    }

    private void validateInputNames(List<InputModel> inputs) {
        Set<String> names = new HashSet<>();
        Set<String> constantNames = new HashSet<>(Set.of(
                "CIRCUIT_NAME", "CIRCUIT_NAME_TEMPLATE", "CIRCUIT_VERSION"));
        for (InputModel input : inputs) {
            if (!names.add(input.baseName())) {
                throw new GenerationException(null, "Duplicate generated input name: " + input.baseName());
            }
            if (!constantNames.add(input.constantName())) {
                throw new GenerationException(null, "Duplicate generated input constant name: " + input.constantName());
            }
        }

        Set<String> flattenedNames = new HashSet<>();
        Map<String, InputModel> flattenedOwners = new java.util.HashMap<>();
        for (InputModel input : inputs) {
            if (isFixedVector(input.valueKind())) {
                if (!input.size().fromCircuitParam()) {
                    int size = Integer.parseInt(input.size().expression());
                    for (int i = 0; i < size; i++) {
                        addFlattenedName(flattenedNames, flattenedOwners, input, input.baseName() + "_" + i);
                    }
                }
            } else {
                addFlattenedName(flattenedNames, flattenedOwners, input, input.baseName());
            }
        }

        for (InputModel input : inputs) {
            InputModel owner = flattenedOwners.get(input.baseName());
            if (owner != null && owner != input) {
                throw new GenerationException(null,
                        "Input base name overlaps a flattened input name: " + input.baseName());
            }
        }

        for (InputModel array : inputs.stream().filter(i -> isFixedVector(i.valueKind())).toList()) {
            for (InputModel other : inputs.stream().filter(i -> i != array).toList()) {
                if (other.baseName().matches(java.util.regex.Pattern.quote(array.baseName()) + "_\\d+")) {
                    throw new GenerationException(null,
                            "Duplicate flattened input name may be generated from array base "
                                    + array.baseName() + " and input " + other.baseName());
                }
            }
        }
    }

    private void addFlattenedName(Set<String> flattenedNames, Map<String, InputModel> flattenedOwners,
                                  InputModel input, String name) {
        if (!flattenedNames.add(name)) {
            throw new GenerationException(null, "Duplicate flattened input name: " + name);
        }
        flattenedOwners.put(name, input);
    }

    private void validateReturnType(ExecutableElement method) {
        TypeMirror returnType = method.getReturnType();
        if (returnType.getKind() == TypeKind.VOID || isType(returnType, ZK_BOOL)) {
            return;
        }
        if (returnType.getKind() == TypeKind.BOOLEAN
                || returnType.toString().equals("java.lang.Boolean")
                || returnType.toString().equals("java.math.BigInteger")) {
            throw new GenerationException(method,
                    "Circuit proof methods must return ZkBool or void because circuit values are symbolic");
        }
        throw new GenerationException(method, "@Prove method must return ZkBool or void");
    }

    private String render(TypeElement sourceType, String packageName, String sourceSimpleName,
                          String generatedSimpleName, ExecutableElement proveMethod,
                          List<CircuitParamModel> circuitParams, List<InputModel> inputs) {
        ZKCircuit circuit = sourceType.getAnnotation(ZKCircuit.class);
        String circuitName = !circuit.name().isBlank() ? circuit.name() : sourceSimpleName;
        String nameTemplate = circuit.nameTemplate();
        int circuitVersion = circuit.version();
        if (circuitVersion <= 0) {
            throw new GenerationException(sourceType, "@ZKCircuit version must be positive");
        }
        boolean parameterized = !circuitParams.isEmpty();
        validateNameTemplate(circuitParams, nameTemplate);
        boolean hasNameTemplate = parameterized && !nameTemplate.isBlank();
        boolean needsInstance = !proveMethod.getModifiers().contains(Modifier.STATIC)
                || inputs.stream().anyMatch(InputModel::fieldStyle);
        Set<String> usedLocalNames = circuitParams.stream()
                .map(CircuitParamModel::javaName)
                .collect(Collectors.toCollection(HashSet::new));
        String builderLocal = uniqueLocalName("__zerojBuilder", usedLocalNames);
        String instanceLocal = needsInstance ? uniqueLocalName("__zerojInstance", usedLocalNames) : "";
        String signalContextLocal = uniqueLocalName("__zerojSignals", usedLocalNames);
        String zkLocal = uniqueLocalName("__zeroj", usedLocalNames);
        String loopLocal = uniqueLocalName("__zerojIndex", usedLocalNames);
        Map<InputModel, String> inputLocals = new java.util.LinkedHashMap<>();
        for (int i = 0; i < inputs.size(); i++) {
            inputLocals.put(inputs.get(i), uniqueLocalName("__zerojInput" + i, usedLocalNames));
        }

        StringBuilder out = new StringBuilder();
        if (!packageName.isEmpty()) {
            out.append("package ").append(packageName).append(";\n\n");
        }
        out.append("import com.bloxbean.cardano.zeroj.api.CircuitId;\n")
                .append("import com.bloxbean.cardano.zeroj.api.CurveId;\n")
                .append("import com.bloxbean.cardano.zeroj.api.ProofSystemId;\n")
                .append("import com.bloxbean.cardano.zeroj.api.PublicInputs;\n")
                .append("import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;\n")
                .append("import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBits;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBytes;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkCircuitMetadata;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkCircuitSchema;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;\n")
                .append("import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;\n\n")
                .append("import java.math.BigInteger;\n")
                .append("import java.util.List;\n")
                .append("import java.util.Map;\n\n")
                .append("public final class ").append(generatedSimpleName).append(" {\n")
                .append("    private ").append(generatedSimpleName).append("() {}\n\n")
                .append("    public static final String CIRCUIT_NAME = ")
                .append(stringLiteral(circuitName)).append(";\n")
                .append("    public static final int CIRCUIT_VERSION = ").append(circuitVersion).append(";\n");

        if (hasNameTemplate) {
            out.append("    public static final String CIRCUIT_NAME_TEMPLATE = ")
                    .append(stringLiteral(nameTemplate)).append(";\n");
        }

        for (InputModel input : inputs) {
            out.append("    public static final String ").append(input.constantName())
                    .append(" = ").append(stringLiteral(input.baseName())).append(";\n");
        }
        out.append("\n");

        out.append("    public static CircuitBuilder build(")
                .append(renderParamSignature(circuitParams))
                .append(") {\n");
        renderFixedSizeParamGuards(out, inputs, "        ");
        if (needsInstance) {
            out.append("        var ").append(instanceLocal).append(" = new ").append(sourceSimpleName).append("(")
                    .append(circuitParams.stream().map(CircuitParamModel::javaName).collect(Collectors.joining(", ")))
                    .append(");\n");
        }
        out.append("        var ").append(builderLocal).append(" = CircuitBuilder.create(")
                .append(parameterized ? "circuitName(" + renderParamNames(circuitParams) + ")" : "CIRCUIT_NAME")
                .append(");\n");

        for (InputModel input : inputs.stream().filter(i -> i.visibility() == Visibility.PUBLIC).toList()) {
            renderVarDeclaration(out, input, builderLocal, loopLocal, "publicVar");
        }
        for (InputModel input : inputs.stream().filter(i -> i.visibility() == Visibility.SECRET).toList()) {
            renderVarDeclaration(out, input, builderLocal, loopLocal, "secretVar");
        }

        out.append("        return ").append(builderLocal).append(".defineSignals(")
                .append(signalContextLocal).append(" -> {\n")
                .append("            var ").append(zkLocal).append(" = new ZkContext(")
                .append(signalContextLocal).append(");\n");

        for (InputModel input : inputs) {
            String inputLocal = inputLocals.get(input);
            out.append("            var ").append(inputLocal).append(" = ")
                    .append(factoryCall(input, signalContextLocal)).append(";\n");
            if (input.fieldStyle()) {
                out.append("            ").append(instanceLocal).append(".").append(input.javaName())
                        .append(" = ").append(inputLocal).append(";\n");
            }
        }

        String call = proveCall(sourceType, proveMethod, inputs, zkLocal, inputLocals, instanceLocal);
        if (proveMethod.getReturnType().getKind() == TypeKind.VOID) {
            out.append("            ").append(call).append(";\n");
        } else {
            out.append("            ").append(call).append(".assertTrue();\n");
        }
        out.append("        });\n")
                .append("    }\n");

        renderSchemaAndInputs(out, circuitParams, inputs, parameterized);

        if (parameterized) {
            Set<String> circuitNameLocals = new HashSet<>(
                    circuitParams.stream().map(CircuitParamModel::javaName).toList());
            String nameLocal = uniqueLocalName("__zerojName", circuitNameLocals);
            out.append("\n    private static String circuitName(")
                    .append(renderParamSignature(circuitParams))
                    .append(") {\n")
                    .append("        String ").append(nameLocal).append(" = ")
                    .append(hasNameTemplate ? "CIRCUIT_NAME_TEMPLATE" : "CIRCUIT_NAME")
                    .append(";\n");
            if (hasNameTemplate) {
                for (CircuitParamModel param : circuitParams) {
                    out.append("        ").append(nameLocal).append(" = ").append(nameLocal)
                            .append(".replace(\"{").append(param.name()).append("}\", circuitParamDisplayValue(")
                            .append(param.javaName()).append("));\n");
                }
            }
            out.append("        return ").append(nameLocal).append(" + circuitParamSuffix(")
                    .append(renderParamNames(circuitParams))
                    .append(");\n")
                    .append("    }\n");

            out.append("\n    private static String circuitParamSuffix(")
                    .append(renderParamSignature(circuitParams))
                    .append(") {\n")
                    .append("        String suffix = \"\";\n");
            for (CircuitParamModel param : circuitParams) {
                out.append("        suffix = suffix + \"--").append(param.name()).append("-\" + circuitParamValue(")
                        .append(param.javaName()).append(");\n");
            }
            out.append("        return suffix;\n")
                    .append("    }\n");

            out.append("\n    private static String circuitParamDisplayValue(Object value) {\n")
                    .append("        if (value == null) {\n")
                    .append("            throw new IllegalArgumentException(\"@CircuitParam values must not be null\");\n")
                    .append("        }\n")
                    .append("        if (value instanceof Enum<?> enumValue) {\n")
                    .append("            return enumValue.name();\n")
                    .append("        }\n")
                    .append("        return String.valueOf(value);\n")
                    .append("    }\n")
                    .append("\n")
                    .append("    private static String circuitParamValue(Object value) {\n")
                    .append("        String displayValue = circuitParamDisplayValue(value);\n")
                    .append("        return displayValue.length() + \":\" + displayValue;\n")
                    .append("    }\n");
        }

        out.append("}\n");
        return out.toString();
    }

    private void renderSchemaAndInputs(StringBuilder out, List<CircuitParamModel> circuitParams,
                                       List<InputModel> inputs, boolean parameterized) {
        out.append("\n    public static ZkCircuitSchema schema(")
                .append(renderParamSignature(circuitParams))
                .append(") {\n");
        renderFixedSizeParamGuards(out, inputs, "        ");
        out.append("        return ZkCircuitSchema.of(")
                .append(parameterized ? "circuitName(" + renderParamNames(circuitParams) + ")" : "CIRCUIT_NAME")
                .append(",\n")
                .append("                ").append(renderParameterSchemaList(circuitParams)).append(",\n")
                .append("                ").append(renderInputSchemaList(inputs, Visibility.PUBLIC)).append(",\n")
                .append("                ").append(renderInputSchemaList(inputs, Visibility.SECRET)).append(");\n")
                .append("    }\n\n")
                .append("    public static Inputs inputs(")
                .append(renderParamSignature(circuitParams))
                .append(") {\n")
                .append("        return new Inputs(schema(")
                .append(renderParamNames(circuitParams))
                .append("));\n")
                .append("    }\n\n")
                .append("    public static CircuitId circuitId(")
                .append(renderParamSignature(circuitParams))
                .append(") {\n")
                .append("        return metadata(")
                .append(renderParamNames(circuitParams))
                .append(").circuitId();\n")
                .append("    }\n\n")
                .append("    public static ZkCircuitMetadata metadata(")
                .append(renderParamSignature(circuitParams))
                .append(") {\n")
                .append("        return ZkCircuitMetadata.of(schema(")
                .append(renderParamNames(circuitParams))
                .append("), CIRCUIT_VERSION);\n")
                .append("    }\n\n")
                .append("    public static List<BigInteger> publicInputs(Inputs inputs) {\n")
                .append("        return inputs.publicValues();\n")
                .append("    }\n\n")
                .append("    public static PublicInputs publicInputValues(Inputs inputs) {\n")
                .append("        return inputs.toPublicInputs();\n")
                .append("    }\n\n")
                .append("    public static BigInteger[] calculateWitness(CircuitBuilder circuit, Inputs inputs, CurveId curve) {\n")
                .append("        return inputs.calculateWitness(circuit, curve);\n")
                .append("    }\n\n")
                .append("    public static ZkProofEnvelope.Builder proofEnvelopeBuilder(\n")
                .append("            CircuitBuilder circuit,\n")
                .append("            ProofSystemId proofSystem,\n")
                .append("            CurveId curve,\n")
                .append("            byte[] proofBytes,\n")
                .append("            Inputs inputs,\n")
                .append("            VerificationKeyRef vkRef) {\n")
                .append("        validateCircuit(circuit, inputs.schema());\n")
                .append("        return ZkCircuitMetadata.of(inputs.schema(), CIRCUIT_VERSION)\n")
                .append("                .proofEnvelopeBuilder(proofSystem, curve, proofBytes, inputs.toPublicInputs(), vkRef);\n")
                .append("    }\n");

        out.append("\n    private static void validateCircuit(CircuitBuilder circuit, ZkCircuitSchema schema) {\n")
                .append("        if (circuit == null) {\n")
                .append("            throw new NullPointerException(\"circuit\");\n")
                .append("        }\n")
                .append("        if (schema == null) {\n")
                .append("            throw new NullPointerException(\"schema\");\n")
                .append("        }\n")
                .append("        String circuitName = circuit.constraintGraph().name();\n")
                .append("        if (!circuitName.equals(schema.name())) {\n")
                .append("            throw new IllegalArgumentException(\"Circuit name \" + circuitName\n")
                .append("                    + \" does not match generated input schema \" + schema.name());\n")
                .append("        }\n")
                .append("    }\n");

        renderInputsClass(out, inputs);
    }

    private void renderFixedSizeParamGuards(StringBuilder out, List<InputModel> inputs, String indent) {
        Map<String, String> sizeParams = new java.util.LinkedHashMap<>();
        for (InputModel input : inputs) {
            if (input.size() != null && input.size().fromCircuitParam()) {
                sizeParams.putIfAbsent(input.size().expression(), input.size().paramName());
            }
        }
        for (Map.Entry<String, String> entry : sizeParams.entrySet()) {
            out.append(indent).append("if (").append(entry.getKey()).append(" <= 0) {\n")
                    .append(indent).append("    throw new IllegalArgumentException(")
                    .append(stringLiteral("@FixedSize(param = \"" + entry.getValue() + "\") must be positive"))
                    .append(");\n")
                    .append(indent).append("}\n");
        }
    }

    private String renderParameterSchemaList(List<CircuitParamModel> circuitParams) {
        if (circuitParams.isEmpty()) {
            return "List.of()";
        }
        return circuitParams.stream()
                .map(param -> "new ZkCircuitSchema.Parameter("
                        + stringLiteral(param.name()) + ", "
                        + stringLiteral(param.type()) + ", "
                        + "circuitParamValue(" + param.javaName() + "))")
                .collect(Collectors.joining(",\n                        ", "List.of(", ")"));
    }

    private String renderInputSchemaList(List<InputModel> inputs, Visibility visibility) {
        List<InputModel> selected = inputs.stream()
                .filter(input -> input.visibility() == visibility)
                .toList();
        if (selected.isEmpty()) {
            return "List.of()";
        }
        return selected.stream()
                .map(this::renderInputSchema)
                .collect(Collectors.joining(",\n                        ", "List.of(", ")"));
    }

    private String renderInputSchema(InputModel input) {
        String prefix = isFixedVector(input.valueKind())
                ? "ZkCircuitSchema.Input.array("
                : "ZkCircuitSchema.Input.scalar(";
        String size = isFixedVector(input.valueKind()) ? ", " + input.size().expression() : "";
        return prefix
                + input.constantName()
                + ", ZkCircuitSchema.Visibility." + input.visibility().name()
                + ", ZkCircuitSchema.Kind." + schemaKind(input)
                + ", " + schemaBits(input)
                + size
                + ")";
    }

    private void renderInputsClass(StringBuilder out, List<InputModel> inputs) {
        out.append("\n    public static final class Inputs {\n")
                .append("        private final ZkCircuitSchema __zerojSchema;\n")
                .append("        private final ZkInputMap __zerojInputs = new ZkInputMap();\n\n")
                .append("        private Inputs(ZkCircuitSchema __zerojSchema) {\n")
                .append("            this.__zerojSchema = __zerojSchema;\n")
                .append("        }\n\n")
                .append("        public ZkCircuitSchema schema() {\n")
                .append("            return __zerojSchema;\n")
                .append("        }\n\n");

        for (InputModel input : inputs) {
            if (isFixedVector(input.valueKind())) {
                renderArrayInputMethods(out, input);
            } else {
                renderScalarInputMethods(out, input);
            }
        }

        out.append("        public Map<String, List<BigInteger>> toWitnessMap() {\n")
                .append("            return __zerojInputs.toWitnessMap();\n")
                .append("        }\n\n")
                .append("        public List<BigInteger> publicValues() {\n")
                .append("            return __zerojInputs.publicValues(__zerojSchema);\n")
                .append("        }\n\n")
                .append("        public PublicInputs toPublicInputs() {\n")
                .append("            return __zerojInputs.publicInputs(__zerojSchema);\n")
                .append("        }\n\n")
                .append("        public BigInteger[] calculateWitness(CircuitBuilder circuit, CurveId curve) {\n")
                .append("            validateCircuit(circuit, __zerojSchema);\n")
                .append("            return circuit.calculateWitness(toWitnessMap(), curve);\n")
                .append("        }\n")
                .append("    }\n");
    }

    private void renderScalarInputMethods(StringBuilder out, InputModel input) {
        out.append("        public Inputs ").append(input.javaName()).append("(BigInteger value) {\n")
                .append("            __zerojInputs.put(").append(input.constantName()).append(", value);\n")
                .append("            return this;\n")
                .append("        }\n\n");
        if (!"wait".equals(input.javaName())) {
            out.append("        public Inputs ").append(input.javaName()).append("(long value) {\n")
                    .append("            return ").append(input.javaName()).append("(BigInteger.valueOf(value));\n")
                    .append("        }\n\n");
        }
    }

    private void renderArrayInputMethods(StringBuilder out, InputModel input) {
        String sizeExpression = "__zerojSchema.input(" + input.constantName() + ").size()";
        out.append("        public Inputs ").append(input.javaName()).append("(int index, BigInteger value) {\n")
                .append("            if (index < 0 || index >= ").append(sizeExpression).append(") {\n")
                .append("                throw new IllegalArgumentException(")
                .append(stringLiteral("index out of bounds for " + input.baseName())).append(");\n")
                .append("            }\n")
                .append("            __zerojInputs.put(").append(input.constantName())
                .append(" + \"_\" + index, value);\n")
                .append("            return this;\n")
                .append("        }\n\n")
                .append("        public Inputs ").append(input.javaName()).append("(int index, long value) {\n")
                .append("            return ").append(input.javaName())
                .append("(index, BigInteger.valueOf(value));\n")
                .append("        }\n\n")
                .append("        public Inputs ").append(input.javaName()).append("(List<BigInteger> values) {\n")
                .append("            if (values.size() != ").append(sizeExpression).append(") {\n")
                .append("                throw new IllegalArgumentException(")
                .append(stringLiteral(input.baseName() + " expects ")).append(" + ").append(sizeExpression)
                .append(" + \" values\");\n")
                .append("            }\n")
                .append("            __zerojInputs.putArray(").append(input.constantName()).append(", values);\n")
                .append("            return this;\n")
                .append("        }\n\n");
    }

    private String schemaKind(InputModel input) {
        if (input.valueKind() == ValueKind.FIELD || input.arrayElementType().equals(ZK_FIELD)) {
            return "FIELD";
        }
        if (input.valueKind() == ValueKind.BOOL || input.arrayElementType().equals(ZK_BOOL)) {
            return "BOOL";
        }
        if (input.valueKind() == ValueKind.UINT || input.arrayElementType().equals(ZK_UINT)) {
            return "UINT";
        }
        if (input.valueKind() == ValueKind.BITS) {
            return "BITS";
        }
        if (input.valueKind() == ValueKind.BYTES) {
            return "BYTES";
        }
        throw new GenerationException(null, "Unsupported schema input type: " + input.valueKind());
    }

    private int schemaBits(InputModel input) {
        if (input.valueKind() == ValueKind.UINT || input.arrayElementType().equals(ZK_UINT)) {
            return input.bits();
        }
        if (input.valueKind() == ValueKind.BOOL || input.arrayElementType().equals(ZK_BOOL)) {
            return 1;
        }
        if (input.valueKind() == ValueKind.BITS) {
            return 1;
        }
        if (input.valueKind() == ValueKind.BYTES) {
            return 8;
        }
        return -1;
    }

    private void renderVarDeclaration(StringBuilder out, InputModel input, String builderLocal,
                                      String loopLocal, String method) {
        if (isFixedVector(input.valueKind())) {
            out.append("        for (int ").append(loopLocal).append(" = 0; ")
                    .append(loopLocal).append(" < ").append(input.size().expression()).append("; ")
                    .append(loopLocal).append("++) {\n")
                    .append("            ").append(builderLocal).append(".").append(method).append("(")
                    .append(input.constantName()).append(" + \"_\" + ").append(loopLocal).append(");\n")
                    .append("        }\n");
        } else {
            out.append("        ").append(builderLocal).append(".").append(method).append("(")
                    .append(input.constantName()).append(");\n");
        }
    }

    private String factoryCall(InputModel input, String signalContextLocal) {
        String visibilityMethod = input.visibility() == Visibility.PUBLIC ? "publicInput" : "secret";
        if (input.valueKind() == ValueKind.FIELD) {
            return "ZkField." + visibilityMethod + "(" + signalContextLocal + ", " + input.constantName() + ")";
        }
        if (input.valueKind() == ValueKind.BOOL) {
            return "ZkBool." + visibilityMethod + "(" + signalContextLocal + ", " + input.constantName() + ")";
        }
        if (input.valueKind() == ValueKind.UINT) {
            return "ZkUInt." + visibilityMethod + "(" + signalContextLocal + ", "
                    + input.constantName() + ", " + input.bits() + ")";
        }
        if (input.valueKind() == ValueKind.BITS) {
            return "ZkBits." + visibilityMethod + "(" + signalContextLocal + ", "
                    + input.constantName() + ", " + input.size().expression() + ")";
        }
        if (input.valueKind() == ValueKind.BYTES) {
            return "ZkBytes." + visibilityMethod + "(" + signalContextLocal + ", "
                    + input.constantName() + ", " + input.size().expression() + ")";
        }
        if (input.arrayElementType().equals(ZK_FIELD)) {
            return "ZkArray." + (input.visibility() == Visibility.PUBLIC ? "publicFields" : "secretFields")
                    + "(" + signalContextLocal + ", " + input.constantName() + ", "
                    + input.size().expression() + ")";
        }
        if (input.arrayElementType().equals(ZK_BOOL)) {
            return "ZkArray." + (input.visibility() == Visibility.PUBLIC ? "publicBools" : "secretBools")
                    + "(" + signalContextLocal + ", " + input.constantName() + ", "
                    + input.size().expression() + ")";
        }
        if (input.arrayElementType().equals(ZK_UINT)) {
            return "ZkArray." + (input.visibility() == Visibility.PUBLIC ? "publicUInts" : "secretUInts")
                    + "(" + signalContextLocal + ", " + input.constantName() + ", "
                    + input.size().expression() + ", " + input.bits() + ")";
        }
        throw new GenerationException(null, "Unsupported ZkArray element type: " + input.arrayElementType());
    }

    private String proveCall(TypeElement sourceType, ExecutableElement proveMethod, List<InputModel> inputs,
                             String zkLocal, Map<InputModel, String> inputLocals, String instanceLocal) {
        String receiver = proveMethod.getModifiers().contains(Modifier.STATIC)
                ? sourceType.getQualifiedName().toString()
                : instanceLocal;
        Map<String, InputModel> byJavaName = inputs.stream()
                .collect(Collectors.toMap(InputModel::javaName, i -> i));

        List<String> args = new ArrayList<>();
        for (VariableElement parameter : proveMethod.getParameters()) {
            if (parameter.getAnnotation(CircuitParam.class) != null) {
                CircuitParam annotation = parameter.getAnnotation(CircuitParam.class);
                args.add(annotation.value().isBlank() ? parameter.getSimpleName().toString() : annotation.value());
            } else if (isType(parameter.asType(), ZK_CONTEXT)) {
                args.add(zkLocal);
            } else {
                InputModel input = byJavaName.get(parameter.getSimpleName().toString());
                if (input == null) {
                    throw new GenerationException(parameter,
                            "@Prove parameters must be ZkContext, @CircuitParam, or symbolic inputs");
                }
                args.add(inputLocals.get(input));
            }
        }
        return receiver + "." + proveMethod.getSimpleName() + "(" + String.join(", ", args) + ")";
    }

    private void validateNameTemplate(List<CircuitParamModel> circuitParams, String nameTemplate) {
        if (circuitParams.isEmpty() || nameTemplate.isBlank()) {
            return;
        }

        Set<String> placeholders = new HashSet<>();
        int index = 0;
        while (index < nameTemplate.length()) {
            int start = nameTemplate.indexOf('{', index);
            if (start < 0) {
                break;
            }
            int end = nameTemplate.indexOf('}', start + 1);
            if (end < 0) {
                throw new GenerationException(null, "Unclosed nameTemplate placeholder");
            }
            placeholders.add(nameTemplate.substring(start + 1, end));
            index = end + 1;
        }

        Set<String> paramNames = circuitParams.stream()
                .map(CircuitParamModel::name)
                .collect(Collectors.toSet());
        for (String placeholder : placeholders) {
            if (!paramNames.contains(placeholder)) {
                throw new GenerationException(null,
                        "nameTemplate references unknown @CircuitParam: " + placeholder);
            }
        }
        for (String paramName : paramNames) {
            if (!placeholders.contains(paramName)) {
                throw new GenerationException(null,
                        "nameTemplate must include @CircuitParam {" + paramName + "}");
            }
        }
    }

    private ValueKind valueKind(VariableElement element) {
        TypeMirror type = element.asType();
        if (isType(type, ZK_FIELD)) return ValueKind.FIELD;
        if (isType(type, ZK_BOOL)) return ValueKind.BOOL;
        if (isType(type, ZK_BITS)) return ValueKind.BITS;
        if (isType(type, ZK_BYTES)) return ValueKind.BYTES;
        if (isType(type, ZK_UINT)) return ValueKind.UINT;
        if (isType(type, ZK_ARRAY)) return ValueKind.ARRAY;
        if (type.toString().equals("java.math.BigInteger") || type.getKind() == TypeKind.BOOLEAN) {
            throw new GenerationException(element,
                    "Symbolic inputs must use ZkField, ZkBool, ZkUInt, ZkArray, ZkBits, or ZkBytes, not " + type);
        }
        throw new GenerationException(element, "Unsupported symbolic input type: " + type);
    }

    private String elementType(TypeMirror type) {
        if (!isType(type, ZK_ARRAY)) {
            return "";
        }
        DeclaredType declared = (DeclaredType) type;
        if (declared.getTypeArguments().size() != 1) {
            throw new GenerationException(null, "ZkArray must declare exactly one element type");
        }
        return erasure(declared.getTypeArguments().get(0));
    }

    private boolean isArrayOf(TypeMirror type, String elementType) {
        return isType(type, ZK_ARRAY) && elementType(type).equals(elementType);
    }

    private boolean isFixedVector(ValueKind valueKind) {
        return valueKind == ValueKind.ARRAY || valueKind == ValueKind.BITS || valueKind == ValueKind.BYTES;
    }

    private String typeLabel(ValueKind valueKind) {
        return switch (valueKind) {
            case ARRAY -> "ZkArray";
            case BITS -> "ZkBits";
            case BYTES -> "ZkBytes";
            default -> valueKind.name();
        };
    }

    private boolean isType(TypeMirror type, String qualifiedName) {
        return erasure(type).equals(qualifiedName);
    }

    private boolean isIntegerCircuitParam(TypeMirror type) {
        return type.getKind() == TypeKind.INT || erasure(type).equals("java.lang.Integer");
    }

    private boolean isSupportedCircuitParamType(TypeMirror type) {
        return switch (type.getKind()) {
            case BOOLEAN, BYTE, SHORT, INT, LONG, CHAR -> true;
            default -> {
                String erased = erasure(type);
                if (Set.of(
                        "java.lang.Boolean",
                        "java.lang.Byte",
                        "java.lang.Short",
                        "java.lang.Integer",
                        "java.lang.Long",
                        "java.lang.Character",
                        "java.lang.String",
                        "java.math.BigInteger").contains(erased)) {
                    yield true;
                }
                Element element = processingEnv.getTypeUtils().asElement(type);
                yield element != null && element.getKind() == ElementKind.ENUM;
            }
        };
    }

    private String erasure(TypeMirror type) {
        return processingEnv.getTypeUtils().erasure(type).toString();
    }

    private String renderParamSignature(List<CircuitParamModel> params) {
        return params.stream()
                .map(p -> p.type() + " " + p.javaName())
                .collect(Collectors.joining(", "));
    }

    private String renderParamNames(List<CircuitParamModel> params) {
        return params.stream().map(CircuitParamModel::javaName).collect(Collectors.joining(", "));
    }

    private String uniqueLocalName(String base, Set<String> usedNames) {
        String candidate = base;
        int suffix = 0;
        while (!usedNames.add(candidate)) {
            suffix++;
            candidate = base + "_" + suffix;
        }
        return candidate;
    }

    private String packageName(TypeElement sourceType) {
        PackageElement packageElement = processingEnv.getElementUtils().getPackageOf(sourceType);
        return packageElement == null || packageElement.isUnnamed()
                ? ""
                : packageElement.getQualifiedName().toString();
    }

    private String singularize(String name) {
        if (name.endsWith("ies") && name.length() > 3) {
            return name.substring(0, name.length() - 3) + "y";
        }
        if (name.endsWith("s") && name.length() > 1) {
            return name.substring(0, name.length() - 1);
        }
        return name;
    }

    private String constName(String name) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isUpperCase(c) && i > 0) {
                out.append('_');
            } else if (!Character.isLetterOrDigit(c)) {
                out.append('_');
                continue;
            }
            out.append(Character.toUpperCase(c));
        }
        String constantName = out.toString().toUpperCase(Locale.ROOT);
        if (constantName.isEmpty()
                || "_".equals(constantName)
                || !Character.isJavaIdentifierStart(constantName.charAt(0))) {
            constantName = "INPUT_" + constantName;
        }
        return constantName;
    }

    private String stringLiteral(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> out.append(c);
            }
        }
        return out.append("\"").toString();
    }

    private boolean isSimpleName(String value) {
        if (value.isEmpty()) {
            return false;
        }
        char first = value.charAt(0);
        if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_')) {
            return false;
        }
        for (int i = 1; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '_')) {
                return false;
            }
        }
        return true;
    }

    private void error(Element element, String message) {
        if (element == null) {
            processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, message);
        } else {
            processingEnv.getMessager().printMessage(Diagnostic.Kind.ERROR, message, element);
        }
    }

    private enum Visibility {
        PUBLIC("public"),
        SECRET("secret");

        private final String label;

        Visibility(String label) {
            this.label = label;
        }

        String label() {
            return label;
        }
    }

    private enum ValueKind {
        FIELD,
        BOOL,
        UINT,
        ARRAY,
        BITS,
        BYTES
    }

    private record CircuitParamModel(String name, String javaName, String type, boolean intLike) {}

    private record SizeModel(String expression, boolean fromCircuitParam, String paramName) {}

    private record InputModel(
            String javaName,
            String baseName,
            String constantName,
            Visibility visibility,
            ValueKind valueKind,
            String arrayElementType,
            int bits,
            SizeModel size,
            Integer order,
            boolean fieldStyle) {}

    private static final class GenerationException extends RuntimeException {
        private final Element element;

        private GenerationException(Element element, String message) {
            super(message);
            this.element = element;
        }

        private Element element() {
            return element;
        }
    }
}
