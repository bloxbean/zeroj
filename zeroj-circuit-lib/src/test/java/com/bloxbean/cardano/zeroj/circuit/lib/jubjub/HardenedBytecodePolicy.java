package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Small class-file reader used by the hardened-Jubjub CI policy.
 *
 * <p>This deliberately reads the compiled artifact rather than Java source: the properties
 * being protected are the dependencies, calls, and control flow that the JVM receives.
 * It is test infrastructure, not part of the cryptographic runtime.
 */
final class HardenedBytecodePolicy {

    private HardenedBytecodePolicy() {
    }

    static ClassFile read(Class<?> type) throws IOException {
        return read(type.getName().replace('.', '/'));
    }

    static ClassFile read(String internalName) throws IOException {
        String resource = "/" + internalName + ".class";
        try (InputStream input =
                     HardenedBytecodePolicy.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IllegalStateException("missing class resource " + resource);
            }
            return parse(input.readAllBytes());
        }
    }

    private static ClassFile parse(byte[] bytecode) throws IOException {
        try (DataInputStream input =
                     new DataInputStream(new ByteArrayInputStream(bytecode))) {
            if (input.readInt() != 0xcafebabe) {
                throw new IllegalArgumentException("not a class file");
            }
            input.readUnsignedShort();
            input.readUnsignedShort();
            ConstantPool pool = ConstantPool.read(input);

            input.readUnsignedShort();
            input.readUnsignedShort();
            input.readUnsignedShort();
            int interfaceCount = input.readUnsignedShort();
            for (int i = 0; i < interfaceCount; i++) {
                input.readUnsignedShort();
            }

            skipMembers(input);

            int methodCount = input.readUnsignedShort();
            Map<String, MethodCode> methodBodies = new LinkedHashMap<>();
            for (int i = 0; i < methodCount; i++) {
                input.readUnsignedShort();
                String name = pool.utf8(input.readUnsignedShort());
                String descriptor = pool.utf8(input.readUnsignedShort());
                int attributeCount = input.readUnsignedShort();
                for (int attribute = 0; attribute < attributeCount; attribute++) {
                    String attributeName = pool.utf8(input.readUnsignedShort());
                    int attributeLength = input.readInt();
                    byte[] contents = input.readNBytes(attributeLength);
                    if (contents.length != attributeLength) {
                        throw new IOException("truncated method attribute");
                    }
                    if ("Code".equals(attributeName)) {
                        try (DataInputStream codeInput = new DataInputStream(
                                new ByteArrayInputStream(contents))) {
                            codeInput.readUnsignedShort();
                            codeInput.readUnsignedShort();
                            int codeLength = codeInput.readInt();
                            byte[] code = codeInput.readNBytes(codeLength);
                            if (code.length != codeLength) {
                                throw new IOException("truncated method code");
                            }
                            methodBodies.put(methodKey(name, descriptor),
                                    new MethodCode(name, descriptor, code, pool));
                        }
                    }
                }
            }

            skipAttributes(input);

            Set<String> classes = new HashSet<>();
            Set<MemberRef> methods = new HashSet<>();
            Set<MemberRef> fields = new HashSet<>();
            pool.collectReferences(classes, methods, fields);
            return new ClassFile(
                    Set.copyOf(classes),
                    Set.copyOf(methods),
                    Set.copyOf(fields),
                    Map.copyOf(methodBodies));
        }
    }

    private static void skipMembers(DataInputStream input) throws IOException {
        int count = input.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            input.readUnsignedShort();
            input.readUnsignedShort();
            input.readUnsignedShort();
            skipAttributes(input);
        }
    }

    private static void skipAttributes(DataInputStream input) throws IOException {
        int count = input.readUnsignedShort();
        for (int i = 0; i < count; i++) {
            input.readUnsignedShort();
            int length = input.readInt();
            input.skipNBytes(length);
        }
    }

    private static String methodKey(String name, String descriptor) {
        return name + descriptor;
    }

    record MemberRef(String owner, String name, String descriptor) {
        @Override
        public String toString() {
            return owner + "." + name + descriptor;
        }
    }

    record ClassFile(
            Set<String> classes,
            Set<MemberRef> methods,
            Set<MemberRef> fields,
            Map<String, MethodCode> methodBodies) {

        MethodCode method(String name, String descriptor) {
            MethodCode method = methodBodies.get(methodKey(name, descriptor));
            if (method == null) {
                throw new IllegalArgumentException(
                        "missing method " + name + descriptor);
            }
            return method;
        }
    }

    record MethodCode(
            String name, String descriptor, byte[] code, ConstantPool pool) {

        List<MemberRef> invokedMethods() {
            List<MemberRef> calls = new ArrayList<>();
            forEachInstruction((offset, opcode) -> {
                if (opcode >= 0xb6 && opcode <= 0xb9) {
                    calls.add(pool.memberRef(unsignedShort(code, offset + 1)));
                }
            });
            return List.copyOf(calls);
        }

        long callsTo(String owner, String methodName) {
            return invokedMethods().stream()
                    .filter(call -> call.owner().equals(owner)
                            && call.name().equals(methodName))
                    .count();
        }

        int conditionalBranchCount() {
            int[] count = {0};
            forEachInstruction((offset, opcode) -> {
                if ((opcode >= 0x99 && opcode <= 0xa6)
                        || opcode == 0xc6 || opcode == 0xc7
                        || opcode == 0xaa || opcode == 0xab) {
                    count[0]++;
                }
            });
            return count[0];
        }

        int unconditionalBranchCount() {
            int[] count = {0};
            forEachInstruction((offset, opcode) -> {
                if (opcode == 0xa7 || opcode == 0xc8) {
                    count[0]++;
                }
            });
            return count[0];
        }

        boolean containsIntPush(int expected) {
            boolean[] found = {false};
            forEachInstruction((offset, opcode) -> {
                int value = switch (opcode) {
                    case 0x02 -> -1;
                    case 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 -> opcode - 0x03;
                    case 0x10 -> code[offset + 1];
                    case 0x11 -> (short) unsignedShort(code, offset + 1);
                    default -> Integer.MIN_VALUE;
                };
                if (value == expected) {
                    found[0] = true;
                }
            });
            return found[0];
        }

        private void forEachInstruction(InstructionConsumer consumer) {
            int offset = 0;
            while (offset < code.length) {
                int opcode = code[offset] & 0xff;
                consumer.accept(offset, opcode);
                int length = instructionLength(code, offset, opcode);
                if (length <= 0 || offset + length > code.length) {
                    throw new IllegalStateException(
                            "invalid bytecode length at " + name + descriptor
                                    + " offset " + offset);
                }
                offset += length;
            }
        }
    }

    @FunctionalInterface
    private interface InstructionConsumer {
        void accept(int offset, int opcode);
    }

    private static int instructionLength(byte[] code, int offset, int opcode) {
        return switch (opcode) {
            case 0x10, 0x12,
                    0x15, 0x16, 0x17, 0x18, 0x19,
                    0x36, 0x37, 0x38, 0x39, 0x3a,
                    0xa9, 0xbc -> 2;
            case 0x11, 0x13, 0x14, 0x84,
                    0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,
                    0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
                    0xa7, 0xa8,
                    0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
                    0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7 -> 3;
            case 0xb9, 0xba, 0xc8, 0xc9 -> 5;
            case 0xc5 -> 4;
            case 0xaa -> tableSwitchLength(code, offset);
            case 0xab -> lookupSwitchLength(code, offset);
            case 0xc4 -> {
                int widened = code[offset + 1] & 0xff;
                yield widened == 0x84 ? 6 : 4;
            }
            default -> 1;
        };
    }

    private static int tableSwitchLength(byte[] code, int offset) {
        int padding = (4 - ((offset + 1) & 3)) & 3;
        int cursor = offset + 1 + padding;
        int low = signedInt(code, cursor + 4);
        int high = signedInt(code, cursor + 8);
        return 1 + padding + 12 + Math.multiplyExact(high - low + 1, 4);
    }

    private static int lookupSwitchLength(byte[] code, int offset) {
        int padding = (4 - ((offset + 1) & 3)) & 3;
        int cursor = offset + 1 + padding;
        int pairs = signedInt(code, cursor + 4);
        return 1 + padding + 8 + Math.multiplyExact(pairs, 8);
    }

    private static int unsignedShort(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static int signedInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 24)
                | ((bytes[offset + 1] & 0xff) << 16)
                | ((bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }

    private static final class ConstantPool {
        private final byte[] tags;
        private final Object[] values;

        private ConstantPool(byte[] tags, Object[] values) {
            this.tags = tags;
            this.values = values;
        }

        static ConstantPool read(DataInputStream input) throws IOException {
            int count = input.readUnsignedShort();
            byte[] tags = new byte[count];
            Object[] values = new Object[count];
            for (int i = 1; i < count; i++) {
                int tag = input.readUnsignedByte();
                tags[i] = (byte) tag;
                switch (tag) {
                    case 1 -> values[i] = input.readUTF();
                    case 3, 4 -> input.readInt();
                    case 5, 6 -> {
                        input.readLong();
                        i++;
                    }
                    case 7, 8, 16, 19, 20 ->
                            values[i] = input.readUnsignedShort();
                    case 9, 10, 11, 12, 17, 18 ->
                            values[i] = new int[]{
                                    input.readUnsignedShort(),
                                    input.readUnsignedShort()
                            };
                    case 15 -> values[i] = new int[]{
                            input.readUnsignedByte(),
                            input.readUnsignedShort()
                    };
                    default -> throw new IllegalArgumentException(
                            "unsupported constant-pool tag " + tag);
                }
            }
            return new ConstantPool(tags, values);
        }

        String utf8(int index) {
            return (String) values[index];
        }

        MemberRef memberRef(int index) {
            int tag = tags[index] & 0xff;
            if (tag != 9 && tag != 10 && tag != 11) {
                throw new IllegalArgumentException(
                        "constant-pool entry is not a member reference: " + index);
            }
            int[] reference = (int[]) values[index];
            String owner = className(reference[0]);
            int[] nameAndType = (int[]) values[reference[1]];
            return new MemberRef(
                    owner, utf8(nameAndType[0]), utf8(nameAndType[1]));
        }

        void collectReferences(
                Set<String> classes,
                Set<MemberRef> methods,
                Set<MemberRef> fields) {
            for (int i = 1; i < tags.length; i++) {
                int tag = tags[i] & 0xff;
                if (tag == 7) {
                    classes.add(className(i));
                } else if (tag == 9) {
                    fields.add(memberRef(i));
                } else if (tag == 10 || tag == 11) {
                    methods.add(memberRef(i));
                }
            }
        }

        private String className(int classIndex) {
            return utf8((Integer) values[classIndex]);
        }
    }
}
