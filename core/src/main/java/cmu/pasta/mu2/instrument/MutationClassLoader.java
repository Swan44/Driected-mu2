package cmu.pasta.mu2.instrument;

import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import cmu.pasta.mu2.mutators.Mutator;
import janala.instrument.SafeClassWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import java.util.IdentityHashMap;

/**
 * Classloader that loads test classes and performs exactly one mutation.
 * <p>
 * Mostly exported from InstrumentingClassLoader with additions to FindClass.
 *
 * @author Bella Laybourn
 */
public class MutationClassLoader extends URLClassLoader {

  /**
   * The mutation instance this class loads
   */
  private final MutationInstance mutationInstance;

  public MutationClassLoader(MutationInstance mutationInstance, URL[] paths, ClassLoader parent) {
    super(paths, parent);
    this.mutationInstance = mutationInstance;
  }

  @Override
  public Class<?> findClass(String name) throws ClassNotFoundException, GuidanceException {
    try {
      byte[] bytes;

      String internalName = name.replace('.', '/');
      String path = internalName.concat(".class");
      try (InputStream in = super.getResourceAsStream(path)) {
        if (in == null) {
          throw new ClassNotFoundException("Cannot find class " + name);
        }
        bytes = in.readAllBytes();
      } catch (IOException e) {
        throw new ClassNotFoundException("I/O exception while loading class.", e);
      }

      String findingClass = name;
      AtomicLong found = new AtomicLong(0);
      ClassReader cr = new ClassReader(bytes);
      ClassWriter cw = new SafeClassWriter(cr, this,
              ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
      cr.accept(new ClassVisitor(Mutator.cvArg, cw) {
        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature,
                                         String[] exceptions) {
          return new MethodVisitor(Mutator.cvArg,
                  cv.visitMethod(access, name, descriptor, signature, exceptions)) {
            final Set<Label> visitedLabels = new HashSet<>();

            // methodId must match Cartographer: (class#name+desc).hashCode()
            final String mName = name;
            final String mDesc = descriptor;
            final int methodId = (findingClass + "#" + mName + mDesc).hashCode();

            final IdentityHashMap<Label, Integer> labelIds = new IdentityHashMap<>();
            int nextLabelId = 1;
            private int getLabelId(Label l) {
              Integer id = labelIds.get(l);
              if (id == null) {
                id = nextLabelId++;
                labelIds.put(l, id);
              }
              return id;
            }

            @Override
            public void visitLabel(Label label) {
              visitedLabels.add(label);
              super.visitLabel(label);
              int lid = getLabelId(label);
              super.visitLdcInsn(methodId);
              super.visitLdcInsn(lid);
              super.visitMethodInsn(Opcodes.INVOKESTATIC,
                      Type.getInternalName(PropagationTracer.class),
                      "hitLabel",
                      "(II)V",
                      false);
            }

            @Override
            public void visitJumpInsn(int opcode, Label label) {
              // Increment timer and check for time outs at each jump instruction
              if (visitedLabels.contains(label)) {
                mv.visitLdcInsn(mutationInstance.id);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(MutationSnoop.class),
                        "checkTimeout", "(I)V", false);
              }

              // Increment offset if the mutator matches
              if (findingClass.equals(mutationInstance.className)
                      && mutationInstance.mutator.isOpportunity(opcode, descriptor)
                      && found.getAndIncrement() == mutationInstance.sequenceIdx) {
                // Mutator and offset match, so perform mutation
                for (InstructionCall ic : mutationInstance.mutator.replaceWith()) {
                  ic.call(mv, label);
                }

                // start trace right AFTER replacement
                super.visitLdcInsn(mutationInstance.id);
                super.visitLdcInsn(methodId);
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(PropagationTracer.class),
                        "forceStart",
                        "(II)V",
                        false);
              } else {
                // No mutation
                super.visitJumpInsn(opcode, label);
              }
            }

            @Override
            public void visitLdcInsn(Object value) {
              // Increment offset if the mutator matches
              if (findingClass.equals(mutationInstance.className)
                      && mutationInstance.mutator.isOpportunity(Opcodes.LDC, descriptor)
                      && found.getAndIncrement() == mutationInstance.sequenceIdx) {
                // Mutator and offset match, so perform mutation
                for (InstructionCall ic : mutationInstance.mutator.replaceWith()) {
                  ic.call(mv, null);
                }
                super.visitLdcInsn(mutationInstance.id);
                super.visitLdcInsn(methodId);
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(PropagationTracer.class),
                        "forceStart",
                        "(II)V",
                        false);
              } else {
                // No mutation
                super.visitLdcInsn(value);
              }
            }

            @Override
            public void visitIincInsn(int var, int increment) {
              // Increment offset if the mutator matches
              if (findingClass.equals(mutationInstance.className)
                      && mutationInstance.mutator.isOpportunity(Opcodes.IINC, descriptor)
                      && found.getAndIncrement() == mutationInstance.sequenceIdx) {
                // Mutator and offset match, so perform mutation
                super.visitIincInsn(var, -increment); // TODO: Why is this hardcoded?
                super.visitLdcInsn(mutationInstance.id);
                super.visitLdcInsn(methodId);
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(PropagationTracer.class),
                        "forceStart",
                        "(II)V",
                        false);
              } else {
                // No mutation
                super.visitIincInsn(var, increment);
              }
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor,
                                        boolean isInterface) {
              // Increment offset if the mutator matches
              if (findingClass.equals(mutationInstance.className)
                      && mutationInstance.mutator.isOpportunity(opcode, descriptor)
                      && found.getAndIncrement() == mutationInstance.sequenceIdx) {
                // Mutator and offset match, so perform mutation
                for (InstructionCall ic : mutationInstance.mutator.replaceWith()) {
                  ic.call(mv, null);
                }
                super.visitLdcInsn(mutationInstance.id);
                super.visitLdcInsn(methodId);
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(PropagationTracer.class),
                        "forceStart",
                        "(II)V",
                        false);
              } else {
                // No mutation
                super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
              }
            }

            @Override
            public void visitInsn(int opcode) {
              // Increment offset if the mutator matches
              if (findingClass.equals(mutationInstance.className)
                      && mutationInstance.mutator.isOpportunity(opcode, descriptor)
                      && found.getAndIncrement() == mutationInstance.sequenceIdx) {
                // Mutator and offset match, so perform mutation
                for (InstructionCall ic : mutationInstance.mutator.replaceWith()) {
                  ic.call(mv, null);
                }
                super.visitLdcInsn(mutationInstance.id);
                super.visitLdcInsn(methodId);
                super.visitMethodInsn(Opcodes.INVOKESTATIC,
                        Type.getInternalName(PropagationTracer.class),
                        "forceStart",
                        "(II)V",
                        false);
              } else {
                // No mutation
                super.visitInsn(opcode);
              }
              // method exit: end trace if active
              switch (opcode) {
                case Opcodes.IRETURN:
                case Opcodes.LRETURN:
                case Opcodes.FRETURN:
                case Opcodes.DRETURN:
                case Opcodes.ARETURN:
                case Opcodes.RETURN:
                case Opcodes.ATHROW:
                  super.visitLdcInsn(methodId);
                  super.visitMethodInsn(Opcodes.INVOKESTATIC,
                          Type.getInternalName(PropagationTracer.class),
                          "endIfActive",
                          "(I)V",
                          false);
                  break;
                default:
                  break;
              }
            }
          };
        }
      }, 0);
      bytes = cw.toByteArray();

      return defineClass(name, bytes, 0, bytes.length);
    } catch (OutOfMemoryError e) {
      throw new GuidanceException(e);
    }
  }
}
