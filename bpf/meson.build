libbpf_dep = dependency('libbpf', required: true)

# BPF program compilation
clang = find_program('clang')
llvm_strip = find_program('llvm-strip')

bpf_gen = generator(
  clang,
  output: '@BASENAME@.bpf.o',
  arguments: [
    '-target', 'bpf',
    '-g',
    '-O2',
    '-D__TARGET_ARCH_x86', # Assuming x86 for now, should ideally be dynamic
    '-I' + meson.current_source_dir(),
    '-I/usr/include', # Often needed for libbpf headers
    '-c', '@INPUT@',
    '-o', '@OUTPUT@'
  ]
)

bpf_object = bpf_gen.process('probe.bpf.c')

custom_target('bpf_object_target',
  input: bpf_object,
  output: 'probe.bpf.o',
  command: ['cp', '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
)
