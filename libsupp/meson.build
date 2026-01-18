libsupp_src = files(
  'clif.c',
)

libsupp = static_library(
  'supp',
  libsupp_src,
  include_directories: inc_dirs,
)

libsupp_dep = declare_dependency(
  link_with: libsupp,
  include_directories: inc_dirs,
)
