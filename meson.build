project(
  'traceroute',
  'c',
  version: '0.0.0',
  default_options: [
    'c_std=gnu11',
    'warning_level=2',
  ],
)

add_project_arguments(
  '-DTRACEROUTE_VERSION="@0@"'.format(meson.project_version()),
  language: 'c',
)

inc_dirs = include_directories(
  'include',
  'libsupp',
)

subdir('libsupp')
subdir('src')
subdir('bpf')
subdir('traceroute')
subdir('tests')
