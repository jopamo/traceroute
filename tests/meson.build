test_udp = executable('test_udp_probe',
  'test_udp_probe.c',
  include_directories: include_directories('../src'),
)

test('udp_probe_test', test_udp)

test_export = executable('test_export',
  'test_export.c',
  '../traceroute/export.c',
  include_directories: [inc_dirs, include_directories('../traceroute')],
)

test('export_test', test_export)