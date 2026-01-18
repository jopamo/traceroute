unit_test_sources = [
  'runner.c',
  'common/fixtures.c',
  'test_parse_ipv4.c',
  'test_parse_ipv6.c',
  'test_ipv6_ext.c',
  'test_parse_transport.c',
  'test_parse_icmp.c',
  'test_icmp_quote.c',
  'test_cmsg.c',
  'test_correlator.c',
  'test_flow.c',
  'test_rtt.c',
  '../../src/io/parse.c',
  '../../src/correlate/match.c',
  '../../src/correlate/correlator.c',
  '../../src/correlate/flow.c',
  '../../src/correlate/rtt.c',
]

unit_test_inc = include_directories('.', 'common', '../../src', '../../traceroute')

unit_test_exe = executable('unit_tests',
  unit_test_sources,
  include_directories: unit_test_inc,
  c_args: ['-fsanitize=address,undefined'],
  link_args: ['-fsanitize=address,undefined'],
)

test('unit_tests', unit_test_exe)
