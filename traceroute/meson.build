cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required: true)

traceroute_src = files(
  'as_lookups.c',
  'csum.c',
  'export.c',
  'extension.c',
  'mod-dccp.c',
  'mod-icmp.c',
  'mod-raw.c',
  'mod-tcp.c',
  'mod-tcpconn.c',
  'mod-udp.c',
  'module.c',
  'poll.c',
  'random.c',
  'time.c',
  'traceroute.c',
)

executable(
  'traceroute',
  traceroute_src,
  include_directories: inc_dirs,
  dependencies: [
    libsupp_dep,
    m_dep,
  ],
  install: true,
)

install_man('traceroute.8')
