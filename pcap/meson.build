# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile

pcap_dep = dependency('libpcap', required: get_option('pcap'))
if not pcap_dep.found()
  subdir_done()
endif

# pcap/pcap-plugin.h may not be installed yet if building against a
# development libpcap. Check the source tree next to grout first.
fs = import('fs')
pcap_srcdir = get_option('pcap_srcdir')
pcap_extra_args = []
if pcap_srcdir == ''
  # Auto-detect ../libpcap relative to the project source root.
  _auto = meson.project_source_root() / '..' / 'libpcap'
  if fs.is_file(_auto / 'pcap' / 'pcap-plugin.h')
    pcap_srcdir = _auto
  endif
endif

if pcap_srcdir != ''
  pcap_extra_args += ['-I' + pcap_srcdir]
endif

# Test that pcap/pcap-plugin.h is available.
if not compiler.has_header('pcap/pcap-plugin.h',
    dependencies: pcap_dep,
    args: pcap_extra_args)
  if get_option('pcap').enabled()
    error('pcap/pcap-plugin.h not found. Set -Dpcap_srcdir=/path/to/libpcap or install libpcap with plugin support.')
  endif
  subdir_done()
endif

# Read the plugin install directory from libpcap's pkg-config.
# Falls back to $libdir/pcap/plugins if not available (e.g. when
# building against a libpcap source tree without pkg-config).
pcap_plugin_dir = get_option('libdir') / 'pcap' / 'plugins'
if pcap_dep.type_name() == 'pkgconfig'
  _pkgdir = pcap_dep.get_variable(pkgconfig: 'plugindir', default_value: '')
  if _pkgdir != ''
    pcap_plugin_dir = _pkgdir
  endif
endif

shared_module(
  'pcap-grout',
  files('pcap-grout.c'),
  include_directories: api_inc,
  dependencies: [pcap_dep],
  c_args: ['-D_GNU_SOURCE', '-fms-extensions'] + pcap_extra_args,
  name_prefix: '',
  install: true,
  install_dir: pcap_plugin_dir,
)
