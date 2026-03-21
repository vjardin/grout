# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Vincent Jardin, Free Mobile

# The pcap-grout.so plugin requires a libpcap with plugin loader
# support (pcap/pcap-plugin.h). This is not yet upstream, so it
# may not be available in system packages. Skip silently when the
# header is missing — the capture subsystem works fine without the
# plugin (grcli capture dump is always available).
pcap_dep = dependency('libpcap', required: false)
if not pcap_dep.found()
  subdir_done()
endif

# pcap/pcap-plugin.h may not be installed yet if building against a
# development libpcap. Check the subproject source tree, then a
# sibling ../libpcap directory, then pcap_srcdir option.
fs = import('fs')
pcap_srcdir = get_option('pcap_srcdir')
pcap_extra_args = []
if pcap_srcdir == ''
  _sub = meson.project_source_root() / 'subprojects' / 'libpcap'
  _sibling = meson.project_source_root() / '..' / 'libpcap'
  if fs.is_file(_sub / 'pcap' / 'pcap-plugin.h')
    pcap_srcdir = _sub
  elif fs.is_file(_sibling / 'pcap' / 'pcap-plugin.h')
    pcap_srcdir = _sibling
  endif
endif

if pcap_srcdir != ''
  pcap_extra_args += ['-I' + pcap_srcdir]
endif

# Test that pcap/pcap-plugin.h is available.
# Skip compiler check for cmake subproject deps (meson rejects internal deps
# in has_header). The fs.is_file check on pcap_srcdir already covers that case.
if pcap_dep.type_name() != 'internal'
  if not compiler.has_header('pcap/pcap-plugin.h',
      dependencies: pcap_dep,
      args: pcap_extra_args)
    # pcap-plugin.h not available — plugin loader not in this libpcap.
    # This is expected on systems with stock libpcap. Skip silently.
    subdir_done()
  endif
elif pcap_srcdir == ''
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
