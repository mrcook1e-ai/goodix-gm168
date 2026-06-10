project('libfprint-goodix-gm168', 'c',
  version: '0.1.0',
  license: 'LGPL-2.1-or-later',
  default_options: ['c_std=c11', 'warning_level=2']
)

glib_dep = dependency('glib-2.0')
usb_dep = dependency('gusb')
openssl_dep = dependency('openssl')
libfprint_dep = dependency('libfprint-2')
threads_dep = dependency('threads')

sources = [
  'goodix_gm168.c',
  'goodix_proto.c',
  'goodix_tls.c',
  'gm168_log.c',
]

shared_library('fprint-goodix-gm168',
  sources,
  dependencies: [
    glib_dep,
    usb_dep,
    openssl_dep,
    libfprint_dep,
    threads_dep
  ],
  install: true,
  install_dir: get_option('libdir') / 'libfprint-2/drivers'
)
