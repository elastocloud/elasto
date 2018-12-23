APPNAME = 'elasto'
VERSION = '0.9.3'
LIBELASTO_API_VERS = '0.1.1'

top = '.'
out = 'build'
recurse_subdirs = 'ccan lib client test doc third_party'

def options(opt):
	opt.load('compiler_c')
	opt.load('gnu_dirs')
	opt.add_option('--developer', action='store_true', default=False,
		       help='build test and debug utilities')
	opt.recurse(recurse_subdirs)

def configure(conf):
	conf.load('compiler_c')
	conf.load('gnu_dirs')
	conf.env.CFLAGS = ['-Wall', '-D_LARGEFILE64_SOURCE', '-D_GNU_SOURCE']
	# append flags from CFLAGS environment var
	conf.cc_add_flags()
	conf.env.DEVEL = conf.options.developer
	conf.env.LIBELASTO_API_VERS = LIBELASTO_API_VERS
	conf.define('LIBELASTO_API_VERS', LIBELASTO_API_VERS)
	conf.define('ELASTO_VERS', VERSION)
	libevent_core_vers = conf.check_cfg(modversion='libevent',
					    mandatory=True)
	if not libevent_core_vers.startswith("2.1."):
		conf.fatal("Unsupported libevent version " + libevent_core_vers)
	conf.check_cfg(package='libevent', args='--libs')
	conf.env.append_unique('LIBEVENT_LIBS', conf.env.LIB_LIBEVENT)
	conf.check_cfg(modversion='libevent_openssl',
		       mandatory=True)
	conf.check_cfg(package='libevent_openssl', args='--libs')
	conf.env.append_unique('LIBEVENT_LIBS', conf.env.LIB_LIBEVENT_OPENSSL)
	conf.check_cfg(package='libcrypto', mandatory=True)
	conf.check_cfg(package='libcrypto', atleast_version='1.1.0',
		       mandatory=False, uselib_store='LIBCRYPTO_110_PLUS')
	conf.check(lib='expat')
	conf.recurse(recurse_subdirs)
	conf.write_config_header('config.h')

def build(bld):
	bld.recurse(recurse_subdirs)
