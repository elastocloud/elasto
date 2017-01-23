APPNAME = 'elasto'
VERSION = '0.7.3'
LIBELASTO_API_VERS = '0.1.0'

top = '.'
out = 'build'
recurse_subdirs = 'ccan lib client test doc third_party tcmu'

def options(opt):
	opt.load('compiler_c')
	opt.load('gnu_dirs')
	opt.recurse(recurse_subdirs)

def configure(conf):
	conf.load('compiler_c')
	conf.load('gnu_dirs')
	conf.env.CFLAGS = ['-Wall', '-D_LARGEFILE64_SOURCE', '-D_GNU_SOURCE']
	# append flags from CFLAGS environment var
	conf.cc_add_flags()
	conf.env.LIBELASTO_API_VERS = LIBELASTO_API_VERS
	conf.define('LIBELASTO_API_VERS', LIBELASTO_API_VERS)
	conf.define('ELASTO_VERS', VERSION)
	libevent_core_vers = conf.check_cfg(package='libevent',
					    modversion='libevent',
					    mandatory=True)
	if not libevent_core_vers.startswith("2.1."):
		conf.fatal("Unsupported libevent version " + libevent_core_vers)
	conf.check_cfg(package='libevent', args='--libs')
	conf.env.append_unique('LIBEVENT_LIBS', conf.env.LIB_LIBEVENT)
	conf.check_cfg(package='libevent_openssl',
		       modversion='libevent_openssl',
		       mandatory=True)
	conf.check_cfg(package='libevent_openssl', args='--libs')
	conf.env.append_unique('LIBEVENT_LIBS', conf.env.LIB_LIBEVENT_OPENSSL)
	conf.check(lib='crypto')
	conf.check(lib='expat')
	conf.recurse(recurse_subdirs)
	conf.write_config_header('config.h')

def build(bld):
	bld.recurse(recurse_subdirs)
