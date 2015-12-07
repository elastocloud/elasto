top = '.'
out = 'build'
recurse_subdirs = 'ccan lib client test doc'

def options(opt):
	opt.load('compiler_c')
	opt.load('gnu_dirs')
	opt.recurse(recurse_subdirs)

def configure(conf):
	conf.load('compiler_c')
	conf.load('gnu_dirs')
	conf.env.CFLAGS = ['-Wall', '-g', '-D_LARGEFILE64_SOURCE']
	conf.check(lib='event')
	# coarse check for libevent >= 2.1.x, whick doesn't have a pkgconfig.
	# a check for bufferevent_openssl_socket_new() would be better.
	conf.check(header_name='event2/visibility.h')
	conf.check(lib='crypto')
	conf.check(lib='expat')
	conf.recurse(recurse_subdirs)

def build(bld):
	bld.recurse(recurse_subdirs)
