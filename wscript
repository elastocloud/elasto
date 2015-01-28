top = '.'
out = 'build'

def options(opt):
	opt.load('compiler_c')
	opt.load('gnu_dirs')

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
	conf.recurse('ccan')
	conf.recurse('lib')
	conf.recurse('lib/file')
	conf.recurse('client')
	conf.recurse('test')
	conf.recurse('doc')

def build(bld):
	bld.recurse('ccan')
	bld.recurse('lib')
	bld.recurse('lib/file')
	bld.recurse('client')
	bld.recurse('test')
	bld.recurse('doc')
