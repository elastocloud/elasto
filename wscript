top = '.'
out = 'build'

def options(opt):
	opt.load('compiler_c')
	opt.load('gnu_dirs')

def configure(conf):
	conf.load('compiler_c')
	conf.load('gnu_dirs')
	conf.env.CFLAGS = ['-Wall','-g']
	conf.check(lib='curl')
	conf.check(lib='apr-1')
	conf.check(lib='aprutil-1')
	conf.check(lib='crypto')
	conf.recurse('ccan')
	conf.recurse('lib')
	conf.recurse('client')
	conf.recurse('test')

def build(bld):
	bld.recurse('ccan')
	bld.recurse('lib')
	bld.recurse('client')
	bld.recurse('test')
