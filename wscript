top = '.'
out = 'build'

def options(opt):
	opt.load('compiler_c')

def configure(conf):
	print("configure!")
	conf.load('compiler_c')
	conf.env.CFLAGS = ['-Wall','-g']
	conf.check(lib='curl')
	conf.check(lib='xml2')
	conf.check(lib='crypto')
	conf.recurse('ccan')
	conf.recurse('lib')
	conf.recurse('client')

def build(bld):
	print("build!")
	bld.recurse('ccan')
	bld.recurse('lib')
	bld.recurse('client')
	bld.program(source='azure_test.c',
		    target='azure_test',
		    lib=['curl','xml2','crypto'],
		    use=['ccan','elasto'])
