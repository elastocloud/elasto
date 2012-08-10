top = '.'
out = 'build'

def options(opt):
	opt.load('compiler_c')

def configure(conf):
	print("configure!")
	conf.load('compiler_c')
#	conf.check(lib=['curl','xml2'], cflags=['-Wall','-g'])
	conf.env.CFLAGS = ['-Wall','-g']
	conf.recurse('ccan')
	conf.recurse('lib')

def build(bld):
	print("build!")
	bld.recurse('ccan')
	bld.recurse('lib')
	bld.program(source='azure_test.c',
		    target='azure_test',
		    lib=['curl','xml2','crypto'],
		    use=['ccan','elasto'])
	bld.program(source='elasto_client.c cli_put.c',
		    target='elasto_cli',
		    lib=['curl','xml2','crypto'],
		    use=['ccan','elasto'])
