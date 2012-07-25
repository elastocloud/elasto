top = '.'
out = 'build'

def options(opt):
	opt.load('compiler_c')

def configure(conf):
	print("configure!")
	conf.load('compiler_c')
#	conf.check(lib=['curl','xml2'], cflags=['-Wall','-g'])
	conf.env.CFLAGS = ['-Wall','-g']

def build(bld):
	print("build!")
	bld.program(source='azure_ssl.c', target='azure_ssl', lib=['curl','xml2'])
