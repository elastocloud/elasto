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

def build(bld):
	print("build!")
	bld.recurse('ccan')
	bld.program(source='azure_test.c azure_xml.c azure_req.c azure_sign.c base64.c azure_conn.c azure_ssl.c', target='azure_test', lib=['curl','xml2','crypto'], use=['ccan'])
