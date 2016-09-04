#!/usr/bin/python
# 
# Copyright (C) SUSE LINUX GmbH 2013-2016, all rights reserved.
# 
# This library is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) version 3.
# 
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# Test suite for the command line client
#
import unittest
import subprocess
import random
import time
import hashlib
import optparse
import os.path
import tempfile
import shutil
import uuid

AZ_ACC_MAXLEN = 24

def md5_for_file(f, block_size=2**20):
	md5 = hashlib.md5()
	while True:
		data = f.read(block_size)
		if not data:
			break
		md5.update(data)
	return md5.digest()

class StarkyContext:
	s3_run = False
	az_run = False
	pub_set_file = None
	s3_creds_file = None
	acc_prefix = "elastotest"
	acc_loc = "West Europe"
	bkt_loc = "eu-west-1"
	az_acc = None
	az_acc_persist_created = False

	def __init__(self, options):
		# find elasto_cli binary
		if (os.path.exists("build/client/elasto_cli")):
			self.cli_bin = "build/client/elasto_cli"
		elif (os.path.exists("../build/client/elasto_cli")):
			self.cli_bin = "../build/client/elasto_cli"
		else:
			raise Exception("Could not locate elasto_cli")

		# add generic params applicable to both PS file and access key
		self.cli_az_cmd = "%s -d %d -u %s" \
				  % (self.cli_bin, options.debug_level,
				     options.server_uri)
		if (options.insecure == True):
			self.cli_az_cmd += " -i"

		if options.ps_file:
			self.pub_set_file = options.ps_file
			if (os.path.exists(self.pub_set_file) == False):
				raise Exception("invalid publish settings file")

			self.cli_az_cmd += " -s \"%s\"" % (self.pub_set_file)

			self.az_acc = self.acc_name_generate()
			self.acc_persist_create()
			self.az_acc_persist_created = True
			self.az_run = True

		if options.az_access_key:
			self.az_access_key = options.az_access_key
			if (options.az_acc == None):
				raise Exception("Azure access key requires \
						additional account parameter")
			self.az_acc = options.az_acc

			if (options.ps_file != None):
				raise Exception("Azure access key cannot be \
						specified with ps file")

			self.cli_az_cmd += " -K \"%s\"" % (options.az_access_key)

			self.acc_stat()
			self.az_acc_persist_created = False
			self.az_run = True

		if options.s3_creds_file:
			self.s3_creds_file = options.s3_creds_file
			if (os.path.exists(self.s3_creds_file) == False):
				raise Exception("invalid S3 creds file")

			self.cli_s3_cmd = "%s -d %d -k %s" \
					  % (self.cli_bin, options.debug_level,
					     options.s3_creds_file)
			if (options.insecure == True):
				self.cli_s3_cmd += " -i"

			self.s3_run = True

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		if self.az_acc_persist_created:
			self.acc_persist_delete()

	def acc_name_get(self):
		return self.az_acc

	def acc_name_generate(self):
		return self.acc_prefix + \
			uuid.uuid4().hex[:AZ_ACC_MAXLEN - len(self.acc_prefix)]

	def acc_persist_create(self):
		sp = subprocess
		cmd = "%s -- create -L \"%s\" %s" \
		      % (self.cli_az_cmd, self.acc_loc,
			 self.acc_name_get())
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			raise

	def acc_persist_delete(self):
		sp = subprocess
		cmd = "%s -- del %s" % (self.cli_az_cmd,
					self.acc_name_get())
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			raise

	def acc_stat(self):
		sp = subprocess
		cmd = "%s -- ls %s" % (self.cli_az_cmd,
					self.acc_name_get())
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			raise

	def bkt_name_get(self):
		return self.acc_name_generate()


class StarkyTestAzureCreate(unittest.TestCase):
	"Azure creation tests"

	def __init__(self, testname, test_ctx):
		super(StarkyTestAzureCreate, self).__init__(testname)
		self.ctx = test_ctx

	def test_account(self):
		'''
		Check for an account's existence using ls.
		'''
		acc = self.ctx.acc_name_get()
		sp = subprocess
		cmd = self.ctx.cli_az_cmd + " -- ls " + acc
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "ls failed with "
					+ str(e.returncode))

	def test_container(self):
		'''
		Create a container, then check for its existence using ls.
		'''
		acc = self.ctx.acc_name_get()
		# use test name as ctnr name, but substitute invalid '_'
		ctnr = self.id().split('.')[-1].replace('_', '-')
		sp = subprocess
		cmd = "%s -- create %s/%s" \
		      % (self.ctx.cli_az_cmd, acc, ctnr)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create container failed with "
					+ str(e.returncode))

		cmd = "%s -- ls %s/%s" \
		      % (self.ctx.cli_az_cmd, acc, ctnr)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "ls failed with "
					+ str(e.returncode))

		cmd = "%s -- del %s/%s" \
		      % (self.ctx.cli_az_cmd, acc, ctnr)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode))

	def test_blob(self):
		'''
		Create a page blob, then check for its existence using ls.
		'''
		acc = self.ctx.acc_name_get()
		sp = subprocess
		# TODO, no client mechanism as yet

class StarkyTestAzureIo(unittest.TestCase):
	"Azure blob IO tests"

	def __init__(self, testname, test_ctx):
		super(StarkyTestAzureIo, self).__init__(testname)
		self.ctx = test_ctx
		self.tmp_dir_created = False

	def setUp(self):
		try:
			self.tmp_dir = tempfile.mkdtemp(prefix='elasto_tmp')
		except:
			self.assertTrue(False, "failed to create tmpdir")
		self.tmp_dir_created = True

		self.acc = self.ctx.acc_name_get()
		# use test name as ctnr name, but substitute invalid '_'
		self.ctnr = self.id().split('.')[-1].replace('_', '-')
		sp = subprocess
		cmd = "%s -- create %s/%s" \
		      % (self.ctx.cli_az_cmd, self.acc, self.ctnr)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create container failed with "
					+ str(e.returncode))

	def tearDown(self):
		if (self.tmp_dir_created == True):
			shutil.rmtree(self.tmp_dir, ignore_errors=True)

		sp = subprocess
		cmd = "%s -- del %s/%s" \
		      % (self.ctx.cli_az_cmd, self.acc, self.ctnr)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode) + e.output)

	def test_put_get_md5(self):
		tmp_path = self.tmp_dir + "/" + "got_blob"
		sp = subprocess
		# put the elasto client binary
		cmd = "%s -- put \"%s\" %s/%s/%s" \
		      % (self.ctx.cli_az_cmd,
			 self.ctx.cli_bin, self.acc, self.ctnr, "blob")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "put blob failed with "
					+ str(e.returncode))

		# read back binary
		cmd = "%s -- get %s/%s/%s %s" \
		      % (self.ctx.cli_az_cmd,
			 self.acc, self.ctnr, "blob", tmp_path)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "get blob failed with "
					+ str(e.returncode))

		# compare md5 on each file
		f = open(self.ctx.cli_bin, "r")
		src_md5 = md5_for_file(f)
		f.close()
		f = open(tmp_path, "r")
		xfer_md5 = md5_for_file(f)
		f.close()

		self.assertEqual(src_md5, xfer_md5, "md5sums do not match")

	def test_cp_md5(self):
		tmp_path = self.tmp_dir + "/" + "got_cp_blob"
		sp = subprocess
		# put the elasto client binary
		cmd = "%s -- put \"%s\" %s/%s/%s" \
		      % (self.ctx.cli_az_cmd,
			 self.ctx.cli_bin, self.acc, self.ctnr, "blob")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "put blob failed with "
					+ str(e.returncode))

		cmd = "%s -- cp %s/%s/%s %s/%s/%s" \
		      % (self.ctx.cli_az_cmd,
			 self.acc, self.ctnr, "blob",
			 self.acc, self.ctnr, "cp_blob")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "cp blob failed with "
					+ str(e.returncode))

		# read back copy of binary
		cmd = "%s -- get %s/%s/%s %s" \
		      % (self.ctx.cli_az_cmd,
			 self.acc, self.ctnr, "cp_blob", tmp_path)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "get blob failed with "
					+ str(e.returncode))

		# compare md5 on each file
		f = open(self.ctx.cli_bin, "r")
		src_md5 = md5_for_file(f)
		f.close()
		f = open(tmp_path, "r")
		xfer_md5 = md5_for_file(f)
		f.close()

		self.assertEqual(src_md5, xfer_md5, "md5sums do not match")

class StarkyTestS3Create(unittest.TestCase):
	"Amazon S3 creation tests"

	def __init__(self, testname, test_ctx):
		super(StarkyTestS3Create, self).__init__(testname)
		self.ctx = test_ctx

	def test_bucket(self):
		'''
		Create a bucket, then check for its existence using ls.
		'''
		bkt_name = self.ctx.bkt_name_get()
		sp = subprocess
		cmd = "%s -- create %s" \
		      % (self.ctx.cli_s3_cmd, bkt_name)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create failed with "
					+ str(e.returncode) + e.output)

		cmd = self.ctx.cli_s3_cmd + " -- ls " + bkt_name
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "ls failed with "
					+ str(e.returncode))

		cmd = self.ctx.cli_s3_cmd + " -- del " + bkt_name
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode))

class StarkyTestS3Io(unittest.TestCase):
	"S3 object IO tests"

	def __init__(self, testname, test_ctx):
		super(StarkyTestS3Io, self).__init__(testname)
		self.ctx = test_ctx
		self.tmp_dir_created = False

	def setUp(self):
		try:
			self.tmp_dir = tempfile.mkdtemp(prefix='elasto_tmp')
		except:
			self.assertTrue(False, "failed to create tmpdir")
		self.tmp_dir_created = True

		self.bkt_name = self.ctx.bkt_name_get()
		sp = subprocess
		cmd = "%s -- create -L %s %s" \
		      % (self.ctx.cli_s3_cmd, self.ctx.bkt_loc, self.bkt_name)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create failed with "
					+ str(e.returncode) + e.output)

	def tearDown(self):
		if (self.tmp_dir_created == True):
			shutil.rmtree(self.tmp_dir, ignore_errors=True)

		sp = subprocess
		cmd = "%s -- del %s" \
		      % (self.ctx.cli_s3_cmd, self.bkt_name)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode) + e.output)

	def test_put_get_obj_md5(self):
		tmp_path = self.tmp_dir + "/" + "got_obj"
		sp = subprocess
		# put the elasto client binary
		cmd = "%s -- put \"%s\" %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.ctx.cli_bin, self.bkt_name, "obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "put object failed with "
					+ str(e.returncode))

		# read back binary
		cmd = "%s -- get %s/%s %s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "obj", tmp_path)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "get object failed with "
					+ str(e.returncode))

		# compare md5 on each file
		f = open(self.ctx.cli_bin, "r")
		src_md5 = md5_for_file(f)
		f.close()
		f = open(tmp_path, "r")
		xfer_md5 = md5_for_file(f)
		f.close()

		self.assertEqual(src_md5, xfer_md5, "md5sums do not match")

		# clean-up, otherwise bucket delete on teardown will fail
		cmd = "%s -- del %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del object failed with "
					+ str(e.returncode))

	def test_cp_obj_md5(self):
		tmp_path = self.tmp_dir + "/" + "got_cp_obj"
		sp = subprocess
		# put the elasto client binary
		cmd = "%s -- put \"%s\" %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.ctx.cli_bin, self.bkt_name, "obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "put object failed with "
					+ str(e.returncode))

		cmd = "%s -- cp %s/%s %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "obj",
			 self.bkt_name, "cp_obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "cp object failed with "
					+ str(e.returncode))

		# read back copy of binary
		cmd = "%s -- get %s/%s %s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "cp_obj", tmp_path)
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "get object failed with "
					+ str(e.returncode))

		# compare md5 on each file
		f = open(self.ctx.cli_bin, "r")
		src_md5 = md5_for_file(f)
		f.close()
		f = open(tmp_path, "r")
		xfer_md5 = md5_for_file(f)
		f.close()

		self.assertEqual(src_md5, xfer_md5, "md5sums do not match")

		# clean-up, otherwise bucket delete on teardown will fail
		cmd = "%s -- del %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del object failed with "
					+ str(e.returncode))

		cmd = "%s -- del %s/%s" \
		      % (self.ctx.cli_s3_cmd,
			 self.bkt_name, "cp_obj")
		try:
			print "-> %s\n" % (cmd)
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del object failed with "
					+ str(e.returncode))

if __name__ == '__main__':
	parser = optparse.OptionParser()
	parser.add_option("-s", "--azure_ps_file",
			  dest="ps_file",
			  help="Azure PublishSettings file",
			  type="string",
			  default=None)
	parser.add_option("-A", "--azure_account",
			  dest="az_acc",
			  help="Azure account",
			  type="string",
			  default=None)
	parser.add_option("-K", "--azure_access_key",
			  dest="az_access_key",
			  help="Access key for given Azure account",
			  type="string",
			  default=None)
	parser.add_option("-k", "--s3_creds_file",
			  dest="s3_creds_file",
			  help="Amazon IAM credentials file",
			  type="string",
			  default=None)
	parser.add_option("-d", "--debug",
			  dest="debug_level",
			  help="Debug level",
			  type="int",
			  default=0)
	parser.add_option("-i", "--insecure",
			  dest="insecure",
			  help="Insecure, use HTTP where possible",
			  action="store_true")
	parser.add_option("-u", "--uri",
			  dest="server_uri",
			  help="REST server URI (default=abb://)",
			  type="string",
			  default="abb://")
	(options, args) = parser.parse_args()
	suite = unittest.TestSuite()
	with StarkyContext(options) as ctx:
		if ctx.az_run:
			if ctx.pub_set_file:
				# acc creation and deletion only possible with ps_file
				suite.addTest(StarkyTestAzureCreate("test_account",
								    ctx))
			suite.addTest(StarkyTestAzureCreate("test_container", ctx))
			suite.addTest(StarkyTestAzureIo("test_put_get_md5", ctx))
			suite.addTest(StarkyTestAzureIo("test_cp_md5", ctx))
		if ctx.s3_run:
			suite.addTest(StarkyTestS3Create("test_bucket", ctx))
			suite.addTest(StarkyTestS3Io("test_put_get_obj_md5", ctx))
			suite.addTest(StarkyTestS3Io("test_cp_obj_md5", ctx))
		unittest.TextTestRunner().run(suite)
