#!/usr/bin/python
# 
# Copyright (C) SUSE LINUX Products GmbH 2013, all rights reserved.
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

def md5_for_file(f, block_size=2**20):
	md5 = hashlib.md5()
	while True:
		data = f.read(block_size)
		if not data:
			break
		md5.update(data)
	return md5.digest()

class StarkyContext:
	pub_set_file = None
	s3_key_duo = None
	acc_prefix = "elastotest"
	acc_loc = "West Europe"
	ctnr = "starky"

	def __init__(self, options):
		# find elasto_cli binary
		if (os.path.exists("build/client/elasto_cli")):
			self.cli_bin = "build/client/elasto_cli"
		elif (os.path.exists("../build/client/elasto_cli")):
			self.cli_bin = "../build/client/elasto_cli"
		else:
			raise Exception("Could not locate elasto_cli")

		if (options.ps_file == None):
			raise Exception("publish settings file not specified")

		self.pub_set_file = options.ps_file
		if (os.path.exists(self.pub_set_file) == False):
			raise Exception("invalid publish settings file")

		self.cli_az_cmd = "%s -d %d -s \"%s\"" \
				  % (self.cli_bin, options.debug_level,
				     self.pub_set_file)

		if (options.s3_key_duo == None):
			raise Exception("S3 key duo not specified")

		self.s3_key_duo = options.s3_key_duo
		self.cli_s3_cmd = "%s -d %d -k %s" \
				  % (self.cli_bin, options.debug_level,
				     options.s3_key_duo)

	def acc_name_get(self):
		# TODO check for uniqueness, must be valid and unique within the
		# azure.com DNS namespace
		return self.acc_prefix + str(random.randint(0, 10000))


class StarkyTestAzureCreate(unittest.TestCase):
	"Azure creation tests"

	def __init__(self, testname, test_ctx):
		super(StarkyTestAzureCreate, self).__init__(testname)
		self.ctx = test_ctx

	def test_account(self):
		'''
		Create an account, then check for its existence using ls.
		'''
		acc_name = self.ctx.acc_name_get()
		sp = subprocess
		cmd = "%s -- create -l label -d desc -L \"%s\" %s" \
		      % (self.ctx.cli_az_cmd, self.ctx.acc_loc, acc_name)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create failed with "
					+ str(e.returncode) + e.output)

		print "create successful with: \n" + out

		cmd = self.ctx.cli_az_cmd + " -- ls " + acc_name
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "ls failed with "
					+ str(e.returncode))

		print "ls successful with: \n" + out

		cmd = self.ctx.cli_az_cmd + " -- del " + acc_name
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode))

		print "del successful with: \n" + out

	def test_container(self):
		'''
		Create a container, then check for its existence using ls.
		'''
		acc_name = self.ctx.acc_name_get()
		sp = subprocess

		cmd = "%s -- create -l label -d desc -L \"%s\" %s" \
		      % (self.ctx.cli_az_cmd, self.ctx.acc_loc, acc_name)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create failed with "
					+ str(e.returncode) + e.output)

		cmd = "%s -- create %s/%s" \
		      % (self.ctx.cli_az_cmd, acc_name, self.ctx.ctnr)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create container failed with "
					+ str(e.returncode))

		cmd = "%s -- ls %s/%s" \
		      % (self.ctx.cli_az_cmd, acc_name, self.ctx.ctnr)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "ls failed with "
					+ str(e.returncode))

		cmd = "%s -- del %s" % (self.ctx.cli_az_cmd, acc_name)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode))

	def test_blob(self):
		'''
		Create a page blob, then check for its existence using ls.
		'''
		acc_name = self.ctx.acc_name_get()
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
		self.tmp_dir_create = True

		self.acc_name = self.ctx.acc_name_get()
		sp = subprocess
		cmd = "%s -- create -l label -d desc -L \"%s\" %s" \
		      % (self.ctx.cli_az_cmd, self.ctx.acc_loc, self.acc_name)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create failed with "
					+ str(e.returncode) + e.output)

		cmd = "%s -- create %s/%s" \
		      % (self.ctx.cli_az_cmd, self.acc_name, self.ctx.ctnr)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "create container failed with "
					+ str(e.returncode))

	def tearDown(self):
		if (self.tmp_dir_created == True):
			shutil.rmtree(self.tmp_dir, ignore_errors=True)

		sp = subprocess
		cmd = "%s -- del %s" \
		      % (self.ctx.cli_az_cmd, self.acc_name)
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "del failed with "
					+ str(e.returncode) + e.output)

	def test_md5(self):
		tmp_path = self.tmp_dir + "/" + "got_blob"
		sp = subprocess
		# put the elasto client binary
		cmd = "%s -- put \"%s\" %s/%s/%s" \
		      % (self.ctx.cli_az_cmd,
			 self.ctx.cli_bin, self.acc_name, self.ctx.ctnr, "blob")
		try:
			out = sp.check_output(cmd, shell=True)
		except sp.CalledProcessError, e:
			self.assertTrue(False, "put blob failed with "
					+ str(e.returncode))

		# read back binary
		cmd = "%s -- get %s/%s/%s %s" \
		      % (self.ctx.cli_az_cmd,
			 self.acc_name, self.ctx.ctnr, "blob", tmp_path)
		try:
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


if __name__ == '__main__':
	parser = optparse.OptionParser()
	parser.add_option("-s", "--azure_ps_file",
			  dest="ps_file",
			  help="Azure PublishSettings file",
			  type="string",
			  default=None)
	parser.add_option("-k", "--s3_key_duo",
			  dest="s3_key_duo",
			  help="Amazon S3 key duo (ID and secret)",
			  type="string",
			  default=None)
	parser.add_option("-d", "--debug",
			  dest="debug_level",
			  help="Debug level",
			  type="int",
			  default=0)
	(options, args) = parser.parse_args()
	ctx = StarkyContext(options)
	suite = unittest.TestSuite()
	suite.addTest(StarkyTestAzureCreate("test_account", ctx))
	suite.addTest(StarkyTestAzureCreate("test_container", ctx))
	suite.addTest(StarkyTestAzureIo("test_md5", ctx))
	unittest.TextTestRunner().run(suite)
