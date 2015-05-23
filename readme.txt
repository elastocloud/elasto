========================================================================
				   Elasto
========================================================================

Summary
-------

Elasto is a cloud library and client utility for manipulating cloud
storage objects via REST. Currently Azure and Amazon S3 are supported as
cloud storage providers.


Building
--------

Elasto uses the Waf build framework - https://github.com/waf-project/waf

libevent, libexpat and openssl (libcrypto) development libraries are
required for building.

To compile the library and client, run the following from the top of the
elasto source tree:
> ./waf configure
> ./waf build


Installing
----------

After building, Elasto can be installed by running:
> ./waf install

Prebuilt packages for GNU/Linux distributions are available via the
Elasto project website.


Running (short version)
-----------------------

= Azure =
  1. Create an Azure account

  2. Download the PublishSettings file for the account:
     https://manage.windowsazure.com/publishsettings/index

  - Blob Service -
  3.a. elasto_cli -s Azure_PublishSettings_File -u abb://

  - File Service -
  3.b. elasto_cli -s Azure_PublishSettings_File -u afs://

= Amazon S3 =
  1. Create Amazon S3 account

  2. Create an IAM group with S3 access, assign a new user to the group
     https://console.aws.amazon.com/iam/home#home

  3. Download the user's access key (credentials.csv) file

  4. elasto_cli -k iam_creds_file


Running (not so short version)
------------------------------

= Azure =
  Create an Azure account at https://azure.microsoft.com

  A PublishSettings file is required for an authenticated connection
  with Azure. It provides a management certificate / private key for
  SSL/TLS, as well as the subscriber ID.
  After creating an Azure account, the PublishSettings file can be
  downloaded at:
  https://manage.windowsazure.com/publishsettings/index

  The PublishSettings file contains security sensitive information, care
  should be taken to ensure the file remains private.

  Commands can then be issued using the elasto_cli client binary, the
  PublishSettings file is given with the -s argument. E.g.

  > elasto_cli -s PublishSettings_file <command>

  elasto_cli will use the Azure Blob Service by default when a
  PublishSettings file is provided. The Azure File Service can be used
  by specifying a "-u afs://" argument.

= Amazon S3 =
  Create an Amazon S3 account at https://aws.amazon.com/s3/

  Create an IAM group with S3 access, assign a new user to the group:
  https://console.aws.amazon.com/iam/home#home
  -> Create a New Group of Users

  The IAM user creation wizard allows for the download of access
  credentials. Select "Generate an access key for each User", and
  subsequently "Download Credentials".

  Commands can then be issued by running the elasto_cli client binary
  with the -k argument. E.g.

  > elasto_cli -k iam_creds_file <command>


Alternatives
------------

Deltacloud:	Provides an API that abstracts differences between clouds.
		http://deltacloud.apache.org/

libs3:		A C Library API for Amazon S3.
		https://github.com/bji/libs3

fog:		Ruby cloud services library.
		http://fog.io/

rest-client-c:	Object-oriented REST client in C.
		https://github.com/emcvipr/rest-client-c

atmos-c:	C library for EMC Atmos cloud storage.
		https://github.com/emcvipr/atmos-client-c

Droplet:	Cloud storage client library
		https://github.com/scality/Droplet
