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

Elasto uses the Waf build framework - http://code.google.com/p/waf/

libcurl, libapr, libapr-util and openssl (libcrypto) development
libraries are required for building.

To compile the library and client, run the following from the top of the
elasto source tree:
> ./waf configure
> ./waf build

Once compiled, the client binary will be placed under ./build/client/.


Running (short version)
-----------------------

= Azure =
  1. Create an Azure account

  2. Download the PublishSettings file for the account:
     https://windows.azure.com/download/publishprofile.aspx

  3. ./elasto_cli -s Azure_PublishSettings_File

= Amazon S3 =
  1. Create Amazon S3 account

  2. Obtain the S3 Access Key ID and Secret Access Key credentials:
     https://console.aws.amazon.com/iam/home?#security_credential

  3. ./elasto_cli -k S3_Access_Key_ID,S3_Secret_Access_Key


Running (not so short version)
------------------------------

= Azure =
  Create an Azure account at https://www.windowsazure.com

  A PublishSettings file is required for an authenticated connection
  with Azure. It provides a management certificate / private key for
  SSL/TLS, as well as the subscriber ID.
  After creating an Azure account, the PublishSettings file can be
  downloaded at:
  https://windows.azure.com/download/publishprofile.aspx

  The PublishSettings file contains security sensitive information, care
  should be taken to ensure the file remains private.

  The client binary will process the PublishSettings XML at runtime, and
  output an X.509 <subscriber_id>.pem file in the same directory as the
  PublishSettings file. This file should also remain private.

  Commands can then be issued using the elasto_cli client binary, the
  PublishSettings file is given with the -s argument. E.g.

  > ./elasto_cli -s PublishSettings_file <command>

= Amazon S3 =
  Create an Amazon S3 account at https://aws.amazon.com/s3/

  The Amazon S3 Access Key ID and Secret Access Key security credentials
  are required for an authenticated connection. These keys can be
  obtained from:
  https://console.aws.amazon.com/iam/home?#security_credential

  Commands can then be issued by running the elasto_cli client binary
  with the -k argument. E.g.

  > ./elasto_cli -k S3_Access_Key_ID,S3_Secret_Access_Key <command>


Alternatives
------------

Deltacloud:	Provides an API that abstracts differences between clouds.
		http://deltacloud.apache.org/

libs3:		A C Library API for Amazon S3.
		http://libs3.ischo.com.s3.amazonaws.com/index.html

fog:		Ruby cloud services library.
		http://fog.io/

rest-client-c:	Object-oriented REST client in C.
		http://code.google.com/p/rest-client-c/

atmos-c:	C library for EMC Atmos cloud storage.
		http://code.google.com/p/atmos-c/

Droplet:	Cloud storage client library
		https://github.com/scality/Droplet
