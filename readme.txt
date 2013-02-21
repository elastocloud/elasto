========================================================================
				   Elasto
========================================================================

Summary
-------

Elasto is a cloud library and client utility for manipulating cloud
storage objects via REST. Currently Azure is the only supported cloud
storage provider.


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

1. Create an Azure account

2. Download the PublishSettings file for the account
   https://windows.azure.com/download/publishprofile.aspx

3. ./build/client/elasto_cli -s PublishSettings_file <command> <args>


Running (not so short version)
------------------------------

Create an Azure account at https://www.windowsazure.com

A PublishSettings file is required for an authenticated connection with
Azure. It provides a management certificate / private key for SSL/TLS,
as well as the subscriber ID.
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

./build/client/elasto_cli -s PublishSettings_file <command> <args>

Run the elasto_cli without arguments for a list of available commands
and corresponding usage.


Alternatives
------------

Deltacloud: Provides an API that abstracts differences between clouds.

libs3: A C Library API for Amazon S3.

fog: Ruby cloud services library.
