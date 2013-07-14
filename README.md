About
=====

These are components of a nomadic filesystem I built between 2002-2007.

libpigeon
=========

Protocol communication using (carrier) pigeon.  Implements connection handling
with GSSAPI authentication and encryption.  Full protocol messages are
specified in ASN.1 and generate message handlers to unserialize inbound data
and make calls into the fileserver.
