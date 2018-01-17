============
Requests Web
============

This is an alternative or replacement for the Supybot and Limnoria Web module which utilises the Requests module instead of urllib or urllib2, save for a couple of functions.  The major advantage of which being that it is significantly easier to support SSL/TLS overrides on a case by case basisand thus support SSL or TLS connections to sites using self-signed certificates or other connections that the standard library will always produce errors with.
