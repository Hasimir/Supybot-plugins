###
# Copyright (c) 2018, Ben McGinnes
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

###

import re
import requests
import sys
import socket

headers = None
proxies = None
# Overrides via alternative config must be added or imported after
# this point.

import supybot.conf as conf
import supybot.utils as utils
from supybot.commands import *
import supybot.utils.minisix as minisix
import supybot.plugins as plugins
import supybot.commands as commands
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
from supybot.i18n import PluginInternationalization, internationalizeDocstring


if minisix.PY3:
    from html.parser import HTMLParser
    from html.entities import entitydefs
    import http.client as http_client
else:
    from HTMLParser import HTMLParser
    from htmlentitydefs import entitydefs
    import httplib as http_client

class Title(utils.web.HtmlToText):
    entitydefs = entitydefs.copy()
    entitydefs['nbsp'] = ' '
    def __init__(self):
        self.inTitle = False
        self.inSvg = False
        utils.web.HtmlToText.__init__(self)

    @property
    def inHtmlTitle(self):
        return self.inTitle and not self.inSvg

    def handle_starttag(self, tag, attrs):
        if tag == 'title':
            self.inTitle = True
        elif tag == 'svg':
            self.inSvg = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.inTitle = False
        elif tag == 'svg':
            self.inSvg = False

    def append(self, data):
        if self.inHtmlTitle:
            super(Title, self).append(data)

class DelayedIrc:
    def __init__(self, irc):
        self._irc = irc
        self._replies = []
    def reply(self, *args, **kwargs):
        self._replies.append(('reply', args, kwargs))
    def error(self, *args, **kwargs):
        self._replies.append(('error', args, kwargs))
    def __getattr__(self, name):
        assert name not in ('reply', 'error', '_irc', '_msg', '_replies')
        return getattr(self._irc, name)

if hasattr(http_client, '_MAXHEADERS'):
    def fetch_sandbox(f):
        """Runs a command in a forked process with limited memory resources
        to prevent memory bomb caused by specially crafted http responses.

        On CPython versions with support for limiting the number of headers,
        this is the identity function"""
        return f
else:
    # For the following CPython versions (as well as the matching Pypy
    # versions):
    # * 2.6 before 2.6.9
    # * 2.7 before 2.7.9
    # * 3.2 before 3.2.6
    # * 3.3 before 3.3.3
    def fetch_sandbox(f):
        """Runs a command in a forked process with limited memory resources
        to prevent memory bomb caused by specially crafted http responses."""
        def process(self, irc, msg, *args, **kwargs):
            delayed_irc = DelayedIrc(irc)
            f(self, delayed_irc, msg, *args, **kwargs)
            return delayed_irc._replies
        def newf(self, irc, *args):
            try:
                replies = commands.process(process, self, irc, *args,
                        timeout=10, heap_size=10*1024*1024,
                        pn=self.name(), cn=f.__name__)
            except (commands.ProcessTimeoutError, MemoryError):
                raise utils.web.Error(_('Page is too big or the server took '
                        'too much time to answer the request.'))
            else:
                for (method, args, kwargs) in replies:
                    getattr(irc, method)(*args, **kwargs)
        newf.__doc__ = f.__doc__
        return newf

def catch_web_errors(f):
    """Display a nice error instead of "An error has occurred"."""
    def newf(self, irc, *args, **kwargs):
        try:
            f(self, irc, *args, **kwargs)
        except utils.web.Error as e:
            irc.reply(str(e))
    return utils.python.changeFunctionName(newf, f.__name__, f.__doc__)

defaultHeaders = {
    'User-agent': 'Mozilla/5.0 (compatible; utils.web python module)'
    }

defaultProxies = {
    "proxies": False
    }

verifyTrue = {
    "verify": True
    }

verifyFalse = {
    "verify": False
    }

if conf.supybot.protocols.ssl.verifyCertificates() is False:
    verifyConf = False
elif conf.supybot.protocols.ssl.verifyCertificates() is True:
    verifyConf = True
else:
    verifyConf = None

class Rweb(callbacks.PluginRegexp):
    """Add the help for "@help Rweb" here."""
    regexps = ['titleSnarfer']
    threaded = True

    def noIgnore(self, irc, msg):
        return not self.registryValue('checkIgnored', msg.args[0])

    def getTitle(self, irc, url, raiseErrors):
        size = conf.supybot.protocols.http.peekSize()
        timeout = self.registryValue('timeout')
        (target, text) = utils.web.getUrlTargetAndContent(url, size=size,
                timeout=timeout)
        try:
            text = text.decode(utils.web.getEncoding(text) or 'utf8',
                    'replace')
        except UnicodeDecodeError:
            pass
        parser = Title()
        if minisix.PY3 and isinstance(text, bytes):
            if raiseErrors:
                irc.error(_('Could not guess the page\'s encoding. (Try '
                        'installing python-charade.)'), Raise=True)
            else:
                return None
        parser.feed(text)
        parser.close()
        title = utils.str.normalizeWhitespace(''.join(parser.data).strip())
        if title:
            return (target, title)
        elif raiseErrors:
            if len(text) < size:
                irc.error(_('That URL appears to have no HTML title.'),
                        Raise=True)
            else:
                irc.error(format(_('That URL appears to have no HTML title '
                                 'within the first %S.'), size), Raise=True)

    @fetch_sandbox
    def titleSnarfer(self, irc, msg, match):
        channel = msg.args[0]
        if not irc.isChannel(channel):
            return
        if callbacks.addressed(irc.nick, msg):
            return
        if self.registryValue('titleSnarfer', channel):
            url = match.group(0)
            if not self._checkURLWhitelist(url):
                return
            r = self.registryValue('nonSnarfingRegexp', channel)
            if r and r.search(url):
                self.log.debug('Not titleSnarfing %q.', url)
                return
            r = self.getTitle(irc, url, False)
            if not r:
                return
            (target, title) = r
            if title:
                domain = utils.web.getDomain(target
                        if self.registryValue('snarferShowTargetDomain', channel)
                        else url)
                s = format(_('Title: %s'), title)
                if self.registryValue('snarferShowDomain', channel):
                    s += format(_(' (at %s)'), domain)
                irc.reply(s, prefixNick=False)
    titleSnarfer = urlSnarfer(titleSnarfer)
    titleSnarfer.__doc__ = utils.web._httpUrlRe

    def _checkURLWhitelist(self, url):
        if not self.registryValue('urlWhitelist'):
            return True
        passed = False
        for wu in self.registryValue('urlWhitelist'):
            if wu.endswith('/') and url.find(wu) == 0:
                passed = True
                break
            if (not wu.endswith('/')) and (url.find(wu + '/') == 0 or url == wu):
                passed = True
                break
        return passed

    @wrap(['httpUrl'])
    @catch_web_errors
    @fetch_sandbox
    def headers(self, irc, msg, args, url, noverify):
        """<url> [<noverify>]

        Returns the HTTP headers of <url>.  Only HTTP urls are valid,
        of course.
        
        Optional noverify setting (default is verification of
        certificates).  If noverify is not modified, will check
        protocols.ssl settings for default preferences, if none will
        then default to verify certificates.
        """
        if not self._checkURLWhitelist(url):
            irc.error("This url is not on the whitelist.")
            return
        timeout = self.registryValue('timeout')
        if headers is None:
            headers = defaultHeaders
        if proxies is None:
            proxies = defaultProxies
        if noverify == 1:
            noverify = True
        elif noverify.lower() == "yes" or "y" or "t" or "true":
            noverify = True
        elif noverify == 0:
            noverify = False
        elif noverify.lower() == "no" or "n" or "f" or "false" or "nil":
            noverify = False
        if verifyConf is None:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        elif verifyConf is False:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
        elif verifyConf is True:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        else:
            fd = requests.get(url, headers=headers, proxies=proxies,
                              timeout=timeout, verify=True)
        # fd = utils.web.getUrlFd(url, timeout=timeout)
        k = []
        v = []
        z = []
        for key in r.headers.keys():
            k.append(key)
        for value in r.headers.values():
            v.append(value)
        for i in range(len(k)):
            z.append("{0}: {1}".format(k[i], v[i]))
        try:
            for s in z:
                irc.reply(s)
        finally:
            fd.close()

    _doctypeRe = re.compile(r'(<!DOCTYPE[^>]+>)', re.M)
    @wrap(['httpUrl'])
    @catch_web_errors
    @fetch_sandbox
    def doctype(self, irc, msg, args, url, noverify):
        """<url> [<noverify>]

        Returns the DOCTYPE string of <url>.  Only HTTP urls are valid, of
        course.
        
        Optional noverify setting (default is verification of
        certificates).  If noverify is not modified, will check
        protocols.ssl settings for default preferences, if none will
        then default to verify certificates.
        """
        if not self._checkURLWhitelist(url):
            irc.error("This url is not on the whitelist.")
            return
        size = conf.supybot.protocols.http.peekSize()
        timeout = self.registryValue('timeout')
        if headers is None:
            headers = defaultHeaders
        if proxies is None:
            proxies = defaultProxies
        if noverify == 1:
            noverify = True
        elif noverify.lower() == "yes" or "y" or "t" or "true":
            noverify = True
        elif noverify == 0:
            noverify = False
        elif noverify.lower() == "no" or "n" or "f" or "false" or "nil":
            noverify = False
        if verifyConf is None:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        elif verifyConf is False:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
        elif verifyConf is True:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        else:
            fd = requests.get(url, headers=headers, proxies=proxies,
                              timeout=timeout, verify=True)
        s = fd.content.strip().decode('utf-8').split('\n')
        # s = utils.web.getUrl(url, size=size, timeout=timeout).decode('utf8')
        m = self._doctypeRe.search(s)
        if m:
            s = utils.str.normalizeWhitespace(m.group(0))
            irc.reply(s)
        else:
            irc.reply(_('That URL has no specified doctype.'))

    @wrap(['httpUrl'])
    @catch_web_errors
    @fetch_sandbox
    def size(self, irc, msg, args, url, noverify):
        """<url> [<noverify>]

        Returns the Content-Length header of <url>.  Only HTTP urls are valid,
        of course.
        
        Optional noverify setting (default is verification of
        certificates).  If noverify is not modified, will check
        protocols.ssl settings for default preferences, if none will
        then default to verify certificates.
        """
        if not self._checkURLWhitelist(url):
            irc.error("This url is not on the whitelist.")
            return
        timeout = self.registryValue('timeout')
        if headers is None:
            headers = defaultHeaders
        if proxies is None:
            proxies = defaultProxies
        if noverify == 1:
            noverify = True
        elif noverify.lower() == "yes" or "y" or "t" or "true":
            noverify = True
        elif noverify == 0:
            noverify = False
        elif noverify.lower() == "no" or "n" or "f" or "false" or "nil":
            noverify = False
        if verifyConf is None:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        elif verifyConf is False:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
        elif verifyConf is True:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        else:
            fd = requests.get(url, headers=headers, proxies=proxies,
                              timeout=timeout, verify=True)
        # fd = utils.web.getUrlFd(url, timeout=timeout)
        s = []
        s.append(fd.content.__sizeof__().real)
        s.append(fd.text.__sizeof__().real)
        try:
            s.append(int(fd.headers['Content-Length']))
            something = fd.headers['Content-Length']
        except:
            s.append(-1)
            something = str(s[2])
        s.append(len(fd.content))
        s.append(len(fd.text))
        x = []
        x.append(s[0])
        x.append(s[1])
        x.sort()
        z = []
        z.append(s[2])
        z.append(s[3])
        z.append(s[4])
        z.sort()
        try:
            try:
                if s[2] == s[3] and s[2] == s[4]:
                    size = something
                elif s[2] == s[3] and s[2] != s[4]:
                    size = something
                elif s[2] != s[3] and s[2] == s[4]:
                    size = something
                elif s[2] != s[3] and != s[2] and s[3] == s[4]:
                    size = str(s[3])
                elif s[2] != s[3] and != s[2] and s[3] != s[4]:
                    if z[-1] > 0:
                        size = str(z[-1])
                    elif x[-1] > z[-1]:
                        size = str(x[-1])
                else:
                    size = str(x[-1])
                if size is None:
                    raise KeyError('content-length')
                else:
                    pass
                irc.reply(format(_('%u is %S long.'), url, int(size)))
            except KeyError:
                size = conf.supybot.protocols.http.peekSize()
                a = fd.content.__sizeof__()
                b = len(fd.content)
                if a != b and a > b and a != size:
                    irc.reply(format(_('%u is %S long.'), url, a))
                elif a != b and b > a and b != size:
                    irc.reply(format(_('%u is %S long.'), url, b))
                else:
                    irc.reply(format(_('The server didn\'t tell me how long %u '
                                     'is but it\'s longer than %S.'),
                                     url, size))
        finally:
            fd.close()

    @wrap([getopts({'no-filter': ''}), 'httpUrl'])
    @catch_web_errors
    @fetch_sandbox
    def title(self, irc, msg, args, optlist, url, noverify):
        """[--no-filter] <url> [<noverify>]

        Returns the HTML <title>...</title> of a URL.
        If --no-filter is given, the bot won't strip special chars (action,
        DCC, ...).
        
        Optional noverify setting (default is verification of
        certificates).  If noverify is not modified, will check
        protocols.ssl settings for default preferences, if none will
        then default to verify certificates.
        """
        if not self._checkURLWhitelist(url):
            irc.error("This url is not on the whitelist.")
            return
        r = self.getTitle(irc, url, True)
        if not r:
            return
        (target, title) = r
        if title:
            if not [y for x,y in optlist if x == 'no-filter']:
                for i in range(1, 4):
                    title = title.replace(chr(i), '')
            irc.reply(title)

    @wrap(['text'])
    def urlquote(self, irc, msg, args, text):
        """<text>

        Returns the URL quoted form of the text.
        """
        irc.reply(utils.web.urlquote(text))

    @wrap(['text'])
    def urlunquote(self, irc, msg, args, text):
        """<text>

        Returns the text un-URL quoted.
        """
        s = utils.web.urlunquote(text)
        irc.reply(s)

    @wrap(['url'])
    @catch_web_errors
    @fetch_sandbox
    def fetch(self, irc, msg, args, url, noverify):
        """<url> [<noverify>]

        Returns the contents of <url>, or as much as is configured in
        supybot.plugins.Web.fetch.maximum.  If that configuration variable is
        set to 0, this command will be effectively disabled.
        
        Optional noverify setting (default is verification of
        certificates).  If noverify is not modified, will check
        protocols.ssl settings for default preferences, if none will
        then default to verify certificates.
        """
        if not self._checkURLWhitelist(url):
            irc.error("This url is not on the whitelist.")
            return
        max = self.registryValue('fetch.maximum')
        timeout = self.registryValue('fetch.timeout')
        if not max:
            irc.error(_('This command is disabled '
                      '(supybot.plugins.Web.fetch.maximum is set to 0).'),
                      Raise=True)
        if headers is None:
            headers = defaultHeaders
        if proxies is None:
            proxies = defaultProxies
        if noverify == 1:
            noverify = True
        elif noverify.lower() == "yes" or "y" or "t" or "true":
            noverify = True
        elif noverify == 0:
            noverify = False
        elif noverify.lower() == "no" or "n" or "f" or "false" or "nil":
            noverify = False
        if verifyConf is None:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        elif verifyConf is False:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
        elif verifyConf is True:
            if noverify is not None and noverify is True:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            elif noverify is not None and noverify is False:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
            elif noverify is not None:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=False)
            else:
                fd = requests.get(url, headers=headers, proxies=proxies,
                                  timeout=timeout, verify=True)
        else:
            fd = requests.get(url, headers=headers, proxies=proxies,
                              timeout=timeout, verify=True)
        # fd = utils.web.getUrl(url, size=max, timeout=timeout).decode('utf8')
        # fdc = fd.content[:max]
        fdt = fd.text[:max]
        irc.reply(fdt)

Class = Rweb



# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
