#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2014 - Krister Hedfors
#
# TODO:
#  * expr for custom group names available in filter: install path, date, ..
#  * counters, matrix, shortnames
#  * SQL server default cred
#  * MS KB\d+
#  * heartbleed
#  * 52001 QuickFixEngineering enumeration (patch installation date info)
#
#

import unittest
import sys
import logging
import optparse
import csv
import re
import collections
import itertools
from functools import partial
from operator import itemgetter
# import ipdb


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def debug(*args, **kw):
    msg = ' '.join(str(a) for a in args)
    logger.debug('  ' + msg)


__usage__ = '''
Lochus integrates Nessus CSV-style result files for effortless shell invocation.

 $ python lochus.py [options] nessus_result.csv
'''


def flatten(it):
    '''
        http://stackoverflow.com/questions/11503065/
         python-function-to-flatten-generator-containing-another-generator
    '''
    for x in it:
        if (isinstance(x, collections.Iterable) and not isinstance(x, str)):
            for y in flatten(x):
                yield y
        else:
            yield x


class LochusAction(object):
    __opt_name__ = None
    __opt_action__ = 'store_true'
    __opt_help__ = 'not set'
    __filter__ = {}
    __refilter__ = {}
    __format__ = ''

    @classmethod
    def opt_arg(cls):
        n = cls.__opt_name__.replace('-', '_')
        while n.startswith('_'):
            n = n[1:]
        return n

    def __init__(self, opt):
        self._opt = opt
        self._outbuf = ''

    def output(self, s):
        self._outbuf += s

    def flush(self):
        sys.stdout.write(self._outbuf)
        sys.stdout.flush()
        self._outbuf = ''

    def _unroll_lines(self, s, defs):
        res = []
        lines = s.splitlines()
        for line in lines:
            for i in flatten(self._unroll(line, defs)):
                res.append(i)
        s = '\n'.join(res) + '\n'
        return s

    def _format_item(self, item):
        return str(item)

    def _unroll(self, line, defs):
        m = re.search('{{(\w+)}}', line)
        if not m:
            yield line
        else:
            name = m.group(1)
            if name not in defs:
                errmsg = 'Format keyword not found: {0}'.format(name)
                raise Exception(errmsg)
            head = line[:m.start()]
            foot = line[m.end():]
            it = defs[name]
            assert type(it) in (list, tuple)
            for item in it:
                line = '{0}{1}{2}'.format(head, self._format_item(item), foot)
                yield self._unroll(line, defs)

    def format(self, tmpl, **defs):
        tmpl = self._unroll_lines(tmpl, defs)
        s = tmpl.format(**defs)
        return s

    def mangle(self, r):
        return r

    def action(self, r):
        '''
        default action: create output from formatting template __format__
        '''
        if self.__format__:
            s = self.format(self.__format__, **r)
            self.output(s)
        else:
            raise NotImplemented

    def match(self, r):
        if not self._match_filter(r):
            return False
        if not self._match_refilter(r):
            return False
        return True

    def _match_filter(self, r):
        if len(self.__filter__):
            for (name, val) in self.__filter__.iteritems():
                assert name in r
                if r[name] != val:
                    return False
        return True

    def _match_refilter(self, r):
        if len(self.__refilter__):
            for (name, val) in self.__refilter__.iteritems():
                assert name in r
                if not re.search(val, r[name]):
                    return False
        return True


class SNMPPublicAction(LochusAction):
    __rid__ = 'SNMPPublicaction'
    __opt_name__ = '--snmp-public'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list hosts responding to SNMP public'
    __filter__ = {'Plugin ID': '41028'}  # X.509 info
    __format__ = '{Host}'


class MicrosoftPatches(LochusAction):
    __rid__ = 'MicrosoftPatches'
    __opt_name__ = '--ms-patches'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list missing Microsoft patches'
    __refilter__ = {'Name': r'MS[0-9]+-[0-9]+|MS.*KB[0-9]+'}
    __format__ = '{Host} {Risk} {Name}'


class DashListAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'
    __format__ = '{Host} {{__dashlist__}}\n'

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall('\s-\s(.*)', o):
            lst.append(item)
        r[self.__rid__] = lst
        r['__dashlist__'] = lst
        return r


class PlusListAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'
    __format__ = '{Host} {{__pluslist__}}\n'

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall('\s\+\s(.*)', o):
            lst.append(item)
        r[self.__rid__] = lst
        r['__pluslist__'] = lst
        return r


class ItemAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'
    __format__ = '{Host} {__item__}\n'
    __expr__ = r''

    def mangle(self, r):
        o = r['Plugin Output']
        m = re.search(self.__expr__, o)
        if not m:
            return None
        item = m.group(1)
        r[self.__rid__] = item
        r['__item__'] = item
        return r


class IcmpTimestamp(ItemAction):
    __rid__ = 'IcmpTimestamp'
    __opt_name__ = '--icmp-timestamp'
    __opt_action__ = 'store_true'
    __opt_help__ = 'get timediff of ICMP timestamp'
    __filter__ = {'Plugin ID': '10114'}
    __expr__ = r'is (-?\d+) seconds'


class ItemListAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'
    __format__ = '{Host} {{__itemlist__}}\n'
    __expr__ = ''

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall(self.__expr__, o):
            lst.append(item)
        r[self.__rid__] = lst
        r['__itemlist__'] = lst
        return r


class UniqueItemListAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'
    __format__ = '{Host} {{__itemlist__}}\n'
    __expr__ = ''

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall(self.__expr__, o):
            if item not in lst:
                lst.append(item)
        r[self.__rid__] = lst
        r['__itemlist__'] = lst
        return r


class CommonNamesAction(UniqueItemListAction):
    __rid__ = 'CommonNames'
    __opt_name__ = '--common-names'
    __opt_action__ = 'store_true'
    __opt_help__ = 'Print all common names from TLS listener certificates'
    __format__ = '{Host} {{__itemlist__}}\n'
    __filter__ = {'Plugin ID': '10863'}  # X.509 info
    __expr__ = 'DNS:\s*(\S+)'

    def mangle(self, r):
        res = super(CommonNamesAction, self).mangle(r)
        o = r['Plugin Output']
        m = re.search(r'Common Name:\s*(\S+)', o)
        if m:
            common_name = m.group(1)
            itemlist = res['__itemlist__']
            if common_name not in itemlist:
                itemlist.insert(0, common_name)
        return res


class FlashPlayerVulns(ItemAction):
    __rid__ = 'FlashPlayer'
    __opt_name__ = '--flash-player-vulns'
    __opt_action__ = 'store_true'
    __opt_help__ = 'shows vulnerable versions of Flash Player'
    __refilter__ = {'Name': r'(?i)flash player'}
    __format__ = '{Host} {Risk} {__item__} {Name}\n'
    __expr__ = '(?i)installed version\s*:\s*(\S+)'


class AdobeReaderVulns(ItemAction):
    __rid__ = 'AdobeReaderVulns'
    __opt_name__ = '--adobe-reader-vulns'
    __opt_action__ = 'store_true'
    __opt_help__ = 'shows vulnerable versions of Adobe Reader'
    __refilter__ = {'Name': r'(?i)adobe reader'}
    __format__ = '{Host} {Risk} {__item__}\n'
    __expr__ = '(?i)installed version\s*:\s*(\S+)'


class FoxitReaderVulns(ItemAction):
    __rid__ = 'FoxitReaderVulns'
    __opt_name__ = '--foxit-reader-vulns'
    __opt_action__ = 'store_true'
    __opt_help__ = 'shows vulnerable versions of Foxit Reader'
    __refilter__ = {'Name': r'(?i)foxit reader'}
    __format__ = '{Host} {Risk} {__item__}\n'
    __expr__ = '(?i)installed version\s*:\s*(\S+)'


class IPMIHash(LochusAction):
    '''
        IPMI v2 Password Hash Disclosure
    '''
    __rid__ = 'IPMIHash'
    __opt_name__ = '--ipmi-hash'
    __opt_action__ = 'store_true'
    __opt_help__ = 'Prints IPMI hash'
    __filter__ = {'Plugin ID': '80101'}
    __format__ = '{Host} {Port}'


class JavaVulns(ItemAction):
    '''
        Has vulnerable version of Oracle Java installed
    '''
    __rid__ = 'JavaVulns'
    __opt_name__ = '--java-vulns'
    __opt_action__ = 'store_true'
    __opt_help__ = 'Prints vulnerable versions of Java installed'
    __refilter__ = {'Name': r'(?i)java.*vulnerabilities'}
    __format__ = '{Host} {Risk} {__item__}\n'
    __expr__ = '(?i)installed version\s*:\s*(\S+)'


class JREUniversal(LochusAction):
    '''
        Has Oracle Java JRE univerally enabled, for all browsers
    '''
    __rid__ = 'JREUniversal'
    __opt_name__ = '--jre-universal'
    __opt_action__ = 'store_true'
    __opt_help__ = 'hosts having Oracle Java JRE universally enabled'
    __filter__ = {'Plugin ID': '65739'}
    __format__ = '{Host}\n'


class JREie(LochusAction):
    '''
        Has Oracle Java JRE enabled for Internet Explorer
    '''
    __rid__ = 'JREie'
    __opt_name__ = '--jre-ie'
    __opt_action__ = 'store_true'
    __opt_help__ = 'hosts having Oracle Java JRE enabled for Internet Explorer'
    __filter__ = {'Plugin ID': '65743'}
    __format__ = '{Host}\n'


class NFSShares(LochusAction):
    '''
        May produce a triplet of output, as nessus reports three
        individual vulnerabilities; one for each one of:
            CVE-1999-0170
            CVE-1999-0211
            CVE-1999-0554
    '''
    __rid__ = 'NFSShares'
    __opt_name__ = '--nfs-shares'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list NFS shares'
    __filter__ = {'Plugin ID': '11356'}
    __format__ = '{Host} {{__nfslist__}}\n'

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall('(^.*\s[\+-]\s\s*.*)$', o, re.MULTILINE):
            item = item.replace('\n', '')
            lst.append(item)
        r[self.__rid__] = lst
        r['__nfslist__'] = lst
        return r


class SmbShares(DashListAction):
    __rid__ = 'SmbShares'
    __opt_name__ = '--smb-shares'
    __opt_help__ = 'list SMB shares'
    __filter__ = {'Plugin ID': '10395'}
    __format__ = '\\\\{Host}\\{{__dashlist__}}'


class AutoDisabledAccounts(DashListAction):
    __rid__ = 'AutoDisabledAccounts'
    __opt_name__ = '--auto-disabled-accounts'
    __opt_help__ = 'list Windows Automatically Disabled Accounts'
    __filter__ = {'Plugin ID': '10895'}


class DisabledAccounts(DashListAction):
    __rid__ = 'DisabledAccounts'
    __opt_name__ = '--disabled-accounts'
    __opt_help__ = 'list Windows Disabled Accounts'
    __filter__ = {'Plugin ID': '10897'}


class NeverChangedPassword(DashListAction):
    __rid__ = 'NeverChangedPassword'
    __opt_name__ = '--never-changed-password'
    __opt_help__ = 'list Windows Accounts which never changed their password'
    __filter__ = {'Plugin ID': '10898'}


class NeverLoggedIn(DashListAction):
    __rid__ = 'NeverLoggedIn'
    __opt_name__ = '--never-logged-in'
    __opt_help__ = 'list Windows accounts which has never logged in'
    __filter__ = {'Plugin ID': '10899'}


class PasswordNeverExpires(DashListAction):
    __rid__ = 'PasswordNeverExpires'
    __opt_name__ = '--password-never-expires'
    __opt_help__ = 'list Windows accounts having passwords which never expire'
    __filter__ = {'Plugin ID': '10900'}


class Admins(DashListAction):
    __rid__ = 'Admins'
    __opt_name__ = '--admins'
    __opt_help__ = 'list Windows Administrator accounts'
    __filter__ = {'Plugin ID': '10902'}


class BackupOperators(DashListAction):
    __rid__ = 'BackupOperators'
    __opt_name__ = '--backup-operators'
    __opt_help__ = 'list Windows Backup Operator accounts'
    __filter__ = {'Plugin ID': '10904'}


class DomainAdmins(DashListAction):
    __rid__ = 'DomainAdmins'
    __opt_name__ = '--domain-admins'
    __opt_help__ = 'list Windows Domain Administrator accounts'
    __filter__ = {'Plugin ID': '10908'}


class DomainSidUsers(DashListAction):
    __rid__ = 'DomainSidUsers'
    __opt_name__ = '--domain-sid-users'
    __opt_help__ = 'Windows Domain-SID enumerated users'
    __filter__ = {'Plugin ID': '10399'}


class HostSidUsers(DashListAction):
    __rid__ = 'HostSidUsers'
    __opt_name__ = '--host-sid-users'
    __opt_help__ = 'Windows Host-SID enumerated users'
    __filter__ = {'Plugin ID': '10860'}


class FQDN(ItemListAction):
    __rid__ = 'FQDN'
    __opt_name__ = '--fqdn'
    __opt_help__ = 'additional DNS hostnames'
    __filter__ = {'Plugin ID': '12053'}
    __expr__ = '.*resolves as (.+)\.'


class Hostnames(DashListAction):
    __rid__ = 'Hostnames'
    __opt_name__ = '--hostnames'
    __opt_help__ = 'additional DNS hostnames'
    __filter__ = {'Plugin ID': '46180'}


class WebServer(LochusAction):
    __rid__ = 'WebServer'
    __opt_name__ = '--webservers'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list web serers'
    __filter__ = {'Plugin ID': '10107'}
    __format__ = '{Host}:{Port} {Webserver}\n'

    def mangle(self, r):
        o = r['Plugin Output']
        r['Webserver'] = o.split('\n')[-1].strip()
        return r


class BrowsableWebDirectories(ItemListAction):
    __rid__ = 'BrowsableWebDirectories'
    __opt_name__ = '--browsable-web-directories'
    __opt_help__ = 'Browsable web directories'
    __filter__ = {'Plugin ID': '40984'}
    __format__ = '{{__itemlist__}}'
    __expr__ = '\n(https?://\S+)'


class Urls(ItemListAction):
    __rid__ = 'Urls'
    __opt_name__ = '--urls'
    __opt_help__ = 'All URLs in Plugin Output. Warning: includes external URLs'
    __refilter__ = {'Plugin Output': r'(https?://\S+)'}
    __format__ = '{{__itemlist__}}  {Name}'
    __expr__ = r'(https?://\S+)'


class Service(LochusAction):
    __rid__ = 'Service'
    __opt_name__ = '--services'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list services'
    __filter__ = {'Plugin ID': '22964'}
    __format__ = '{Host} {Port} {ServiceDesc}\n'

    def mangle(self, r):
        o = r['Plugin Output']
        r['ServiceDesc'] = o.strip()
        return r


class IpListAction(LochusAction):
    __rid__ = None
    __opt_action__ = 'store_true'

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall('^(\d+\.\d+\.\d+\.\d+)', o, re.MULTILINE):
            lst.append(item)
        r[self.__rid__] = lst
        r['__iplist__'] = lst
        return r


class Traceroute(IpListAction):
    __opt_name__ = '--traceroute'
    __opt_action__ = 'store_true'
    __opt_help__ = 'show traceroute'
    __filter__ = {'Plugin ID': '10287'}

    def _action(self, r):
        s = r['Host'] + ':'
        s += ' ' * (30 - len(s))
        s += ' '.join(r['__iplist__'])
        s += '\n'
        self.output(s)

    def action(self, r):
        s = ' '.join(r['__iplist__'])
        s += ' ({0})'.format(r['Host'])
        s += '\n'
        self.output(s)


class CommonPlatformEnumeration(LochusAction):
    __rid__ = 'CommonPlatformEnumeration'
    __opt_name__ = '--cpe'
    __opt_action__ = 'store_true'
    __opt_help__ = 'show Common Platform Enumeration results'
    __filter__ = {'Plugin ID': '45590'}
    __format__ = '{Host} {{__cpelist__}}'

    def mangle(self, r):
        lst = []
        o = r['Plugin Output']
        for item in re.findall('^.*(cpe:/.*)$', o, re.MULTILINE):
            lst.append(item)
        r[self.__rid__] = lst
        r['__cpelist__'] = lst
        return r


class CommonPlatformEnumerationReverse(CommonPlatformEnumeration):
    __rid__ = 'CommonPlatformEnumerationReverse'
    __opt_name__ = '--cpe2'
    __opt_help__ = 'show Common Platform Enumeration results, reverse order'
    __format__ = '{{__cpelist__}} {Host}'


class Lochus(object):

    def get_option_parser(self):
        parser = optparse.OptionParser(usage=__usage__)
        parser.add_option('-f', '--format',
                          help='specify custom output format')
        parser.add_option('', '--format-show', action='store_true',
                          help='show default format')
        parser.add_option('-O', '--overview', action='store_true',
                          help='show overview of what can be parsed')
        parser.add_option('-H', '--byhost', action='store_true',
                          help='list all issues by host')
        parser.add_option('-V', '--byvuln', action='store_true',
                          help='list all issues by vulnerability')
        parser.add_option('-v', '--verbose', action='count',
                          help='increase verbosity')
        for ac in self._get_action_classes():
            parser.add_option('',
                              ac.__opt_name__,
                              action=ac.__opt_action__,
                              help=ac.__opt_help__)
        return parser

    def load_nessus_csv_files(self, files):
        _reader = partial(csv.DictReader, delimiter=',', quotechar='"')
        _readers = map(_reader, files)
        self._rchain = itertools.chain(*_readers)

    def _get_action_classes(self, opt=None):
        '''
            Get LochusAction subclasses from globals().
            If opt is specified, only return those matching supplied
            command-line args.
        '''
        lst = []
        for (_, obj) in globals().iteritems():
            try:
                if issubclass(obj, LochusAction):
                    #
                    # These are abstract
                    #
                    if obj is LochusAction:
                        continue
                    if obj is ItemAction:
                        continue
                    if obj is ItemListAction:
                        continue
                    if obj is UniqueItemListAction:
                        continue
                    if obj is PlusListAction:
                        continue
                    if obj is DashListAction:
                        continue
                    if obj is IpListAction:
                        continue
                    if not opt or opt.__dict__[obj.opt_arg()]:
                        lst.append(obj)
            except TypeError:
                pass
        return lst

    def format_show(self, opt):
        actions = [ac(opt) for ac in self._get_action_classes(opt)]
        for a in actions:
            print a.__format__

    def run(self, opt):
        actions = [ac(opt) for ac in self._get_action_classes(opt)]
        for r in self._rchain:
            for a in actions:
                if a.match(r):
                    r = a.mangle(r)
                    if r is None:
                        continue
                    if opt.format:
                        s = a.format(opt.format, **r)
                        a.output(s)
                    else:
                        a.action(r)
        for action in actions:
            action.flush()

    def overview(self, opt):
        actions = [ac(opt) for ac in self._get_action_classes()]
        adict = {}
        for r in self._rchain:
            for a in actions:
                if hasattr(a, '__rid__') and a.__rid__:
                    if a.match(r):
                        adict.setdefault(a, 0)
                        adict[a] += 1
        for (action, count) in adict.iteritems():
            print '{0}\t{1} ({2})'.format(count, action.__rid__,
                                          action.__opt_name__)

    def byvuln(self, opt):
        rlist = [r for r in self._rchain]
        rlist.sort(key=itemgetter('CVSS', 'Risk'), reverse=1)
        keys = ['CVSS', 'Risk', 'Host', 'Synopsis']
        # keys += ['Description']
        # keys += ['Plugin Output']
        for r in rlist:
            if not r['CVSS']:
                r['CVSS'] = '0.0'
            print '  '.join(itemgetter(*keys)(r))


def main():
    lochus = Lochus()
    parser = lochus.get_option_parser()
    (opt, files) = parser.parse_args()
    if opt.format_show:
        lochus.format_show(opt)
        sys.exit(0)
    if len(files) == 0:
        parser.print_help()
        sys.exit()
    if '-' in files:
        idx = files.find('-')
        files[idx] = '/dev/stdin'
    if opt.format:
        fmt = opt.format
        fmt = fmt.replace('\\r', '\r')
        fmt = fmt.replace('\\n', '\n')
        fmt = fmt.replace('\\t', '\t')
        opt.format = fmt
    files = map(open, files)
    lochus.load_nessus_csv_files(files)
    if opt.overview:
        lochus.overview(opt)
        sys.exit(0)
    if opt.byvuln:
        lochus.byvuln(opt)
        sys.exit(0)
    lochus.run(opt)


class Test(unittest.TestCase):

    def test_test(self):
        assert 1 == 1

    def test1(self):
        pass

if __name__ == '__main__':
    sys.exit(main())
