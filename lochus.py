#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2014 - Krister Hedfors
#
# TODO:
#  + unroll {{name}}
#  + Host / Domain SID user enumeration?
#  * counters, matrix, shortnames
#  * SQL server default cred
#  * MS KB\d+
#  * heartbleed
#  * 52001 QuickFixEngineering enumeration (patch installation date info)
#
import unittest
import sys
import logging
import optparse
import csv
import re
import collections
from functools import partial
import itertools
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


class MicrosoftPatches(LochusAction):
    __opt_name__ = '--ms-patches'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list missing Microsoft patches'
    __refilter__ = {'Name': '^MS\d+-\d+'}

    def mangle(self, r):
        MSID, NameDesc = r['Name'].split(':', 1)
        NameDesc = NameDesc.lstrip()
        r['MSID'] = MSID
        r['NameDesc'] = NameDesc
        return r

    def action(self, r):
        s = r['Host'] + ' ' + r['MSID']
        if self._opt.verbose:
            s += ' ' + r['NameDesc']
        s += '\n'
        self.output(s)


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


class Hostnames(DashListAction):
    __rid__ = 'Hostnames'
    __opt_name__ = '--hostnames'
    __opt_help__ = 'additional DNS hostnames'
    __filter__ = {'Plugin ID': '46180'}


class WebServer(LochusAction):
    __opt_name__ = '--webservers'
    __opt_action__ = 'store_true'
    __opt_help__ = 'list web serers'
    __filter__ = {'Plugin ID': '10107'}
    __format__ = '{Host}:{Port} {Webserver}\n'

    def mangle(self, r):
        o = r['Plugin Output']
        r['Webserver'] = o.split('\n')[-1].strip()
        return r


class Service(LochusAction):
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

    def action(self, r):
        s = r['Host'] + ':'
        s += ' ' * (17 - len(s))
        s += ' '.join(r['__iplist__'])
        s += '\n'
        self.output(s)


class Lochus(object):

    def get_option_parser(self):
        parser = optparse.OptionParser(usage=__usage__)
        parser.add_option('-f', '--format',
                          help='specify custom output format')
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
                    if obj is DashListAction:
                        continue
                    if obj is IpListAction:
                        continue
                    if not opt or opt.__dict__[obj.opt_arg()]:
                        lst.append(obj)
            except TypeError:
                pass
        return lst

    def run(self, opt):
        actions = [ac(opt) for ac in self._get_action_classes(opt)]
        for r in self._rchain:
            for a in actions:
                if a.match(r):
                    r = a.mangle(r)
                    if opt.format:
                        s = a.format(opt.format, **r)
                        a.output(s)
                    else:
                        a.action(r)
        for action in actions:
            action.flush()


def main():
    lochus = Lochus()
    parser = lochus.get_option_parser()
    (opt, files) = parser.parse_args()
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
    lochus.run(opt)


class Test(unittest.TestCase):

    def test_test(self):
        assert 1 == 1

    def test1(self):
        pass

if __name__ == '__main__':
    sys.exit(main())
