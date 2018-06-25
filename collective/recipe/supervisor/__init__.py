# -*- coding: utf-8 -*-
"""Recipe supervisor"""
from collective.recipe.supervisor import templates

import os
import re
import zc.recipe.egg


def option_setting(options, key, supervisor_key):
    return options.get(key, False) \
        and ('%s = %s' % (supervisor_key, options.get(key))) \
        or ''


class ProgramSpecParser(object):
    class UnexpectedToken(Exception):
        pass

    # "(?P<priority>\d+)"
    # "\s+"
    # "(?P<processname>[^\s]+)"
    # "(\s+\((?P<processopts>([^\)]+))\))?"
    # "\s+"
    # "(?P<command>[^\s]+)"
    # "(\s+\[(?P<args>(?!true|false)[^\]]+)\])?"
    # "(\s+(?P<directory>(?!true|false)[^\s]+))?"
    # "(\s+(?P<redirect>(true|false)))?"
    # "(\s+(?P<user>[^\s]+))?")

    def __init__(self, s):
        self.s = s
        self.priority = None
        self.processname = None
        self.processopts = None
        self.command = None
        self.args = None
        self.directory = None
        self.redirect = None
        self.user = None
        self._putback_buffer = []

    def _next_token(self, *args):
        try:
            if len(self._putback_buffer) == 0:
                t = self.s.next()
                d = t.groupdict()
                k = [k for k, v in d.items() if v is not None][0]
                if k in args:
                    return k, d[k]
            else:
                k, v = self._putback_buffer.pop()
                if k in args:
                    return k, v
        except StopIteration:
            k = 'EOF'
            if k in args:
                return k, ''
        raise self.UnexpectedToken('expected %s, got %s' % (', '.join(args), k))

    def _putback(self, kv):
        self._putback_buffer.append(kv)

    def _unescape_string(self, v):
        return re.sub(r'\\(.)', '\\1', v)

    def parse_priority(self):
        _, v = self._next_token('decimal')
        self.priority = v

    def parse_spaces(self):
        self._next_token('spaces')

    def parse_processname(self):
        result = []
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces')
            if k == 'spaces':
                self._putback((k, v))
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        self.processname = ''.join(result)

    def parse_processopts(self):
        k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
        if k != 'lparen':
            self._putback((k, v))
            self.processopts = ''
            return None
        self.processopts = self._parse_processopts(v)[1:-1]
        self._next_token('spaces')

    def _parse_processopts(self, v):
        result = [v]
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces')
            if k == 'lparen':
                result.append(self._parse_processopts(v))
            elif k == 'rparen':
                result.append(v)
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        return ''.join(result)

    def parse_command(self):
        result = []
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
            if k == 'spaces' or k == 'EOF':
                self._putback((k, v))
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        self.command = ''.join(result)

    def parse_args(self):
        k, v = self._next_token('spaces', 'EOF')
        if k == 'EOF':
            self._putback((k, v))
            return
        result = []
        self._next_token('lbracket')
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces')
            if k == 'rbracket':
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        self.args = ''.join(result)

    def parse_directory(self):
        pk, pv = self._next_token('spaces', 'EOF')
        if pk == 'EOF':
            self._putback((pk, pv))
            return
        k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
        if k in ('boolean', 'EOF'):
            self._putback((k, v))
            self._putback((pk, pv))
            return
        result = [v]
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
            if k in ('spaces', 'EOF'):
                self._putback((k, v))
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        self.directory = ''.join(result)

    def parse_redirect(self):
        pk, pv = self._next_token('spaces', 'EOF')
        if pk == 'EOF':
            self._putback((pk, pv))
            return
        k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
        if k == 'boolean':
            self.redirect = v
        else:
            self._putback((k, v))
            self._putback((pk, pv))

    def parse_user(self):
        k, v = self._next_token('spaces', 'EOF')
        if k == 'EOF':
            self._putback((k, v))
            return
        result = []
        while True:
            k, v = self._next_token('decimal', 'boolean', 'string', 'variable', 'lparen', 'rparen', 'lbracket', 'rbracket', 'chunk', 'spaces', 'EOF')
            if k in ('spaces', 'EOF'):
                self._putback((k, v))
                break
            else:
                if k == 'string':
                    v = self.unescape_string(v[1:-1])
                result.append(v)
        self.user = ''.join(result)

    def parse(self):
        self.parse_priority()
        self.parse_spaces()
        self.parse_processname()
        self.parse_spaces()
        self.parse_processopts()
        self.parse_command()
        self.parse_args()
        self.parse_directory()
        self.parse_redirect()
        self.parse_user()

    def groupdict(self):
        return {
            'priority': self.priority,
            'processname': self.processname,
            'processopts': self.processopts,
            'command': self.command,
            'args': self.args,
            'directory': self.directory,
            'redirect': self.redirect,
            'user': self.user,
            }

    def __call__(self):
        try:
            self.parse()
        except self.UnexpectedToken:
            return None
        return self


class ProgramSpecMatcher(object):
    token_re = re.compile('|'.join((
        r'''(?P<decimal>\d+)''',
        r'''(?P<spaces>\s+)''',
        r'''(?P<boolean>true|false)''',
        r'''(?P<string>"(?:[^"\\]|\\.)"|'(?:[^'\\]|\\.)')''',
        r'''(?P<variable>\$\{[^}]*\})''',
        r'''(?P<lparen>\()''',
        r'''(?P<rparen>\))''',
        r'''(?P<lbracket>\[)''',
        r'''(?P<rbracket>\])''',
        r'''(?P<chunk>[^()[\]\s\d"']+)''',
        )))
    def __init__(self):
        pass

    def match(self, s):
        return ProgramSpecParser(self.token_re.finditer(s))()


class Recipe(object):
    """zc.buildout recipe"""

    def __init__(self, buildout, name, options):
        self.buildout, self.name, self.options = buildout, name, options

        if self.options.get('supervisord-conf') is None:
            self.options['supervisord-conf'] = os.path.join(
                self.buildout['buildout']['parts-directory'],
                self.name,
                'supervisord.conf',
                )

    @property
    def _sections(self):
        default = 'global ctl http rpc services'

        return self.options.get('sections', default).split()

    def install(self):
        """Installer"""
        # Return files that were created by the recipe. The buildout
        # will remove all returned files upon reinstall.

        # general options
        buildout_dir = self.buildout['buildout']['directory']

        config_data = ""

        param = dict()

        param['user'] = self.options.get('user', '')
        param['password'] = self.options.get('password', '')
        param['port'] = self.options.get('port', '127.0.0.1:9001')
        param['file'] = self.options.get('file', '')
        param['chmod'] = self.options.get('chmod', '0700')

        http_socket = self.options.get('http-socket', 'inet')
        host_default = param['port']
        if http_socket == 'inet':
            if ':' not in host_default:
                host_default = 'localhost:{0}'.format(host_default)
            host_default = 'http://{0}'.format(host_default)
        elif http_socket == 'unix':
            host_default = 'unix://%s' % param['file']

        param['serverurl'] = self.options.get('serverurl', host_default)

        if 'global' in self._sections:
            # supervisord service
            param['logfile'] = self.options.get(
                'logfile',
                os.path.join(buildout_dir, 'var', 'log', 'supervisord.log')
            )
            param['pidfile'] = self.options.get(
                'pidfile',
                os.path.join(buildout_dir, 'var', 'supervisord.pid')
            )
            param['childlogdir'] = self.options.get(
                'childlogdir',
                os.path.join(buildout_dir, 'var', 'log')
            )
            if not os.path.isdir(param['childlogdir']):
                os.makedirs(param['childlogdir'])

            param['log_dir'] = os.path.abspath(
                os.path.dirname(param['logfile'])
            )
            if not os.path.isdir(param['log_dir']):
                os.makedirs(param['log_dir'])

            param['pid_dir'] = os.path.abspath(
                os.path.dirname(param['logfile'])
            )
            if not os.path.isdir(param['pid_dir']):
                os.makedirs(param['pid_dir'])

            param['logfile_maxbytes'] = self.options.get(
                'logfile-maxbytes',
                '50MB'
            )

            param['minfds'] = self.options.get(
                'minfds',
                '1024'
            )

            param['logfile_backups'] = self.options.get(
                'logfile-backups',
                '10'
            )
            param['loglevel'] = self.options.get('loglevel', 'info')
            param['umask'] = self.options.get('umask', '022')
            param['nodaemon'] = self.options.get('nodaemon', 'false')
            param['nocleanup'] = self.options.get('nocleanup', 'false')

            param['supervisord_user'] = option_setting(
                self.options,
                'supervisord-user',
                'user'
            )
            param['supervisord_directory'] = option_setting(
                self.options,
                'supervisord-directory',
                'directory'
            )
            param['supervisord_environment'] = option_setting(
                self.options,
                'supervisord-environment',
                'environment'
            )
            config_data += templates.GLOBAL % param

            # environment PATH variable
            env_path = self.options.get('env-path', None)
            if env_path is not None:
                config_data += templates.PATH % locals()

        if 'ctl' in self._sections:
            # (unix|inet)_http_server
            if 'http' in self._sections:
                if http_socket == 'inet':
                    config_data += templates.INET_HTTP % param
                elif http_socket == 'unix':
                    config_data += templates.UNIX_HTTP % param
                else:
                    raise ValueError(
                        "http-socket only supports values inet or nix."
                    )

            # supervisorctl
            config_data += templates.CTL % param

            ctlplugins = [c for c in self.options.get('ctlplugins', '').splitlines() if c]
            pattern = re.compile("(?P<name>[^\s]+)"
                                 "\s+"
                                 "(?P<callable>[^\s]+)")
            for ctlplugin in ctlplugins:
                match = pattern.match(ctlplugin)
                if not match:
                    raise ValueError("CTL plugins line incorrect: %s" % ctlplugin)

                config_data += templates.CTLPLUGIN_TEMPLATE % match.groupdict()

        # rpc
        if 'rpc' in self._sections:
            config_data += templates.RPC

            rpcplugins = [r for r in self.options.get('rpcplugins', '').splitlines() if r]
            pattern = re.compile("(?P<name>[^\s]+)"
                                 "\s+"
                                 "(?P<callable>[^\s]+)")
            for rpcplugin in rpcplugins:
                match = pattern.match(rpcplugin)
                if not match:
                    raise ValueError("RPC plugins line incorrect: %s" % rpcplugin)

                config_data += templates.RPC_EXTRA_TEMPLATE % match.groupdict()


        # programs
        programs = [p for p in self.options.get('programs', '').splitlines()
                    if p]
        pattern = ProgramSpecMatcher()

        if "services" in self._sections:
            for program in programs:
                match = pattern.match(program)
                if not match:
                    raise ValueError("Program line incorrect: %s" % program)

                parts = match.groupdict()
                program_user = parts.get('user')
                process_options = parts.get('processopts')
                extras = []

                if program_user:
                    extras.append('user = %s' % program_user)
                if process_options:
                    for part in process_options.split():
                        if part.find('=') == -1:
                            continue
                        (key, value) = part.split('=', 1)
                        if key and value:
                            extras.append("%s = %s" % (key, value))

                tpl_parameters = dict(
                    program=parts.get('processname'),
                    command=parts.get('command'),
                    priority=parts.get('priority'),
                    redirect_stderr=parts.get('redirect') or 'false',
                    directory=(parts.get('directory') or
                               os.path.dirname(parts.get('command'))),
                    args=parts.get('args') or '',
                    extra_config="\n".join(extras),
                )
                config_data += templates.PROGRAM % tpl_parameters

            # eventlisteners
            pattern = re.compile("(?P<processname>[^\s]+)"
                                 "(\s+\((?P<processopts>([^\)]+))\))?"
                                 "\s+"
                                 "(?P<events>[^\s]+)"
                                 "\s+"
                                 "(?P<command>[^\s]+)"
                                 "(\s+\[(?P<args>[^\]]+)\])?")

            ev_lines = self.options.get('eventlisteners', '').splitlines()
            eventlisteners = [e for e in ev_lines if e]

            for eventlistener in eventlisteners:
                match = pattern.match(eventlistener)
                if not match:
                    raise ValueError(
                        "Event Listeners line incorrect: {0}".format(
                            eventlistener
                        )
                    )

                parts = match.groupdict()
                process_options = parts.get('processopts')
                extras = []

                if process_options:
                    for part in process_options.split():
                        if part.find('=') == -1:
                            continue
                        (key, value) = part.split('=', 1)
                        if key and value:
                            extras.append("%s = %s" % (key, value))
                ev_params = dict(**param)
                ev_params['name'] = parts.get('processname')
                ev_params['events'] = parts.get('events')
                ev_params['command'] = parts.get('command')
                ev_params['args'] = parts.get('args')
                ev_params['extra_config'] = "\n".join(extras)

                config_data += templates.EVENTLISTENER % ev_params

            # groups
            groups = [g for g in self.options.get('groups', '').splitlines()
                      if g]

            pattern = re.compile("(?P<priority>\d+)"
                                 "\s+"
                                 "(?P<group>[^\s]+)"
                                 "\s+"
                                 "(?P<programs>[^\s]+)")

            for group in groups:
                match = pattern.match(group)
                if not match:
                    raise ValueError("Group line incorrect: %s" % group)

                parts = match.groupdict()

                tpl_parameters = dict(
                    priority=parts.get('priority'),
                    group=parts.get('group'),
                    programs=parts.get('programs'),
                )
                config_data += templates.GROUP % tpl_parameters

            # include
            files = [f for f in self.options.get('include', '').splitlines()
                     if f]
            if files:
                stringfiles = " ".join(files)
                config_data += templates.INCLUDE % {'stringfiles': stringfiles}

        conf_file = self.options.get('supervisord-conf')

        if not os.path.exists(os.path.dirname(conf_file)):
            os.makedirs(os.path.dirname(conf_file))

        with open(conf_file, 'w') as cf:
            cf.write(config_data)

        return self._install_scripts()

    def _install_scripts(self):
        installed = []
        conf_file = self.options.get('supervisord-conf')

        init_stmt = 'import sys; sys.argv.extend(["-c","{0}"])'.format(
            conf_file
        )

        #install extra eggs if any
        plugins = self.options.get('plugins', '')
        if plugins:
            pluginsscript = zc.recipe.egg.Egg(
                self.buildout,
                self.name,
                {'eggs': plugins}
            )
            installed += list(pluginsscript.install())

        if 'global' in self._sections:
            dscript = zc.recipe.egg.Egg(
                self.buildout,
                self.name,
                {'eggs': '\n'.join(['supervisor', plugins]),
                 'scripts': 'supervisord=%sd' % self.name,
                 'initialization': init_stmt,
                 })
            installed = list(dscript.install())

        memscript = zc.recipe.egg.Egg(
            self.buildout,
            self.name,
            {'eggs': '\n'.join(['supervisor', plugins]),
             'scripts': 'memmon=memmon',
             })
        installed += list(memscript.install())

        init_stmt = 'import sys; sys.argv[1:1] = ["-c", "{0}"]'.format(
            conf_file
        )
        if 'ctl' in self._sections:
            ctlscript = zc.recipe.egg.Egg(
                self.buildout,
                self.name,
                {'eggs': '\n'.join(['supervisor', plugins]),
                 'scripts': 'supervisorctl=%sctl' % self.name,
                 'initialization': init_stmt,
                 'arguments': 'sys.argv[1:]',
                 })
            installed += list(ctlscript.install())

        installed += [conf_file]
        return installed

    def update(self):
        """Updater"""
        return self._install_scripts()
