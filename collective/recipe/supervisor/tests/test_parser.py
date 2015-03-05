import unittest

class ProgramSpecMatcherTest(unittest.TestCase):
    def test_full(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname (processopts=(a)) true/a/b/command [args args] directory true user")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, 'processopts=(a)')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, 'directory')
        self.assertEqual(result.redirect, 'true')
        self.assertEqual(result.user, 'user')

    def test_without_user(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname (processopts=(a)) true/a/b/command [args args] directory true")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, 'processopts=(a)')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, 'directory')
        self.assertEqual(result.redirect, 'true')
        self.assertEqual(result.user, None)

    def test_without_user_and_redirect(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname (processopts=(a)) true/a/b/command [args args] directory")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, 'processopts=(a)')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, 'directory')
        self.assertEqual(result.redirect, None)
        self.assertEqual(result.user, None)

    def test_without_redirect(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname (processopts=(a)) true/a/b/command [args args] directory user")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, 'processopts=(a)')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, 'directory')
        self.assertEqual(result.redirect, None)
        self.assertEqual(result.user, 'user')

    def test_without_directory(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname (processopts=(a)) true/a/b/command [args args] true user")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, 'processopts=(a)')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, None)
        self.assertEqual(result.redirect, 'true')
        self.assertEqual(result.user, 'user')

    def test_no_opts(self):
        from .. import ProgramSpecMatcher
        result = ProgramSpecMatcher().match("1 processname true/a/b/command [args args] directory true user")
        self.assertEqual(result.priority, '1')
        self.assertEqual(result.processname, 'processname')
        self.assertEqual(result.processopts, '')
        self.assertEqual(result.command, 'true/a/b/command')
        self.assertEqual(result.args, 'args args')
        self.assertEqual(result.directory, 'directory')
        self.assertEqual(result.redirect, 'true')
        self.assertEqual(result.user, 'user')


