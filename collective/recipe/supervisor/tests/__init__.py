# package

def test_suite():
    import unittest
    suite = unittest.TestSuite()
    from . import test_parser
    suite.addTests(unittest.TestLoader().loadTestsFromModule(test_parser))
    from . import test_docs 
    suite.addTests(test_docs.test_suite())
    return suite
