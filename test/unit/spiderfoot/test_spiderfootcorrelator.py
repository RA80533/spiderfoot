# test_spiderfootcorrelator.py
import unittest

from spiderfoot import SpiderFootCorrelator, SpiderFootDb


class TestSpiderFootCorrelator(unittest.TestCase):
    """
    Test SpiderFootCorrelator
    """

    def test_init_argument_ruleset_invalid_rule_should_raise_SyntaxError(self):
        sfdb = SpiderFootDb(self.default_options, False)

        ruleset = {"sample rule": "invalid yaml"}
        with self.assertRaises(SyntaxError):
            SpiderFootCorrelator(sfdb, ruleset)

    def test_run_correlations_invalid_scan_instance_should_raise_ValueError(self):
        sfdb = SpiderFootDb(self.default_options, False)

        correlator = SpiderFootCorrelator(sfdb, {}, 'example scan id')
        with self.assertRaises(ValueError):
            correlator.run_correlations()

    def test_check_ruleset_validity_should_return_bool(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        ruleset = [{"sample": "sample"}]
        self.assertIsInstance(correlator.check_ruleset_validity(ruleset), bool)

        invalid_types = [None, str(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                self.assertIsInstance(correlator.check_ruleset_validity(invalid_type), bool)

    def test_check_rule_validity_invalid_rule_should_return_false(self):
        sfdb = SpiderFootDb(self.default_options, False)
        correlator = SpiderFootCorrelator(sfdb, {})

        invalid_types = [None, str(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                self.assertFalse(correlator.check_rule_validity(invalid_type))
