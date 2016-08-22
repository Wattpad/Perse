from twisted.names import dns
from twisted.trial import unittest

from dns.networking import FixedResolver


class NetworkingTestCase(unittest.TestCase):

    test_name = 'example.com'

    def setUp(self):
        self.resolver = FixedResolver()

    def test_resolve(self):
        response = self.resolver.query(dns.Query(name=self.test_name))
        self.assertEqual(response.result[0][0].payload.dottedQuad(),
                         FixedResolver.default_proxy_ip)
