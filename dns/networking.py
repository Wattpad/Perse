from django.conf import settings
from twisted.internet import reactor, defer
from twisted.names import client, dns, server


class FixedResolver(object):
    default_proxy_ip = '127.0.0.1'

    def get_fixed_response(self, query):
        name = query.name.name
        answer = dns.RRHeader(
            name=name,
            payload=dns.Record_A(address=self.default_proxy_ip))
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional

    def query(self, query_, timeout=None):
        return defer.succeed(self.get_fixed_response(query_))


def run():
    print("Started")
    clients = [FixedResolver()]
    if settings.DNS_RELAY:
        clients.append(client.Resolver(resolv='/etc/resolv.conf'))

    factory = server.DNSServerFactory(clients=clients)
    protocol = dns.DNSDatagramProtocol(controller=factory)

    reactor.listenUDP(settings.DNS_PORT, protocol)
    reactor.listenTCP(settings.DNS_PORT, factory)

    reactor.run()
