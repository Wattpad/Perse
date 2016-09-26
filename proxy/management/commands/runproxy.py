from django.core.management.base import BaseCommand

from proxy.proxy2 import run


class Command(BaseCommand):

    help = 'Runs the proxy.'

    def handle(self, *args, **options):
        run()
