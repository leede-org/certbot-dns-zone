from setuptools import setup

setup(
    name='certbot-dns-zone',
    package='certbot_dns_zone.py',
    install_requires=[
        'certbot',
        'requests'
    ],
    entry_points={
        'certbot.plugins': [
            'dns-zone = certbot_dns_zone:Authenticator'
        ],
    },
)
