from setuptools import setup, find_packages

setup(
    name='certbot-dns-zone',
    version='1.0.0',
    description="Zone DNS Authenticator plugin for Certbot",
    url="https://github.com/leede-org/certbot-dns-zone",
    author="Leede",
    author_email="info@leede.ee",
    license="MIT License",
    python_requires=">=3.7",
    packages=find_packages(),
    install_requires=[
        'certbot',
        'requests'
    ],
    entry_points={
        'certbot.plugins': [
            'dns-zone = certbot_dns_zone._internal.dns_zone:Authenticator'
        ],
    },
)
