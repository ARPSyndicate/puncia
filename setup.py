from setuptools import setup, find_packages

setup(
    name="puncia",
    version="0.11",
    author="ARPSyndicate",
    author_email="arpsyndicate@pm.me",
    keywords="subdomains subdomain exploits exploit arpsyndicate panthera uncia puncia snow leopard",
    url="https://github.com/ARPSyndicate/puncia",
    project_urls={
        "Subdomain Center": "https://subdomain.center",
        "Exploit Observer": "https://exploit.observer"
    },
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    description='The Panthera(P.)uncia of Cybersecurity - Subdomain & Exploit Hunter powered by AI',
    packages=find_packages(),
    entry_points={"console_scripts": ["puncia=puncia.puncia:main"]}
)
