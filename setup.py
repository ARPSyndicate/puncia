from setuptools import setup, find_packages

setup(
    name="puncia",
    version="0.21",
    author="A.R.P. Syndicate",
    author_email="ayush@arpsyndicate.io",
    keywords="subdomains subdomain exploits exploit arpsyndicate panthera uncia puncia snow leopard",
    url="https://github.com/ARPSyndicate/puncia",
    project_urls={
        "A.R.P. Syndicate": "https://www.arpsyndicate.io",
        "Subdomain Center": "https://subdomain.center",
        "Exploit Observer": "https://exploit.observer",
    },
    license="MIT",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    description="The Panthera(P.)uncia of Cybersecurity - Official CLI utility for Subdomain Center & Exploit Observer",
    packages=find_packages(),
    install_requires=[
        "requests",
    ],
    entry_points={"console_scripts": ["puncia=puncia.__main__:main"]},
)
