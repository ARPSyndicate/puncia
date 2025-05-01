from setuptools import setup, find_packages

setup(
    name="puncia",
    version="0.32",
    author="A.R.P. Syndicate",
    author_email="ayush@arpsyndicate.io",
    keywords="information discovery cyber intelligence llm ai chat subdomains subdomain exploits exploit sbom cyclonedx arpsyndicate panthera uncia puncia snow leopard",
    url="https://github.com/ARPSyndicate/puncia",
    project_urls={
        "A.R.P. Syndicate": "https://www.arpsyndicate.io",
        "Subdomain Center": "https://subdomain.center",
        "Exploit Observer": "https://exploit.observer",
        "Osprey Vision": "https://osprey.vision",
    },
    license="MIT",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    description="Panthera(P.)uncia - Official CLI utility for Osprey Vision, Subdomain Center & Exploit Observer",
    packages=find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
        "aiofiles",
        "asyncio"
    ],
    entry_points={"console_scripts": ["puncia=puncia.__main__:scriptrun"]},
)
