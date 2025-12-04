from setuptools import setup, find_packages


def readme():
    with open("README.md") as f:
        return f.read()


def get_license():
    with open("LICENSE") as f:
        return f.read()


setup(
    name="tmxcaliber",
    version="0.3.9",
    description=(
        "CLI utility to filter down a TrustOnCloud ThreatModel and "
        "get more refined information."
    ),
    long_description=readme(),
    long_description_content_type="text/markdown",
    author="TrustOnCloud",
    author_email="dev@trustoncloud.com",
    python_requires=">=3.8",
    install_requires=[x for x in open("requirements.txt").readlines()],
    packages=find_packages(include=["tmxcaliber", "tmxcaliber.*"], exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    include_package_data=True,
    package_data={
        "tmxcaliber": ["schema/*.json", "schema/*/*.json"],
    },
    license=get_license(),
    entry_points={"console_scripts": ["tmxcaliber=tmxcaliber.cli:main"]},
)
