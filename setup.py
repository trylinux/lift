from setuptools import setup, find_packages

setup(
    name="lift",
    version="1.0.0",
    description="",
    url="https://github.com/trylinux/lift",
    license="Freeeee",
    author="Zachary Wikholm",
    author_email="kestrel@trylinux.us",
    packages=find_packages(where="."),
    python_requires='>=3.9',
    install_requires=[
        "beautifulsoup4 ~= 4.12",
        "dnspython",
        "scapy ~= 2.5"
    ],
    package_data={
        "lift.lib": [
            "profiles/*.txt",
            "ipasn.dat"
        ]
    },
    entry_points={
        "console_scripts": [
            "lift=lift.__main__:main"
        ]
    },
)
