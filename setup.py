
from setuptools import setup

plugin_identifier = "mfa_passkeys"
plugin_package = "octoprint_mfa_passkeys"
plugin_name = "OctoPrint-Passkeys"
plugin_version = "0.2.8"
plugin_description = "Passkey-first login plugin for OctoPrint"
plugin_author = "Robert Cole"
plugin_author_email = "noreply@example.com"
plugin_url = "https://github.com/daedalas1981/OctoPrint-Passkeys"
plugin_license = "AGPLv3"

plugin_requires = [
    "webauthn>=2.7.1",
]

setup(
    name=plugin_name,
    version=plugin_version,
    description=plugin_description,
    author=plugin_author,
    author_email=plugin_author_email,
    url=plugin_url,
    license=plugin_license,
    packages=[plugin_package],
    include_package_data=True,
    install_requires=plugin_requires,
    entry_points={
        "octoprint.plugin": [
            f"{plugin_identifier} = {plugin_package}"
        ]
    },
)
