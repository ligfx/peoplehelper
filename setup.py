from setuptools import setup

setup(
    name="Email Finder for Google Sheets",
    app=["personhelper.py"],
    data_files=[],
    options={
        "py2app": {
            "iconfile": "emailfinder.icns",
            # 'includes': ['googleapiclient'],
            "packages": ["httplib2", "requests", "certifi", "keyring"],
        }
    },
    setup_requires=["py2app"],
)
