from setuptools import find_packages, setup

try:
    from setupext_janitor import janitor
    CleanCommand = janitor.CleanCommand
except ImportError:
    CleanCommand = None

cmd_classes = {}
if CleanCommand is not None:
    cmd_classes['clean'] = CleanCommand

tests_require = [
    'pytest',
    'pytest-cov',
    'pytest-pep8'
]

install_requires = [
    'Flask',
    'flask_wtf',
    'passlib',
    'wtforms',
    'flask_login',
    'netifaces',
]

setup_requires = [
    'pytest-runner'
]


packages = find_packages()

setup(
    name='Flask-Protect',
    version='0.1.0',
    description=__doc__,
    long_description='tmp',
    keywords='flask protect',
    license='MIT',
    author='Steven Swanson',
    author_email='kiln707development@gmail.com',
    url='https://github.com/Kiln707/Flask-Protect',
    packages=packages,
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    # extras_require=extras_require,
    install_requires=install_requires,
    setup_requires=setup_requires,
    tests_require=tests_require,
    cmdclass=cmd_classes,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Development Status :: 4 - Beta',
    ],
)
