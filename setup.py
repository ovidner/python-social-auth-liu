from setuptools import setup

setup(
    name='social-auth-liu',
    version='0.0.1',
    py_modules=['social_liu'],
    url='https://github.com/ovidner/python-social-auth-liu',
    license='MIT',
    author='Olle Vidner',
    author_email='olle@vidner.se',
    description='',
    install_requires=[
        'social-auth-core==1.2.*',
        'PyJWT==1.4.*',
        'cryptography==1.8.*',
    ]
)
