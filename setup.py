from distutils.core import setup

setup(
    name='python-social-auth-liu',
    version='0.0.0',
    py_modules=['social_liu'],
    url='https://github.com/ovidner/python-social-auth-liu',
    license='MIT',
    author='Olle Vidner',
    author_email='olle@vidner.se',
    description='',
    install_requires=[
        'python-social-auth',
        'PyJWT',
        'cryptography',
    ]
)
