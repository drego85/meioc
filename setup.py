from setuptools import setup

setup(
    name='meioc',
    version='0.1.0',
    description='Extract indicators of compromise from an eml file',
    author='Andrea Draghetti',
    author_email='drego85@draghetti.it',
    url='https://github.com/drego85/meioc',
    py_modules=['meioc'],
    entry_points={
        'console_scripts': ['meioc = meioc:main']},
    long_description='''\
Meioc (Mail Extractor IoC) extracts indicators of compromise from eMail.

Meioc allows you to extract the following information from an e-mail, in JSON format:

 * From
 * Sender
 * X-Sender
 * To
 * Cc
 * Bcc
 * Envelope-to
 * Delivered-to
 * Return-Path
 * Subject
 * Date
 * X-Originating-IP
 * Relay Full
 * Relay IP (Only the IPs involved with the possibility of excluding private IPs)
 * Urls
 * Domains
 * Attachments with hash
 * Check SPF record

''',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
    ])
