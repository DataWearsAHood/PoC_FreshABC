#!/usr/local/bin/python
from __future__ import print_function
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

random_generator = Random.new()
IV = random_generator.read(8)
print(IV)