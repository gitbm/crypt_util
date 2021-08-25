#!/usr/bin/env python3

# You should be able to run this on any PC with Python3 installed but only tested
# on Mac.  The imports should be included in standard python installations but not
# necessarily all online python runners
#
# For running online you could use docker playground to get a ubuntu terminal which has 
# python3 installed but you will need to signup (free though).  Just copy the contents
# of this file to a file and run it (I am assuming you know how to manage an editor
# and execute a python script in bash).  Or you can run python3 REPL in ubuntu (just type
# python3 at command line) and cut and paste the
# marked section below
# 
# https://labs.play-with-docker.com/
#
# There are also many websites that support running python code online but these are
# subject to change over time.  The following seemed to work in one way or another at
# the time of writing.  Some are like a REPL and some have code in an editor that you
# then execute.  Pros and cons to each but the REPL allows you to be bit more paranoid
# and not have your secrets in clear text
# Hopefully one of these is available when you need it:
#
# https://www.python.org/
# https://www.w3schools.com/python/
# https://replit.com/languages/python3
# https://onecompiler.com/python
# https://trinket.io/embed/python3
#
# ---------- cut and paste from here for online python runners ----------

import sys
import argparse
import os
from typing import Tuple

from getpass import getpass
import secrets
import base64
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
default_iterations = 100_000

def derive_key(password: bytes, salt: bytes, iterations: int = default_iterations) -> bytes:
  """Derive a secret key from a given password and salt"""
  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(), length=32, salt=salt,
      iterations=iterations, backend=backend)
  return b64e(kdf.derive(password))

def raw_encrypt(message: bytes, password: str, iterations: int = default_iterations) -> bytes:
  salt = secrets.token_bytes(16)
  key = derive_key(password.encode(), salt, iterations)
  return b64e(
      b'%b%b%b' % (
          salt,
          iterations.to_bytes(4, 'big'),
          b64d(Fernet(key).encrypt(message)),
      )
  )

def raw_decrypt(token: bytes, password: str) -> bytes:
  decoded = b64d(token)
  salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
  iterations = int.from_bytes(iter, 'big')
  key = derive_key(password.encode(), salt, iterations)
  return Fernet(key).decrypt(token)

def askIf(message: str, password: str, messageSecret: bool = True) -> Tuple[str, str]:
  msgPrompt = "enter message: "
  msg = message or (getpass(msgPrompt) if messageSecret else input(msgPrompt))
  pwd = password or getpass("enter password: ")
  return (msg, pwd)

def encrypt(message: str = None, password: str = None) -> str:
  (msg, pwd) = askIf(message, password)
  return raw_encrypt(msg.encode(), pwd).decode()

def decrypt(message: str = None, password: str = None) -> str:
  (msg, pwd) = askIf(message, password, False)
  return raw_decrypt(msg.encode(), pwd).decode()

# If don't have a REPL (ie your python runner doesn't allow input
# uncomment and edit one of the following:
# 
# encrypt("some message", "mypassword")
# decrypt("encrpted base64 message", "mypassword")
#
# If you have a REPL then you can run without params and get prompted for 
# message and/or password to avoid secrets in clear text eg
# encrypt()
# decrypt("encrpted base64 message")
#
# ---------- cut and paste to here for online python runners ----------

# following is for running as a script on a PC or VM/docker container

def main():
  parser = argparse.ArgumentParser(description='Encrypt/decrypt small messages')
  parser.add_argument("--encrypt", "-e", action="store_true", help="encrpyt - default is decrypt")
  parser.add_argument("--decrypt", "-d", action="store_true", help="encrpyt - default is decrypt")
  parser.add_argument("--password-env", "-p", type=str, help="name of environment variable containing password otherwise prompts")
  parser.add_argument("--msg-env", "-m", type=str, help="name of environment variable containing message - useful for encryption")
  parser.add_argument("--stdin", "-i", action="store_true", help="read message from stdin")
  parser.add_argument("message", nargs='?', help="message to encrypt/decrypt - prefer stdin or --msg-env for encryption")
  args = parser.parse_args()

  message = sys.stdin.read() if args.stdin else (os.getenv(args.msg_env) if args.msg_env else args.message)
  password = os.getenv(args.password_env) if args.password_env else None

  out = decrypt(message, password) if (args.decrypt or not args.encrypt) else encrypt(message, password)

  print(out)


if __name__ == "__main__": main()


