# crypt_util
Utility for passphrase encryption using strong encryption and best practices for salts and IVs

Created to allow secure way to store master passwords (eg for password manager) that can't be reset.  Keep encrypted message
along with clues for the passphrase (that would only make sense to you or people you trust).  Preferably keep in a safe place
but the security of the encryption allows one to consider public accessibility (though maybe obscured or hidden) to enable a
receovery when you have forgotten password and are locked out of all your private online resources and don't have physical access
to where you have securely stored it.

Creates url safe base64 (so not standard base64) text for given input text and passphrase with secure encryption

Can be used as command line utility or the core functions can be copied to an online python runner (eg python.org)

Passphrase and message can be passed in via environment variables or be prompted for (without displaying) if run interactively.  Input message can be read
via stdin as well so can be used as part of a pipeline.

Look at code in **crypt.py** for more documentation
