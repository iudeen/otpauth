import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import time
from typing import Union, ByteString, Callable

from clipper import copy


class OTPGenerator:
    def __init__(self, token_length: int = 6):
        self.token_length = token_length

    def __token_validator__(
            self,
            token: Union[ByteString, str, int],
            token_length: int = None
    ) -> bool:
        """Determines if given value is acceptable as a token. Used when validating
        tokens.
        :param token: token value to be checked
        :param token_length: allowed length of token
        :return: True if can be a candidate for token, False otherwise
        """
        if not token_length:
            token_length = self.token_length
        if not isinstance(token, bytes):
            token = str(token).encode()
        return token.isdigit() and len(token) <= token_length

    def get_hotp(
            self,
            secret: Union[str, ByteString],
            intervals_no: int,
            as_string: bool = False,
            casefold: bool = True,
            digest_method: Callable = hashlib.sha1,
            token_length: int = None,
    ) -> Union[str, int]:
        """
        Get HMAC-based one-time password on the basis of given secret and
        interval number.

        :param secret: the base32-encoded string acting as secret key
        :param intervals_no: interval number used for getting different tokens, it
            is incremented with each use
        :param as_string: True if result should be padded string, False otherwise
        :param casefold: True (default), if should accept also lowercase alphabet
        :param digest_method: method of generating digest (hashlib.sha1 by default)
        :param token_length: length of the token (6 by default)
        :return: generated HOTP token
        """
        if not token_length:
            token_length = self.token_length

        if isinstance(secret, str):
            # It is unicode, convert it to bytes
            secret = secret.encode('utf-8')

        # Get rid of all the spacing:
        secret = secret.replace(b' ', b'')

        try:
            key = base64.b32decode(secret, casefold=casefold)
        except TypeError:
            raise TypeError('Incorrect secret')

        msg = struct.pack('>Q', intervals_no)
        hmac_digest = hmac.new(key, msg, digest_method).digest()
        ob = hmac_digest[19]
        o = ob & 15
        token_base = struct.unpack('>I', hmac_digest[o:o + 4])[0] & 0x7fffffff
        token = token_base % (10 ** token_length)

        if as_string:
            return '{{:0{}d}}'.format(token_length).format(token)
        else:
            return token

    def get_totp(
            self,
            secret: Union[str, ByteString],
            as_string: bool = False,
            digest_method: Callable = hashlib.sha1,
            token_length: int = None,
            interval_length: int = 30,
            clock: int = None,
    ) -> Union[str, int]:
        """Get time-based one-time password on the basis of given secret and time.

        :param secret: the base32-encoded string acting as secret key
        :param as_string: True if result should be padded string, False otherwise
        :param digest_method: method of generating digest (hashlib.sha1 by default)
        :param token_length: length of the token (6 by default)
        :param interval_length: length of TOTP interval (30 seconds by default)
        :param clock: time in epoch seconds to generate totp for, default is now
        :return: generated TOTP token
        """
        if not token_length:
            token_length = self.token_length
        if clock is None:
            clock = time.time()
        interv_no = int(clock) // interval_length
        return self.get_hotp(
            secret,
            intervals_no=interv_no,
            as_string=as_string,
            digest_method=digest_method,
            token_length=token_length,
        )

    def valid_hotp(
            self,
            token: Union[str, int],
            secret: str,
            last: int = 1,
            trials: int = 1000,
            digest_method: Callable = hashlib.sha1,
            token_length: int = None,
    ) -> Union[bool, int]:
        """Check if given token is valid for given secret. Return interval number
        that was successful, or False if not found.

        :param token: token being checked
        :param secret: secret for which token is checked
        :param last: last used interval (start checking with next one)
        :param trials: number of intervals to check after 'last'
        :param digest_method: method of generating digest (hashlib.sha1 by default)
        :param token_length: length of the token (6 by default)
        :return: interval number, or False if check unsuccessful
        """

        if not token_length:
            token_length = self.token_length

        if not self.__token_validator__(token, token_length=token_length):
            return False
        for i in range(last + 1, last + trials + 1):
            token_candidate = self.get_hotp(
                secret=secret,
                intervals_no=i,
                digest_method=digest_method,
                token_length=token_length,
            )
            if token_candidate == int(token):
                return i
        return False

    def valid_totp(
            self,
            token: Union[str, int],
            secret: str,
            digest_method: Callable = hashlib.sha1,
            token_length: int = None,
            interval_length: int = 30,
            clock: int = None,
            window: int = 0,
    ) -> bool:
        """Check if given token is valid time-based one-time password for given
        secret.

        :param token: token which is being checked
        :param secret: secret for which the token is being checked
        :param digest_method: method of generating digest (hashlib.sha1 by default)
        :param token_length: length of the token (6 by default)
        :param interval_length: length of TOTP interval (30 seconds by default)
        :param clock: time in epoch seconds to generate totp for, default is now
        :param window: compensate for clock skew, number of intervals to check on
            each side of the current time. (default is 0 - only check the current
            clock time)
        :return: True, if is valid token, False otherwise
        """
        if not token_length:
            token_length = self.token_length

        if self.__token_validator__(token, token_length=token_length):
            if clock is None:
                clock = time.time()
            for w in range(-window, window + 1):
                if int(token) == self.get_totp(
                        secret,
                        digest_method=digest_method,
                        token_length=token_length,
                        interval_length=interval_length,
                        clock=int(clock) + (w * interval_length)
                ):
                    return True
        return False


def main(app_name: str = 'vpn', secret_key: str = None):
    otp_generator = OTPGenerator()
    if not secret_key:
        with open("secrets", "r") as f:
            secret_json = json.load(f)
        secret_key = secret_json.get(app_name)
        del secret_json
    if not secret_key or secret_key == "" or len(secret_key) < 1:
        print(f"The App name {app_name} is not a valid entry.")
        raise ValueError("Invalid Secret Key or Option")

    ttop = otp_generator.get_totp(secret=secret_key, as_string=True)

    del secret_key

    copy(ttop)
    print(f"Your token for {app_name} is {ttop}")

    del ttop
    print("Valid for 30 Seconds!")
    for _ in range(0, 30):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(1)
    print("\nThank you")
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('app_name', metavar='N', type=str, help='app_name')
    args = parser.parse_args().__dict__
    main(app_name=args.get("app_name"))
