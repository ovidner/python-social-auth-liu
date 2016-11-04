from base64 import b64decode
from uuid import UUID

from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import jwt
from social.backends.oauth import BaseOAuth2
from social.exceptions import AuthTokenError


# Don't use this directly. Will probably be broken out from this package.
class ADFSOAuth2(BaseOAuth2):
    name = 'adfs'

    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_PARAMETER_NAME = 'resource'

    token_payload = None

    def get_host(self):
        return self.setting('HOST')

    def get_user_id_claim(self):
        return self.setting('UID_CLAIM', 'guid')

    def get_x509_cert(self):
        return self.setting('X509_CERT')

    def authorization_url(self):
        return 'https://{0}/adfs/oauth2/authorize'.format(self.get_host())

    def access_token_url(self):
        return 'https://{0}/adfs/oauth2/token'.format(self.get_host())

    def get_token_key(self):
        raw_cert = b64decode(self.get_x509_cert())
        cert = load_der_x509_certificate(raw_cert, default_backend())

        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def request_access_token(self, *args, **kwargs):
        response = super(ADFSOAuth2, self).request_access_token(*args, **kwargs)

        try:
            self.token_payload = jwt.decode(
                response.get('access_token'),
                audience=self.get_scope_argument()[self.SCOPE_PARAMETER_NAME],
                key=self.get_token_key(),
                leeway=self.setting('LEEWAY', 0),
                options=dict(
                    verify_signature=True,
                    verify_exp=True,
                    verify_nbf=False,
                    verify_iat=True,
                    verify_aud=True,
                    verify_iss=False,
                    require_exp=True,
                    require_iat=True,
                    require_nbf=False
                )
            )
        except jwt.InvalidTokenError as exc:
            raise AuthTokenError(self, exc)

        return response

    def get_user_id(self, details, response):
        uid = UUID(bytes_le=b64decode(
            self.token_payload.get(self.get_user_id_claim())))
        return str(uid)

    def get_user_details(self, response):
        fullname, first_name, last_name = self.get_user_names(
            self.token_payload.get('name') or '')

        return dict(
            username=self.token_payload.get('nameid').split('@')[0],
            email=self.token_payload.get('email'),
            fullname=fullname,
            first_name=first_name,
            last_name=last_name
        )


class LiuBackend(ADFSOAuth2):
    name = 'liu'

    def get_host(self):
        return self.setting('HOST', default='fs.liu.se')

    def get_user_id_claim(self):
        return self.setting('UID_CLAIM', default='norEduPersonLIN')

    def get_x509_cert(self):
        return self.setting('X509_CERT',
                            default='MIIC4DCCAcigAwIBAgIQPBvTT2H2+qlGro81M0mw0j'
                                    'ANBgkqhkiG9w0BAQsFADAsMSowKAYDVQQDEyFBREZT'
                                    'IFNpZ25pbmcgLSBhZGZzLmxhYi52aWRuZXQuaW8wHh'
                                    'cNMTYxMDAyMTcwNjI4WhcNMTcxMDAyMTcwNjI4WjAs'
                                    'MSowKAYDVQQDEyFBREZTIFNpZ25pbmcgLSBhZGZzLm'
                                    'xhYi52aWRuZXQuaW8wggEiMA0GCSqGSIb3DQEBAQUA'
                                    'A4IBDwAwggEKAoIBAQCjsi6ZKjc9OVoZsiMH36vdKY'
                                    'ik7+/1YCs0sVXfiu4CwTMAKyRy9zDuQecOJz8qnAhs'
                                    'kpa3vTRUjFEG90S2bYJfbIr6Ze0RdwqpoEfYqmC7x+'
                                    'OyhfLID4+FE16Vf60g7nH+EScCRpnL+ICOSL568fYn'
                                    'LwpmBwvMLI85S3lkPqRWaHklTSHx2+gaZkX5c/ChCi'
                                    'dOMIdI9PpBKPYoGlSTHN1366niFc5JRdOzdk4lapPT'
                                    'hNIV3OMoSeyZ4tJ+dkJ3SPnrbwLOtKGu6tVy33C6G3'
                                    '1f1cqTeVx8ec8BYloUlbBStQBPwRYx3xc53j1y6bDY'
                                    '8FfWyQaZ0CkVJo2XY5wyZNOpAgMBAAEwDQYJKoZIhv'
                                    'cNAQELBQADggEBAAyqKzrEcbydSs1gqgqSbaKcqCPw'
                                    'tfFfcyAd5TYMwtldsOOf/L0K2lqxWBfk9UZfCSed8r'
                                    'L5ME43op1gK6+FUS7ynlgI+CLi8UUuL7PWQTZYudVY'
                                    'Fk8ARpCB59DedSGofk0dFVRxsDumME/19B1XOQ7lco'
                                    'q1D7RliR5JKvvCNQn/8dDBrDAoIWClk1jQB7xp1RTp'
                                    'CfuKOpLx1+sHQBDvfQEKvqth1iJeTq9hjElMpLs/+3'
                                    'hOxV13/0HkXbEKzXvfRJPxiDmWVtQ0npjIRlqpoN9m'
                                    'XHCICevTA0k4AWbQXxZna32uKK6oLZ2+VXGFsZyWD+'
                                    '4W2397H1j5P0vRxkhdCSY=')
