from base64 import b64decode
from uuid import UUID

from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import jwt
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthTokenError


LIU_X509_CERT = (
    'MIIFOTCCBCGgAwIBAgIQAdlHVjMUXk6RFVjqYeenpjANBgkqhkiG9w0BAQsFADBkMQswCQYDVQ'
    'QGEwJOTDEWMBQGA1UECBMNTm9vcmQtSG9sbGFuZDESMBAGA1UEBxMJQW1zdGVyZGFtMQ8wDQYD'
    'VQQKEwZURVJFTkExGDAWBgNVBAMTD1RFUkVOQSBTU0wgQ0EgMzAeFw0xNTAxMDcwMDAwMDBaFw'
    '0xODAxMTExMjAwMDBaMIGJMQswCQYDVQQGEwJTRTEXMBUGA1UECAwOw5ZzdGVyZ8O2dGxhbmQx'
    'EzARBgNVBAcMCkxpbmvDtnBpbmcxIDAeBgNVBAoMF0xpbmvDtnBpbmdzIHVuaXZlcnNpdGV0MQ'
    '8wDQYDVQQLEwZMaVUtSVQxGTAXBgNVBAMTEGZzc2lnbmluZy5saXUuc2UwggEiMA0GCSqGSIb3'
    'DQEBAQUAA4IBDwAwggEKAoIBAQCS5bpEkEcbJAsNdgyK1QYAbuq5PKl8bAcujqKIRZAr4uixWu'
    'dDxRVhwOxDyZMTZGN0vNVdf+ZtUZQ9NWYaLcgEvzxhNbsA0fmTSwRlMvxj0R/JbDs5Slmew11w'
    'Z6rxgX7wRv8rjB3PSdf/SVc5LKgcDuCCGCLv+OE7d4K13OfKBxUv/vrD7upz6lgT79OWX6udFh'
    'U8sXmP8u8P/mID83o5N32hwxymRuEmjnLiVIrUR4cF5EwgblrpoqQKeGKdkroZApU0EJxvtope'
    'sVgUEGXW4tkogTJ8qtSPQK8iPEeteR6YpFCIxIbE0gpwDgo0bubt8T+FkQE71SLvbhv9RcZBAg'
    'MBAAGjggG/MIIBuzAfBgNVHSMEGDAWgBRn/YggFCeYxwnSJRm76VERY3VQYjAdBgNVHQ4EFgQU'
    '8vPdaPx+JhyN970NWqrTcbU/c0MwGwYDVR0RBBQwEoIQZnNzaWduaW5nLmxpdS5zZTAOBgNVHQ'
    '8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGsGA1UdHwRkMGIwL6At'
    'oCuGKWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9URVJFTkFTU0xDQTMuY3JsMC+gLaArhilodH'
    'RwOi8vY3JsNC5kaWdpY2VydC5jb20vVEVSRU5BU1NMQ0EzLmNybDBCBgNVHSAEOzA5MDcGCWCG'
    'SAGG/WwBATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMG4GCC'
    'sGAQUFBwEBBGIwYDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMDgGCCsG'
    'AQUFBzAChixodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vVEVSRU5BU1NMQ0EzLmNydDAMBg'
    'NVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCgqdZfizsQZYpLif+sV+mgkkln6WVGv1KV'
    'w2xvRDO9jF192qjkL9zmB081qOydPtt8aLbXQHp13M/URoFK2Vvdikq5WQMkGxJu3zLtQD4lJs'
    'JXAaGdm7nSwWS4NHHIf5yg0rWC5kQBJnWhAHhPedFzfgGR9lUohhvnLJJ/PFuvN0sCsYYpRraQ'
    'T880RdTq1imsFB3wAUHjN9tQCS3Ss9Cf6MOvwHb3flDe4OLwxxMZfI3oGwoUJHltib7xFuT7w5'
    'hOYts3Js+BBtsSskGSp/dz8PiH6NDQZG/9USNN1biuUCDxrhTBgSHIAeB3h7k6wue5C30EE8SC'
    'LfZ6Xxsmk1rn'
)


# Don't use this directly. Will probably be broken out from this package.
class ADFSOAuth2(BaseOAuth2):
    name = 'adfs'

    ACCESS_TOKEN_METHOD = 'POST'
    SCOPE_PARAMETER_NAME = 'resource'

    DEFAULT_HOST = None
    DEFAULT_X509_CERT = None

    token_payload = None

    def get_host(self):
        return self.setting('HOST', default=self.DEFAULT_HOST)

    def get_x509_cert(self):
        return self.setting('X509_CERT', default=self.DEFAULT_X509_CERT)

    def authorization_url(self):
        return 'https://{0}/adfs/oauth2/authorize'.format(self.get_host())

    def access_token_url(self):
        return 'https://{0}/adfs/oauth2/token'.format(self.get_host())

    def issuer_url(self):
        return 'http://{0}/adfs/services/trust'.format(self.get_host())

    def get_token_key(self):
        raw_cert = self.get_x509_cert()
        # b64decode freaks out over unpadded base64, so we must pad it if
        # needed. See
        # http://stackoverflow.com/questions/2941995#comment12174484_2942039
        padded_raw_cert = raw_cert + '=' * (-len(raw_cert) % 4)
        cert = load_der_x509_certificate(b64decode(padded_raw_cert),
                                         default_backend())

        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def request_access_token(self, *args, **kwargs):
        response = super(ADFSOAuth2, self).request_access_token(*args, **kwargs)

        try:
            self.token_payload = jwt.decode(
                response.get('access_token'),
                audience=self.get_scope_argument()[self.SCOPE_PARAMETER_NAME],
                key=self.get_token_key(),
                leeway=self.setting('LEEWAY', 0),
                iss=self.issuer_url(),
                options=dict(
                    verify_signature=True,
                    verify_exp=True,
                    verify_nbf=False,
                    verify_iat=self.setting('VERIFY_IAT', True),
                    verify_aud=True,
                    verify_iss=True,
                    require_exp=True,
                    require_iat=True,
                    require_nbf=False
                )
            )
        except jwt.InvalidTokenError as exc:
            raise AuthTokenError(self, exc)

        return response

    def get_user_id(self, details, response):
        return str(UUID(bytes_le=b64decode(self.token_payload.get('ppid'))))

    def get_user_details(self, response):
        return dict(
            # sub = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier
            username=self.token_payload.get('sub').split('@')[0],
            # email = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
            email=self.token_payload.get('email'),
            # unique_name = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
            fullname=self.token_payload.get('unique_name'),
            # given_name = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
            first_name=self.token_payload.get('given_name'),
            # family_name = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
            last_name=self.token_payload.get('family_name')
        )


class LiuBackend(ADFSOAuth2):
    name = 'liu'

    EXTRA_DATA = [
        ('nor_edu_person_lin', 'nor_edu_person_lin'),
    ]

    DEFAULT_HOST = 'fs.liu.se'
    DEFAULT_X509_CERT = LIU_X509_CERT

    def user_data(self, access_token, *args, **kwargs):
        return dict(
            nor_edu_person_lin=self.token_payload.get(
                'http://liu.se/claims/norEduPersonLIN')
        )
