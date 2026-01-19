# token_credential.py
import time
from azure.core.credentials import AccessToken, TokenCredential

class StaticTokenCredential(TokenCredential):
    """
    Wrap a bearer token (string) so Azure SDK clients can use it like DefaultAzureCredential.
    """
    def __init__(self, token: str, expires_in: int = 3300):
        self._token = token
        self._expires_on = int(time.time()) + expires_in

    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return AccessToken(self._token, self._expires_on)
