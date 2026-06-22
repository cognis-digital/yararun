# Example application config that accidentally committed secrets and unsafe
# flags. All values below are FAKE placeholders for demonstration only.

DEBUG = True
ALLOWED_HOSTS = ['*']

# DO NOT do this in real code — secrets belong in a vault / env vars.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"          # AWS's own published example key
api_key = "sk_test_EXAMPLE0000000000000000demo"

import requests
resp = requests.get("https://internal.example.test/health", verify=False)
