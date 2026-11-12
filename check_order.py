import os, sys, requests
from dotenv import load_dotenv
load_dotenv()
base = "https://api-m.sandbox.paypal.com"
tok = requests.post(base + "/v1/oauth2/token", auth=(os.getenv("PAYPAL_CLIENT_ID", ""), os.getenv("PAYPAL_SECRET", "")), data={"grant_type": "client_credentials"}, timeout=15).json().get("access_token")
h = {"Authorization": "Bearer " + str(tok), "Content-Type": "application/json"}
oid = sys.argv[1]
r = requests.get(base + "/v2/checkout/orders/" + oid, headers=h, timeout=15)
print("order status:", r.json().get("status"))
if len(sys.argv) > 2:
    c = requests.post(base + "/v2/checkout/orders/" + oid + "/capture", headers=h, timeout=15)
    j = c.json()
    print("capture HTTP", c.status_code, "|", j.get("name"), "|", [d.get("issue") for d in j.get("details", [])])
