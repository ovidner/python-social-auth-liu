# python-social-auth-liu
A `python-social-auth` backend for Linköping University through ADFS/OAuth2. See
documentation for `python-social-auth` on how to use it.

## Identity Provider setup
You need to have your application set up as a Relying Party in LiU ADFS. Contact
the LiU helpdesk. The script can be used as follows:

1. `.\AddLiURelyingPartyTrust "Application Name" "https://yourapplication.com"`
2. `Add-ADFSClient -Name "Client Name" -ClientId "*uuid or something similar*" -RedirectUri "https://yourapplication.com/callback-url/"`
3. Repeat step 2 if necessary.
