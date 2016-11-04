param(
  [string]$name = $(throw "Name for the application is required."),
  [string]$realm = $(throw "Realm for the application is required. E.g.: http://whatever.com or urn:whatever.")
)

# Remove existing
if (Get-ADFSRelyingPartyTrust -Identifier $realm) {
  Write-Host "Removing existing Relying Party Trust $realm"
  Remove-ADFSRelyingPartyTrust -TargetIdentifier $realm
}

$transformRules = @'
  @RuleTemplate = "LdapClaims"
  @RuleName = "norEduPersonLIN, LiU ID, email address, name, first name, last name as claims"
  c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
    => issue(
      store = "Active Directory",
      types = (
        "http://liu.se/claims/norEduPersonLIN",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
      ),
      query = ";norEduPersonLIN,userPrincipalName,mail,displayName,givenName,sn;{0}",
      param = c.Value
    );
'@

$authorizationRules = @'
  @RuleTemplate = "AllowAllAuthzRule"
  => issue(
    Type = "http://schemas.microsoft.com/authorization/claims/permit",
    Value = "true"
  );
'@

Add-ADFSRelyingPartyTrust -Name $name -Identifier $realm -EnableJWT $true -IssuanceTransformRules $transformRules -IssuanceAuthorizationRules $authorizationRules

Write-Host "Relying Party Trust '$name' ($realm) added succesfully."
