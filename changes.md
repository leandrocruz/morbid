# Morbid

 - Account/User provisioning (temporary)
 - Enabled slf4j logging

## Release v0.0.3
LTS: 01/11/2024
 
 - Using chimney 1.3.0
 - Renaming `SingleAppRawUser` to `SingleAppUser`
 - Removing `simple` and `mini`
 - Changed `Token.RawUser` to `Token.CompactUser` for better/smaller serialization
 - Removing dead code
 - Finding users not associated with any groups (refactoring of DatabaseRepo.userGiven)

## Release v0.0.2
LTS: 29/10/2024

 - Added TokenValidator to protected routes
 - Creating legacy users when provisioning SAML users
 - Added MorbidConfig.printQueries
 - Provisioning SAML users
 - Added LegacyMorbid