# Morbid

 - Implementing Account/User management
 - Routes added:
   - GET    `/app/:app/account/:account/users` 
   - GET    `/app/:app/accounts/:tenant`
   - POST   `/app/:app/account`
   - POST   `/app/:app/account/user/set/groups`
   - POST   `/app/:app/account/user`
   - DELETE `/app/:app/account/:account/user/:user`
   - DELETE `/app/:app/account/:account`
   - GET    `/app/:app/account/:account/groups`
   - GET    `/app/:app/account/:account/user/:user/groups`
 - Client methods added:
   - `MorbidClient.groupsByAccount`
   - `MorbidClient.groupsByUser`
   - `MorbidClient.accounts`
   - `MorbidClient.configureGroupsByUser`
   - `MorbidClient.storeAccount`
   - `MorbidClient.storeAccountUser`
   - `MorbidClient.removeAccountUser`
   - `MorbidClient.removeAccount`
   - `MorbidClient.usersByAccount`

## Release v0.0.8
LTS: 17/07/2025

 - Added `FakeMorbidClient`

## Release v0.0.7
LTS: 31/03/2025

 - Excluding deleted groups and roles when retrieving users

## Release v0.0.6
LTS: 24/03/2025

 - Using guara v1.1.4

## Release v0.0.5
LTS: 13/03/2025

 - Updating dependencies

## Release v0.0.4
LTS: 12/11/2024

 - Account/User provisioning (temporary)
 - Enabled slf4j logging
 - Added route POST `/app/:app/password/change`
 - Added `MorbidClient.passwordChange`

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