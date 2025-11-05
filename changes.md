# Morbid

## Release v1.5.0
LTS: 05/10/2025

 - Added service token authentication for internal API access
 - New service routes: 
   - `/service/app/{app}/users`
   - `/service/app/{app}/accounts`
 - Added `FindAccountsByApp` and `FindUsersByApp` commands
 - Added `RawAccount` JSON codec support
 - Service configuration with token-based authentication

## Release v1.4.1
LTS: 24/09/2025 

 - Added method to get user from Firebase
 - Fix: When the id is empty, just get the user from Firebase, otherwise try to insert

## Release v1.4.0
LTS: 24/09/2025

 - Temporarily disabled insert users without id in repo
 - Using UID from Firebase

## Release v1.3.0
LTS: 22/09/2025

 - Added ApplicationCode to `MorbidClient.fake(appcode)` (better for testing/mocking)

## Release v1.2.0
LTS: 16/09/2025

 - Improved account/user provisioning
 - Code format
 - Optimizing imports
 - Added script `diff-compare.sc`

## Release v1.1.3
LTS: 11/09/2025

 - Updating firebase-admin from 9.3.0 to 9.6.0
 - Testing the return of auth.generatePasswordResetLink for nulls

## Release v1.1.2
LTS: 09/09/2025

 - Creating new user identities for new users only

## Release v1.1.1
LTS: 09/09/2025

 - Using guara v1.1.9

## Release v1.1.0
LTS: 09/09/2025

 - Returning inactive users

## Release v1.0.0
LTS: 24/07/2025
 
 - Moving the `ImpersonationRequest` to morbid-commons

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