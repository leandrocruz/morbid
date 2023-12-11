# Morbid

Morbid is an authentication and authorization server written using [Scala](https://scala-lang.org/) and [ZIO](https://zio.dev/)  

As of today, Morbid uses Google Cloud Identity / Firebase to authenticate its users.  
After the user is authenticated, the authorization info for a given user is loaded and serialized as a jwt token.  
Here is an example:  

```json
{
    "account": "a1",
    "code": "UID1",
    "email": "user1@0.com",
    "tenant": "DEFAULT",
    "applications": {
        "main_app": {
            "groups": [ "g1" ],
            "roles": {
                "adm": [ "create", "read", "update", "delete" ]
            }
        },
        "other_app": {
            "groups": [ "other" ],
            "roles": {
                "cred_adm":   [ "create",  "read", "update" ],
                "policy_adm": [ "read"]
            }
        }
    }
}
```

This jwt token can be used internally at your organization to check which resources a given user should have access to


## Database Schema
You can find the dbml [here](https://dbdiagram.io/d/Morbid-6577264356d8064ca0cd919d)

## Build

Clone the [guara](https://github.com/leandrocruz/guara-zio/) project into your machine, then publish it locally using 
> sbt publishLocal

## Running
1. Create the `morbid` database using `./reset-db.sh morbid` (Postgresql)
2. Create a secret key for jwt (TBD)
3. Create a Google Cloud Project and configure the authentication providers (TBD)
4. Run the Morbid Backend using sbt

## Deployment
TBD