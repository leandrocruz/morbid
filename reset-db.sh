#!/usr/bin/env bash

function reset() {
  docker stop pg-$db
  docker rm pg-$db
  docker run --name pg-$db -e POSTGRES_PASSWORD=localdev -d -p 5432:5432 postgres:13
  sleep 2
  PGPASSWORD=localdev psql -h localhost -U postgres     < sql/create.sql
  PGPASSWORD=localdev psql -h localhost -U postgres $db < sql/schema.sql
  PGPASSWORD=localdev psql -h localhost -U postgres $db < sql/sample.sql
}

db=$1
if [ "$db" == "" ]
then 
  echo "Sorry. No db name provided" 
else 
  reset
fi


