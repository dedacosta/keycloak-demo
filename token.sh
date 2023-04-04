TOKEN=`curl -s -X POST 'http://localhost:8080/auth/realms/Demo/protocol/openid-connect/token' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=password' \
  --data-urlencode 'client_id=demo-client' \
  --data-urlencode 'username=costade' \
  --data-urlencode 'password=costade' \
  | jq -c .access_token | tr -d '"'`


curl -v  http://localhost:4080/test/user \
   -H "Authorization: Bearer $TOKEN"

#curl -- header