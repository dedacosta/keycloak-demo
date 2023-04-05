COMMANDS=("token" "test" "show" "help")

init(){
  mkdir -p target
  TOKEN=$(cat ./target/token.txt)
}

test() {
  init
  curl --header "Authorization: Bearer $TOKEN" http://localhost:4080/test/user
  curl --header "Authorization: Bearer $TOKEN" http://localhost:4080/test/anonymous
  curl --header "Authorization: Bearer $TOKEN" http://localhost:4080/test/anonymous
}

show(){
  init
  echo $TOKEN
}

token(){
  curl -s -X POST 'http://localhost:8080/auth/realms/Demo/protocol/openid-connect/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=password' \
    --data-urlencode 'client_id=demo-client' \
    --data-urlencode 'username=user1' \
    --data-urlencode 'password=user1' |
    jq -c .access_token | tr -d '"' | tee ./target/token.txt
}

help(){
  echo "do.sh token|test|show|help"
}

#Main code
if [[ "$1" = "" ]]; then
  help;
  exit 0;
fi
# shellcheck disable=SC2199
if [[ " ${COMMANDS[@]} " =~ " $1 " ]]; then
  $1
else
  echo "I do not understand the command."
fi
