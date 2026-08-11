#!/bin/bash
PKIMETAL_URL="http://127.0.0.1:8080"
#PKIMETAL_URL="https://pkimet.al"
REQ_FILE=`mktemp`
for filename in *.crt; do
  echo "$filename"
  echo -n "b64input=" > $REQ_FILE
  openssl x509 -in "$filename" -outform der | base64 -w0 | sed "s/+/%2B/g" | sed "s/\//%2F/g" | sed "s/=/%3D/g" >> $REQ_FILE
  wget --quiet --post-file $REQ_FILE -O /dev/stdout $PKIMETAL_URL/lintcert | jq | grep Profile
done
rm $REQ_FILE
