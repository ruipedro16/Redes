#!/usr/bin/env sh

./delegated.py -o out

# shellcheck disable=SC2028
echo "\nVerifying new certification chain"
openssl verify -verbose -x509_strict -show_chain -crl_check_all -CRLfile out/rca.crl -CRLfile out/ica2.crl \
-CRLfile out/sica2.crl -trusted out/rca.pem -untrusted out/ica2.pem -untrusted out/sica2.pem out/ee.pem

# shellcheck disable=SC2028
echo "\nVerifying old certification chain => Invalid CRL signature"
openssl verify -verbose -x509_strict -show_chain -crl_check_all -CRLfile out/rca.crl -CRLfile out/ica2.crl \
-CRLfile out/sica2.crl -trusted out/rca.pem -untrusted out/ica.pem -untrusted out/sica.pem out/ee.pem

# shellcheck disable=SC2028
echo "\nVerying old certification chain with CRL signed by the old key => Certificate Revoked"
openssl verify -verbose -x509_strict -show_chain -crl_check_all -CRLfile out/rca.crl -CRLfile out/ica.crl \
-CRLfile out/sica2.crl -trusted out/rca.pem -untrusted out/ica.pem -untrusted out/sica.pem out/ee.pem
