Test from http://www.strozhevsky.com/free_docs/TEST_SUITE.zip

Files were created using:
for i in tc*.ber; do echo "\$ fq -d asn1_ber v $i" > $i.fqtest ; done
rename 's/transformed_//' transformed_tc*
