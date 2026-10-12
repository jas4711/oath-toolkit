#!/bin/sh

# tst_bypass_sign.sh - regression check pskctool verify for CVE-2026-109117

# Copyright (C) 2012-2026 Simon Josefsson

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -e

if test -f ../../libpskc/config.h; then
    grep '#define USE_XMLSEC 1' ../../libpskc/config.h > /dev/null \
	|| exit 77
fi

PSKCTOOL=${PSKCTOOL:-../pskctool}

srcdir="${srcdir:-.}"
pskc_all="$srcdir/pskc-all.xml"

if ! command -v xmlsec1 > /dev/null; then
    echo SKIP: Cannot find xmlsec1 tool
    exit 77
fi

if ! command -v openssl > /dev/null; then
    echo SKIP: Cannot find openssl tool
    exit 77
fi

if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout trusted.key -out trusted.crt -days 3650 -subj "/CN=Trusted PSKC Signer" > /dev/null 2>&1; then
    echo "FAIL: openssl req baseline failed (rc $?)"
    exit 1
fi

if ! $PSKCTOOL --sign --sign-key trusted.key --sign-crt trusted.crt $pskc_all > signed-legit.xml; then
    echo "FAIL: pskctool --sign baseline failed (rc $?)"
    exit 1
fi

if ! $PSKCTOOL --verify --verify-crt trusted.crt signed-legit.xml; then
    echo "FAIL: pskctool --verify baseline failed (rc $?)"
    exit 1
fi

cat<<EOF>attack-template.xml
<?xml version="1.0" encoding="UTF-8"?>
  <KeyContainer Version="1.0" Id="KC0001"
xmlns="urn:ietf:params:xml:ns:keyprov:pskc">
   <KeyPackage>
    <Key Id="12345678" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">
     <Issuer>Attacker</Issuer>
     <Data>
      <Secret>
       <PlainValue>QUJDREVGR0gK</PlainValue>
      </Secret>
     </Data>
    </Key>
   </KeyPackage>
   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
     <CanonicalizationMethod
Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
     <SignatureMethod
Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
     <Reference URI="">
      <Transforms>
       <Transform
Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
      </Transforms>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      <DigestValue/>
     </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
     <KeyValue/>
    </KeyInfo>
   </Signature>
  </KeyContainer>
EOF

if ! openssl req -x509 -newkey rsa:2048 -nodes -keyout attacker.key -out attacker.crt -days 3650 -subj "/CN=Attacker" > /dev/null 2>&1; then
    echo "FAIL: openssl req failed (rc $?)"
    exit 1
fi

if ! xmlsec1 --sign --privkey-pem attacker.key --output attack-signed.xml attack-template.xml; then # --enabled-key-data rsa,key-value
    xmlsec1 --version
    xmlsec1 --list-key-data
    echo "SKIP: xmlsec1 --sign failed (rc $?)"
    exit 77
fi

if $PSKCTOOL --verify --verify-crt trusted.crt attack-signed.xml; then
    echo "PASS: pskctool --verify on attacker data accepted incorrectly"
    exit 1
fi

echo "PASS: pskctool --verify on attacker data rejected properly"

rm -f attack-template.xml attack-signed.xml attacker.crt attacker.key signed-legit.xml trusted.crt trusted.key

exit 0
