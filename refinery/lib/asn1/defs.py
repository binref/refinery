from refinery.lib.asn1.compiler import compile_asn1

_x509 = compile_asn1("""
    PKIX1 DEFINITIONS EXPLICIT TAGS ::= BEGIN

        AlgorithmIdentifier ::= SEQUENCE {
            algorithm   OBJECT IDENTIFIER,
            parameters  ANY OPTIONAL
        }

        Time ::= CHOICE {
            utcTime     UTCTime,
            generalTime GeneralizedTime
        }

        AttributeTypeAndValue ::= SEQUENCE {
            type  OBJECT IDENTIFIER,
            value ANY
        }

        RDN ::= SET OF AttributeTypeAndValue

        Name ::= SEQUENCE OF RDN

        Validity ::= SEQUENCE {
            notBefore Time,
            notAfter  Time
        }

        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm        AlgorithmIdentifier,
            subjectPublicKey BIT STRING
        }

        Extension ::= SEQUENCE {
            extnID   OBJECT IDENTIFIER,
            critical BOOLEAN DEFAULT FALSE,
            extnValue OCTET STRING
        }

        Extensions ::= SEQUENCE OF Extension

        TBSCertificate ::= SEQUENCE {
            version         [0] EXPLICIT INTEGER DEFAULT 0,
            serialNumber    INTEGER,
            signature       AlgorithmIdentifier,
            issuer          Name,
            validity        Validity,
            subject         Name,
            subjectPublicKeyInfo SubjectPublicKeyInfo,
            issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL,
            subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL,
            extensions      [3] EXPLICIT Extensions OPTIONAL
        }

        Certificate ::= SEQUENCE {
            tbsCertificate     TBSCertificate,
            signatureAlgorithm AlgorithmIdentifier,
            signatureValue     BIT STRING
        }

        RevokedCertificate ::= SEQUENCE {
            userCertificate   INTEGER,
            revocationDate    Time,
            crlEntryExtensions Extensions OPTIONAL
        }

        TBSCertList ::= SEQUENCE {
            version             INTEGER OPTIONAL,
            signature           AlgorithmIdentifier,
            issuer              Name,
            thisUpdate          Time,
            nextUpdate          Time OPTIONAL,
            revokedCertificates SEQUENCE OF RevokedCertificate OPTIONAL,
            crlExtensions       [0] EXPLICIT Extensions OPTIONAL
        }

        CertificateList ::= SEQUENCE {
            tbsCertList        TBSCertList,
            signatureAlgorithm AlgorithmIdentifier,
            signatureValue     BIT STRING
        }

        CertificationRequestInfo ::= SEQUENCE {
            version    INTEGER,
            subject    Name,
            subjectPKInfo SubjectPublicKeyInfo,
            attributes [0] IMPLICIT ANY OPTIONAL
        }

        CertificationRequest ::= SEQUENCE {
            certificationRequestInfo CertificationRequestInfo,
            signatureAlgorithm       AlgorithmIdentifier,
            signature                BIT STRING
        }

    END
""")

_rsa = compile_asn1("""
    PKCS1 DEFINITIONS EXPLICIT TAGS ::= BEGIN

        RSAPrivateKey ::= SEQUENCE {
            version         INTEGER,
            modulus         INTEGER,
            publicExponent  INTEGER,
            privateExponent INTEGER,
            prime1          INTEGER,
            prime2          INTEGER,
            exponent1       INTEGER,
            exponent2       INTEGER,
            coefficient     INTEGER
        }

        RSAPublicKey ::= SEQUENCE {
            modulus        INTEGER,
            publicExponent INTEGER
        }

    END
""", externals=_x509)

_cms = compile_asn1("""
    CMS DEFINITIONS IMPLICIT TAGS ::= BEGIN

        Attribute ::= SEQUENCE {
            attrType   OBJECT IDENTIFIER,
            attrValues SET OF ANY
        }

        EncapsulatedContentInfo ::= SEQUENCE {
            eContentType OBJECT IDENTIFIER,
            eContent     [0] EXPLICIT OCTET STRING OPTIONAL
        }

        IssuerAndSerialNumber ::= SEQUENCE {
            issuer       Name,
            serialNumber INTEGER
        }

        SignerIdentifier ::= CHOICE {
            issuerAndSerialNumber IssuerAndSerialNumber,
            subjectKeyIdentifier  [0] OCTET STRING
        }

        SignerInfo ::= SEQUENCE {
            version            INTEGER,
            sid                SignerIdentifier,
            digestAlgorithm    AlgorithmIdentifier,
            signedAttrs        [0] IMPLICIT SET OF Attribute OPTIONAL,
            signatureAlgorithm AlgorithmIdentifier,
            signature          OCTET STRING,
            unsignedAttrs      [1] IMPLICIT SET OF Attribute OPTIONAL
        }

        SignedData ::= SEQUENCE {
            version          INTEGER,
            digestAlgorithms SET OF AlgorithmIdentifier,
            encapContentInfo EncapsulatedContentInfo,
            certificates     [0] IMPLICIT SET OF Certificate OPTIONAL,
            crls             [1] IMPLICIT ANY OPTIONAL,
            signerInfos      SET OF SignerInfo
        }

        ContentInfo ::= SEQUENCE {
            contentType OBJECT IDENTIFIER,
            content     [0] EXPLICIT ANY OPTIONAL
        }

        SignedContentInfo ::= SEQUENCE {
            contentType OBJECT IDENTIFIER,
            content     [0] EXPLICIT SignedData OPTIONAL
        }

    END
""", externals=_x509)

_tsp = compile_asn1("""
    TSP DEFINITIONS IMPLICIT TAGS ::= BEGIN

        MessageImprint ::= SEQUENCE {
            hashAlgorithm AlgorithmIdentifier,
            hashedMessage OCTET STRING
        }

        TimeStampReq ::= SEQUENCE {
            version        INTEGER,
            messageImprint MessageImprint,
            reqPolicy      OBJECT IDENTIFIER OPTIONAL,
            nonce          INTEGER OPTIONAL,
            certReq        BOOLEAN DEFAULT FALSE,
            extensions     [0] IMPLICIT Extensions OPTIONAL
        }

    END
""", externals=_x509)

_pkcs8 = compile_asn1("""
    PKCS8 DEFINITIONS EXPLICIT TAGS ::= BEGIN

        PrivateKeyInfo ::= SEQUENCE {
            version             INTEGER,
            privateKeyAlgorithm AlgorithmIdentifier,
            privateKey          OCTET STRING
        }

        EncryptedPrivateKeyInfo ::= SEQUENCE {
            encryptionAlgorithm AlgorithmIdentifier,
            encryptedData       OCTET STRING
        }

    END
""", externals=_x509)

_ec = compile_asn1("""
    EC DEFINITIONS EXPLICIT TAGS ::= BEGIN

        ECPrivateKey ::= SEQUENCE {
            version    INTEGER,
            privateKey OCTET STRING,
            parameters [0] EXPLICIT ANY OPTIONAL,
            publicKey  [1] EXPLICIT BIT STRING OPTIONAL
        }

    END
""")

_pkcs12 = compile_asn1("""
    PKCS12 DEFINITIONS IMPLICIT TAGS ::= BEGIN

        DigestInfo ::= SEQUENCE {
            digestAlgorithm AlgorithmIdentifier,
            digest          OCTET STRING
        }

        MacData ::= SEQUENCE {
            mac        DigestInfo,
            macSalt    OCTET STRING,
            iterations INTEGER DEFAULT 1
        }

        PFX ::= SEQUENCE {
            version  INTEGER,
            authSafe ContentInfo,
            macData  MacData OPTIONAL
        }

    END
""", externals={**_x509, **_cms})

_tsp = compile_asn1("""
    TSP DEFINITIONS IMPLICIT TAGS ::= BEGIN

        MessageImprint ::= SEQUENCE {
            hashAlgorithm AlgorithmIdentifier,
            hashedMessage OCTET STRING
        }

        TimeStampReq ::= SEQUENCE {
            version        INTEGER,
            messageImprint MessageImprint,
            reqPolicy      OBJECT IDENTIFIER OPTIONAL,
            nonce          INTEGER OPTIONAL,
            certReq        BOOLEAN DEFAULT FALSE,
            extensions     [0] IMPLICIT Extensions OPTIONAL
        }

        PKIStatusInfo ::= SEQUENCE {
            status     INTEGER,
            statusString SEQUENCE OF UTF8String OPTIONAL,
            failInfo   BIT STRING OPTIONAL
        }

        TimeStampResp ::= SEQUENCE {
            status         PKIStatusInfo,
            timeStampToken ContentInfo OPTIONAL
        }

    END
""", externals={**_x509, **_cms})

_ocsp = compile_asn1("""
    OCSP DEFINITIONS EXPLICIT TAGS ::= BEGIN

        CertID ::= SEQUENCE {
            hashAlgorithm  AlgorithmIdentifier,
            issuerNameHash OCTET STRING,
            issuerKeyHash  OCTET STRING,
            serialNumber   INTEGER
        }

        Request ::= SEQUENCE {
            reqCert                 CertID,
            singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
        }

        TBSRequest ::= SEQUENCE {
            version            [0] EXPLICIT INTEGER DEFAULT 0,
            requestorName      [1] EXPLICIT ANY OPTIONAL,
            requestList        SEQUENCE OF Request,
            requestExtensions  [2] EXPLICIT Extensions OPTIONAL
        }

        Signature ::= SEQUENCE {
            signatureAlgorithm AlgorithmIdentifier,
            signature          BIT STRING,
            certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
        }

        OCSPRequest ::= SEQUENCE {
            tbsRequest         TBSRequest,
            optionalSignature  [0] EXPLICIT Signature OPTIONAL
        }

        ResponseBytes ::= SEQUENCE {
            responseType OBJECT IDENTIFIER,
            response     OCTET STRING
        }

        OCSPResponse ::= SEQUENCE {
            responseStatus ENUMERATED,
            responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
        }

    END
""", externals=_x509)

_ldap = compile_asn1("""
    LDAP DEFINITIONS IMPLICIT TAGS ::= BEGIN

        Control ::= SEQUENCE {
            controlType  OCTET STRING,
            criticality  BOOLEAN DEFAULT FALSE,
            controlValue OCTET STRING OPTIONAL
        }

        Controls ::= SEQUENCE OF Control

        LDAPResult ::= SEQUENCE {
            resultCode        ENUMERATED,
            matchedDN         OCTET STRING,
            diagnosticMessage OCTET STRING,
            referral          [3] SEQUENCE OF OCTET STRING OPTIONAL
        }

        LDAPMessage ::= SEQUENCE {
            messageID  INTEGER,
            protocolOp CHOICE {
                bindRequest    [APPLICATION 0] SEQUENCE {
                    version        INTEGER,
                    name           OCTET STRING,
                    authentication CHOICE {
                        simple [0] OCTET STRING,
                        sasl   [3] SEQUENCE {
                            mechanism   OCTET STRING,
                            credentials OCTET STRING OPTIONAL
                        }
                    }
                },
                bindResponse   [APPLICATION 1] SEQUENCE {
                    resultCode        ENUMERATED,
                    matchedDN         OCTET STRING,
                    diagnosticMessage OCTET STRING,
                    referral          [3] SEQUENCE OF OCTET STRING OPTIONAL,
                    serverSaslCreds   [7] OCTET STRING OPTIONAL
                },
                unbindRequest    [APPLICATION 2] NULL,
                searchRequest    [APPLICATION 3] SEQUENCE {
                    baseObject   OCTET STRING,
                    scope        ENUMERATED,
                    derefAliases ENUMERATED,
                    sizeLimit    INTEGER,
                    timeLimit    INTEGER,
                    typesOnly    BOOLEAN,
                    filter       ANY,
                    attributes   SEQUENCE OF OCTET STRING
                },
                searchResEntry   [APPLICATION 4] SEQUENCE {
                    objectName OCTET STRING,
                    attributes SEQUENCE OF SEQUENCE {
                        type OCTET STRING,
                        vals SET OF OCTET STRING
                    }
                },
                searchResDone    [APPLICATION 5] LDAPResult,
                modifyRequest    [APPLICATION 6] SEQUENCE {
                    object  OCTET STRING,
                    changes SEQUENCE OF SEQUENCE {
                        operation    ENUMERATED,
                        modification SEQUENCE {
                            type OCTET STRING,
                            vals SET OF OCTET STRING
                        }
                    }
                },
                modifyResponse   [APPLICATION 7] LDAPResult,
                addRequest       [APPLICATION 8] SEQUENCE {
                    entry      OCTET STRING,
                    attributes SEQUENCE OF SEQUENCE {
                        type OCTET STRING,
                        vals SET OF OCTET STRING
                    }
                },
                addResponse      [APPLICATION 9] LDAPResult,
                delRequest       [APPLICATION 10] OCTET STRING,
                delResponse      [APPLICATION 11] LDAPResult,
                modDNRequest     [APPLICATION 12] SEQUENCE {
                    entry        OCTET STRING,
                    newrdn       OCTET STRING,
                    deleteoldrdn BOOLEAN,
                    newSuperior  [0] OCTET STRING OPTIONAL
                },
                modDNResponse    [APPLICATION 13] LDAPResult,
                compareRequest   [APPLICATION 14] SEQUENCE {
                    entry OCTET STRING,
                    ava   SEQUENCE {
                        attributeDesc  OCTET STRING,
                        assertionValue OCTET STRING
                    }
                },
                compareResponse  [APPLICATION 15] LDAPResult,
                abandonRequest   [APPLICATION 16] INTEGER,
                searchReference  [APPLICATION 19] SEQUENCE OF OCTET STRING,
                extendedReq      [APPLICATION 23] SEQUENCE {
                    requestName  [0] OCTET STRING,
                    requestValue [1] OCTET STRING OPTIONAL
                },
                extendedResp     [APPLICATION 24] SEQUENCE {
                    resultCode        ENUMERATED,
                    matchedDN         OCTET STRING,
                    diagnosticMessage OCTET STRING,
                    referral          [3] SEQUENCE OF OCTET STRING OPTIONAL,
                    responseName      [10] OCTET STRING OPTIONAL,
                    responseValue     [11] OCTET STRING OPTIONAL
                },
                intermediateResponse [APPLICATION 25] SEQUENCE {
                    responseName  [0] OCTET STRING OPTIONAL,
                    responseValue [1] OCTET STRING OPTIONAL
                }
            },
            controls [0] Controls OPTIONAL
        }

    END
""")

Certificate = _x509['Certificate']
CertificateList = _x509['CertificateList']
CertificationRequest = _x509['CertificationRequest']
RSAPrivateKey = _rsa['RSAPrivateKey']
RSAPublicKey = _rsa['RSAPublicKey']
ContentInfo = _cms['ContentInfo']
SignedContentInfo = _cms['SignedContentInfo']
PrivateKeyInfo = _pkcs8['PrivateKeyInfo']
EncryptedPrivateKeyInfo = _pkcs8['EncryptedPrivateKeyInfo']
ECPrivateKey = _ec['ECPrivateKey']
PFX = _pkcs12['PFX']
TimeStampReq = _tsp['TimeStampReq']
TimeStampResp = _tsp['TimeStampResp']
OCSPRequest = _ocsp['OCSPRequest']
OCSPResponse = _ocsp['OCSPResponse']
LDAPMessage = _ldap['LDAPMessage']

ROOT_SCHEMAS = [
    ('SignedContentInfo', SignedContentInfo, 0),
    ('ContentInfo', ContentInfo, 0),
    ('Certificate', Certificate, 0),
    ('CertificateList', CertificateList, 0),
    ('CertificationRequest', CertificationRequest, 0),
    ('PFX', PFX, 64),
    ('RSAPrivateKey', RSAPrivateKey, 64),
    ('PrivateKeyInfo', PrivateKeyInfo, 16),
    ('EncryptedPrivateKeyInfo', EncryptedPrivateKeyInfo, 16),
    ('ECPrivateKey', ECPrivateKey, 16),
    ('RSAPublicKey', RSAPublicKey, 32),
    ('TimeStampResp', TimeStampResp, 0),
    ('TimeStampReq', TimeStampReq, 16),
    ('OCSPResponse', OCSPResponse, 0),
    ('OCSPRequest', OCSPRequest, 16),
    ('LDAPMessage', LDAPMessage, 0),
]
