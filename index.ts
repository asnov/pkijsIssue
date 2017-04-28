/**
 * Created by alexnew on 28/04/17.
 */

// preparation for Node.js only
/// <reference path="node_modules/node-webcrypto-ossl/index.d.ts" />
const WebCryptoForNode = require('node-webcrypto-ossl');
(<any>global).self = (<any>global).self || {};
(<any>global).self.crypto = (<any>global).self.crypto || new WebCryptoForNode();    // CryptoEngine

import * as asn1js from 'asn1js';
import {stringToArrayBuffer, fromBase64} from 'pvutils';
import Certificate from 'pkijs/build/Certificate';
import SignedData from 'pkijs/build/SignedData';
import SignerInfo from 'pkijs/build/SignerInfo';
import IssuerAndSerialNumber from 'pkijs/build/IssuerAndSerialNumber';
import 'regenerator-runtime/runtime';


// Go Daddy Secure Certificate Authority - G2, GoDaddy Secure Server Certificate (Intermediate Certificate) - G2
const certificate = new Certificate({
    schema: asn1js.fromBER(stringToArrayBuffer(fromBase64(
        `MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMxMDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYuswZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am+GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1gO7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQWOlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqFBxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyIBslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwlTxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKocyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkKrqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDAB`
    ))).result,
});

// Get signature buffer
const signedBuffer: ArrayBuffer = stringToArrayBuffer(fromBase64('base64 signature'));
// Get signed data buffer
const signedDataBuffer: ArrayBuffer = stringToArrayBuffer('string to sign');

// validating the signed seal
const cmsSignedSimp: SignedData = new SignedData({
    certificates: [certificate],
    signerInfos: [
        new SignerInfo({
            version: certificate.version,
            sid: new IssuerAndSerialNumber({
                issuer: certificate.issuer,
                serialNumber: certificate.serialNumber
            }),
            digestAlgorithm: certificate.signatureAlgorithm,
            signature: new asn1js.OctetString({valueHex: signedBuffer}),
        })
    ],
});

cmsSignedSimp
    .verify({
        signer: 0,
        data: signedDataBuffer,
        extendedMode: true,
    })
    .then(verifyResult => {
        if (!verifyResult.signatureVerified) {
            delete verifyResult.signerCertificate;
            delete verifyResult.signerCertificateVerified;
            console.error(`SignedData.verify() failed`, verifyResult);
        } else {
            console.log(`SignedData.verify() succeed.`);
        }
    })
    .catch(err => {
        console.error(`SignedData.verify() catched error`, err);
    });
