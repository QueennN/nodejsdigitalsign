var chilkat = require('@chilkat/ck-node12-win64');
//https://www.example-code.com/nodejs/load_certificate_on_smartcard_in_reader.asp
//https://cservices.certum.pl/muc-customer/pfx/generator
const signer = require('node-signpdf').default
var fs = require('fs');
const { sign } = require('crypto');

function cades() {
    //----------------------CADES BES---------------------
    var crypt = new chilkat.Crypt2();
    // Use a digital certificate and private key from a PFX file (.pfx or .p12).
    var pfxPath = "keyBag.pfx";
    var pfxPassword = "1234";
    var cert = new chilkat.Cert();

    var success = cert.LoadPfxFile(pfxPath, pfxPassword);
    if (success !== true) {
        console.log("Load Pfx File err");
        return;
    }

    // Tell the crypt component to use this cert.
    success = crypt.SetSigningCert(cert);
    if (success !== true) {
        console.log("Set Sign Cert err");
        return;
    }

    // The CadesEnabled property applies to all methods that create PKCS7 signatures. 
    // To create a CAdES-BES signature, set this property equal to true. 
    crypt.CadesEnabled = true;

    // We can sign any type of file, creating a .p7s as output:
    var inFile = "test.pdf";
    var sigFile = "ample.p7s";

    // Create the detached CAdES-BES signature:
    success = crypt.CreateP7S(inFile, sigFile);
    if (success == false) {
        console.log(crypt.LastErrorText);
        return;
    }

    success = crypt.VerifyP7S(inFile, sigFile);
    if (success == false) {
        console.log(crypt.LastErrorText);
        return;
    }
    console.log("Success!");
}


//
function readSmartcard() {
    //--------------SMART CARD READER-----------
    var cert = new chilkat.Cert();
    var cspName = "";

    success = cert.LoadFromSmartcard(cspName);
    if (success == false) {
        console.error(cert.LastErrorText);
        return false;
    }

    console.log("Cert loaded from smartcard: " + cert.SubjectCN);

    // The CSP can be explicitly specified.  It can be a CSP in the list
    // above, or any CSP that Chilkat does not yet know about..
    cspName = "My Smartcard Vendor CSP";
    success = cert.LoadFromSmartcard(cspName);
    if (success == false) {
        console.log(cert.LastErrorText);
        return;
    }

}

function xades() {
    // This example requires the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    // This example will sign the following XML document:

    // <?xml version="1.0" encoding="utf-8"?>
    // <InitUpload xmlns="http://e-dokumenty.mf.gov.pl">
    //     <DocumentType>JPK</DocumentType>
    //     <Version>01.02.01.20160617</Version>
    //     <EncryptionKey algorithm="RSA" encoding="Base64" mode="ECB" padding="PKCS#1">...</EncryptionKey>
    //     <DocumentList>
    //         <Document>
    //             <FormCode schemaVersion="1-1" systemCode="JPK_VAT (3)">JPK_VAT</FormCode>
    //             <FileName>JPK_VAT_3_v1-1_20181208.xml</FileName>
    //             <ContentLength>8736</ContentLength>
    //             <HashValue algorithm="SHA-256" encoding="Base64">JEEI1pItwh6dj/Xe1uts/x61qnjZ4DLHpkRMhmf1oQQ=</HashValue>
    //             <FileSignatureList filesNumber="1">
    //                 <Packaging>
    //                     <SplitZip mode="zip" type="split"/>
    //                 </Packaging>
    //                 <Encryption>
    //                     <AES block="16" mode="CBC" padding="PKCS#7" size="256">
    //                         <IV bytes="16" encoding="Base64">FFsCRAPYJD3J6cRvd44UDA==</IV>
    //                     </AES>
    //                 </Encryption>
    //                 <FileSignature>
    //                     <OrdinalNumber>1</OrdinalNumber>
    //                     <FileName>JPK_VAT_3_v1-1_20181208-000.xml.zip.aes</FileName>
    //                     <ContentLength>16</ContentLength>
    //                     <HashValue algorithm="MD5" encoding="Base64">BX2DTD3ASC/zF6aq/012Cg==</HashValue>
    //                 </FileSignature>
    //             </FileSignatureList>
    //         </Document>
    //     </DocumentList>
    // </InitUpload>

    // First we build the XML to be signed.
    // 
    // Use this online tool to generate the code from sample XML: 
    // Generate Code to Create XML

    var success = true;
    var xmlToSign = new chilkat.Xml();
    xmlToSign.Tag = "InitUpload";
    xmlToSign.AddAttribute("xmlns", "http://e-dokumenty.mf.gov.pl");
    xmlToSign.UpdateChildContent("DocumentType", "JPK");
    xmlToSign.UpdateChildContent("Version", "01.02.01.20160617");
    xmlToSign.UpdateAttrAt("EncryptionKey", true, "algorithm", "RSA");
    xmlToSign.UpdateAttrAt("EncryptionKey", true, "encoding", "Base64");
    xmlToSign.UpdateAttrAt("EncryptionKey", true, "mode", "ECB");
    xmlToSign.UpdateAttrAt("EncryptionKey", true, "padding", "PKCS#1");
    xmlToSign.UpdateChildContent("EncryptionKey", "...");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FormCode", true, "schemaVersion", "1-1");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FormCode", true, "systemCode", "JPK_VAT (3)");
    xmlToSign.UpdateChildContent("DocumentList|Document|FormCode", "JPK_VAT");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileName", "JPK_VAT_3_v1-1_20181208.xml");
    xmlToSign.UpdateChildContent("DocumentList|Document|ContentLength", "8736");
    xmlToSign.UpdateAttrAt("DocumentList|Document|HashValue", true, "algorithm", "SHA-256");
    xmlToSign.UpdateAttrAt("DocumentList|Document|HashValue", true, "encoding", "Base64");
    xmlToSign.UpdateChildContent("DocumentList|Document|HashValue", "JEEI1pItwh6dj/Xe1uts/x61qnjZ4DLHpkRMhmf1oQQ=");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList", true, "filesNumber", "1");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Packaging|SplitZip", true, "mode", "zip");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Packaging|SplitZip", true, "type", "split");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES", true, "block", "16");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES", true, "mode", "CBC");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES", true, "padding", "PKCS#7");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES", true, "size", "256");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES|IV", true, "bytes", "16");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|Encryption|AES|IV", true, "encoding", "Base64");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileSignatureList|Encryption|AES|IV", "FFsCRAPYJD3J6cRvd44UDA==");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileSignatureList|FileSignature|OrdinalNumber", "1");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileSignatureList|FileSignature|FileName", "JPK_VAT_3_v1-1_20181208-000.xml.zip.aes");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileSignatureList|FileSignature|ContentLength", "16");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|FileSignature|HashValue", true, "algorithm", "MD5");
    xmlToSign.UpdateAttrAt("DocumentList|Document|FileSignatureList|FileSignature|HashValue", true, "encoding", "Base64");
    xmlToSign.UpdateChildContent("DocumentList|Document|FileSignatureList|FileSignature|HashValue", "BX2DTD3ASC/zF6aq/012Cg==");

    // Also see the online tool to generate the code from sample already-signed XML: 
    // Generate XML Signature Creation Code from an Already-Signed XML Sample

    var gen = new chilkat.XmlDSigGen();

    gen.SigLocation = "InitUpload";
    gen.SigId = "id-1234";
    gen.SigNamespacePrefix = "ds";
    gen.SigNamespaceUri = "http://www.w3.org/2000/09/xmldsig#";
    gen.SignedInfoCanonAlg = "EXCL_C14N";
    gen.SignedInfoDigestMethod = "sha256";

    // Create an Object to be added to the Signature.
    var object1 = new chilkat.Xml();
    object1.Tag = "xades:QualifyingProperties";
    object1.AddAttribute("Target", "#id-1234");
    object1.AddAttribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
    object1.UpdateAttrAt("xades:SignedProperties", true, "Id", "xades-id-1234");
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningTime", "TO BE GENERATED BY CHILKAT");
    object1.UpdateAttrAt("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:CertDigest|ds:DigestMethod", true, "Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:CertDigest|ds:DigestValue", "TO BE GENERATED BY CHILKAT");
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:IssuerSerial|ds:X509IssuerName", "TO BE GENERATED BY CHILKAT");
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedSignatureProperties|xades:SigningCertificate|xades:Cert|xades:IssuerSerial|ds:X509SerialNumber", "TO BE GENERATED BY CHILKAT");
    object1.UpdateAttrAt("xades:SignedProperties|xades:SignedDataObjectProperties|xades:DataObjectFormat", true, "ObjectReference", "#r-id-1");
    object1.UpdateChildContent("xades:SignedProperties|xades:SignedDataObjectProperties|xades:DataObjectFormat|xades:MimeType", "text/xml");

    gen.AddObject("", object1.GetXml(), "", "");

    // -------- Reference 1 --------
    gen.AddSameDocRef("", "sha256", "EXCL_C14N", "", "");
    gen.SetRefIdAttr("", "r-id-1");

    // -------- Reference 2 --------
    gen.AddObjectRef("xades-id-1234", "sha256", "EXCL_C14N", "", "http://uri.etsi.org/01903#SignedProperties");

    // Provide a certificate + private key. (PFX password is test123)
    // See Load Certificate on Smartcard for an example showing how to load the cert from a smartcard..
    var cert = new chilkat.Cert();
    success = cert.LoadPfxFile("keyBag.pfx", "1234");
    if (success !== true) {
        console.log(cert.LastErrorText);
        return;
    }

    gen.SetX509Cert(cert, true);

    gen.KeyInfoType = "X509Data";
    gen.X509Type = "Certificate";

    // Load XML to be signed...
    var sbXml = new chilkat.StringBuilder();
    xmlToSign.GetXmlSb(sbXml);

    gen.Behaviors = "IndentedSignature,TransformSignatureXPath,IssuerSerialHex";

    // Sign the XML...
    success = gen.CreateXmlDSigSb(sbXml);
    if (success !== true) {
        console.log(gen.LastErrorText);
        return;
    }

    // Save the signed XMl to a file.
    success = sbXml.WriteFile("qa_output/signedXml.xml", "utf-8", false);

    console.log(sbXml.GetAsString());

    // ----------------------------------------
    // Verify the signature we just produced...
    var verifier = new chilkat.XmlDSig();
    success = verifier.LoadSignatureSb(sbXml);
    if (success !== true) {
        console.log(verifier.LastErrorText);
        return;
    }

    var verified = verifier.VerifySignature(true);
    if (verified !== true) {
        console.log(verifier.LastErrorText);
        return;
    }

    console.log("This signature was successfully verified.");

}

//----------------------PADES ----------------------
function pades() {
    var tmpPdf = fs.readFileSync("./test.pdf")
    var tmpCert = fs.readFileSync("./keyBag.pfx")
    console.log(tmpPdf)
    console.log(tmpCert)

    var signedPdf = signer.sign(tmpPdf, tmpCert)
    var { signature, signedData } = extractSignature(signedPdf);


    console.log('pdf')
    console.log(signedData)
    console.log(signature)
}

readSmartcard()