//---------------------------------------------------------------------------
// Copyright 2014 The Open Source Electronic Health Record Agent
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------

unit Wcrypt2;

interface 

uses  Windows;


const

  {
    Most Values from in the const were taken from
    http://www.math.uiuc.edu/~gfrancis/illimath/windows/aszgard_mini/bin/MinGW/include/wincrypt.h

    Others have their source mentioned in comments above
    the value
  }
  CRYPT32     = 'crypt32.dll';
  ADVAPI32    = 'Advapi32.dll';
  ALG_CLASS_ANY=0;
  ALG_CLASS_SIGNATURE=8192;
  ALG_CLASS_MSG_ENCRYPT=16384;
  ALG_CLASS_DATA_ENCRYPT=24576;
  ALG_CLASS_HASH =32768;
  ALG_CLASS_KEY_EXCHANGE=40960;
  CALG_SHA_256 = $0000800c;
  CALG_RC2 = $00006602;

  CRYPT_EXPORTABLE = 1;
  CRYPT_CREATE_SALT = 4;
  CRYPT_USER_PROTECTED = 2;
  CRYPT_MACHINE_DEFAULT= 0;
  CRYPT_FIRST = 1;
  CRYPT_NEXT  = 2;

    PROV_RSA_AES  = 24;
  CRYPT_NEWKEYSET  = $00000008;
  PP_NAME = 4;
  PP_CONTAINER = 6;
  PP_VERSION = 5;
  PP_SIGNATURE_PIN=33;
  PP_ENUMALGS=1;

  //http://www.jensign.com/JavaScience/dotnet/HashStream/HashStream.txt
  PKCS_7_ASN_ENCODING = $00000001;
  X509_ASN_ENCODING =   $00010000;
  HP_HASHVAL = $00000002;

  CERT_CLOSE_STORE_FORCE_FLAG = 0;
  CERT_CONTEXT_REVOCATION_TYPE = True;
  CERT_VERIFY_REV_SERVER_OCSP_FLAG = True;
  CERT_NAME_SIMPLE_DISPLAY_TYPE = 0;
  CERT_CHAIN_REVOCATION_CHECK_CHAIN=0;

  szOID_RSA_SHA1RSA = '';
  szOID_RSA_SHA256RSA = '';
  szOID_RSA_SHA384RSA = '';
  szOID_RSA_SHA512RSA = '';
  CMSG_CONTENT_PARAM = 0;
  CMSG_SIGNER_CERT_INFO_PARAM = 0;
  CMSG_CTRL_VERIFY_SIGNATURE = 0;
  CERT_STORE_PROV_MSG = '';
  USAGE_MATCH_TYPE_AND=0;
  x509_CRL_DIST_POINTS=0;
  CRL_DIST_POINT_FULL_NAME=0;
  CERT_ALT_NAME_URL=0;
  
  CERT_DIGITAL_SIGNATURE_KEY_USAGE=0;
  CERT_KEY_AGREEMENT_KEY_USAGE=0;
  CERT_KEY_CERT_SIGN_KEY_USAGE=0;
  CERT_KEY_ENCIPHERMENT_KEY_USAGE=0;
  CERT_DATA_ENCIPHERMENT_KEY_USAGE=0;
  CERT_NON_REPUDIATION_KEY_USAGE=0;
  CERT_OFFLINE_CRL_SIGN_KEY_USAGE=0;
  
  CERT_NAME_EMAIL_TYPE=0;
  
  
  //Trust Error Conditions; used XuDigsigS:1236
  CERT_TRUST_NO_ERROR=0;
  CERT_TRUST_IS_NOT_TIME_VALID=1;
  CERT_TRUST_IS_NOT_TIME_NESTED=2;
  CERT_TRUST_IS_REVOKED=3;
  CERT_TRUST_IS_NOT_SIGNATURE_VALID=4;
  CERT_TRUST_IS_NOT_VALID_FOR_USAGE=5;
  CERT_TRUST_IS_UNTRUSTED_ROOT=6;
  CERT_TRUST_REVOCATION_STATUS_UNKNOWN=7;
  CERT_TRUST_IS_CYCLIC=8;
  CERT_TRUST_IS_PARTIAL_CHAIN=9;
  CERT_TRUST_CTL_IS_NOT_TIME_VALID=10;
  CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID=11;
  CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE=12;
  
  //Trust Information Status: XuDigsigS:1275
  CERT_TRUST_HAS_EXACT_MATCH_ISSUER=0;
  CERT_TRUST_HAS_KEY_MATCH_ISSUER=1;
  CERT_TRUST_HAS_NAME_MATCH_ISSUER=2;
  CERT_TRUST_IS_SELF_SIGNED=3;
  CERT_TRUST_HAS_PREFERRED_ISSUER=4;
  CERT_TRUST_HAS_ISSUANCE_CHAIN_POLICY=5;
  CERT_TRUST_HAS_VALID_NAME_CONSTRAINTS=6;
  CERT_TRUST_IS_COMPLEX_CHAIN=7;
  
type

  HCRYPTPROV = ULONG;
  PHCRYPTPROV = ^HCRYPTPROV;
  HCRYPTKEY  = ULONG;
  HCRYPTHASH = ULONG;
  HCRYPTSTORE = ULONG;
  HCRYPTMSG   = pointer;
  HCERTSTORE  = Integer;
  HCERTCHAINENGINE = Integer;

  WCRYPT2Type = record
      class operator Implicit(a:WCRYPT2Type): boolean;
      class operator Implicit(a:WCRYPT2Type): cardinal;
      class operator GreaterThan(a:WCRYPT2Type;b:integer):boolean;
      class operator Equal(a:WCRYPT2Type;b:integer):boolean;
      class operator NotEqual(a:WCRYPT2Type;b:integer):boolean;
  end;

  CERT_CHAIN_ENGINE_CONFIG = record
    cbSize:integer;
    hRestrictedRoot :integer;
    hRestrictedTrust:integer;
    hRestrictedOther:integer;
    cAdditionalStore:integer;
    rghAdditionalStore:integer;
    dwUrlRetrievalTimeout:integer;
    MaximumCachedCertificates:integer;
    CycleDetectionModulus:integer;
    dwFlags: integer;
  end;
  
  TRUST_STATUS = record
    dwErrorStatus: integer;
    dwInfoStatus : integer;
  end;
  
  CERT_CHAIN_CONTEXT = record
    TrustStatus: TRUST_STATUS;
    cbSize: integer;
    cChain: integer;
  end;
  
  PCCERT_CHAIN_CONTEXT = ^CERT_CHAIN_CONTEXT;
  
  CERT_ENHKEY_USAGE = record
    cUsageIdentifier:integer;
    rgpszUsageIdentifier:pointer;
  end;
    
  CERT_USAGE_MATCH = record
    dwType: integer;
    Usage: CERT_ENHKEY_USAGE;
  end;
  CERT_CHAIN_PARA = record
    cbSize:integer;
    RequestedUsage: CERT_USAGE_MATCH;
  end;
  
  ALG_ID = DWORD;
  
  Serial_Number = class
    cbData: integer;
    pbData: pbyte;
  end;
  
  extension_param = record
    CbData : DWORD;
  end;
  
  PCERT_EXTENSION = ^CERT_EXTENSION;
  CERT_EXTENSION = record
    pszObjID : LPSTR;
    fCritical: boolean;
    Value: Serial_Number;
	Parameters: extension_param  ;
  end;
  
  PCERT_REVOCATION_STATUS = pointer;

  pCert_Info = class
    SerialNumber : Serial_Number;
    NotAfter     : _FILETIME;
    rgExtension  : PCERT_EXTENSION;
    cExtension   : DWORD;
  end;
  
  PCCERT_CONTEXT = class
    pCertInfo : pCert_Info;
  end;

  CERT_REVOCATION_STATUS = class
    dwIndex : integer;
    dwError : integer;
    cbSize  : integer;
  end;
  
  CERT_REVOCATION_PARA = class
    cbSize : integer;
  end;
  
  PPVOID = pointer;

  CRYPT_SIGN_MESSAGE_PARA = record
    cbSize: integer;
    cMsgCert: integer;
    cMsgCrl: integer;
    cAuthAttr: integer;
    cUnauthAttr: integer;
    dwFlags: integer;
    dwInnerContentType: integer;
    
    pvHashAuxInfo: pointer;
    rgpMsgCert: pointer;
    rgpMsgCrl: pointer;
    rgAuthAttr: pointer;
    rgUnauthAttr: pointer;
    
    pSigningCert: PCCERT_CONTEXT;
    dwMsgEncodingType: DWORD;
    HashAlgorithm : CERT_EXTENSION;
  end;
  
  CRYPT_KEY_PROV_INFO = class
    pwszContainerName: pointer;
    pwszProvName: pointer;
    dwKeySpec : integer;  
  end;
  PCRL_DIST_POINT = ^CRL_DIST_POINT;
  
  PCRL_DIST_POINTS_INFO=^CRL_DIST_POINTS_INFO;
  CRL_DIST_POINTS_INFO = record
    rgDistPoint:PCRL_DIST_POINT;
    cDistPoint: DWORD;
  end;
  PCERT_ALT_NAME_ENTRY = record
    pwszURL:STRING;
    dwAltNameChoice:integer;
  end;
  CERT_ALT_NAME_INFO = record
    rgAltEntry: PCERT_ALT_NAME_ENTRY;
  end;

  CRL_DIST_POINT_NAME =record
    dwDistPointNameChoice: DWORD;
    FullName : CERT_ALT_NAME_INFO;
  end;
  CRL_DIST_POINT = record
    DistPointName: CRL_DIST_POINT_NAME;
  end;


  var
    MasterCertChain :  boolean;


    
  function CryptAcquireContextA( i: Pointer; j: PAnsiChar; k: PAnsiChar; l: ULONG; h: ULONG) : boolean; stdcall;
  function CryptAcquireContext( i: Pointer; j: PAnsiChar; k: PAnsiChar; l: ULONG; h: ULONG) : boolean; stdcall;
  function CryptGetProvParam(i: ULONG; j: DWORD; k:  pointer; l: pointer; h: ULONG) : boolean; stdcall;
  function CryptDestroyKey(hPassKey: HCRYPTKEY) : boolean; stdcall;
  function CryptCreateHash(hProv: HCRYPTPROV; c_HASH_ALGID: ALG_ID;i: ULONG; j: ULONG;hHash: pointer) : boolean; stdcall;
  function CryptDestroyHash(hHash: HCRYPTHASH) : boolean; stdcall;
  function CryptHashData(hHash: HCRYPTHASH; pB: pByte; cnt: integer; flag: integer) : boolean; stdcall;
  function CryptReleaseContext(hProv: HCRYPTPROV; force_flag: ULONG) : boolean; stdcall;
  function CryptGetHashParam(hHash: HCRYPTHASH; HP_HASHVAL: integer; j: pointer;dwLen: pointer; i: integer) : boolean; stdcall;
  function CryptSignMessage(msgparam: pointer; detachedsig:boolean;i:integer;rgpb:pointer;rgcb:pointer;return:pointer;encodedblob: pointer): boolean; stdcall;
  function CryptMsgOpenToDecode(encodingtype:DWORD;i:integer;j:integer;k:integer;recip:pointer;stream:pointer): HCRYPTMSG; stdcall;
  function CryptMsgUpdate(hmsg:pointer; pBlob: pointer;blobsize:integer;lastcall:boolean):boolean; stdcall;
  function CryptMsgGetParam(hmsg:pointer;CMSG_param:integer;index:integer;i:pointer;decoded:pointer) : boolean; stdcall;
  function CryptMsgControl(msg:HCRYPTMSG;flags:integer;CMSG_CTRL_VERIFY_SIGNATURE:integer;certinfo:pCert_Info): boolean; stdcall;
  function CryptDecodeObject(encodingtype:DWORD;x509_CRL_DIST_POINTS:integer;pbData:pointer;cbData:integer;flag:integer;dist_info:PCRL_DIST_POINTS_INFO;cbuff:pointer):boolean; stdcall;
  function CryptSetProvParam(handleValue:DWORD;i:integer;text:pointer;Flags:Cardinal): boolean; stdcall;
  function CryptMsgClose(hmsg: pointer):boolean; stdcall;
  function GET_ALG_CLASS(algid:DWORD):DWORD;

  function CryptEnumProvidersA(index:DWORD;reserved:pointer;flags:DWORD;provtype:pointer;provname:pointer;provnamesize:pointer): boolean ; stdcall;
  function CryptEnumProviderTypesA(index:DWORD;reserved:pointer;flags:DWORD;provtype:pointer;provtypename:pointer;provtypenamesize:pointer):boolean ; stdcall;
  function CryptGetDefaultProviderA(index:DWORD;reserved:pointer;flags:DWORD;provname:pointer;provnamesize:pointer) : boolean ; stdcall;


  function CertVerifyRevocation(c_ENCODING_TYPE: DWORD; CERT_CONTEXT_REVOCATION_TYPE: boolean; cContext: integer; prgp: pointer; CERT_VERIFY_REV_SERVER_OCSP_FLAG:boolean; j: pointer; pRevStatus: pointer) : boolean; stdcall;
  function CertOpenSystemStoreA(i: integer; j: PAnsiChar) : integer; stdcall;
  function CertOpenSystemStore(i: integer; j: pchar) : integer; stdcall;
  function CertEnumCertificatesInStore(hCertStore: HCERTSTORE;i: pointer): PCCERT_CONTEXT; stdcall;
  function CertGetNameString(pcertContext: pointer; CERT_NAME_SIMPLE_DISPLAY_TYPE: integer; i: integer; j: integer; nameString: pchar; k : integer): WCRYPT2Type; stdcall;
  function CertVerifyTimeValidity(i: pointer; pCertInfo: pCert_Info): integer; stdcall;
  function CertFindExtension( address :LPCSTR; cExtension: DWORD; rgExtension: PPVOID) : PCERT_EXTENSION; stdcall; stdcall;
  function CertOpenStore( CERT_STORE_PROV_MSG: string;encoding_type: DWORD;i:integer;flags:integer;hMsg:HCRYPTMSG):HCERTSTORE; stdcall;
  function CertGetSubjectCertificateFromStore(hCertStore:HCERTSTORE;encoding_type:DWORD;infoblob:pointer): PCCERT_CONTEXT; stdcall;
  function CertCreateCertificateChainEngine( config: pointer;chainEngine:HCERTCHAINENGINE):boolean; stdcall;
  function CertGetCertificateChain(chainEngine:HCERTCHAINENGINE;CertContext:PCCERT_CONTEXT;time:pointer;additionalstores:integer;ChainPara:pointer;dwFlags:integer;reserved:pointer;ChainContext:PCCERT_CHAIN_CONTEXT):boolean; stdcall;
  function CertGetIntendedKeyUsage(encodingtype:DWORD;pCertInfo:pCert_Info;pb:pbyte;flag:integer):boolean; stdcall;
  procedure CertFreeCertificateContext(pCertContext: pointer); stdcall;
  procedure CertFreeCertificateChainEngine(chainengine: HCERTCHAINENGINE); stdcall;
  procedure CertFreeCertificateChain(chain: PCCERT_CHAIN_CONTEXT); stdcall;
  function CertCloseStore(hCertStore :HCERTSTORE; dwFlags :DWORD):BOOL ; stdcall;

implementation

  class operator WCRYPT2Type.Implicit(a:WCRYPT2Type): boolean;
  begin
    Result := (a <> 0);
  end;

  class operator WCRYPT2Type.Implicit(a:WCRYPT2Type): cardinal;
  begin
    Result := a;
  end;

  class operator WCRYPT2Type.GreaterThan(a:WCRYPT2Type;b:integer): boolean;
  begin
    Result := (a > b);
  end;

  class operator WCRYPT2Type.Equal(a:WCRYPT2Type;b:integer): boolean;
  begin
    Result := (a = b);
  end;

  class operator WCRYPT2Type.NotEqual(a:WCRYPT2Type;b:integer): boolean;
  begin
    Result := not(a = b);
  end;

  function GET_ALG_CLASS(algid: DWORD):DWORD;
  begin
    Result :=algid;
  end;

  function CryptAcquireContextA; external ADVAPI32 name 'CryptAcquireContextA';
  function CryptAcquireContext; external ADVAPI32 name 'CryptAcquireContextA';
  function CryptReleaseContext; external ADVAPI32 name 'CryptReleaseContext';
  function CryptGetProvParam ; external ADVAPI32 name 'CryptGetProvParam';
  function CryptSetProvParam; external ADVAPI32 name 'CryptSetProvParam';

  function CryptDestroyKey; external ADVAPI32 name 'CryptDestroyKey';

  function CryptDestroyHash; external ADVAPI32 name 'CryptDestroyHash';
  function CryptCreateHash; external ADVAPI32 name 'CryptCreateHash';
  function CryptGetHashParam; external ADVAPI32 name 'CryptGetHashParam';
  function CryptHashData; external ADVAPI32 name 'CryptHashData';

  function CryptMsgClose; external CRYPT32 name 'CryptMsgClose';  
  function CryptMsgOpenToDecode; external CRYPT32 name 'CryptMsgOpenToDecode';
  function CryptMsgUpdate; external CRYPT32 name 'CryptMsgUpdate';
  function CryptSignMessage; external CRYPT32 name 'CryptSignMessage';
  function CryptMsgGetParam; external CRYPT32 name 'CryptMsgGetParam';
  function CryptMsgControl; external CRYPT32 name 'CryptMsgControl';

  function CryptDecodeObject; external CRYPT32 name 'CryptDecodeObject';
  function CryptEnumProvidersA; external ADVAPI32 name 'CryptEnumProvidersA';
  function CryptEnumProviderTypesA; external ADVAPI32 name 'CryptEnumProviderTypesA';
  function CryptGetDefaultProviderA; external ADVAPI32 name 'CryptGetDefaultProviderA';

  function CertOpenStore; external CRYPT32 name 'CertOpenStore';
  function CertCloseStore; external CRYPT32 name 'CertCloseStore';
  procedure CertFreeCertificateContext; external CRYPT32 name 'CertFreeCertificateContext';
  procedure CertFreeCertificateChainEngine; external CRYPT32 name 'CertFreeCertificateChainEngine';
  procedure CertFreeCertificateChain; external CRYPT32 name 'CertFreeCertificateChain';
  function CertVerifyRevocation; external CRYPT32 name 'CertVerifyRevocation';
  function CertOpenSystemStoreA; external CRYPT32 name 'CertOpenSystemStoreA';
  function CertOpenSystemStore; external CRYPT32 name 'CertOpenSystemStoreA';
  function CertEnumCertificatesInStore; external CRYPT32 name 'CertEnumCertificatesInStore';
  function CertGetNameString; external CRYPT32 name 'CertGetNameStringA';
  function CertVerifyTimeValidity; external CRYPT32 name 'CertVerifyTimeValidity';
  function CertFindExtension; external CRYPT32 name 'CertFindExtension';
  function CertGetSubjectCertificateFromStore; external CRYPT32 name 'CertGetSubjectCertificateFromStore'; 
  function CertCreateCertificateChainEngine; external CRYPT32 name 'CertCreateCertificateChainEngine';
  function CertGetCertificateChain; external CRYPT32 name 'CertGetCertificateChain';
  function CertGetIntendedKeyUsage; external CRYPT32 name 'CertGetIntendedKeyUsage';

  end.