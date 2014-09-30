unit AES256;

{$MODE DELPHI}{$H+}


{$i std.inc}

interface


uses
  Hash,
  HMAC,
  KDF,
  sha512,
  AES_Type,
  AES_CTR,
  AES_EAX;

const
  C_FCA_Sig = 'SC';

var
  KeyIterations: longword = 20000;                {Iterations in KeyDeriv}

type
  TFCAAESSalt = array[0..15] of longint;          {512 Bit salt}

  TFCAAESHdr = record
    FCAsig: array[0..1] of char;                  {Crypt-X File Sig}
    Flags: word;                                  {1 = AES, 2 = Twofish, 4 = Serpend, 8 = Salsa20, 16 = Camellia, 128 = Compression}
    Salt: TFCAAESSalt;
    Iterations: longword;
    PW_Ver: word;
    Version: word;                                {Version needed to decrypt}
  end;

  TFCAAES_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACAES_Context = record
    aes_ctx: TAESContext;      {crypt context}
    hmac_ctx: THMAC_Context;   {auth  context}
  end;


function FCA_EAXAES_init(var cx: TAES_EAXContext; pPW: pointer; pLen: word; var hdr: TFCAAESHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_EAXAES_initS(var cx: TAES_EAXContext; sPW: string; var hdr: TFCAAESHdr; Iterations: longint = 20000): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_EAXAES_encrypt(var cx: TAES_EAXContext; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update EAX}

function FCA_EAXAES_decrypt(var cx: TAES_EAXContext; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update EAX}

procedure FCA_EAXAES_final(var cx: TAES_EAXContext; var auth: TFCAAES_AuthBlock);
{-return final EAX tag}


function FCA_HMACAES_init(var cx: TFCA_HMACAES_Context; pPW: pointer; pLen: word; var hdr: TFCAAESHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACAES_initS(var cx: TFCA_HMACAES_Context; sPW: string; var hdr: TFCAAESHdr): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_HMACAES_encrypt(var cx: TFCA_HMACAES_Context; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update HMAC}

function FCA_HMACAES_decrypt(var cx: TFCA_HMACAES_Context; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACAES_final(var cx: TFCA_HMACAES_Context; var auth: TFCAAES_AuthBlock);
{-return final HMAC-SHA512-128 digest}


implementation


type
  TXAESKey = packed record            {eXtended key for PBKDF}
    ak: packed array[0..31] of byte;  {AES  256 bit key      }
    hk: packed array[0..31] of byte;  {HMAC key / EAX nonce  }
    pv: word;                         {password verifier     }
  end;

//=================================================================================================
function FCA_HMACAES_init(var cx: TFCA_HMACAES_Context; pPW: pointer; pLen: word; var hdr: TFCAAESHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXAESKey;
  CTR: TAESBlock;
  pwph: PHashDesc;
  Err: integer;
begin
  {CTR=0, random/uniqness from hdr.salt}
  fillchar(CTR, sizeof(CTR), 0);

  {derive the AES, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_SHA512);
  Err := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCAAESSalt), KeyIterations, XKey, sizeof(XKey));

  {init AES CTR mode with ak}
  if Err = 0 then
    Err := AES_CTR_Init(XKey.ak, 8 * sizeof(XKey.ak), CTR, cx.aes_ctx);

  {exit if any error}
  FCA_HMACAES_init := Err;
  if Err <> 0 then
    exit;

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $01;
  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_HMACAES_initS(var cx: TFCA_HMACAES_Context; sPW: string; var hdr: TFCAAESHdr): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  FCA_HMACAES_initS := FCA_HMACAES_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_HMACAES_encrypt(var cx: TFCA_HMACAES_Context; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update HMAC}
begin
  FCA_HMACAES_encrypt := AES_CTR_Encrypt(@Data, @Data, dLen, cx.aes_ctx);
  hmac_update(cx.hmac_ctx, @Data, dLen);
end;

//=================================================================================================
function FCA_HMACAES_decrypt(var cx: TFCA_HMACAES_Context; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @Data, dLen);
  FCA_HMACAES_decrypt := AES_CTR_Encrypt(@Data, @Data, dLen, cx.aes_ctx);
end;

//=================================================================================================
procedure FCA_HMACAES_final(var cx: TFCA_HMACAES_Context; var auth: TFCAAES_AuthBlock);
{-return final HMAC-Whirlpool-128 digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx, mac);
  move(mac, auth, sizeof(auth));
end;

//=================================================================================================
function FCA_EAXAES_init(var cx: TAES_EAXContext; pPW: pointer; pLen: word; var hdr: TFCAAESHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXAESKey;
  Err: integer;
begin

  {derive the EAX key / nonce and pw verifier}
  Err := pbkdf2(FindHash_by_ID(_SHA512), pPW, pLen, @hdr.salt, sizeof(TFCAAESSalt), KeyIterations, XKey, sizeof(XKey));

  {init AES EAX mode with ak/hk}
  if Err = 0 then
    Err := AES_EAX_Init(XKey.ak, 8 * sizeof(XKey.ak), xkey.hk, sizeof(XKey.hk), cx);

  {exit if any error}
  FCA_EAXAES_init := Err;
  if Err <> 0 then
    exit;

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $01;
  hdr.Iterations := KeyIterations;
  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_EAXAES_initS(var cx: TAES_EAXContext; sPW: string; var hdr: TFCAAESHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_EAXAES_initS := FCA_EAXAES_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_EAXAES_encrypt(var cx: TAES_EAXContext; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update EAX}
begin
  FCA_EAXAES_encrypt := AES_EAX_Encrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
function FCA_EAXAES_decrypt(var cx: TAES_EAXContext; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update EAX}
begin
  FCA_EAXAES_decrypt := AES_EAX_decrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
procedure FCA_EAXAES_final(var cx: TAES_EAXContext; var auth: TFCAAES_AuthBlock);
{-return final EAX tag}
begin
  AES_EAX_Final(TAESBlock(auth), cx);
end;

end.
