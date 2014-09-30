unit Twofish256;

{$MODE DELPHI}{$H+}


{$i std.inc}

interface


uses
  Hash,
  HMAC,
  KDF,
  whirl512,
  TF_Base,
  TF_CTR,
  TF_EAX;

const
  C_FCA_Sig = 'SC';

var
  KeyIterations: longword = 20000;                {Iterations in KeyDeriv}

type
  TFCATFSalt = array[0..15] of longint;           {512 Bit salt}

  TFCATFHdr = record
    FCAsig: array[0..1] of char;                  {Crypt-X File Sig}
    Flags: word;                                  {1 = AES, 2 = Twofish, 4 = Serpend, 8 = Salsa20, 16 = Camellia, 128 = Compression}
    Salt: TFCATFSalt;
    Iterations: longword;
    PW_Ver: word;
    Version: word;                                {Version needed to decrypt}
  end;

  TFCATF_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACTF_Context = record
    tf_ctx: TTFContext;       {crypt context}
    hmac_ctx: THMAC_Context;  {auth  context}
  end;


function FCA_EAXTF_init(var cx: TTF_EAXContext; pPW: pointer; pLen: word; var hdr: TFCATFHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_EAXTF_initS(var cx: TTF_EAXContext; sPW: string; var hdr: TFCATFHdr; Iterations: longint = 20000): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_EAXTF_encrypt(var cx: TTF_EAXContext; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update EAX}

function FCA_EAXTF_decrypt(var cx: TTF_EAXContext; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update EAX}

procedure FCA_EAXTF_final(var cx: TTF_EAXContext; var auth: TFCATF_AuthBlock);
{-return final EAX tag}


function FCA_HMACTF_init(var cx: TFCA_HMACTF_Context; pPW: pointer; pLen: word; var hdr: TFCATFHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACTF_initS(var cx: TFCA_HMACTF_Context; sPW: string; var hdr: TFCATFHdr): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_HMACTF_encrypt(var cx: TFCA_HMACTF_Context; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update HMAC}

function FCA_HMACTF_decrypt(var cx: TFCA_HMACTF_Context; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACTF_final(var cx: TFCA_HMACTF_Context; var auth: TFCATF_AuthBlock);
{-return final HMAC-SHA512-128 digest}


implementation


type
  TXTFKey = packed record                       {eXtended key for PBKDF}
    ak: packed array[0..31] of byte;  {tf  256 bit key      }
    hk: packed array[0..31] of byte;  {HMAC key / EAX nonce  }
    pv: word;                         {password verifier     }
  end;

//=================================================================================================
function FCA_HMACTF_init(var cx: TFCA_HMACTF_Context; pPW: pointer; pLen: word; var hdr: TFCATFHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXTFKey;
  CTR: TTFBlock;
  pwph: PHashDesc;
  Err: integer;
begin
  {CTR=0, random/uniqness from hdr.salt}
  fillchar(CTR, sizeof(CTR), 0);

  {derive the tf, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_Whirlpool);
  Err := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCATFSalt), KeyIterations, XKey, sizeof(XKey));

  {init tf CTR mode with ak}
  if Err = 0 then
    Err := TF_CTR_Init(XKey.ak, 8 * sizeof(XKey.ak), CTR, cx.tf_ctx);

  {exit if any error}
  FCA_HMACTF_init := Err;
  if Err <> 0 then
    exit;

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $02;

  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_HMACTF_initS(var cx: TFCA_HMACTF_Context; sPW: string; var hdr: TFCATFHdr): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  FCA_HMACTF_initS := FCA_HMACTF_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_HMACTF_encrypt(var cx: TFCA_HMACTF_Context; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update HMAC}
begin
  FCA_HMACTF_encrypt := TF_CTR_Encrypt(@Data, @Data, dLen, cx.tf_ctx);
  hmac_update(cx.hmac_ctx, @Data, dLen);
end;

//=================================================================================================
function FCA_HMACTF_decrypt(var cx: TFCA_HMACTF_Context; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @Data, dLen);
  FCA_HMACTF_decrypt := TF_CTR_Encrypt(@Data, @Data, dLen, cx.tf_ctx);
end;

//=================================================================================================
procedure FCA_HMACTF_final(var cx: TFCA_HMACTF_Context; var auth: TFCATF_AuthBlock);
{-return final HMAC-Whirlpool-128 digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx, mac);
  move(mac, auth, sizeof(auth));
end;

//=================================================================================================
function FCA_EAXTF_init(var cx: TTF_EAXContext; pPW: pointer; pLen: word; var hdr: TFCATFHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXTFKey;
  Err: integer;
begin

  {derive the EAX key / nonce and pw verifier}
  Err := pbkdf2(FindHash_by_ID(_Whirlpool), pPW, pLen, @hdr.salt, sizeof(TFCATFSalt), KeyIterations, XKey, sizeof(XKey));

  {init tf EAX mode with ak/hk}
  if Err = 0 then
    Err := TF_EAX_Init(XKey.ak, 8 * sizeof(XKey.ak), xkey.hk, sizeof(XKey.hk), cx);

  {exit if any error}
  FCA_EAXTF_init := Err;
  if Err <> 0 then
    exit;

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $02;
  hdr.Iterations := KeyIterations;

  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_EAXTF_initS(var cx: TTF_EAXContext; sPW: string; var hdr: TFCATFHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_EAXTF_initS := FCA_EAXTF_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_EAXTF_encrypt(var cx: TTF_EAXContext; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update EAX}
begin
  FCA_EAXTF_encrypt := TF_EAX_Encrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
function FCA_EAXTF_decrypt(var cx: TTF_EAXContext; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update EAX}
begin
  FCA_EAXTF_decrypt := TF_EAX_decrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
procedure FCA_EAXTF_final(var cx: TTF_EAXContext; var auth: TFCATF_AuthBlock);
{-return final EAX tag}
begin
  TF_EAX_Final(TTFBlock(auth), cx);
end;

end.
