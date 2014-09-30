unit Serpend256;

{$MODE DELPHI}{$H+}


{$i std.inc}

interface


uses
  Hash,
  HMAC,
  KDF,
  whirl512,
  SP_BASE,
  SP_CTR,
  SP_EAX;

const
  C_FCA_Sig = 'SC';

var
  KeyIterations: longword = 20000;                {Iterations in KeyDeriv}

type
  TFCASPSalt = array[0..15] of longint;           {512 Bit salt}

  TFCASPHdr = record
    FCAsig: array[0..1] of char;                  {Crypt-X File Sig}
    Flags: word;                                  {1 = AES, 2 = Twofish, 4 = Serpend, 8 = Salsa20, 16 = Camellia, 128 = Compression}
    Salt: TFCASPSalt;
    Iterations: longword;
    PW_Ver: word;
    Version: word;                                {Version needed to decrypt}
  end;

  TFCASP_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACSP_Context = record
    SP_ctx: TSPContext;       {crypt context}
    hmac_ctx: THMAC_Context;  {auth  context}
  end;


function FCA_EAXSP_init(var cx: TSP_EAXContext; pPW: pointer; pLen: word; var hdr: TFCASPHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_EAXSP_initS(var cx: TSP_EAXContext; sPW: string; var hdr: TFCASPHdr; Iterations: longint = 20000): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_EAXSP_encrypt(var cx: TSP_EAXContext; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update EAX}

function FCA_EAXSP_decrypt(var cx: TSP_EAXContext; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update EAX}

procedure FCA_EAXSP_final(var cx: TSP_EAXContext; var auth: TFCASP_AuthBlock);
{-return final EAX tag}


function FCA_HMACSP_init(var cx: TFCA_HMACSP_Context; pPW: pointer; pLen: word; var hdr: TFCASPHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACSP_initS(var cx: TFCA_HMACSP_Context; sPW: string; var hdr: TFCASPHdr): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_HMACSP_encrypt(var cx: TFCA_HMACSP_Context; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update HMAC}

function FCA_HMACSP_decrypt(var cx: TFCA_HMACSP_Context; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACSP_final(var cx: TFCA_HMACSP_Context; var auth: TFCASP_AuthBlock);
{-return final HMAC-SHA512-128 digest}


implementation


type
  TXSPKey = packed record            {eXtended key for PBKDF}
    ak: packed array[0..31] of byte;  {SP  256 bit key      }
    hk: packed array[0..31] of byte;  {HMAC key / EAX nonce  }
    pv: word;                         {password verifier     }
  end;

//=================================================================================================
function FCA_HMACSP_init(var cx: TFCA_HMACSP_Context; pPW: pointer; pLen: word; var hdr: TFCASPHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXSPKey;
  CTR: TSPBlock;
  pwph: PHashDesc;
  Err: integer;
begin
  {CTR=0, random/uniqness from hdr.salt}
  fillchar(CTR, sizeof(CTR), 0);

  {derive the SP, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_Whirlpool);
  Err := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCASPSalt), KeyIterations, XKey, sizeof(XKey));

  {init SP CTR mode with ak}
  if Err = 0 then
    Err := SP_CTR_Init(XKey.ak, 8 * sizeof(XKey.ak), CTR, cx.SP_ctx);

  {exit if any error}
  FCA_HMACSP_init := Err;
  if Err <> 0 then
    exit;

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $04;
  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_HMACSP_initS(var cx: TFCA_HMACSP_Context; sPW: string; var hdr: TFCASPHdr): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  FCA_HMACSP_initS := FCA_HMACSP_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_HMACSP_encrypt(var cx: TFCA_HMACSP_Context; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update HMAC}
begin
  FCA_HMACSP_encrypt := SP_CTR_Encrypt(@Data, @Data, dLen, cx.SP_ctx);
  hmac_update(cx.hmac_ctx, @Data, dLen);
end;

//=================================================================================================
function FCA_HMACSP_decrypt(var cx: TFCA_HMACSP_Context; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @Data, dLen);
  FCA_HMACSP_decrypt := SP_CTR_Encrypt(@Data, @Data, dLen, cx.SP_ctx);
end;

//=================================================================================================
procedure FCA_HMACSP_final(var cx: TFCA_HMACSP_Context; var auth: TFCASP_AuthBlock);
{-return final HMAC-Whirlpool-128 digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx, mac);
  move(mac, auth, sizeof(auth));
end;

//=================================================================================================
function FCA_EAXSP_init(var cx: TSP_EAXContext; pPW: pointer; pLen: word; var hdr: TFCASPHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXSPKey;
  Err: integer;
begin

  {derive the EAX key / nonce and pw verifier}
  Err := pbkdf2(FindHash_by_ID(_Whirlpool), pPW, pLen, @hdr.salt, sizeof(TFCASPSalt), KeyIterations, XKey, sizeof(XKey));

  {init SP EAX mode with ak/hk}
  if Err = 0 then
    Err := SP_EAX_Init(XKey.ak, 8 * sizeof(XKey.ak), xkey.hk, sizeof(XKey.hk), cx);


  {exit if any error}
  FCA_EAXSP_init := Err;
  if Err <> 0 then
    exit;

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $04;
  hdr.Iterations := KeyIterations;
  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_EAXSP_initS(var cx: TSP_EAXContext; sPW: string; var hdr: TFCASPHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_EAXSP_initS := FCA_EAXSP_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_EAXSP_encrypt(var cx: TSP_EAXContext; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update EAX}
begin
  FCA_EAXSP_encrypt := SP_EAX_Encrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
function FCA_EAXSP_decrypt(var cx: TSP_EAXContext; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update EAX}
begin
  FCA_EAXSP_decrypt := SP_EAX_decrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
procedure FCA_EAXSP_final(var cx: TSP_EAXContext; var auth: TFCASP_AuthBlock);
{-return final EAX tag}
begin
  SP_EAX_Final(TSPBlock(auth), cx);
end;



end.
