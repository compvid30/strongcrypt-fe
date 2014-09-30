unit Camellia256;

{$MODE DELPHI}{$H+}


{$i std.inc}

interface


uses
  Hash,
  HMAC,
  KDF,
  whirl512,
  CAM_Base,
  CAM_CTR,
  CAM_EAX;

const
  C_FCA_Sig = 'SC';

var
  KeyIterations: longword = 20000;                {Iterations in KeyDeriv}

type
  TFCACAMSalt = array[0..15] of longint;      {512 Bit salt}

  TFCACAMHdr = record
    FCAsig: array[0..1] of char;  {Crypt-X File Sig}
    Flags: word;              {1 = AES, 2 = Twofish, 4 = Serpend, 128 = Compression Flag}
    Salt: TFCACAMSalt;
    Iterations: longword;
    PW_Ver: word;
    Version: word;             {Version needed to decrypt}
  end;

  TFCACAM_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACCAM_Context = record
    cam_ctx: TCAMContext;    {crypt context}
    hmac_ctx: THMAC_Context;  {auth  context}
  end;


function FCA_EAXCAM_init(var cx: TCAM_EAXContext; pPW: pointer; pLen: word; var hdr: TFCACAMHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_EAXCAM_initS(var cx: TCAM_EAXContext; sPW: string; var hdr: TFCACAMHdr; Iterations: longint = 20000): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_EAXCAM_encrypt(var cx: TCAM_EAXContext; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update EAX}

function FCA_EAXCAM_decrypt(var cx: TCAM_EAXContext; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update EAX}

procedure FCA_EAXCAM_final(var cx: TCAM_EAXContext; var auth: TFCACAM_AuthBlock);
{-return final EAX tag}


function FCA_HMACCAM_init(var cx: TFCA_HMACCAM_Context; pPW: pointer; pLen: word; var hdr: TFCACAMHdr): integer;
{-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACCAM_initS(var cx: TFCA_HMACCAM_Context; sPW: string; var hdr: TFCACAMHdr): integer;
{-Initialize crypt context using password string sPW and hdr.salt}

function FCA_HMACCAM_encrypt(var cx: TFCA_HMACCAM_Context; var Data; dLen: word): integer;
{-encyrypt a block of data in place and update HMAC}

function FCA_HMACCAM_decrypt(var cx: TFCA_HMACCAM_Context; var Data; dLen: word): integer;
{-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACCAM_final(var cx: TFCA_HMACCAM_Context; var auth: TFCACAM_AuthBlock);
{-return final HMAC-SHA512-128 digest}


implementation


type
  TXCAMKey = packed record                       {eXtended key for PBKDF}
    ak: packed array[0..31] of byte;  {CAM  256 bit key      }
    hk: packed array[0..31] of byte;  {HMAC key / EAX nonce  }
    pv: word;                         {password verifier     }
  end;

//=================================================================================================
function FCA_HMACCAM_init(var cx: TFCA_HMACCAM_Context; pPW: pointer; pLen: word; var hdr: TFCACAMHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXCAMKey;
  CTR: TCAMBlock;
  pwph: PHashDesc;
  Err: integer;
begin
  {CTR=0, random/uniqness from hdr.salt}
  fillchar(CTR, sizeof(CTR), 0);

  {derive the cam, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_Whirlpool);
  Err := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCACAMSalt), KeyIterations, XKey, sizeof(XKey));

  {init cam CTR mode with ak}
  if Err = 0 then
    Err := CAM_CTR_Init(XKey.ak, 8 * sizeof(XKey.ak), CTR, cx.cam_ctx);

  {exit if any error}
  FCA_HMACCAM_init := Err;
  if Err <> 0 then
    exit;

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $20;

  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_HMACCAM_initS(var cx: TFCA_HMACCAM_Context; sPW: string; var hdr: TFCACAMHdr): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  FCA_HMACCAM_initS := FCA_HMACCAM_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_HMACCAM_encrypt(var cx: TFCA_HMACCAM_Context; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update HMAC}
begin
  FCA_HMACCAM_encrypt := CAM_CTR_Encrypt(@Data, @Data, dLen, cx.cam_ctx);
  hmac_update(cx.hmac_ctx, @Data, dLen);
end;

//=================================================================================================
function FCA_HMACCAM_decrypt(var cx: TFCA_HMACCAM_Context; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @Data, dLen);
  FCA_HMACCAM_decrypt := CAM_CTR_Encrypt(@Data, @Data, dLen, cx.cam_ctx);
end;

//=================================================================================================
procedure FCA_HMACCAM_final(var cx: TFCA_HMACCAM_Context; var auth: TFCACAM_AuthBlock);
{-return final HMAC-Whirlpool-128 digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx, mac);
  move(mac, auth, sizeof(auth));
end;

//=================================================================================================
function FCA_EAXCAM_init(var cx: TCAM_EAXContext; pPW: pointer; pLen: word; var hdr: TFCACAMHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXCAMKey;
  Err: integer;
begin

  {derive the EAX key / nonce and pw verifier}
  Err := pbkdf2(FindHash_by_ID(_Whirlpool), pPW, pLen, @hdr.salt, sizeof(TFCACAMSalt), KeyIterations, XKey, sizeof(XKey));

  {init cam EAX mode with ak/hk}
  if Err = 0 then
    Err := CAM_EAX_Init(XKey.ak, 8 * sizeof(XKey.ak), xkey.hk, sizeof(XKey.hk), cx);

  {exit if any error}
  FCA_EAXCAM_init := Err;
  if Err <> 0 then
    exit;

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags := hdr.Flags or $10;
  hdr.Iterations := KeyIterations;

  {burn XKey}
  fillchar(XKey, sizeof(XKey), 0);
end;

//=================================================================================================
function FCA_EAXCAM_initS(var cx: TCAM_EAXContext; sPW: string; var hdr: TFCACAMHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_EAXCAM_initS := FCA_EAXCAM_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
function FCA_EAXCAM_encrypt(var cx: TCAM_EAXContext; var Data; dLen: word): integer;
  {-encyrypt a block of data in place and update EAX}
begin
  FCA_EAXCAM_encrypt := CAM_EAX_Encrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
function FCA_EAXCAM_decrypt(var cx: TCAM_EAXContext; var Data; dLen: word): integer;
  {-decyrypt a block of data in place and update EAX}
begin
  FCA_EAXCAM_decrypt := CAM_EAX_decrypt(@Data, @Data, dLen, cx);
end;

//=================================================================================================
procedure FCA_EAXCAM_final(var cx: TCAM_EAXContext; var auth: TFCACAM_AuthBlock);
{-return final EAX tag}
begin
  CAM_EAX_Final(TCAMBlock(auth), cx);
end;

end.                               
