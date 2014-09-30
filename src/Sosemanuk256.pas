unit Sosemanuk256;

{$MODE Delphi}

{$i std.inc}

interface


uses
  Hash, HMAC, Whirl512, KDF, Sosemanu;




const
  C_FCA_Sig = 'CX';

var  
  KeyIterations : LongWord = 20000;             	{Iterations in KeyDeriv}

type
  TFCASoseSalt  = array[0..15] of longint;      	{512 Bit salt}
  TFCASoseIv = array[0..3] of longint;			{128 Bit iv}
  TFCASoseHdr   = packed record
                   FCAsig: array[0..1] of Char;  	{Crypt-X File Sig}
                   Flags : Byte;              		{1 = AES, 2 = Twofish, 4 = Serpend, 8 = Salsa20, 16 = Camellia, 32 = Camellia, 128 = Compression}
                   Salt  : TFCASoseSalt;
		     Iterations: longword;
                   PW_Ver: Word;
                   Version: Word;                       {Version needed to decrypt}
                   Iv: TFCASoseIv;                      
                 end;

  TFCASose_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACSose_Context  = record
                            Sose_ctx  : Sosemanu.Sose_ctx;    {crypt context}
                            hmac_ctx : THMAC_Context;          {auth  context}
                          end;

function FCA_HMACSose_init(var cx: TFCA_HMACSose_Context; pPW: pointer; pLen: word; var hdr: TFCASoseHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACSose_initS(var cx: TFCA_HMACSose_Context; sPW: string; var hdr: TFCASoseHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}

procedure FCA_HMACSose_encrypt(var cx: TFCA_HMACSose_Context; var data; dLen: word);
  {-encyrypt a block of data in place and update HMAC}

procedure FCA_HMACSose_decrypt(var cx: TFCA_HMACSose_Context; var data; dLen: word);
  {-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACSose_final(var cx: TFCA_HMACSose_Context; var auth: TFCASose_AuthBlock);
  {-return final HMAC-Whirlpool digest}


implementation



type
  TXSoseKey = packed record                     {eXtended key for PBKDF}
               ak: packed array[0..31] of byte;  {Sose  256 bit key      }
               hk: packed array[0..31] of byte;  {HMAC key  }
               pv: word;                         {password verifier     }
             end;


//=================================================================================================
function FCA_HMACSose_init(var cx: TFCA_HMACSose_Context; pPW: pointer; pLen: word; var hdr: TFCASoseHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXSoseKey;
  pwph: PHashDesc;
  Err : integer;
begin

  {derive the Soseemanuk, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_Whirlpool);
  Err  := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCASoseSalt), KeyIterations, XKey, sizeof(XKey));
  if Err<>0 then exit;
  
  Sose_keysetup(cx.Sose_ctx, @XKey.ak, 256);
  Sose_ivsetup(cx.Sose_ctx, @hdr.IV);
  
  {exit if any error}
  FCA_HMACSose_init := Err;
  if Err<>0 then exit; 

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags  := hdr.Flags or $10;
  hdr.Iterations := KeyIterations;
  {burn XKey}
  fillchar(XKey, sizeof(XKey),0);
end;

//=================================================================================================
function FCA_HMACSose_initS(var cx: TFCA_HMACSose_Context; sPW: string; var hdr: TFCASoseHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_HMACSose_initS := FCA_HMACSose_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
procedure FCA_HMACSose_encrypt(var cx: TFCA_HMACSose_Context; var data; dLen: word);
  {-encyrypt a block of data in place and update HMAC}
begin
  Sose_encrypt_bytes(cx.Sose_ctx, @data, @data, dLen);
  hmac_update(cx.hmac_ctx, @data, dLen);
end;

//=================================================================================================
procedure FCA_HMACSose_decrypt(var cx: TFCA_HMACSose_Context; var data; dLen: word);
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @data, dLen);
  Sose_encrypt_bytes(cx.Sose_ctx, @data, @data, dLen);
end;

//=================================================================================================
procedure FCA_HMACSose_final(var cx: TFCA_HMACSose_Context; var auth: TFCASose_AuthBlock);
  {-return final HMAC-Whirlpool digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx,mac);
  move(mac, auth, sizeof(auth));
end;

end.
