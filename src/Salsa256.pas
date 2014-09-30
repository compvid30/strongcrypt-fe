unit Salsa256;

{$MODE Delphi}

{$i std.inc}

interface


uses
  Hash, HMAC, Whirl512, KDF, Salsa20;




const
  C_FCA_Sig = 'CX';

var  
  KeyIterations : LongWord = 20000;             	{Iterations in KeyDeriv}

type
  TFCASalsaSalt  = array[0..15] of longint;      	{512 Bit salt}
  TFCASalsaIv = array[0..1] of longint;			{64 Bit iv}
  TFCASalsaHdr   = packed record
                   FCAsig: array[0..1] of Char;  	{Crypt-X File Sig}
                   Flags : Byte;              		{1 = AES, 2 = Twofish, 4 = Serpend, 8 = Salsa20, 16 = Camellia, 128 = Compression}
                   Salt  : TFCASalsaSalt;
		   Iterations: longword;
                   PW_Ver: Word;
                   Version: Word;{Version needed to decrypt}
                   Iv: TFCASalsaIv;                      
                 end;

  TFCASalsa_AuthBlock = array[0..15] of byte;


type
  TFCA_HMACSalsa_Context  = record
                            salsa_ctx  : salsa20.salsa_ctx;    {crypt context}
                            hmac_ctx : THMAC_Context;          {auth  context}
                          end;

function FCA_HMACSalsa_init(var cx: TFCA_HMACSalsa_Context; pPW: pointer; pLen: word; var hdr: TFCASalsaHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}

function FCA_HMACSalsa_initS(var cx: TFCA_HMACSalsa_Context; sPW: string; var hdr: TFCASalsaHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}

procedure FCA_HMACSalsa_encrypt(var cx: TFCA_HMACSalsa_Context; var data; dLen: word);
  {-encyrypt a block of data in place and update HMAC}

procedure FCA_HMACSalsa_decrypt(var cx: TFCA_HMACSalsa_Context; var data; dLen: word);
  {-decyrypt a block of data in place and update HMAC}

procedure FCA_HMACSalsa_final(var cx: TFCA_HMACSalsa_Context; var auth: TFCASalsa_AuthBlock);
  {-return final HMAC-Whirlpool digest}


implementation



type
  TXSalsaKey = packed record                     {eXtended key for PBKDF}
               ak: packed array[0..31] of byte;  {Salsa  256 bit key      }
               hk: packed array[0..31] of byte;  {HMAC key  }
               pv: word;                         {password verifier     }
             end;


//=================================================================================================
function FCA_HMACSalsa_init(var cx: TFCA_HMACSalsa_Context; pPW: pointer; pLen: word; var hdr: TFCASalsaHdr): integer;
  {-Initialize crypt context using password pointer pPW and hdr.salt}
var
  XKey: TXSalsaKey;
  pwph: PHashDesc;
  Err : integer;
begin

  {derive the Salsa20, HMAC keys and pw verifier}
  pwph := FindHash_by_ID(_Whirlpool);
  Err  := pbkdf2(pwph, pPW, pLen, @hdr.salt, sizeof(TFCASalsaSalt), KeyIterations, XKey, sizeof(XKey));
  if Err<>0 then exit;
  
  salsa_xkeysetup(cx.salsa_ctx, @XKey.ak, 256, 20);
  salsa_ivsetup(cx.salsa_ctx, @hdr.IV);
  
  {exit if any error}
  FCA_HMACSalsa_init := Err;
  if Err<>0 then exit; 

  {initialise HMAC with hk, here pwph is valid}
  hmac_init(cx.hmac_ctx, pwph, @XKey.hk, sizeof(XKey.hk));

  {return pw verifier}
  hdr.PW_Ver := XKey.pv;
  hdr.FCASig := C_FCA_Sig;
  hdr.Flags  := hdr.Flags or $08;
  hdr.Iterations := KeyIterations;
  {burn XKey}
  fillchar(XKey, sizeof(XKey),0);
end;

//=================================================================================================
function FCA_HMACSalsa_initS(var cx: TFCA_HMACSalsa_Context; sPW: string; var hdr: TFCASalsaHdr; Iterations: longint = 20000): integer;
  {-Initialize crypt context using password string sPW and hdr.salt}
begin
  KeyIterations := Iterations;
  FCA_HMACSalsa_initS := FCA_HMACSalsa_init(cx, @sPW[1], length(sPW), hdr);
end;

//=================================================================================================
procedure FCA_HMACSalsa_encrypt(var cx: TFCA_HMACSalsa_Context; var data; dLen: word);
  {-encyrypt a block of data in place and update HMAC}
begin
  salsa_encrypt_bytes(cx.salsa_ctx, @data, @data, dLen);
  hmac_update(cx.hmac_ctx, @data, dLen);
end;

//=================================================================================================
procedure FCA_HMACSalsa_decrypt(var cx: TFCA_HMACSalsa_Context; var data; dLen: word);
  {-decyrypt a block of data in place and update HMAC}
begin
  hmac_update(cx.hmac_ctx, @data, dLen);
  salsa_encrypt_bytes(cx.salsa_ctx, @data, @data, dLen);
end;

//=================================================================================================
procedure FCA_HMACSalsa_final(var cx: TFCA_HMACSalsa_Context; var auth: TFCASalsa_AuthBlock);
  {-return final HMAC-Whirlpool digest}
var
  mac: THashDigest;
begin
  hmac_final(cx.hmac_ctx,mac);
  move(mac, auth, sizeof(auth));
end;

end.
