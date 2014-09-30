unit uRnd;

{$MODE DELPHI}{$H+}

interface

uses
  Classes,
  SysUtils,
  FileUtil,
  Forms,
  Controls,
  Graphics,
  Dialogs,
  StdCtrls,
  Spin,
  ExtCtrls,
  Buttons,
  ComCtrls,
  hash,
  whirl512,
  TSC,
  Dates,
  CryptxUtils,
  Isaac;

type

  { TfrmRnd }

  TfrmRnd = class(TForm)
    Bevel1: TBevel;
    Bevel2: TBevel;
    btnGenerate: TButton;
    btnCancel: TButton;
    btnOK: TButton;
    btnClipboard: TButton;
    chkUpper: TCheckBox;
    chkLower: TCheckBox;
    chkDigits: TCheckBox;
    chkSpecial: TCheckBox;
    chkBrackets: TCheckBox;
    chkSpace: TCheckBox;
    edtPasswd: TEdit;
    gbOptions: TGroupBox;
    lblQuality: TLabel;
    lblLength: TLabel;
    lblBits: TLabel;
    prbBits: TProgressBar;
    speLength: TSpinEdit;
    procedure btnClipboardClick(Sender: TObject);
    procedure btnGenerateClick(Sender: TObject);
    procedure btnOKClick(Sender: TObject);
    procedure edtPasswdChange(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmRnd: TfrmRnd;

implementation

uses
  uEncrypt,
  uMain;

{$R *.lfm}

{ TfrmRnd }

//=================================================================================================
function GetRandom(range: longword): longword;
var
  Ctr: TCtrRec;
  JD, msC, isaac: longint;
  sctx: THashContext;
  sdig: TWhirlDigest;
  rng: longword;
  ctx: isaac_ctx;
begin
  // Hash Date, Time, Randseed, TSC and Isaac PRNG
  _ReadCounter(Ctr);
  JD := CurrentJulianDay;
  msC := msCount;
  isaac_init (ctx, msC xor JD);
  isaac := isaac_long(ctx);
  Randomize;
  Whirl_Init(sctx);
  Whirl_Update(sctx, @Ctr, sizeof(Ctr));
  Whirl_Update(sctx, @JD, sizeof(JD));
  Whirl_Update(sctx, @msC, sizeof(msC));
  Whirl_Update(sctx, @isaac, sizeof(isaac));
  Whirl_Update(sctx, @randseed, sizeof(randseed));
  Whirl_Final(sctx, sdig);
  move(sdig, rng, sizeof(rng));
  Result := rng mod range;
end;

//=================================================================================================
function RandomPassword(PLen: integer; Upper: boolean = False; Lower: boolean = False; Digit: boolean = False;
  Bracket: boolean = False; Special: boolean = False; Space: boolean = False): string;
const
  UpperCase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  LowerCase = 'zyxwvutsrqponmlkjihgfedcba';
  Digits = '0123456789';
  Brackets = '[]{}()<>';
  Specials = '!\"#$%&*+,-./:;=?^_|~''';
  Spaces = ' ';
var
  Str: string;
  c, d: char;
begin
  Result := '';
  Str := '';
  d := ' ';
  if Upper then
    Str := Str + UpperCase;
  if Lower then
    Str := Str + LowerCase;
  if Digit then
    Str := Str + Digits;
  if Bracket then
    Str := Str + Brackets;
  if Special then
    Str := Str + Specials;
  if Space then
    Str := Str + Spaces;
  Result := '';
  repeat
    c := Str[(GetRandom(Length(Str)) + 1)];
    if Length(Result) > 0 then
      d := Result[Length(Result)];
    if c <> d then
      Result := Result + c
    else
      Result := Result;
  until (Length(Result) = PLen);
end;

//=================================================================================================
procedure TfrmRnd.btnGenerateClick(Sender: TObject);
begin
  edtPasswd.Text := RandomPassword(speLength.Value, chkUpper.Checked, chkLower.Checked, chkDigits.Checked,
    chkBrackets.Checked, chkSpecial.Checked, chkSpace.Checked);

 {$IFDEF DARWIN}
  edtPasswd.OnChange(Self);  // Mac OS X does not fire the OnChange event, so we need to do that
 {$ENDIF}
end;

//=================================================================================================
procedure TfrmRnd.btnClipboardClick(Sender: TObject);
begin
  edtPasswd.SelectAll;
  edtPasswd.CopyToClipboard;
end;

//=================================================================================================
procedure TfrmRnd.btnOKClick(Sender: TObject);
begin
  if frmEncrypt.Visible then
  begin
    frmEncrypt.edtPasswd.Text := edtPasswd.Text;
    frmEncrypt.edtConfirm.Text := edtPasswd.Text;
  end;
end;

//=================================================================================================
procedure TfrmRnd.edtPasswdChange(Sender: TObject);
var
  bits: longword;
  s: string;
begin
  btnOK.Enabled := edtPasswd.Text <> '';
  btnClipboard.Enabled := edtPasswd.Text <> '';
  s := edtPasswd.Text;
  EstimatePasswordBits(s, bits);
  lblBits.Caption := IntToStr(bits) + ' ' + uMain.Bits;
  prbBits.Position := round((100 * bits) / 128);
end;

//=================================================================================================
procedure TfrmRnd.FormShow(Sender: TObject);
var
  X, Y: integer;
  MainForm: TCustomForm;
begin
  {$IFDEF WINDOWS}
  // We need this because Lazarus poMainFormCenter sux
  MainForm := Application.MainForm;
  X := ((MainForm.Width - Width) div 2) + MainForm.Left;
  Y := ((MainForm.Height - Height) div 2) + MainForm.Top;
  if X < Screen.DesktopLeft then
    X := Screen.DesktopLeft;
  if Y < Screen.DesktopTop then
    Y := Screen.DesktopTop + 2;
  SetBounds(X, Y, Width, Height);
  {$ENDIF}
end;

end.
