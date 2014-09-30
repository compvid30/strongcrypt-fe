unit uEncrypt;

{$MODE DELPHI}{$H+}

interface

uses
  LCLIntf,
  LCLType,
  SysUtils,
  Variants,
  Classes,
  Graphics,
  Controls,
  Forms,
  Dialogs,
  Buttons,
  StdCtrls,
  ExtCtrls,
  ComCtrls,
  CryptxUtils,
  FileUtil,
  IniFiles;

type

  { TfrmEncrypt }

  TfrmEncrypt = class(TForm)
    Bevel2: TBevel;
    Bevel3: TBevel;
    btnGenerate: TButton;
    cboAlgo: TComboBox;
    chkKeyfile: TCheckBox;
    chkShowPwd: TCheckBox;
    edtPasswd: TEdit;
    edtConfirm: TEdit;
    edtKeyfile: TEdit;
    btnOK: TButton;
    btnCancel: TButton;
    lblAlgo: TLabel;
    lblBits: TLabel;
    lblQuality: TLabel;
    lblKeyfile: TLabel;
    lblPasswd: TLabel;
    lblConfirm: TLabel;
    btnKeyfile: TSpeedButton;
    dlgOpen: TOpenDialog;
    prbBits: TProgressBar;
    procedure btnGenerateClick(Sender: TObject);
    procedure btnKeyfileClick(Sender: TObject);
    procedure btnOKClick(Sender: TObject);
    procedure chkKeyfileChange(Sender: TObject);
    procedure chkShowPwdChange(Sender: TObject);
    procedure edtPasswdChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { Private-Deklarationen }
  public
    { Public-Deklarationen }
  end;

var
  frmEncrypt: TfrmEncrypt;

implementation

uses
  uRnd,
  uMain;

{$R *.lfm}

{ TfrmEncrypt }

//=================================================================================================
procedure TfrmEncrypt.FormCreate(Sender: TObject);
begin
  edtPasswd.PasswordChar := #8226;
  edtConfirm.PasswordChar := #8226;

  {$IFDEF CAMELLIA}
  cboAlgo.Items.Add('Camellia - 256 Bits');
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmEncrypt.FormShow(Sender: TObject);

  function AddSlash(s: string): string;
  begin
    Result := IncludeTrailingPathDelimiter(s);
  end;

var
  X, Y: integer;
  MainForm: TCustomForm;
  ConfigIni: TInifile;
  Path: string;
begin
  {$IFDEF WINDOWS}
  // We need this because Lazarus poMainFormCenter sux
  MainForm := Application.MainForm;
  X := ((MainForm.Width - Width) div 22) + MainForm.Left;
  Y := ((MainForm.Height - Height) div 2) + MainForm.Top;
  if X < Screen.DesktopLeft then
    X := Screen.DesktopLeft;
  if Y < Screen.DesktopTop then
    Y := Screen.DesktopTop + 2;
  SetBounds(X, Y, Width, Height);
  {$ENDIF}


  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'config.ini';
  ConfigIni := TIniFile.Create(Path);
  try
    cboAlgo.ItemIndex := ConfigIni.ReadInteger('Config', 'Algorithm', 2);
  finally
    ConfigIni.Free;
  end;
end;

//=================================================================================================
procedure TfrmEncrypt.btnOKClick(Sender: TObject);
begin
  if edtPasswd.Text <> edtConfirm.Text then
  begin
    MessageDlg('StrongCrypt-FE', 'Password does not match. please enter again.', mtError, [mbOK], 0);
    exit;
  end;

  if chkKeyfile.Checked then
  begin
    if not FileExistsUTF8(edtKeyfile.Text) then
    begin
      MessageDlg('StrongCrypt-FE', 'Key file does not exist.', mtError, [mbOK], 0);
      exit;
    end;
  end
  else
  if edtPasswd.Text = '' then
  begin
    MessageDlg('StrongCrypt-FE', 'Encrypting without a password and a key file makes no sense.', mtError, [mbOK], 0);
    exit;
  end;

  ModalResult := mrOk;

end;

//=================================================================================================
procedure TfrmEncrypt.chkKeyfileChange(Sender: TObject);
begin
  lblKeyfile.Enabled := chkKeyfile.Checked;
  edtKeyfile.Enabled := chkKeyfile.Checked;
  btnKeyfile.Enabled := chkKeyfile.Checked;
end;

procedure TfrmEncrypt.chkShowPwdChange(Sender: TObject);
begin
  if chkShowPwd.Checked then
  begin
    edtPasswd.PasswordChar := #0;
    edtPasswd.Font.Style := [];
    edtConfirm.PasswordChar := #0;
    edtConfirm.Font.Style := [];
  end
  else
  begin
    edtPasswd.PasswordChar := #8226;
    edtPasswd.Font.Style := [fsBold];
    edtConfirm.PasswordChar := #8226;
    edtConfirm.Font.Style := [fsBold];
  end;
end;

//=================================================================================================
procedure TfrmEncrypt.edtPasswdChange(Sender: TObject);
var
  bits: cardinal;
  s: string;
begin
  s := UTF8Encode(edtPasswd.Text);
  EstimatePasswordBits(s, bits);
  lblBits.Caption := IntToStr(bits) + ' ' + uMain.Bits;
  prbBits.Position := round((100 * bits) / 128);
end;

//=================================================================================================
procedure TfrmEncrypt.btnGenerateClick(Sender: TObject);
begin
  frmRnd.ShowModal;
end;

//=================================================================================================
procedure TfrmEncrypt.btnKeyfileClick(Sender: TObject);
begin
  dlgOpen.Title := TitleOpen;
  dlgOpen.Filter := Filter1;
  if dlgOpen.Execute then
    edtKeyfile.Text := dlgOpen.Filename;
end;


end.
