unit uDecrypt;

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
  Buttons,
  ExtCtrls;

type

  { TfrmDecrypt }

  TfrmDecrypt = class(TForm)
    Bevel1: TBevel;
    btnCancel: TButton;
    btnOK: TButton;
    chkShowPwd: TCheckBox;
    dlgOpen: TOpenDialog;
    edtPasswd: TEdit;
    edtKeyfile: TEdit;
    lblPasswd: TLabel;
    lblKeyfile: TLabel;
    btnKeyfile: TSpeedButton;
    lblFileName: TLabel;
    procedure chkShowPwdChange(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnKeyfileClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmDecrypt: TfrmDecrypt;

implementation

uses
  uMain;

{$R *.lfm}

{ TfrmDecrypt }

//=================================================================================================
procedure TfrmDecrypt.chkShowPwdChange(Sender: TObject);
begin
  if chkShowPwd.Checked then
  begin
    edtPasswd.PasswordChar := #0;
    edtPasswd.Font.Style := [];
  end
  else
  begin
    edtPasswd.PasswordChar := #8226;
    edtPasswd.Font.Style := [fsBold];
  end;
end;

//=================================================================================================
procedure TfrmDecrypt.FormCreate(Sender: TObject);
begin
  edtPasswd.PasswordChar := #8226;
end;

procedure TfrmDecrypt.btnKeyfileClick(Sender: TObject);
begin
  dlgOpen.Title := TitleOpen;
  dlgOpen.Filter := Filter1;
  if dlgOpen.Execute then
    edtKeyfile.Text := dlgOpen.Filename;
end;

//=================================================================================================
procedure TfrmDecrypt.FormShow(Sender: TObject);
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
