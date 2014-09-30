unit uConfig;

{$MODE DELPHI}{$H+}

{.$DEFINE CAMELLIA}

interface

uses
  Classes,
  SysUtils,
  FileUtil,
  Forms,
  Controls,
  Graphics,
  Dialogs,
  ComCtrls,
  StdCtrls,
  Spin,
  IniFiles;

type

  { TfrmConfig }

  TfrmConfig = class(TForm)
    btnOK: TButton;
    btnCancel: TButton;
    cboAlgo: TComboBox;
    chkCompression: TCheckBox;
    cboLevel: TComboBox;
    cbolanguage: TComboBox;
    cboWipe: TComboBox;
    gbAlgo: TGroupBox;
    gbKdf: TGroupBox;
    gbCompression: TGroupBox;
    gblanguage: TGroupBox;
    gbWipe: TGroupBox;
    lblAlgo: TLabel;
    lblRounds: TLabel;
    lbllanguage: TLabel;
    lblLevel: TLabel;
    lblmethod: TLabel;
    pcConfig: TPageControl;
    edtRounds: TSpinEdit;
    tab1: TTabSheet;
    tab2: TTabSheet;
    procedure btnOKClick(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmConfig: TfrmConfig;


implementation


{$R *.lfm}

{ TfrmConfig }

//=================================================================================================
procedure TfrmConfig.FormActivate(Sender: TObject);
var
  sl: TStrings;
  i: integer;
  LangIni: TIniFile;
  ConfigIni: TIniFile;
begin
  LangIni := TIniFile.Create('lang.dat');
  sl := TStringList.Create;
  try
    LangIni.ReadSections(sl);
    for i := 0 to sl.Count - 1 do
      cboLanguage.Items.Add(sl.Strings[i]);
  finally
    sl.Free;
    LangIni.Free;
  end;

  ConfigIni := TIniFile.Create('config.ini');
  try
    cboAlgo.ItemIndex := ConfigIni.ReadInteger('Config', 'Algorithm', 2);
    edtRounds.Value := ConfigIni.ReadInteger('Config', 'Iterations', 20000);
    cboLevel.ItemIndex := ConfigIni.ReadInteger('Config', 'CompressionLevel', 1);
    chkCompression.Checked := ConfigIni.ReadBool('Config', 'Compression', True);
    cboWipe.ItemIndex := ConfigIni.ReadInteger('Config', 'Wipe', 0);
    cboLanguage.ItemIndex := cboLanguage.Items.Indexof(ConfigIni.ReadString('Config', 'Language', 'English'));
  finally
    ConfigIni.Free;
  end;
end;

procedure TfrmConfig.FormCreate(Sender: TObject);
begin
  {$IFDEF CAMELLIA}
  cboAlgo.Items.Add('Camellia - 256 Bits');
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmConfig.FormShow(Sender: TObject);
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

//=================================================================================================
procedure TfrmConfig.btnOKClick(Sender: TObject);

  function AddSlash(s: string): string;
  begin
    Result := IncludeTrailingPathDelimiter(s);
  end;

var
  ConfigIni: TIniFile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'config.ini';
  ConfigIni := TIniFile.Create(Path);
  try
    ConfigIni.WriteInteger('Config', 'Algorithm', cboAlgo.ItemIndex);
    ConfigIni.WriteInteger('Config', 'Iterations', edtRounds.Value);
    ConfigIni.WriteInteger('Config', 'CompressionLevel', cboLevel.ItemIndex);
    ConfigIni.WriteBool('Config', 'Compression', chkCompression.Checked);
    ConfigIni.WriteInteger('Config', 'Wipe', cboWipe.ItemIndex);
    ConfigIni.WriteString('Config', 'Language', cboLanguage.Text);
  finally
    ConfigIni.Free;
  end;
end;

end.
