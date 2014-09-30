unit uAbout;

{$mode delphi}

interface

uses
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, lclintf;

type

  { TfrmAbout }

  TfrmAbout = class(TForm)
    btnOK: TButton;
    btnDonate: TButton;
    Image1: TImage;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    procedure btnDonateClick(Sender: TObject);
    procedure btnOKClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  frmAbout: TfrmAbout;

implementation

{$R *.lfm}

{ TfrmAbout }

procedure TfrmAbout.FormShow(Sender: TObject);
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

procedure TfrmAbout.btnOKClick(Sender: TObject);
begin
  close;
end;

procedure TfrmAbout.btnDonateClick(Sender: TObject);
begin
  OpenURL('http://www.strongcrypt.org');
end;

end.

