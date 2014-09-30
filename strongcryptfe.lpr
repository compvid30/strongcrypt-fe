program strongcryptfe;

{$MODE DELPHI}

uses
  Forms, Interfaces,
  uMain in 'uMain.pas',
  uEncrypt in 'uEncrypt.pas',
  uRnd in 'uRnd.pas',
  uDecrypt in 'uDecrypt.pas',
  uConfig in 'uConfig.pas',
  uAbout in 'uAbout.pas';

{$R *.res}

begin
  Application.Initialize;
  {$IFDEF WINDOWS}
  Application.MainFormOnTaskbar := True;
  {$ENDIF}
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TfrmEncrypt, frmEncrypt);
  Application.CreateForm(TfrmRnd, frmRnd);
  Application.CreateForm(TfrmDecrypt, frmDecrypt);
  Application.CreateForm(TfrmConfig, frmConfig);
  Application.CreateForm(TfrmAbout, frmAbout);
  Application.Run;
end.
