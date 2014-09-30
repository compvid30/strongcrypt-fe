unit uMain;

{$I std.inc}

{$MODE DELPHI}{$H+}

{.$DEFINE CAMELLIA}

interface

uses
  LCLIntf,
  LCLType,
  {$IFDEF WINDOWS}
  Windows,
  ShellApi,
  {$ELSE}
  Unix,
  BaseUnix,
  Process,
  {$ENDIF}
  SysUtils,
  Variants,
  Classes,
  lazutf8classes,
  Graphics,
  Controls,
  Forms,
  Dialogs,
  StdCtrls,
  hash,
  sha512,
  whirl512,
  aes_eax,
  AES256,
  tf_eax,
  Twofish256,
  sp_eax,
  Serpend256,
  {$IFDEF CAMELLIA}
  cam_eax,
  Camellia256,
  {$ENDIF}
  tsc,
  dates,
  mem_util,
  ExtCtrls,
  Menus,
  ActnList,
  ComCtrls,
  EXPanel,
  FileUtil,
  zlibhcx,
  zlibexcx,
  strUtils,
  IniFiles,
  isaac;

type


  TFCUserAES = record
    cxe: TAES_EAXContext;     // EAX context
    fi: TFileStreamUTF8;
    fo: TFileStreamUTF8;
    Rest: int64;             // remaining input file length
  end;
  PFCUserAES = ^TFCUserAES;

  TFCUserTF = record
    cxe: TTF_EAXContext;     // EAX context
    fi: TFileStreamUTF8;
    fo: TFileStreamUTF8;
    Rest: int64;             // remaining input file length
  end;
  PFCUserTF = ^TFCUserTF;

  TFCUserSP = record
    cxe: TSP_EAXContext;     // EAX context
    fi: TFileStreamUTF8;
    fo: TFileStreamUTF8;
    Rest: int64;             // remaining input file length
  end;
  PFCUserSP = ^TFCUserSP;

  {$IFDEF CAMELLIA}
type
  TFCUserCAM = record
    cxe: TCAM_EAXContext;     // EAX context
    fi: TFileStreamUTF8;
    fo: TFileStreamUTF8;
    Rest: int64;             // remaining input file length
  end;
  PFCUserCAM = ^TFCUserCAM;
  {$ENDIF}

  TMetaBlock = record       // AxCrypt restores all 3 file times under Windows. We store only modified for some reasons.
    FileName: string[255];
    Age: longint;
  end;

type
  TXKey = packed record                  // eXtended key for PBKDF
    ak: packed array[0..31] of byte;     // 256 bit key
    hk: packed array[0..31] of byte;     // EAX key
    pv: word;                            // password verifier
  end;

type
  TTwoFiles = record
    pf1: TFileStreamUTF8;
    pf2: TFileStreamUTF8;
  end;
  PTwoFiles = ^TTwoFiles;

  RawByteString = ansistring;

{$IFDEF WINDOWS}
type
  TMemoryStatusEx = packed record
    dwLength: DWORD;
    dwMemoryLoad: DWORD;
    ullTotalPhys: int64;
    ullAvailPhys: int64;
    ullTotalPageFile: int64;
    ullAvailPageFile: int64;
    ullTotalVirtual: int64;
    ullAvailVirtual: int64;
    ullAvailExtendedVirtual: int64;
  end;
{$ENDIF}

  { TfrmMain }
  TfrmMain = class(TForm)
    actDecrypt: TAction;
    actEncrypt: TAction;
    actEncryptFolder: TAction;
    actDecryptFolder: TAction;
    actWipeFolder: TAction;
    actWipe: TAction;
    actView: TAction;
    aclActions: TActionList;
    btnEncrypt: TEXPanel;
    btnDecrypt: TEXPanel;
    btnWipe: TEXPanel;
    btnView: TEXPanel;
    imgBotom: TImage;
    imgInfo: TImage;
    lblInfo: TLabel;
    popEncryptFiles: TMenuItem;
    popWipeFiles: TMenuItem;
    popDecryptFiles: TMenuItem;
    popPasswd: TMenuItem;
    popSep3: TMenuItem;
    popSep2: TMenuItem;
    popConfig: TMenuItem;
    popSep1: TMenuItem;
    popDecryptFolder: TMenuItem;
    popAbout: TMenuItem;
    popMenu: TPopupMenu;
    popWipeFolder: TMenuItem;
    popEncryptFolder: TMenuItem;
    popEncrypt: TPopupMenu;
    popDecrypt: TPopupMenu;
    popWipe: TPopupMenu;
    dlgOpen: TOpenDialog;
    imgTop: TImage;
    imlImages: TImageList;
    popLanguage: TMenuItem;
    lblTop: TStaticText;
    dlgFolder: TSelectDirectoryDialog;
    prbProgress: TProgressBar;
    procedure actDecryptExecute(Sender: TObject);
    procedure actDecryptFolderExecute(Sender: TObject);
    procedure actEncryptExecute(Sender: TObject);
    procedure actEncryptFolderExecute(Sender: TObject);
    procedure actWipeExecute(Sender: TObject);
    procedure actViewExecute(Sender: TObject);
    procedure actWipeFolderExecute(Sender: TObject);
    procedure btnDecryptClick(Sender: TObject);
    procedure btnEncryptClick(Sender: TObject);
    procedure btnEncryptMouseEnter(Sender: TObject);
    procedure btnEncryptMouseLeave(Sender: TObject);
    procedure btnWipeClick(Sender: TObject);
    procedure btnViewClick(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormMouseEnter(Sender: TObject);
    procedure imgDecryptClick(Sender: TObject);
    procedure imgInfoClick(Sender: TObject);
    procedure popConfigClick(Sender: TObject);
    procedure popAboutClick(Sender: TObject);
    procedure popPasswdClick(Sender: TObject);
  private
    { private declarations }
    FAge: longint;
    FFileName: string;
    procedure EncryptTF(const sPW, InName, OutName: string);
    procedure EncryptAES(const sPW, InName, OutName: string);
    procedure EncryptSP(const sPW, InName, OutName: string);
    function DecryptTF(const sPW, InName, OutName: string): boolean;
    function DecryptAES(const sPW, InName, OutName: string): boolean;
    function DecryptSP(const sPW, InName, OutName: string): boolean;
    {$IFDEF CAMELLIA}
    procedure EncryptCAM(const sPW, InName, OutName: string);
    function DecryptCAM(const sPW, InName, OutName: string): boolean;
    {$ENDIF}
    procedure EncryptShell;
    procedure DecryptShell;
    procedure RenameShell;
    procedure WipeShell;
    procedure AddLangMenu;
    procedure LangItemClick(Sender: TObject);
    procedure Shredder(fn: string);
    procedure RandomRename(fn: string);
  public
    { public declarations }
    procedure LoadConfig;
    procedure SaveConfig;
    procedure LoadLanguage(Lang: string);
  end;

var
  frmMain: TfrmMain;
  FileLength: qword;
  ProgCounter: qword;

  ActivateCounter: byte = 0;

  Algorithm: byte = 0;
  Iterations: longint = 20000;
  CompressionLevel: integer = 1;
  Compression: boolean = True;
  clevel: integer;
  Wipe: byte = 0;
  Language: string = 'English';

  Bits: string = 'Bits';
  Filter1: string = 'All Files (*.*)|*';
  Filter2: string = 'StrongCrypt-FE Files (*.sce)|*.sce|All Files (*.*)|*';

  ErrorSig: string = 'Wrong Signature, this file is damaged or not a StrongCrypt-FE file.';
  ErrorPwd: string = 'Wrong Password!';
  ErrorAut: string = 'Authentication failed.';

  strEnc: string = 'Encrypting:';
  strDec: string = 'Decrypting:';
  strWipe: string = 'Wiping:';

  TitleEnc: string = 'Encrypt';
  TitleDec: string = 'Decrypt';
  TitleView: string = 'View';
  TitleWipe: string = 'Wipe';
  TitleOpen: string = 'Open';

implementation

{$R *.lfm}

uses
  uEncrypt,
  uDecrypt,
  uConfig,
  uRnd,
  uAbout;

const
  BUFSIZE = $D000;

{$IFDEF WINDOWS}
  Slash = '\';
{$ELSE}
  Slash = '/';
{$ENDIF}

var
  buf: array[0..BUFSIZE - 1] of byte;   //file IO buffer

// some already compressed file formats, did I forget any?
const
  CompFiles: array[0..39] of string = ('.bz2', '.gz', '.lz', '.lzma', '.lzo', '.rz', '.xz',
    '.flv', '.swf', '.wmv', '.ogg', '.png', '.jpg', '.gif', '.mp3', '.mp4', '.mpg', '.avi', '.mov', '.rm',
    '.z', '.7z', '.s7z', '.bh', '.cab', '.dmg', '.lzh', '.lha', '.lzx', '.iso', '.pak', '.rar',
    '.rk', '.sit', '.sitx', '.sqx', '.yz1', '.zip', '.zipx', '.axx');


{$IFDEF UNIX}
function mlock(addr: Pointer; size: integer): integer; cdecl; external;  // Not declaired in FPC
function munlock(addr: Pointer; size: integer): integer; cdecl; external;  // Not declaired in FPC
{$ENDIF}

{$IFDEF WINDOWS}
function GlobalMemoryStatusEx(var lpBuffer: TMemoryStatusEx): BOOL; stdcall; external kernel32;
function GetShellWindow: HWND; stdcall; external 'user32.dll' name 'GetShellWindow';

// Collect some random data for seeding our prng
function CollectRND(var WD: TWhirlDigest): boolean;
var
  sctx: THashContext;
  ctr: TCtrRec;
  ctrInt: longint;
  tick: longword;
  msc: longint;
  pID: longword;
  tID: longword;
  Status: TMemoryStatusEx;
  pos: TPoint;
  PCreationTime: TFileTime;
  TCreationTime: TFileTime;
  ExitTime: TFileTime;
  PKernelTime: TFileTime;
  TKernelTime: TFileTime;
  UserTime: TFileTime;
  min: longword;
  max: longword;
  hwnd: longword;
  hwnd2: longword;
  hwnd3: longword;
  hwnd4: longword;
  hwnd5: longword;
  heaphwnd: longword;
  cp: longword;
  mt: longint;
  dt: TDateTime;
begin

  try
    Result := True;

    // ms since midnight
    _ReadCounter(Ctr);

    // ms since system start
    tick := GetTickCount;

    // current time as ms
    msc := MsCount;

    // Get global memory status
    ZeroMemory(@Status, SizeOf(TMemoryStatusEx));
    Status.dwLength := SizeOf(TMemoryStatusEx);
    GlobalMemoryStatusEx(Status);

    // Get cursor position
    GetCursorPos(Pos);

    // Get process creation time
    GetProcessTimes(GetCurrentProcess, PCreationTime, ExitTime, PKernelTime, UserTime);

    // Get thread creation time
    GetThreadTimes(GetCurrentProcess, TCreationTime, ExitTime, TKernelTime, UserTime);

    // Get the minimum and maximum working set size
    GetProcessWorkingSetSize(GetCurrentProcess, min, max);

    // Get current process and thread ID
    pID := GetCurrentProcessId;
    tID := GetCurrentThreadId;

    // Handle of focused window
    hwnd := GetFocus;

    // Get desktop window handle
    hwnd2 := GetDesktopWindow;

    // Get handle of last popup window
    hwnd3 := GetLastActivePopup(hwnd2);

    // Get handle of clipboard owner
    hwnd4 := GetClipboardOwner;

    // Retrieves a handle to the Shell's desktop window
    hwnd5 := GetShellWindow;

    // Get handle to process heap
    heaphwnd := GetProcessHeap;

    // Get code page
    cp := GetOEMCP;

    // Retrieves the message time for the last message retrieved by the GetMessage function
    mt := GetMessageTime;

    // Just now
    dt := now;

    // Hash all values with whirlpool to get the seed for the prng
    Whirl_Init(sctx);

    Whirl_Update(sctx, @ctr, SizeOf(ctr));
    Whirl_Update(sctx, @tick, SizeOf(tick));
    Whirl_Update(sctx, @msc, SizeOf(msc));
    Whirl_Update(sctx, @status, SizeOf(status));
    Whirl_Update(sctx, @pos, SizeOf(pos));
    Whirl_Update(sctx, @PCreationTime, SizeOf(PCreationTime));
    Whirl_Update(sctx, @TKernelTime, SizeOf(TKernelTime));
    Whirl_Update(sctx, @min, SizeOf(min));
    Whirl_Update(sctx, @max, SizeOf(max));
    Whirl_Update(sctx, @pID, SizeOf(pID));
    Whirl_Update(sctx, @tID, SizeOf(tID));
    Whirl_Update(sctx, @hwnd, SizeOf(hwnd));
    Whirl_Update(sctx, @hwnd2, SizeOf(hwnd2));
    Whirl_Update(sctx, @hwnd3, SizeOf(hwnd3));
    Whirl_Update(sctx, @hwnd4, SizeOf(hwnd4));
    Whirl_Update(sctx, @hwnd5, SizeOf(hwnd5));
    Whirl_Update(sctx, @heaphwnd, SizeOf(heaphwnd));
    Whirl_Update(sctx, @cp, SizeOf(cp));
    Whirl_Update(sctx, @mt, SizeOf(mt));
    Whirl_Update(sctx, @dt, SizeOf(dt));

    Whirl_Final(sctx, WD);

  except
    on E: Exception do
    begin
      Result := False;
    end;
  end;

end;

{$ENDIF}

//=================================================================================================
{$IFDEF LINUX}
procedure KDE_Plasma_Repaint;
begin
  // Doing this for Lazarus GTK2-KDE Plasma 4.0 bug. Remove dark background stage from form.
  // Not needed if linked against QT.
  frmMain.Hide;
  frmMain.Position := poDefault;
  frmMain.Show;
end;

{$ENDIF}

//=================================================================================================
function AES_EAX_Selftest: boolean;
const
  Key256: array[0..31] of byte =
    ($00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f,
    $00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f);

  sample = 'This is a simple self test for AES EAX mode.'#0;

var
  i: integer;
  Nonce: packed array[0..31] of byte;
  ct, pt, plain: array[1..length(sample)] of char;
  Err: integer;
  Context: TAES_EAXContext;

  function DeCryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      DeCryptData := -1
    else
      DeCryptData := AES_EAX_Decrypt(InData, OutData, InDataLen, context);
  end;

  function CryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      CryptData := -1
    else
      CryptData := AES_EAX_Encrypt(InData, OutData, InDataLen, context);
  end;

begin
  Result := False;

  for i := 0 to 31 do
    Nonce[i] := random(256);
  plain := sample;
  pt := plain;

  //Encrypt plain text
  Err := AES_EAX_Init(key256, 256, Nonce, 256, context);
  Err := CryptData(@pt, sizeof(plain), @ct, sizeof(ct));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Decrypt encrypted text
  pt := ct;

  Err := AES_EAX_Init(key256, 256, Nonce, 256, context);
  Err := DeCryptData(@pt, sizeof(pt), @pt, sizeof(pt));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Compare encrypted/decrypted text against org text
  Result := CompMem(@pt, @plain, sizeof(plain));
end;

//=================================================================================================
function TF_EAX_Selftest: boolean;
const
  Key256: array[0..31] of byte =
    ($00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f,
    $00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f);

  sample = 'This is a simple self test for Twofish EAX mode.'#0;

var
  i: integer;
  Nonce: packed array[0..31] of byte;
  ct, pt, plain: array[1..length(sample)] of char;
  Err: integer;
  Context: TTF_EAXContext;

  function DeCryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      DeCryptData := -1
    else
      DeCryptData := TF_EAX_Decrypt(InData, OutData, InDataLen, context);
  end;

  function CryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      CryptData := -1
    else
      CryptData := TF_EAX_Encrypt(InData, OutData, InDataLen, context);
  end;

begin
  Result := False;

  for i := 0 to 31 do
    Nonce[i] := random(256);
  plain := sample;
  pt := plain;

  //Encrypt plain text
  Err := TF_EAX_Init(key256, 256, Nonce, 256, context);
  Err := CryptData(@pt, sizeof(plain), @ct, sizeof(ct));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Decrypt encrypted text
  pt := ct;

  Err := TF_EAX_Init(key256, 256, Nonce, 256, context);
  Err := DeCryptData(@pt, sizeof(pt), @pt, sizeof(pt));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Compare encrypted/decrypted text against org text
  Result := CompMem(@pt, @plain, sizeof(plain));
end;

//=================================================================================================
function SP_EAX_Selftest: boolean;
const
  Key256: array[0..31] of byte =
    ($00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f,
    $00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f);

  sample = 'This is a simple self test for Serpend EAX mode.'#0;

var
  i: integer;
  Nonce: packed array[0..31] of byte;
  ct, pt, plain: array[1..length(sample)] of char;
  Err: integer;
  Context: TSP_EAXContext;

  function DeCryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      DeCryptData := -1
    else
      DeCryptData := SP_EAX_Decrypt(InData, OutData, InDataLen, context);
  end;

  function CryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      CryptData := -1
    else
      CryptData := SP_EAX_Encrypt(InData, OutData, InDataLen, context);
  end;

begin
  Result := False;

  for i := 0 to 31 do
    Nonce[i] := random(256);
  plain := sample;
  pt := plain;

  //Encrypt plain text
  Err := SP_EAX_Init(key256, 256, Nonce, 256, context);
  Err := CryptData(@pt, sizeof(plain), @ct, sizeof(ct));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Decrypt encrypted text
  pt := ct;

  Err := SP_EAX_Init(key256, 256, Nonce, 256, context);
  Err := DeCryptData(@pt, sizeof(pt), @pt, sizeof(pt));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Compare encrypted/decrypted text against org text
  Result := CompMem(@pt, @plain, sizeof(plain));
end;

//=================================================================================================
{$IFDEF CAMELLIA}
function CAM_EAX_Selftest: boolean;
const
  Key256: array[0..31] of byte =
    ($00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f,
    $00, $01, $02, $03, $04, $05, $06, $07,
    $08, $09, $0a, $0b, $0c, $0d, $0e, $0f);

  sample = 'This is a simple self test for Camellia EAX mode.'#0;

var
  i: integer;
  Nonce: packed array[0..31] of byte;
  ct, pt, plain: array[1..length(sample)] of char;
  Err: integer;
  Context: TCAM_EAXContext;

  function DeCryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      DeCryptData := -1
    else
      DeCryptData := CAM_EAX_Decrypt(InData, OutData, InDataLen, context);
  end;

  function CryptData(InData: pointer; InDataLen: integer; OutData: pointer; OutDataLen: integer): integer;
  begin
    if InDataLen > OutDataLen then
      CryptData := -1
    else
      CryptData := CAM_EAX_Encrypt(InData, OutData, InDataLen, context);
  end;

begin
  Result := False;

  for i := 0 to 31 do
    Nonce[i] := random(256);
  plain := sample;
  pt := plain;

  //Encrypt plain text
  Err := CAM_EAX_Init(key256, 256, Nonce, 256, context);
  Err := CryptData(@pt, sizeof(plain), @ct, sizeof(ct));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Decrypt encrypted text
  pt := ct;

  Err := CAM_EAX_Init(key256, 256, Nonce, 256, context);
  Err := DeCryptData(@pt, sizeof(pt), @pt, sizeof(pt));
  if Err <> 0 then
  begin
    Result := False;
    exit;
  end;

  //Compare encrypted/decrypted text against org text
  Result := CompMem(@pt, @plain, sizeof(plain));
end;

{$ENDIF}

//=================================================================================================
function bread(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
var
  n: longint;
begin
  n := PTwoFiles(userdata)^.pf1.Read(bufp^, mlen);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  bread := n;
  done := PTwoFiles(Userdata)^.pf1.position >= PTwoFiles(Userdata)^.pf1.size;
end;

//=================================================================================================
function bwrite(bufp, userdata: pointer; size: word): longint;
var
  n: longint;
begin
  n := PTwoFiles(userdata)^.pf2.Write(bufp^, size);
  bwrite := n;
end;

//=================================================================================================
procedure CompressFile(inFile, outFile: string; level: int);
var
  User: TTwofiles;
begin
  User.pf1 := TFileStreamUTF8.Create(inFile, fmOpenRead or fmShareDenyNone);
  User.pf1.Seek(0, soFromBeginning);

  User.pf2 := TFileStreamUTF8.Create(outFile, fmCreate);
  User.pf2.Seek(0, soFromBeginning);
  try
    DeflateEx(@bread, @bwrite, level, @User);
  finally
    User.pf1.Free;
    User.pf2.Free;
  end;
end;

//=================================================================================================
procedure DecompressFile(inFile, outFile: string);
var
  User: TTwofiles;
begin
  User.pf1 := TFileStreamUTF8.Create(inFile, fmOpenRead or fmShareDenyNone);
  User.pf1.Seek(0, soFromBeginning);

  User.pf2 := TFileStreamUTF8.Create(outFile, fmCreate);
  User.pf2.Seek(0, soFromBeginning);
  try
    InflateEx(@bread, @bwrite, @User);
  finally
    User.pf1.Free;
    User.pf2.Free;
  end;
end;

//=================================================================================================
{$IFDEF WINDOWS}
procedure RunShell(Executable: string);
var
  Info: TShellExecuteInfo;
  pInfo: LPShellExecuteInfo;
  exitCode: DWord;
begin
  pInfo := @Info;
  with Info do
  begin
    cbSize := SizeOf(Info);
    fMask := SEE_MASK_NOCLOSEPROCESS;
    wnd := frmMain.Handle;
    lpVerb := 'open';
    lpFile := PChar(Executable);
    lpParameters := nil;
    lpDirectory := nil;
    nShow := SW_SHOW;
    hInstApp := 0;
  end;
  ShellExecuteEx(pInfo);
  repeat
    exitCode := WaitForSingleObject(Info.hProcess, 500);
    Application.ProcessMessages;
  until (exitCode <> WAIT_TIMEOUT);
end;

{$ENDIF}

//=================================================================================================
{$IFNDEF WINDOWS}
function FindFilenameOfCmd(ProgramFilename: string): string;
begin
  Result := TrimFilename(ProgramFilename);
  if not FilenameIsAbsolute(Result) then
  begin
    if Pos(PathDelim, Result) > 0 then
    begin
      // with sub directory => relative to current directory
      Result := CleanAndExpandFilename(Result);
    end
    else
    begin
      // search in PATH
      Result := FindDefaultExecutablePath(Result);
    end;
  end;
  if (Result <> '') and not (FileExistsUTF8(Result)) then
    Result := '';
end;

//=================================================================================================
procedure RunCmdFromPath(ProgramFilename, CmdLineParameters: string);
var
  OldProgramFilename: string;
  BrowserProcess: TProcess;
begin
  OldProgramFilename := ProgramFilename;
  ProgramFilename := FindFilenameOfCmd(ProgramFilename);

  if ProgramFilename = '' then
    raise EFOpenError.Create('Error - File open');
  if not FileIsExecutable(ProgramFilename) then
    raise EFOpenError.Create('Error - File is not executable');

  BrowserProcess := TProcess.Create(nil);
  try
    if Pos(' ', ProgramFilename) > 0 then
      ProgramFilename := '"' + ProgramFilename + '"';

    BrowserProcess.CommandLine := ProgramFilename;
    if CmdLineParameters <> '' then
      BrowserProcess.CommandLine := BrowserProcess.CommandLine + ' ' + CmdLineParameters;
    BrowserProcess.Options := BrowserProcess.Options + [poWaitOnExit];
    BrowserProcess.Execute;
    while BrowserProcess.active do
      Application.ProcessMessages;

  finally
    BrowserProcess.Free;
  end;
end;

{$ENDIF}

//=================================================================================================
{$IFDEF LINUX}
function RunShell(APath: string): boolean;
var
  lApp: string;
begin
  Result := True;
  if not FileExistsUTF8(APath) then
    exit(False);

  lApp := FindFilenameOfCmd('xdg-open'); // standard on Linux
  if lApp = '' then
    lApp := FindFilenameOfCmd('kfmclient'); // KDE command
  if lApp = '' then
    lApp := FindFilenameOfCmd('gnome-open'); // GNOME command
  if lApp = '' then
    Exit(False);

  if (APath <> '') and (APath[1] <> '"') then
    APath := QuotedStr(APath);
  RunCmdFromPath(lApp, APath);
end;

{$ENDIF}

//=================================================================================================
{$IFDEF DARWIN}
function RunShell(APath: string): boolean;
var
  ResultingPath: string;
begin
  Result := True;
  if not FileExistsUTF8(APath) then
    exit(False);
  // Paths with spaces need to be quoted
  if (APath <> '') and (APath[1] <> '''') then
    ResultingPath := QuotedStr(APath)
  else
    ResultingPath := APath;
  RunCmdFromPath('open', ResultingPath);
end;

{$ENDIF}

//=================================================================================================
{$IFDEF WINDOWS}
function GetDesktopPath: string;
var
  ppidl: PItemIdList;
begin
  ppidl := nil;
  SHGetSpecialFolderLocation(frmMain.Handle, CSIDL_DESKTOPDIRECTORY, ppidl);
  SetLength(Result, MAX_PATH);
  if not SHGetPathFromIDList(ppidl, PChar(Result)) then
    raise Exception.Create('SHGetPathFromIDList failed : invalid pidl');
  SetLength(Result, lStrLen(PChar(Result)));
end;

{$ENDIF}

//=================================================================================================
{$IFDEF DARWIN}
function GetDesktopPath: string;
begin
  Result := GetEnvironmentVariable('HOME') + DirectorySeparator + 'Desktop';
end;

{$ENDIF}

//=================================================================================================
{$IFDEF LINUX}
function g_get_user_special_dir(directory: integer): PChar; cdecl; external;  // Not declaired in FPC

function GetDesktopPath: string;
begin
  Result := g_get_user_special_dir(0);
end;

{$ENDIF}

//=================================================================================================
function HashFile(const FileName: string): ansistring;

  function HexString(const x: array of byte): ansistring;
  begin
    Result := HexStr(@x, SizeOf(x));
  end;

var
  WhirlContext: THashContext;
  WhirlDigest: TWhirlDigest;
  buf: array[1..$F000] of byte;
  f: file;
  n: integer;

begin
  Whirl_Init(WhirlContext);

  assignfile(f, FileName);
  reset(f, 1);
  try
    repeat
      blockread(f, buf, SizeOf(buf), n);
      if IOResult <> 0 then
      begin
        raise Exception.Create('Read Error');
        break;
      end;
      if n <> 0 then
      begin
        Application.ProcessMessages;
        Whirl_Update(WhirlContext, @buf, n);
      end;
    until n <> SizeOf(buf);
  finally
    closefile(f);
  end;

  Whirl_Final(WhirlContext, WhirlDigest);

  Result := HexString(WhirlDigest);

end;

//=================================================================================================
{$IFDEF WINDOWS}
function FileFlush(Handle: THandle): boolean;
begin
  Result := FlushFileBuffers(Handle);
end;

{$ELSE}
function FileFlush(Handle: THandle): boolean;
begin
  Result := (fpfsync(Handle) = 0);
end;

{$ENDIF}

//=================================================================================================
function AddSlash(s: string): string;
begin
  Result := IncludeTrailingPathDelimiter(s);
end;

//=================================================================================================
function DelSlash(s: string): string;
begin
  Result := ExcludeTrailingPathDelimiter(s);
end;

//=================================================================================================
procedure ScanDirectory(path: string; hitlist: TStrings);
var
  searchResult: TSearchRec;
begin
  if FindFirstUTF8(path + Slash + '*', faAnyFile, searchResult) = 0 then
  begin
    try
      repeat
        if (searchResult.Attr and faDirectory) = 0 then
        begin
          hitlist.Add(AddSlash(path) + searchResult.Name);
        end
        else
        if (searchResult.Name <> '.') and (searchResult.Name <> '..') then
        begin
          ScanDirectory(AddSlash(path) + searchResult.Name, hitlist);
        end;
      until FindNextUTF8(searchResult) <> 0
    finally
      FindCloseUTF8(searchResult);
    end;
  end;
end;

//=================================================================================================
function ReturnTempFilename(strLen: integer): string;
var
  str: string;
begin
  str := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  Result := '';
  repeat
    Result := Result + str[Random(Length(str)) + 1];
  until (Length(Result) = strLen);

  Result := '$SC' + Result + '.TMP';

end;

//=================================================================================================
function CheckPermission(Dir: string): boolean;
var
  fn: string;
begin
  repeat
    fn := ChangeFileExt(ReturnTempFilename(8), '');
  until not DirectoryExistsUTF8(fn);

  try
    CreateDirUTF8(AddSlash(Dir) + fn);
  except
    Result := False;
  end;
  RemoveDirUTF8(AddSlash(Dir) + fn);
  Result := True;
end;

//=================================================================================================
procedure ShredderFileDoD7(const filename: string);
const
  Fillchars: array[0..1] of char = (char($00), char($FF));
  BLOCK_SIZE = 8192;
  dfn = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxx';
var
  fs: TFileStreamUTF8;
  buffer: string;
  i, j: integer;
  newfilename: string;
begin
  fs := TFileStreamUTF8.Create(filename, fmOpenReadWrite or fmShareExclusive);
  try
    // Expand file to next Clusters to overwrite slack.
    fs.Size := ((fs.Size div BLOCK_SIZE) + 2) * BLOCK_SIZE;

    FileLength := fs.Size * 7;

    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    frmMain.lblInfo.Caption := strWipe + ' ' + ExtractFilename(filename);

    for i := 0 to 1 do
    begin
      fs.Position := 0;
      buffer := StringOfChar(Fillchars[i], BLOCK_SIZE);

      for j := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
      FileFlush(fs.Handle);
    end;

    Randomize;
    fs.Position := 0;
    for j := 1 to fs.Size div BLOCK_SIZE do
    begin
      for i := 0 to 8191 do
      begin
        buffer[i] := char(random(256));
      end;
      ProgCounter := ProgCounter + BLOCK_SIZE;
      frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
      Application.ProcessMessages;
      fs.WriteBuffer(buffer[1], BLOCK_SIZE);
    end;
    FileFlush(fs.Handle);

    begin
      fs.Position := 0;
      buffer := StringOfChar(char($96), BLOCK_SIZE);
      for j := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
      FileFlush(fs.Handle);
    end;


    for i := 0 to 1 do
    begin
      fs.Position := 0;
      buffer := StringOfChar(Fillchars[i], BLOCK_SIZE);

      for j := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
      FileFlush(fs.Handle);
    end;

    fs.Position := 0;
    for j := 1 to fs.Size div BLOCK_SIZE do
    begin
      for i := 0 to 8191 do
      begin
        buffer[i] := char(random(256));
      end;
      ProgCounter := ProgCounter + BLOCK_SIZE;
      frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
      Application.ProcessMessages;
      fs.WriteBuffer(buffer[1], BLOCK_SIZE);
    end;
    FileFlush(fs.Handle);
  finally
    fs.Free;
  end;

  newfilename := ExtractFilepath(filename) + dfn;

  {$IFDEF WINDOWS}
  if length(newfilename) > MAX_PATH then
    // Windows path limit is 260
    Delete(newFilename, MAX_PATH - 1, length(newFilename) - MAX_PATH + 1);
  {$ELSE}
  if length(newfilename) > MaxPathLen then
    // Linux is 4096, Mac OS X is 1024
    Delete(newFilename, MaxPathLen - 1, length(newFilename) - MaxPathLen + 1);
  {$ENDIF}

  RenameFileUTF8(filename, newfilename);
  DeleteFileUTF8(newfilename);
end;

//=================================================================================================
procedure ShredderFileVSITR(const filename: string);
const
  Fillchars: array[0..6] of char =
    (char($00), char($FF), char($00), char($FF), char($00), char($FF), char($AA));
  BLOCK_SIZE = 8192;
  dfn = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxx';
var
  fs: TFileStreamUTF8;
  buffer: string;
  i, j: integer;
  newfilename: string;
begin
  fs := TFileStreamUTF8.Create(filename, fmOpenReadWrite or fmShareExclusive);
  try
    // Expand file to next Clusters to overwrite slack.
    fs.Size := ((fs.Size div BLOCK_SIZE) + 2) * BLOCK_SIZE;

    FileLength := fs.Size * 7;

    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    frmMain.lblInfo.Caption := strWipe + ' ' + ExtractFilename(filename);

    for i := 0 to 6 do
    begin
      fs.Position := 0;
      buffer := StringOfChar(Fillchars[i], BLOCK_SIZE);

      for j := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
      FileFlush(fs.Handle);
    end;
  finally
    fs.Free;
  end;

  newfilename := ExtractFilepath(filename) + dfn;

  {$IFDEF WINDOWS}
  if length(newfilename) > MAX_PATH then
    // Windows path limit is 255
    Delete(newFilename, MAX_PATH - 1, length(newFilename) - MAX_PATH + 1);
  {$ELSE}
  if length(newfilename) > MaxPathLen then
    // Linux is 4096, Mac OS X is 1024
    Delete(newFilename, MaxPathLen - 1, length(newFilename) - MaxPathLen + 1);
  {$ENDIF}


  RenameFileUTF8(filename, newfilename);
  DeleteFileUTF8(newfilename);
end;

//=================================================================================================
procedure ShredderFileZero(const filename: string);
const
  BLOCK_SIZE = 8192;
  dfn = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxx';
var
  fs: TFileStreamUTF8;
  buffer: string;
  i: integer;
  newfilename: string;
begin
  fs := TFileStreamUTF8.Create(filename, fmOpenReadWrite or fmShareExclusive);
  try
    // Expand file to next Clusters to overwrite slack.
    fs.Size := ((fs.Size div BLOCK_SIZE) + 2) * BLOCK_SIZE;
    FileLength := fs.Size;

    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    frmMain.lblInfo.Caption := strWipe + ' ' + ExtractFilename(filename);

    begin
      fs.Position := 0;
      buffer := StringOfChar(char($00), BLOCK_SIZE);
      for i := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
    end;
  finally
    fs.Free;
  end;

  newfilename := ExtractFilepath(filename) + dfn;

  {$IFDEF WINDOWS}
  if length(newfilename) > MAX_PATH then
    // Windows path limit is 255
    Delete(newFilename, MAX_PATH - 1, length(newFilename) - MAX_PATH + 1);
  {$ELSE}
  if length(newfilename) > MaxPathLen then
    // Linux is 4096, Mac OS X is 1024
    Delete(newFilename, MaxPathLen - 1, length(newFilename) - MaxPathLen + 1);
  {$ENDIF}

  RenameFileUTF8(filename, newfilename);
  DeleteFileUTF8(newfilename);
end;

//=================================================================================================
procedure ShredderFilePRNG(const filename: string);
const
  BLOCK_SIZE = 8192;
  dfn = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxx';
var
  fs: TFileStreamUTF8;
  buffer: string;
  i, j: integer;
  newfilename: string;
begin
  fs := TFileStreamUTF8.Create(filename, fmOpenReadWrite or fmShareExclusive);
  try
    // Expand file to next Clusters to overwrite slack.
    fs.Size := ((fs.Size div BLOCK_SIZE) + 2) * BLOCK_SIZE;
    FileLength := fs.Size;

    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    frmMain.lblInfo.Caption := strWipe + ' ' + ExtractFilename(filename);

    buffer := StringOfChar('0', BLOCK_SIZE);
    Randomize;
    fs.Position := 0;
    for j := 1 to fs.Size div BLOCK_SIZE do
    begin
      for i := 0 to 8191 do
      begin
        buffer[i] := char(random(256));
      end;
      ProgCounter := ProgCounter + BLOCK_SIZE;
      frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
      Application.ProcessMessages;
      fs.WriteBuffer(buffer[1], BLOCK_SIZE);
    end;
  finally
    fs.Free;
  end;

  newfilename := ExtractFilepath(filename) + dfn;

  {$IFDEF WINDOWS}
  if length(newfilename) > MAX_PATH then
    // Windows path limit is 255
    Delete(newFilename, MAX_PATH - 1, length(newFilename) - MAX_PATH + 1);
  {$ELSE}
  if length(newfilename) > MaxPathLen then
    // Linux is 4096, Mac OS X is 1024
    Delete(newFilename, MaxPathLen - 1, length(newFilename) - MaxPathLen + 1);
  {$ENDIF}

  RenameFileUTF8(filename, newfilename);
  DeleteFileUTF8(newfilename);
end;

//=================================================================================================
procedure ShredderFileDoD3(const filename: string);
const
  Fillchars: array[0..1] of char = (char($00), char($FF));
  BLOCK_SIZE = 8192;
  dfn = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.xxx';
var
  fs: TFileStreamUTF8;
  buffer: string;
  i, j: integer;
  newfilename: string;
begin
  fs := TFileStreamUTF8.Create(filename, fmOpenReadWrite or fmShareExclusive);
  try
    // Expand file to next Clusters to overwrite slack.
    fs.Size := ((fs.Size div BLOCK_SIZE) + 2) * BLOCK_SIZE;

    FileLength := fs.Size * 3;

    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    frmMain.lblInfo.Caption := strWipe + ' ' + ExtractFilename(filename);

    for i := 0 to 1 do
    begin
      fs.Position := 0;
      buffer := StringOfChar(Fillchars[i], BLOCK_SIZE);

      for j := 1 to fs.Size div BLOCK_SIZE do
      begin
        ProgCounter := ProgCounter + BLOCK_SIZE;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
        fs.WriteBuffer(buffer[1], BLOCK_SIZE);
      end;
      FileFlush(fs.Handle);
    end;

    Randomize;
    fs.Position := 0;
    for j := 1 to fs.Size div BLOCK_SIZE do
    begin
      for i := 0 to 8191 do
      begin
        buffer[i] := char(random(256));
      end;
      ProgCounter := ProgCounter + BLOCK_SIZE;
      frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
      Application.ProcessMessages;
      fs.WriteBuffer(buffer[1], BLOCK_SIZE);
    end;
  finally
    fs.Free;
  end;

  newfilename := ExtractFilepath(filename) + dfn;

  {$IFDEF WINDOWS}
  if length(newfilename) > MAX_PATH then
    // Windows path limit is 255
    Delete(newFilename, MAX_PATH - 1, length(newFilename) - MAX_PATH + 1);
  {$ELSE}
  if length(newfilename) > MaxPathLen then
    // Linux is 4096, Mac OS X is 1024
    Delete(newFilename, MaxPathLen - 1, length(newFilename) - MaxPathLen + 1);
  {$ENDIF}

  RenameFileUTF8(filename, newfilename);
  DeleteFileUTF8(newfilename);
end;

//=================================================================================================
procedure GetSaltAES(var salt: TFCAAESSalt);      // SHA512 Salt for AES
var
  Ctr: TCtrRec;
  JD, msC, isaac: longint;
  sctx: THashContext;
  sdig: TSHA512Digest;
  ctx: isaac_ctx;
  i: integer;
  WD: TWhirlDigest;
  IsaacSeed: array[0..15] of LongInt;
begin
  // Hash Date, Time, Randseed, TSC and Isaac PRNG
  _ReadCounter(Ctr);
  JD := CurrentJulianDay;
  msC := msCount;
  {$IFDEF WINDOWS}
  if CollectRND(WD) then
  begin
    move(WD, IsaacSeed, SizeOf(IsaacSeed));
    // Feed Isaac with our seeds
    isaac_inita(ctx, IsaacSeed, 16);
  end
  else
    isaac_init(ctx, msC xor JD);
  {$ELSE}
  isaac_init(ctx, msC xor JD);
  {$ENDIF}
  Randomize;
  for i := 0 to (Random(255) + 1) do   // do not just pick the first here
    isaac := isaac_long(ctx);
  SHA512Init(sctx);
  Sha512Update(sctx, @Ctr, SizeOf(Ctr));
  Sha512Update(sctx, @JD, SizeOf(JD));
  Sha512Update(sctx, @msC, SizeOf(msC));
  Sha512Update(sctx, @isaac, SizeOf(isaac));
  Sha512Update(sctx, @randseed, SizeOf(randseed));
  Sha512Final(sctx, sdig);
  move(sdig, salt, SizeOf(salt));
end;

//=================================================================================================
procedure GetSaltTF(var salt: TFCATFSalt);      // Whirlpool Salt for Twofish
var
  Ctr: TCtrRec;
  JD, msC, isaac: longint;
  sctx: THashContext;
  sdig: TWhirlDigest;
  ctx: isaac_ctx;
  i: integer;
  WD: TWhirlDigest;
  IsaacSeed: array[0..15] of LongInt;
begin
  // Hash Date, Time, Randseed, TSC and Isaac PRNG
  _ReadCounter(Ctr);
  JD := CurrentJulianDay;
  msC := msCount;
  {$IFDEF WINDOWS}
  if CollectRND(WD) then
  begin
    move(WD, IsaacSeed, SizeOf(IsaacSeed));
    // Feed Isaac with our seeds
    isaac_inita(ctx, IsaacSeed, 16);
  end
  else
    isaac_init(ctx, msC xor JD);
  {$ELSE}
  isaac_init(ctx, msC xor JD);
  {$ENDIF}
  Randomize;
  for i := 0 to (Random(255) + 1) do   // do not just pick the first here
    isaac := isaac_long(ctx);
  Whirl_Init(sctx);
  Whirl_Update(sctx, @Ctr, SizeOf(Ctr));
  Whirl_Update(sctx, @JD, SizeOf(JD));
  Whirl_Update(sctx, @msC, SizeOf(msC));
  Whirl_Update(sctx, @isaac, SizeOf(isaac));
  Whirl_Update(sctx, @randseed, SizeOf(randseed));
  Whirl_Final(sctx, sdig);
  move(sdig, salt, SizeOf(salt));
end;

//=================================================================================================
procedure GetSaltSP(var salt: TFCASPSalt);      // Whirlpool Salt for Serpend
var
  Ctr: TCtrRec;
  JD, msC, isaac: longint;
  sctx: THashContext;
  sdig: TWhirlDigest;
  ctx: isaac_ctx;
  i: integer;
  WD: TWhirlDigest;
  IsaacSeed: array[0..15] of LongInt;
begin
  // Hash Date, Time, Randseed, TSC and Isaac PRNG
  _ReadCounter(Ctr);
  JD := CurrentJulianDay;
  msC := msCount;
  {$IFDEF WINDOWS}
  if CollectRND(WD) then
  begin
    move(WD, IsaacSeed, SizeOf(IsaacSeed));
    // Feed Isaac with our seeds
    isaac_inita(ctx, IsaacSeed, 16);
  end
  else
    isaac_init(ctx, msC xor JD);
  {$ELSE}
  isaac_init(ctx, msC xor JD);
  {$ENDIF}
  Randomize;
  for i := 0 to (Random(255) + 1) do   // do not just pick the first here
    isaac := isaac_long(ctx);
  Whirl_Init(sctx);
  Whirl_Update(sctx, @Ctr, SizeOf(Ctr));
  Whirl_Update(sctx, @JD, SizeOf(JD));
  Whirl_Update(sctx, @msC, SizeOf(msC));
  Whirl_Update(sctx, @isaac, SizeOf(isaac));
  Whirl_Update(sctx, @randseed, SizeOf(randseed));
  Whirl_Final(sctx, sdig);
  move(sdig, salt, SizeOf(salt));
end;

//=================================================================================================
{$IFDEF CAMELLIA}
procedure GetSaltCAM(var salt: TFCACAMSalt);      // Whirlpool Salt for Camellia
var
  Ctr: TCtrRec;
  JD, msC, isaac: longint;
  sctx: THashContext;
  sdig: TWhirlDigest;
  ctx: isaac_ctx;
  i: integer;
  WD: TWhirlDigest;
  IsaacSeed: array[0..15] of LongInt;
begin
  // Hash Date, Time, Randseed, TSC and Isaac PRNG
  _ReadCounter(Ctr);
  JD := CurrentJulianDay;
  msC := msCount;
  {$IFDEF WINDOWS}
  if CollectRND(WD) then
  begin
    move(WD, IsaacSeed, SizeOf(IsaacSeed));
    // Feed Isaac with our seeds
    isaac_inita(ctx, IsaacSeed, 16);
  end
  else
    isaac_init(ctx, msC xor JD);
  {$ELSE}
  isaac_init(ctx, msC xor JD);
  {$ENDIF}
  Randomize;
  for i := 0 to (Random(255) + 1) do   // do not just pick the first here
    isaac := isaac_long(ctx);
  Whirl_Init(sctx);
  Whirl_Update(sctx, @Ctr, SizeOf(Ctr));
  Whirl_Update(sctx, @JD, SizeOf(JD));
  Whirl_Update(sctx, @msC, SizeOf(msC));
  Whirl_Update(sctx, @isaac, SizeOf(isaac));
  Whirl_Update(sctx, @randseed, SizeOf(randseed));
  Whirl_Final(sctx, sdig);
  move(sdig, salt, SizeOf(salt));
end;

{$ENDIF}

//=================================================================================================
function DecWriteAES(bufp, userdata: pointer; size: word): longint;
  // Callback: write to output file
var
  n: longword;
begin
  n := PFCUserAES(Userdata)^.fo.Write(bufp^, size);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
end;

//=================================================================================================
function DecReadAES(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file and decrypt
var
  nread: longword;
  nmax: word;
begin
  if PFCUserAES(Userdata)^.Rest > mlen then
    nmax := mlen
  else
    nmax := PFCUserAES(Userdata)^.Rest;
  // read encrypted input, use and update rest
  nread := PFCUserAES(Userdata)^.fi.Read(bufp^, nmax);
  // decrypt
  Result := nread;
  Dec(PFCUserAES(Userdata)^.Rest, nread);
  done := PFCUserAES(Userdata)^.fi.position >= PFCUserAES(Userdata)^.fi.size;
  if FCA_EAXAES_decrypt(PFCUserAES(Userdata)^.cxe, bufp^, nread) <> 0 then
    raise Exception.Create('FCA_EAX_decrypt');
end;

//=================================================================================================
{$IFDEF CAMELLIA}
function DecWriteCAM(bufp, userdata: pointer; size: word): longint;
  // Callback: write to output file
var
  n: longword;
begin
  n := PFCUserCAM(Userdata)^.fo.Write(bufp^, size);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
end;

//=================================================================================================
function DecReadCAM(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file and decrypt
var
  nread: longword;
  nmax: word;
begin
  if PFCUserCAM(Userdata)^.Rest > mlen then
    nmax := mlen
  else
    nmax := PFCUserCAM(Userdata)^.Rest;
  // read encrypted input, use and update rest
  nread := PFCUserCAM(Userdata)^.fi.Read(bufp^, nmax);
  // decrypt
  Result := nread;
  Dec(PFCUserCAM(Userdata)^.Rest, nread);
  done := PFCUserCAM(Userdata)^.fi.position >= PFCUserCAM(Userdata)^.fi.size;
  if FCA_EAXCAM_decrypt(PFCUserCAM(Userdata)^.cxe, bufp^, nread) <> 0 then
    raise Exception.Create('FCA_EAX_decrypt');
end;

{$ENDIF}

//=================================================================================================
function DecWriteTF(bufp, userdata: pointer; size: word): longint;
  //Callback: write to output file
var
  n: longword;
begin
  n := PFCUserTF(Userdata)^.fo.Write(bufp^, size);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
end;

//=================================================================================================
function DecReadTF(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file and decrypt
var
  nread: longword;
  nmax: word;
begin
  if PFCUserTF(Userdata)^.Rest > mlen then
    nmax := mlen
  else
    nmax := PFCUserTF(Userdata)^.Rest;
  // read encrypted input, use and update rest
  nread := PFCUserTF(Userdata)^.fi.Read(bufp^, nmax);
  // decrypt
  Result := nread;
  Dec(PFCUserTF(Userdata)^.Rest, nread);
  done := PFCUserTF(Userdata)^.fi.position >= PFCUserTF(Userdata)^.fi.size;
  if FCA_EAXTF_decrypt(PFCUserTF(Userdata)^.cxe, bufp^, nread) <> 0 then
    raise Exception.Create('FCA_EAX_decrypt');
end;

//=================================================================================================
function DecWriteSP(bufp, userdata: pointer; size: word): longint;
  //Callback: write to output file
var
  n: longword;
begin
  n := PFCUserSP(Userdata)^.fo.Write(bufp^, size);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
end;

//=================================================================================================
function DecReadSP(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file and decrypt
var
  nread: longword;
  nmax: word;
begin
  if PFCUserSP(Userdata)^.Rest > mlen then
    nmax := mlen
  else
    nmax := PFCUserSP(Userdata)^.Rest;
  // read encrypted input, use and update rest
  nread := PFCUserSP(Userdata)^.fi.Read(bufp^, nmax);
  // decrypt
  Result := nread;
  Dec(PFCUserSP(Userdata)^.Rest, nread);
  done := PFCUserSP(Userdata)^.fi.position >= PFCUserSP(Userdata)^.fi.size;
  if FCA_EAXSP_decrypt(PFCUserSP(Userdata)^.cxe, bufp^, nread) <> 0 then
    raise Exception.Create('FCA_EAX_decrypt');
end;

//=================================================================================================
function EncReadAES(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file
var
  n: longword;
begin
  // read unencrypted input
  n := PFCUserAES(Userdata)^.fi.Read(bufp^, mlen);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
  done := PFCUserAES(Userdata)^.fi.position >= PFCUserAES(Userdata)^.fi.size;
end;

//=================================================================================================
function EncWriteAES(bufp, userdata: pointer; size: word): longint;
  // Callback: encrypt bufp, write to output file
var
  n: longword;
begin
  if FCA_EAXAES_encrypt(PFCUserAES(Userdata)^.cxe, bufp^, size) <> 0 then
    raise Exception.Create('FCA_EAX_encrypt');
  n := PFCUserAES(Userdata)^.fo.Write(bufp^, size);
  Result := n;
end;

//=================================================================================================
{$IFDEF CAMELLIA}
function EncReadCAM(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file
var
  n: longword;
begin
  // read unencrypted input
  n := PFCUserCAM(Userdata)^.fi.Read(bufp^, mlen);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
  done := PFCUserCAM(Userdata)^.fi.position >= PFCUserCAM(Userdata)^.fi.size;
end;

//=================================================================================================
function EncWriteCAM(bufp, userdata: pointer; size: word): longint;
  // Callback: encrypt bufp, write to output file
var
  n: longword;
begin
  if FCA_EAXCAM_encrypt(PFCUserCAM(Userdata)^.cxe, bufp^, size) <> 0 then
    raise Exception.Create('FCA_EAX_encrypt');
  n := PFCUserCAM(Userdata)^.fo.Write(bufp^, size);
  Result := n;
end;

{$ENDIF}
//=================================================================================================
function EncReadTF(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file
var
  n: longword;
begin
  // read unencrypted input
  n := PFCUserTF(Userdata)^.fi.Read(bufp^, mlen);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
  done := PFCUserTF(Userdata)^.fi.position >= PFCUserTF(Userdata)^.fi.size;
end;

//=================================================================================================
function EncWriteTF(bufp, userdata: pointer; size: word): longint;
  // Callback: encrypt bufp, write to output file
var
  n: longword;
begin
  if FCA_EAXTF_encrypt(PFCUserTF(Userdata)^.cxe, bufp^, size) <> 0 then
    raise Exception.Create('FCA_EAX_encrypt');
  n := PFCUserTF(Userdata)^.fo.Write(bufp^, size);
  Result := n;
end;

//=================================================================================================
function EncReadSP(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
  // Callback: read from input file
var
  n: longword;
begin
  // read unencrypted input
  n := PFCUserSP(Userdata)^.fi.Read(bufp^, mlen);
  ProgCounter := ProgCounter + n;
  frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
  Application.ProcessMessages;
  Result := n;
  done := PFCUserSP(Userdata)^.fi.position >= PFCUserSP(Userdata)^.fi.size;
end;

//=================================================================================================
function EncWriteSP(bufp, userdata: pointer; size: word): longint;
  // Callback: encrypt bufp, write to output file
var
  n: longword;
begin
  if FCA_EAXSP_encrypt(PFCUserSP(Userdata)^.cxe, bufp^, size) <> 0 then
    raise Exception.Create('FCA_EAX_encrypt');
  n := PFCUserSP(Userdata)^.fo.Write(bufp^, size);
  Result := n;
end;

//=================================================================================================
procedure TfrmMain.Shredder(fn: string);
begin
  LoadConfig;
  case Wipe of
    0: ShredderFileZero(fn);
    1: ShredderFilePRNG(fn);
    2: ShredderFileDoD3(fn);
    3: ShredderFileVSITR(fn);
    4: ShredderFileDoD7(fn);
  end;
end;

//=================================================================================================
function ShredderTree(Dir: string): boolean;

  procedure Del(const Dir: string);
  var
    SearchRec: TSearchRec;
    Found: cardinal;
  begin
    FindFirstUTF8(Dir + '*', faAnyFile, SearchRec);
    FindNextUTF8(SearchRec);
    Found := FindNext(SearchRec);
    while (Found = 0) do
    begin
      if (SearchRec.Attr and faDirectory > 0) then
        Del(Dir + IncludeTrailingPathDelimiter(SearchRec.Name))
      else
        frmMain.Shredder(Dir + SearchRec.Name);
      Found := FindNext(SearchRec);
    end;
    FindCloseUTF8(SearchRec);
    RemoveDirUTF8(dir);
  end;

begin
  Dir := IncludeTrailingPathDelimiter(Dir);
  Result := True;
  if DirectoryExists(Dir) then
  begin
    Del(Dir);
    if DirectoryExistsUTF8(Dir) then
      Result := False;
  end
  else
    Result := False;
end;

//=================================================================================================
procedure TfrmMain.RandomRename(fn: string);
var
  path: string;
  newname: string;
begin
  path := ExtractFilePath(fn);
  repeat
    newname := ReturnTempFilename(15);
    newname := LeftStr(newname, 11);
    newname := RightStr(newname, 8) + '.sce';
  until not FileexistsUTF8(path + newname);
  RenameFileUTF8(fn, path + newname);
end;

//=================================================================================================
procedure TfrmMain.EncryptAES(const sPW, InName, OutName: string);
// Encrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdr: TFCAAESHdr;
  auth: TFCAAES_AuthBlock;
  User: TFCUserAES;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Randomize;
  lblInfo.Caption := 'Encypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
  User.fo.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName);

    Meta.Filename := ExtractFilename(Inname);
    Meta.Age := FileAgeUTF8(Inname);

    GetSaltAES(hdr.salt);

    hdr.Flags := $00;

    UseZL := Compression and not (AnsiMatchStr(ExtractFileExt(Inname), CompFiles));

    if UseZL then
      hdr.Flags := hdr.Flags or $80;

    if FCA_EAXAES_initS(User.cxe, sPW, hdr, Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    User.fo.WriteBuffer(hdr, SizeOf(hdr));

    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;


    if UseZL then
    begin
      DeflateEx(@EncReadAES, @EncWriteAES, CompressionLevel, @User);
    end
    else
    begin
      while User.Rest > 0 do
      begin
        if User.Rest > SizeOf(buf) then
          n := SizeOf(buf)
        else
          n := User.Rest;

        User.fi.ReadBuffer(buf, n);

        Dec(User.Rest, n);

        if FCA_EAXAES_encrypt(User.cxe, buf, n) <> 0 then
          raise Exception.Create('FCA_EAX_encrypt');

        User.fo.WriteBuffer(buf, n);

        ProgCounter := ProgCounter + n;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
      end;
    end;


    //move and encrypt Metablock then write it to output file
    Move(Meta, buf[0], SizeOf(Meta));
    if FCA_EAXAES_encrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_encrypt');

    User.fo.WriteBuffer(buf, SizeOf(Meta));

    FCA_EAXAES_final(User.cxe, auth);
    User.fo.WriteBuffer(auth, SizeOf(auth));

  finally
    User.fo.Free;
    User.fi.Free;
  end;
end;

//=================================================================================================
function TfrmMain.DecryptAES(const sPW, InName, OutName: string): boolean;
var
  n: word; // read/write counter
  hdrk: TFCAAESHdr; // hdr from key deriv
  hdrf: TFCAAESHdr; // hdr from file deriv
  authf: TFCAAES_AuthBlock;
  authc: TFCAAES_AuthBlock;
  User: TFCUserAES;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Result := False;
  lblInfo.Caption := 'Decypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName) - SizeOf(hdrf) - SizeOf(authf) - SizeOf(Meta);

    User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

    if (hdrf.FCASig <> C_FCA_Sig) then
    begin
      MessageDlg('StrongCrypt-FE', ErrorSig, mtError, [mbOK], 0);
      Exit;
    end;

    hdrk := hdrf;

    if FCA_EAXAES_initS(User.cxe, sPW, hdrk, hdrf.Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    if hdrf.PW_ver <> hdrk.PW_ver then
    begin
      MessageDlg('StrongCrypt-FE', InName + #13#10 + ErrorPwd, mtError, [mbOK], 0);
      Exit;
    end;


    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    lblInfo.Caption := 'Decypting: ' + ExtractFilename(Inname);

    UseZL := hdrf.Flags and $80 <> 0;

    User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
    User.fo.Seek(0, soFromBeginning);

    try
      if UseZL then
      begin
        InflateEx(@DecReadAES, @DecWriteAES, @User);
      end
      else
      begin
        while User.Rest > 0 do
        begin
          if User.Rest > SizeOf(buf) then
            n := SizeOf(buf)
          else
            n := User.Rest;
          User.fi.ReadBuffer(buf, n);

          Dec(User.Rest, n);

          if FCA_EAXAES_decrypt(User.cxe, buf, n) <> 0 then
            raise Exception.Create('FCA_EAX_decrypt');

          User.fo.WriteBuffer(buf, n);
          ProgCounter := ProgCounter + n;
          frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
          Application.ProcessMessages;
        end;
      end;
    finally
      User.fo.Free;
    end;
    User.fi.ReadBuffer(buf, SizeOf(Meta));
    if FCA_EAXAES_decrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_decrypt');

    Move(buf, Meta, SizeOf(Meta));

    FFileName := Meta.FileName;
    FAge := Meta.Age;

    FCA_EAXAES_final(User.cxe, authc);

    User.fi.ReadBuffer(authf, SizeOf(authf));

    Result := CompMem(@authf, @authc, SizeOf(authf));
    if not Result then
      MessageDlg('StrongCrypt-FE', ErrorAut, mtError, [mbOK], 0);

  finally
    User.fi.Free;
    if not Result and (FileExistsUTF8(OutName)) then
      Shredder(OutName);
  end;

end;

//=================================================================================================
{$IFDEF CAMELLIA}
procedure TfrmMain.EncryptCAM(const sPW, InName, OutName: string);
// Encrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdr: TFCACAMHdr;
  auth: TFCACAM_AuthBlock;
  User: TFCUserCAM;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Randomize;
  lblInfo.Caption := 'Encypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
  User.fo.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName);

    Meta.Filename := ExtractFilename(Inname);
    Meta.Age := FileAgeUTF8(Inname);

    GetSaltCAM(hdr.salt);

    hdr.Flags := $00;

    UseZL := Compression and not (AnsiMatchStr(ExtractFileExt(Inname), CompFiles));

    if UseZL then
      hdr.Flags := hdr.Flags or $80;

    if FCA_EAXCAM_initS(User.cxe, sPW, hdr, Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    User.fo.WriteBuffer(hdr, SizeOf(hdr));

    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;


    if UseZL then
    begin
      DeflateEx(@EncReadCAM, @EncWriteCAM, CompressionLevel, @User);
    end
    else
    begin
      while User.Rest > 0 do
      begin
        if User.Rest > SizeOf(buf) then
          n := SizeOf(buf)
        else
          n := User.Rest;

        User.fi.ReadBuffer(buf, n);

        Dec(User.Rest, n);

        if FCA_EAXCAM_encrypt(User.cxe, buf, n) <> 0 then
          raise Exception.Create('FCA_EAX_encrypt');

        User.fo.WriteBuffer(buf, n);

        ProgCounter := ProgCounter + n;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
      end;
    end;


    //move and encrypt Metablock then write it to output file
    Move(Meta, buf[0], SizeOf(Meta));
    if FCA_EAXCAM_encrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_encrypt');

    User.fo.WriteBuffer(buf, SizeOf(Meta));

    FCA_EAXCAM_final(User.cxe, auth);
    User.fo.WriteBuffer(auth, SizeOf(auth));

  finally
    User.fo.Free;
    User.fi.Free;
  end;
end;

//=================================================================================================
function TfrmMain.DecryptCAM(const sPW, InName, OutName: string): boolean;
var
  n: word; // read/write counter
  hdrk: TFCACAMHdr; // hdr from key deriv
  hdrf: TFCACAMHdr; // hdr from file deriv
  authf: TFCACAM_AuthBlock;
  authc: TFCACAM_AuthBlock;
  User: TFCUserCAM;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Result := False;
  lblInfo.Caption := 'Decypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName) - SizeOf(hdrf) - SizeOf(authf) - SizeOf(Meta);

    User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

    if (hdrf.FCASig <> C_FCA_Sig) then
    begin
      MessageDlg('StrongCrypt-FE', ErrorSig, mtError, [mbOK], 0);
      Exit;
    end;

    hdrk := hdrf;

    if FCA_EAXCAM_initS(User.cxe, sPW, hdrk, hdrf.Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    if hdrf.PW_ver <> hdrk.PW_ver then
    begin
      MessageDlg('StrongCrypt-FE', InName + #13#10 + ErrorPwd, mtError, [mbOK], 0);
      Exit;
    end;


    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;
    lblInfo.Caption := 'Decypting: ' + ExtractFilename(Inname);

    UseZL := hdrf.Flags and $80 <> 0;

    User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
    User.fo.Seek(0, soFromBeginning);

    try
      if UseZL then
      begin
        InflateEx(@DecReadCAM, @DecWriteCAM, @User);
      end
      else
      begin
        while User.Rest > 0 do
        begin
          if User.Rest > SizeOf(buf) then
            n := SizeOf(buf)
          else
            n := User.Rest;
          User.fi.ReadBuffer(buf, n);

          Dec(User.Rest, n);

          if FCA_EAXCAM_decrypt(User.cxe, buf, n) <> 0 then
            raise Exception.Create('FCA_EAX_decrypt');

          User.fo.WriteBuffer(buf, n);
          ProgCounter := ProgCounter + n;
          frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
          Application.ProcessMessages;
        end;
      end;
    finally
      User.fo.Free;
    end;
    User.fi.ReadBuffer(buf, SizeOf(Meta));
    if FCA_EAXCAM_decrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_decrypt');

    Move(buf, Meta, SizeOf(Meta));

    FFileName := Meta.FileName;
    FAge := Meta.Age;

    FCA_EAXCAM_final(User.cxe, authc);

    User.fi.ReadBuffer(authf, SizeOf(authf));

    Result := CompMem(@authf, @authc, SizeOf(authf));
    if not Result then
      MessageDlg('StrongCrypt-FE', ErrorAut, mtError, [mbOK], 0);

  finally
    User.fi.Free;
    if not Result and (FileExistsUTF8(OutName)) then
      Shredder(OutName);
  end;

end;

{$ENDIF}

//=================================================================================================
procedure TfrmMain.EncryptTF(const sPW, InName, OutName: string);
// Encrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdr: TFCATFHdr;
  auth: TFCATF_AuthBlock;
  User: TFCUserTF;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Randomize;
  lblInfo.Caption := 'Encypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
  User.fo.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName);

    Meta.Filename := ExtractFilename(Inname);
    Meta.Age := FileAgeUTF8(Inname);

    GetSaltTF(hdr.salt);

    hdr.Flags := $00;

    UseZL := Compression and not (AnsiMatchStr(ExtractFileExt(Inname), CompFiles));

    if UseZL then
      hdr.Flags := hdr.Flags or $80;

    if FCA_EAXTF_initS(User.cxe, sPW, hdr, Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    User.fo.WriteBuffer(hdr, SizeOf(hdr));

    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;

    if UseZL then
    begin
      DeflateEx(@EncReadTF, @EncWriteTF, CompressionLevel, @User);
    end
    else
    begin
      while User.Rest > 0 do
      begin
        if User.Rest > SizeOf(buf) then
          n := SizeOf(buf)
        else
          n := User.Rest;

        User.fi.ReadBuffer(buf, n);

        Dec(User.Rest, n);

        if FCA_EAXTF_encrypt(User.cxe, buf, n) <> 0 then
          raise Exception.Create('FCA_EAX_encrypt');

        User.fo.WriteBuffer(buf, n);

        ProgCounter := ProgCounter + n;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
      end;
    end;


    //move and encrypt Metablock then write it to output file
    Move(Meta, buf[0], SizeOf(Meta));
    if FCA_EAXTF_encrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_encrypt');

    User.fo.WriteBuffer(buf, SizeOf(Meta));

    FCA_EAXTF_final(User.cxe, auth);
    User.fo.WriteBuffer(auth, SizeOf(auth));

  finally
    User.fo.Free;
    User.fi.Free;
  end;
end;

//=================================================================================================
function TfrmMain.DecryptTF(const sPW, InName, OutName: string): boolean;
  // Decrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdrk: TFCATFHdr; //hdr from key deriv
  hdrf: TFCATFHdr; //hdr from file deriv
  authf: TFCATF_AuthBlock;
  authc: TFCATF_AuthBlock;
  User: TFCUserTF;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Result := False;
  lblInfo.Caption := 'Decypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  try

    User.Rest := FileSize(InName) - SizeOf(hdrf) - SizeOf(authf) - SizeOf(Meta);

    User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

    if (hdrf.FCASig <> C_FCA_Sig) then
    begin
      MessageDlg('StrongCrypt-FE', ErrorSig, mtError, [mbOK], 0);
      Exit;
    end;

    hdrk := hdrf;

    if FCA_EAXTF_initS(User.cxe, sPW, hdrk, hdrf.Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    if hdrf.PW_ver <> hdrk.PW_ver then
    begin
      MessageDlg('StrongCrypt-FE', InName + #13#10 + ErrorPwd, mtError, [mbOK], 0);
      Exit;
    end;


    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;

    UseZL := hdrf.Flags and $80 <> 0;

    User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
    User.fo.Seek(0, soFromBeginning);

    try
      if UseZL then
      begin
        InflateEx(@DecReadTF, @DecWriteTF, @User);
      end
      else
      begin
        while User.Rest > 0 do
        begin
          if User.Rest > SizeOf(buf) then
            n := SizeOf(buf)
          else
            n := User.Rest;
          User.fi.ReadBuffer(buf, n);

          Dec(User.Rest, n);

          if FCA_EAXTF_decrypt(User.cxe, buf, n) <> 0 then
            raise Exception.Create('FCA_EAX_decrypt');

          User.fo.WriteBuffer(buf, n);
          ProgCounter := ProgCounter + n;
          frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
          Application.ProcessMessages;
        end;
      end;

    finally
      User.fo.Free;
    end;

    User.fi.ReadBuffer(buf, SizeOf(Meta));
    if FCA_EAXTF_decrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_decrypt');

    Move(buf, Meta, SizeOf(Meta));

    FFileName := Meta.FileName;
    FAge := Meta.Age;

    FCA_EAXTF_final(User.cxe, authc);

    User.fi.ReadBuffer(authf, SizeOf(authf));

    Result := CompMem(@authf, @authc, SizeOf(authf));
    if not Result then
      MessageDlg('StrongCrypt-FE', ErrorAut, mtError, [mbOK], 0);

  finally
    User.fi.Free;
    if not Result and (FileExistsUTF8(OutName)) then
      Shredder(OutName);
  end;

end;

//=================================================================================================
procedure TfrmMain.EncryptSP(const sPW, InName, OutName: string);
// Encrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdr: TFCASPHdr;
  auth: TFCASP_AuthBlock;
  User: TFCUserSP;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Randomize;
  lblInfo.Caption := 'Encypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
  User.fo.Seek(0, soFromBeginning);

  try
    User.Rest := FileSize(InName);

    Meta.Filename := ExtractFilename(Inname);
    Meta.Age := FileAgeUTF8(Inname);

    GetSaltSP(hdr.salt);

    hdr.Flags := $00;

    UseZL := Compression and not (AnsiMatchStr(ExtractFileExt(Inname), CompFiles));

    if UseZL then
      hdr.Flags := hdr.Flags or $80;

    if FCA_EAXSP_initS(User.cxe, sPW, hdr, Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    User.fo.WriteBuffer(hdr, SizeOf(hdr));

    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;



    if UseZL then
    begin
      DeflateEx(@EncReadSP, @EncWriteSP, CompressionLevel, @User);
    end
    else
    begin
      while User.Rest > 0 do
      begin
        if User.Rest > SizeOf(buf) then
          n := SizeOf(buf)
        else
          n := User.Rest;

        User.fi.ReadBuffer(buf, n);

        Dec(User.Rest, n);

        if FCA_EAXSP_encrypt(User.cxe, buf, n) <> 0 then
          raise Exception.Create('FCA_EAX_encrypt');

        User.fo.WriteBuffer(buf, n);

        ProgCounter := ProgCounter + n;
        frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
        Application.ProcessMessages;
      end;
    end;


    //move and encrypt Metablock then write it to output file
    Move(Meta, buf[0], SizeOf(Meta));
    if FCA_EAXSP_encrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_encrypt');

    User.fo.WriteBuffer(buf, SizeOf(Meta));

    FCA_EAXSP_final(User.cxe, auth);
    User.fo.WriteBuffer(auth, SizeOf(auth));

  finally
    User.fo.Free;
    User.fi.Free;
  end;
end;

//=================================================================================================
function TfrmMain.DecryptSP(const sPW, InName, OutName: string): boolean;
  // Decrypt file InName to OutName using password sPW
var
  n: word; //read/write counter
  hdrk: TFCASPHdr; //hdr from key deriv
  hdrf: TFCASPHdr; //hdr from file deriv
  authf: TFCASP_AuthBlock;
  authc: TFCASP_AuthBlock;
  User: TFCUserSP;
  UseZL: boolean;
  Meta: TMetaBlock;
begin
  Result := False;
  lblInfo.Caption := 'Decrypting: ' + ExtractFilename(Inname);
  frmMain.prbProgress.Position := 0;
  User.fi := TFileStreamUTF8.Create(Inname, fmOpenRead);
  User.fi.Seek(0, soFromBeginning);

  try

    User.Rest := FileSize(InName) - SizeOf(hdrf) - SizeOf(authf) - SizeOf(Meta);

    User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

    if (hdrf.FCASig <> C_FCA_Sig) then
    begin
      MessageDlg('StrongCrypt-FE', ErrorSig, mtError, [mbOK], 0);
      Exit;
    end;

    hdrk := hdrf;

    if FCA_EAXSP_initS(User.cxe, sPW, hdrk, hdrf.Iterations) <> 0 then
      raise Exception.Create('FCA_EAX_init');

    if hdrf.PW_ver <> hdrk.PW_ver then
    begin
      MessageDlg('StrongCrypt-FE', InName + #13#10 + ErrorPwd, mtError, [mbOK], 0);
      Exit;
    end;


    FileLength := User.Rest;
    frmMain.prbProgress.Max := 1000;
    frmMain.prbProgress.Min := 0;
    ProgCounter := 0;


    UseZL := hdrf.Flags and $80 <> 0;

    User.fo := TFileStreamUTF8.Create(OutName, fmCreate);
    User.fo.Seek(0, soFromBeginning);
    try
      if UseZL then
      begin
        InflateEx(@DecReadSP, @DecWriteSP, @User);
      end
      else
      begin
        while User.Rest > 0 do
        begin
          if User.Rest > SizeOf(buf) then
            n := SizeOf(buf)
          else
            n := User.Rest;
          User.fi.ReadBuffer(buf, n);

          Dec(User.Rest, n);

          if FCA_EAXSP_decrypt(User.cxe, buf, n) <> 0 then
            raise Exception.Create('FCA_EAX_decrypt');

          User.fo.WriteBuffer(buf, n);
          ProgCounter := ProgCounter + n;
          frmMain.prbProgress.Position := Round(ProgCounter / FileLength * 1000);
          Application.ProcessMessages;
        end;
      end;

    finally
      User.fo.Free;
    end;

    User.fi.ReadBuffer(buf, SizeOf(Meta));
    if FCA_EAXSP_decrypt(User.cxe, buf, SizeOf(Meta)) <> 0 then
      raise Exception.Create('FCA_EAX_decrypt');

    Move(buf, Meta, SizeOf(Meta));

    FFileName := Meta.FileName;
    FAge := Meta.Age;

    FCA_EAXSP_final(User.cxe, authc);

    User.fi.ReadBuffer(authf, SizeOf(authf));

    Result := CompMem(@authf, @authc, SizeOf(authf));
    if not Result then
      MessageDlg('StrongCrypt-FE', ErrorAut, mtError, [mbOK], 0);

  finally
    User.fi.Free;
    if not Result and (FileExistsUTF8(OutName)) then
      Shredder(OutName);
  end;

end;

//=================================================================================================
procedure TfrmMain.actDecryptExecute(Sender: TObject);
var
  i: integer;
  j: integer;
  Passwd: string;
  Dec, Ori: string;
  hdrf: TFCATFHdr;
  User: TFCUserAES;
  Algo: byte;
  fn: string;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    dlgOpen.Title := TitleDec;
    dlgOpen.Filter := Filter2;
    dlgOpen.Options := dlgOpen.Options + [ofAllowMultiSelect];
    if dlgOpen.Execute then
    begin
      if frmDecrypt.ShowModal = mrOk then
      begin
        Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text);

        if FileExistsUTF8(frmDecrypt.edtKeyfile.Text) then
          Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text) + HashFile(frmDecrypt.edtKeyfile.Text);

        frmDecrypt.edtPasswd.Text := '';
        frmDecrypt.edtKeyfile.Text := '';

      {$IFDEF WINDOWS}
        VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

        frmDecrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        frmDecrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      {$ELSE}
        mlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
      {$ENDIF}
        prbProgress.Visible := True;
        lblInfo.Visible := True;
        try
          for i := 0 to dlgOpen.Files.Count - 1 do
          begin
            if not (DirectoryExistsUTF8(dlgOpen.Files[i])) then
            begin
              User.fi := TFileStreamUTF8.Create(dlgOpen.Files[i], fmOpenRead);
              User.fi.Seek(0, soFromBeginning);
              try
                User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

                if hdrf.Flags and $01 <> 0 then
                  Algo := 1;

                if hdrf.Flags and $02 <> 0 then
                  Algo := 2;

                if hdrf.Flags and $04 <> 0 then
                  Algo := 4;


              {$IFDEF CAMELLIA}
                if hdrf.Flags and $20 <> 0 then
                  Algo := 32;
              {$ENDIF}

              finally
                User.fi.Free;
              end;

              Dec := AddSlash(ExtractFileDir(dlgOpen.Files[i])) + ReturnTempFilename(8);
              Ori := dlgOpen.Files[i];

              prbProgress.Max := 1000;

              case Algo of
                1: if not DecryptAES(Passwd, Ori, Dec) then
                    continue;
                2: if not DecryptTF(Passwd, Ori, Dec) then
                    continue;
                4: if not DecryptSP(Passwd, Ori, Dec) then
                    continue;
              {$IFDEF CAMELLIA}
                32: if not DecryptCAM(Passwd, Ori, Dec) then
                    continue;
              {$ENDIF}
              end;

              Shredder(Ori);

              j := 2;
              repeat
                fn := ExtractFilePath(Dec) + FFilename;
                if FileExistsUTF8(fn) then
                  fn := ChangeFileExt(fn, '') + '(' + IntToStr(j) + ')' + ExtractFileExt(fn);
                Inc(j);
              until not FileExistsUTF8(fn);

              RenameFileUTF8(Dec, fn);
              FileSetDateUTF8(fn, FAge);

            end;
          end;

        finally
          FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);
        {$IFDEF WINDOWS}
          VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
        {$ELSE}
          munlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
        {$ENDIF}
          prbProgress.Visible := False;
          lblInfo.Visible := False;
        end;
      end;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.actDecryptFolderExecute(Sender: TObject);
var
  i: integer;
  j: integer;
  Passwd: string;
  Dec, Ori: string;
  hdrf: TFCATFHdr;
  User: TFCUserAES;
  Algo: byte;
  fn: string;
  list: TStrings;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    list := TStringList.Create;
    dlgFolder.Title := TitleDec;
    if dlgFolder.Execute then
    begin
      if frmDecrypt.ShowModal = mrOk then
      begin
        Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text);

        if FileExistsUTF8(frmDecrypt.edtKeyfile.Text) then
          Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text) + HashFile(frmDecrypt.edtKeyfile.Text);

        frmDecrypt.edtPasswd.Text := '';
        frmDecrypt.edtKeyfile.Text := '';

      {$IFDEF WINDOWS}
        VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

        frmDecrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        frmDecrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      {$ELSE}
        mlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
      {$ENDIF}

        prbProgress.Visible := True;
        lblInfo.Visible := True;

        try
          Scandirectory(dlgFolder.FileName, list);

          for i := 0 to list.Count - 1 do
          begin
            if not (DirectoryExistsUTF8(list.Strings[i])) and (ExtractFileExt(list.Strings[i]) = '.sce') then
            begin

              User.fi := TFileStreamUTF8.Create(list.Strings[i], fmOpenRead);
              User.fi.Seek(0, soFromBeginning);
              try
                User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

                if hdrf.Flags and $01 <> 0 then
                  Algo := 1;

                if hdrf.Flags and $02 <> 0 then
                  Algo := 2;

                if hdrf.Flags and $04 <> 0 then
                  Algo := 4;

              {$IFDEF CAMELLIA}
                if hdrf.Flags and $20 <> 0 then
                  Algo := 32;
              {$ENDIF}

              finally
                User.fi.Free;
              end;

              Dec := AddSlash(ExtractFileDir(list.Strings[i])) + ReturnTempFilename(8);
              Ori := list.Strings[i];

              prbProgress.Max := 1000;

              case Algo of
                1: if not DecryptAES(Passwd, Ori, Dec) then
                    continue;
                2: if not DecryptTF(Passwd, Ori, Dec) then
                    continue;
                4: if not DecryptSP(Passwd, Ori, Dec) then
                    continue;
              {$IFDEF CAMELLIA}
                32: if not DecryptCAM(Passwd, Ori, Dec) then
                    continue;
              {$ENDIF}
              end;

              Shredder(Ori);

              j := 2;
              repeat
                fn := ExtractFilePath(Dec) + FFilename;
                if FileExistsUTF8(fn) then
                  fn := ChangeFileExt(fn, '') + '(' + IntToStr(j) + ')' + ExtractFileExt(fn);
                Inc(j);
              until not FileExistsUTF8(fn);

              RenameFileUTF8(Dec, fn);
              FileSetDateUTF8(fn, FAge);

            end;
          end;
        finally
          FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);
        {$IFDEF WINDOWS}
          VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
        {$ELSE}
          munlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
        {$ENDIF}
          list.Free;
          prbProgress.Visible := False;
          lblInfo.Visible := False;
        end;
      end;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.actEncryptExecute(Sender: TObject);
var
  i: integer;
  Passwd: string;
  Enc, Ori: string;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    dlgOpen.Title := TitleEnc;
    dlgOpen.Filter := Filter1;
    dlgOpen.Options := dlgOpen.Options + [ofAllowMultiSelect];
    if dlgOpen.Execute then
    begin
      if frmEncrypt.ShowModal = mrOk then
      begin
        Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text);

        if (frmEncrypt.chkKeyfile.Checked) and (FileExistsUTF8(frmEncrypt.edtKeyfile.Text)) then
          Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text) + HashFile(frmEncrypt.edtKeyfile.Text);

        frmEncrypt.edtPasswd.Text := '';
        frmEncrypt.edtConfirm.Text := '';
        frmEncrypt.edtKeyfile.Text := '';

      {$IFDEF WINDOWS}
        VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

        frmEncrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        frmEncrypt.edtConfirm.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        frmEncrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      {$ELSE}
        mlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
      {$ENDIF}

        prbProgress.Visible := True;
        lblInfo.Visible := True;

        try

          for i := 0 to dlgOpen.Files.Count - 1 do
          begin
            if not DirectoryExistsUTF8(dlgOpen.Files[i]) then
            begin

              Ori := dlgOpen.Files[i];

              if FileSize(Ori) = 0 then  // Skip empty files
                Continue;

              Enc := AddSlash(ExtractFileDir(dlgOpen.Files[i])) + ReturnTempFilename(8);

              LoadConfig;

              Algorithm := frmEncrypt.cboAlgo.ItemIndex;

              case Algorithm of
                0: EncryptAES(Passwd, Ori, Enc);
                1: EncryptTF(Passwd, Ori, Enc);
                2: EncryptSP(Passwd, Ori, Enc);
              {$IFDEF CAMELLIA}
                3: EncryptCam(Passwd, Ori, Enc);
              {$ENDIF}
              end;
            end;

            SaveConfig;

            Shredder(Ori);
            if ExtractFileExt(Ori) <> '.sce' then
              RenameFileUTF8(Enc, Ori + '.sce')
            else
              RenameFileUTF8(Enc, Ori);
          end;

        finally
          FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);
        {$IFDEF WINDOWS}
          VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
        {$ELSE}
          munlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
        {$ENDIF}
          prbProgress.Visible := False;
          lblInfo.Visible := False;
        end;
      end;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.WipeShell;
var
  i: integer;
  sl: TStrings;
  TempFile: string;
begin
  sl := TStringList.Create;

  if (Copy(ParamStr(2), 1, 1) = '@') then
    TempFile := (Copy(ParamStr(2), 2, MaxInt))
  else
    exit;
  sl.LoadFromFile(TempFile);
  Shredder(TempFile);
  prbProgress.Visible := True;
  lblInfo.Visible := True;
  try
    for i := 0 to sl.Count - 1 do
    begin
      if DirectoryExistsUTF8(sl.Strings[i]) then
        ShredderTree(sl.Strings[i])
      else
        Shredder(sl.Strings[i]);
    end;
  finally
    prbProgress.Visible := False;
    lblInfo.Visible := False;
    sl.Free;
    Application.Terminate;
  end;
end;

//=================================================================================================
procedure TfrmMain.RenameShell;

  function ReturnRandFilename(strLen: integer): string;
  var
    str: string;
  begin
    str := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    Result := '';
    repeat
      Result := Result + str[Random(Length(str)) + 1];
    until (Length(Result) = strLen);
  end;

var
  i: integer;
  Ren, Ori: string;
  list, sl: TStrings;
  TempFile: string;
begin
  list := TStringList.Create;
  sl := TStringList.Create;
  if (Copy(ParamStr(2), 1, 1) = '@') then
    TempFile := (Copy(ParamStr(2), 2, MaxInt))
  else
    exit;
  sl.LoadFromFile(TempFile);
  Shredder(TempFile);
  try
    for i := 0 to sl.Count - 1 do
    begin
      if DirectoryExistsUTF8(sl.Strings[i]) then
        Scandirectory(sl.Strings[i], list)
      else
        list.Add(sl.Strings[i]);
    end;

    for i := 0 to list.Count - 1 do
    begin
      if not DirectoryExistsUTF8(list.Strings[i]) then
      begin
        Ori := list.Strings[i];

        if (FileSize(Ori) = 0) or (ExtractFileExt(Ori) <> '.sce') then  // Skip empty files and non encrypted files.
          Continue;

        repeat
          Ren := AddSlash(ExtractFileDir(list.Strings[i])) + ReturnRandFilename(12);
        until not Fileexists(Ren);

        if FileExists(Ori) then
          RenameFileUTF8(Ori, Ren + '.sce');
      end;
    end;
  finally
    list.Free;
    sl.Free;
    Application.Terminate;
  end;
end;

//=================================================================================================
procedure TfrmMain.EncryptShell;
var
  i: integer;
  Passwd: string;
  Enc, Ori: string;
  list, sl: TStrings;
  TempFile: string;
begin
  list := TStringList.Create;
  sl := TStringList.Create;

  if (Copy(ParamStr(2), 1, 1) = '@') then
    TempFile := (Copy(ParamStr(2), 2, MaxInt))
  else
    exit;
  sl.LoadFromFile(TempFile);
  Shredder(TempFile);
  try
    if frmEncrypt.ShowModal = mrOk then
    begin
      Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text);

      if (frmEncrypt.chkKeyfile.Checked) and (FileExistsUTF8(frmEncrypt.edtKeyfile.Text)) then
        Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text) + HashFile(frmEncrypt.edtKeyfile.Text);

      frmEncrypt.edtPasswd.Text := '';
      frmEncrypt.edtConfirm.Text := '';
      frmEncrypt.edtKeyfile.Text := '';

      {$IFDEF WINDOWS}
      VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

      frmEncrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      frmEncrypt.edtConfirm.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      frmEncrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
      {$ENDIF}

      for i := 0 to sl.Count - 1 do
      begin
        if DirectoryExistsUTF8(sl.Strings[i]) then
          Scandirectory(sl.Strings[i], list)
        else
          list.Add(sl.Strings[i]);
      end;

      prbProgress.Visible := True;
      lblInfo.Visible := True;
      for i := 0 to list.Count - 1 do
      begin
        if not DirectoryExistsUTF8(list.Strings[i]) then
        begin
          Ori := list.Strings[i];

          if FileSize(Ori) = 0 then  // Skip empty files
            Continue;

          Enc := AddSlash(ExtractFileDir(list.Strings[i])) + ReturnTempFilename(8);

          LoadConfig;

          Algorithm := frmEncrypt.cboAlgo.ItemIndex;

          case Algorithm of
            0: EncryptAES(Passwd, Ori, Enc);
            1: EncryptTF(Passwd, Ori, Enc);
            2: EncryptSP(Passwd, Ori, Enc);
            {$IFDEF CAMELLIA}
            3: EncryptCam(Passwd, Ori, Enc);
            {$ENDIF}
          end;
        end;

        SaveConfig;

        if ParamStr(1) = '--enc=shell' then
          Shredder(Ori);

        if ExtractFileExt(Ori) <> '.sce' then
          RenameFileUTF8(Enc, Ori + '.sce')
        else
          RenameFileUTF8(Enc, Ori);
      end;
    end;
  finally
    prbProgress.Visible := False;
    lblInfo.Visible := False;
    list.Free;
    sl.Free;

    //Burn Password
    FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);

    {$IFDEF WINDOWS}
    VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
    {$ENDIF}

    Application.Terminate;
  end;
end;

//=================================================================================================
procedure TfrmMain.DecryptShell;
var
  i: integer;
  j: integer;
  Passwd: string;
  Dec, Ori: string;
  hdrf: TFCATFHdr;
  User: TFCUserAES;
  Algo: byte;
  fn: string;
  list, sl: TStrings;
  TempFile: string;
begin
  list := TStringList.Create;
  sl := TStringList.Create;

  if (Copy(ParamStr(2), 1, 1) = '@') then
    TempFile := (Copy(ParamStr(2), 2, MaxInt))
  else
    exit;

  sl.LoadFromFile(TempFile);
  Shredder(TempFile);
  try
    begin
      if frmDecrypt.ShowModal = mrOk then
      begin
        Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text);

        if FileExistsUTF8(frmDecrypt.edtKeyfile.Text) then
          Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text) + HashFile(frmDecrypt.edtKeyfile.Text);

        frmDecrypt.edtPasswd.Text := '';
        frmDecrypt.edtKeyfile.Text := '';

        {$IFDEF WINDOWS}
        VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

        frmDecrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        frmDecrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        {$ENDIF}

        for i := 0 to sl.Count - 1 do
        begin
          if DirectoryExistsUTF8(sl.Strings[i]) then
            Scandirectory(sl.Strings[i], list)
          else
            list.Add(sl.Strings[i]);
        end;

        prbProgress.Visible := True;
        lblInfo.Visible := True;
        for i := 0 to list.Count - 1 do
        begin
          if not (DirectoryExistsUTF8(list.Strings[i])) and (ExtractFileExt(list.Strings[i]) = '.sce') then
          begin

            User.fi := TFileStreamUTF8.Create(list.Strings[i], fmOpenRead);
            User.fi.Seek(0, soFromBeginning);
            try
              User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

              if hdrf.Flags and $01 <> 0 then
                Algo := 1;

              if hdrf.Flags and $02 <> 0 then
                Algo := 2;

              if hdrf.Flags and $04 <> 0 then
                Algo := 4;

              {$IFDEF CAMELLIA}
              if hdrf.Flags and $20 <> 0 then
                Algo := 32;
              {$ENDIF}

            finally
              User.fi.Free;
            end;

            Dec := AddSlash(ExtractFileDir(list.Strings[i])) + ReturnTempFilename(8);
            Ori := list.Strings[i];

            prbProgress.Max := 1000;

            case Algo of
              1: if not DecryptAES(Passwd, Ori, Dec) then
                  continue;
              2: if not DecryptTF(Passwd, Ori, Dec) then
                  continue;
              4: if not DecryptSP(Passwd, Ori, Dec) then
                  continue;
              {$IFDEF CAMELLIA}
              32: if not DecryptCAM(Passwd, Ori, Dec) then
                  continue;
              {$ENDIF}
            end;

            Shredder(Ori);

            j := 2;
            repeat
              fn := ExtractFilePath(Dec) + FFilename;
              if FileExistsUTF8(fn) then
                fn := ChangeFileExt(fn, '') + '(' + IntToStr(j) + ')' + ExtractFileExt(fn);
              Inc(j);
            until not FileExistsUTF8(fn);

            RenameFileUTF8(Dec, fn);
            FileSetDateUTF8(fn, FAge);

          end;
        end;
      end;
    end;
  finally
    prbProgress.Visible := False;
    lblInfo.Visible := False;
    sl.Free;
    List.Free;

    FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);

    {$IFDEF WINDOWS}
    VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
    {$ENDIF}

    Application.Terminate;
  end;
end;

//=================================================================================================
procedure TfrmMain.actEncryptFolderExecute(Sender: TObject);
var
  i: integer;
  list: TStrings;
  Passwd: string;
  Enc, Ori: string;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    list := TStringList.Create;
    try
      dlgFolder.Title := TitleEnc;
      if dlgFolder.Execute then
      begin
        if frmEncrypt.ShowModal = mrOk then
        begin
          Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text);

          if (frmEncrypt.chkKeyfile.Checked) and (FileExistsUTF8(frmEncrypt.edtKeyfile.Text)) then
            Passwd := UTF8Encode(frmEncrypt.edtPasswd.Text) + HashFile(frmEncrypt.edtKeyfile.Text);

          frmEncrypt.edtPasswd.Text := '';
          frmEncrypt.edtConfirm.Text := '';
          frmEncrypt.edtKeyfile.Text := '';

        {$IFDEF WINDOWS}
          VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

          frmEncrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
          frmEncrypt.edtConfirm.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
          frmEncrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        {$ELSE}
          mlock(@Passwd, Sizeof(char) * Sizeof(Passwd));
        {$ENDIF}

          Scandirectory(dlgFolder.FileName, list);

          prbProgress.Visible := True;
          lblInfo.Visible := True;
          for i := 0 to list.Count - 1 do
          begin
            if not DirectoryExistsUTF8(list.Strings[i]) then
            begin
              Ori := list.Strings[i];

              if FileSize(Ori) = 0 then  // Skip empty files
                Continue;

              Enc := AddSlash(ExtractFileDir(list.Strings[i])) + ReturnTempFilename(8);

              LoadConfig;

              Algorithm := frmEncrypt.cboAlgo.ItemIndex;

              case Algorithm of
                0: EncryptAES(Passwd, Ori, Enc);
                1: EncryptTF(Passwd, Ori, Enc);
                2: EncryptSP(Passwd, Ori, Enc);
              {$IFDEF CAMELLIA}
                3: EncryptCam(Passwd, Ori, Enc);
              {$ENDIF}
              end;
            end;

            SaveConfig;

            Shredder(Ori);
            RenameFileUTF8(Enc, Ori + '.sce');
          end;

        end;
      end;
    finally
      prbProgress.Visible := False;
      lblInfo.Visible := False;
      FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);

    {$IFDEF WINDOWS}
      VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
    {$ELSE}
      munlock(@Passwd, Sizeof(char) * Sizeof(Passwd));
    {$ENDIF}

      list.Free;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.actWipeExecute(Sender: TObject);
var
  i: integer;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    dlgOpen.Title := TitleWipe;
    dlgOpen.Filter := Filter1;
    if dlgOpen.Execute then
    begin
      prbProgress.Visible := True;
      lblInfo.Visible := True;
      for i := 0 to dlgOpen.Files.Count - 1 do
        if not DirectoryExistsUTF8(dlgOpen.Files[i]) then
          Shredder(dlgOpen.Files[i]);
      prbProgress.Visible := False;
      lblInfo.Visible := False;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.actViewExecute(Sender: TObject);
var
  Passwd: string;
  Dec, Ori: string;
  hdrf: TFCATFHdr;
  User: TFCUserAES;
  Algo: byte;
  fn: string;
  TempFolder: string;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    dlgOpen.Title := TitleView;
    dlgOpen.Filter := Filter2;
    dlgOpen.Options := dlgOpen.Options - [ofAllowMultiSelect];
    if dlgOpen.Execute then
    begin
      if frmDecrypt.ShowModal = mrOk then
      begin
        try
          Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text);

          if FileExistsUTF8(frmDecrypt.edtKeyfile.Text) then
            Passwd := UTF8Encode(frmDecrypt.edtPasswd.Text) + HashFile(frmDecrypt.edtKeyfile.Text);

          frmDecrypt.edtPasswd.Text := '';
          frmDecrypt.edtKeyfile.Text := '';

        {$IFDEF WINDOWS}
          VirtualLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // VirtualLock here so Password does not go to page file.

          frmDecrypt.edtPasswd.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
          frmDecrypt.edtKeyfile.Perform(EM_EMPTYUNDOBUFFER, 0, 0);
        {$ELSE}
          mlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
        {$ENDIF}

          prbProgress.Visible := True;
          lblInfo.Visible := True;

          if not DirectoryExistsUTF8(dlgOpen.Filename) then
          begin

            User.fi := TFileStreamUTF8.Create(dlgOpen.Filename, fmOpenRead);
            User.fi.Seek(0, soFromBeginning);
            try
              User.fi.ReadBuffer(hdrf, SizeOf(hdrf));

              if hdrf.Flags and $01 <> 0 then
                Algo := 1;

              if hdrf.Flags and $02 <> 0 then
                Algo := 2;

              if hdrf.Flags and $04 <> 0 then
                Algo := 4;


            {$IFDEF CAMELLIA}
              if hdrf.Flags and $20 <> 0 then
                Algo := 32;
            {$ENDIF}

            finally
              User.fi.Free;
            end;

            TempFolder := AddSlash(GetDesktopPath) + AddSlash('SCE_TMP') + ChangeFileExt(ReturnTempFilename(8), '');

            ForceDirectories(TempFolder);

            Dec := AddSlash(TempFolder) + ReturnTempFilename(8);
            Ori := dlgOpen.Filename;

            prbProgress.Max := 1000;

            case Algo of
              1: if not DecryptAES(Passwd, Ori, Dec) then
                  exit;
              2: if not DecryptTF(Passwd, Ori, Dec) then
                  exit;
              4: if not DecryptSP(Passwd, Ori, Dec) then
                  exit;
            {$IFDEF CAMELLIA}
              32: if not DecryptCAM(Passwd, Ori, Dec) then
                  exit;
            {$ENDIF}
            end;

            fn := ExtractFilePath(Dec) + FFilename;

            RenameFileUTF8(Dec, fn);
            FileSetDate(fn, FAge);


          {$IFDEF WINDOWS}
            RunShell(fn);

            if FileAgeUTF8(fn) <> FAge then
              case Algo of
                1: EncryptAES(Passwd, fn, Ori);
                2: EncryptTF(Passwd, fn, Ori);
                4: EncryptSP(Passwd, fn, Ori);
              {$IFDEF CAMELLIA}
                32: EncryptCam(Passwd, fn, Ori);
              {$ENDIF}
              end;
          {$ELSE}
            OpenDocument(fn);
          {$ENDIF}

          end;
        finally
          FillChar(Passwd, length(Passwd) * SizeOf(Passwd[1]), 0);

        {$IFDEF WINDOWS}
          VirtualUnLock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));  // Do I need to unlock here? Dunno.
        {$ELSE}
          munlock(@Passwd[1], length(Passwd) * SizeOf(Passwd[1]));
        {$ENDIF}

          prbProgress.Visible := False;
          lblInfo.Visible := False;
        end;
      end;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.actWipeFolderExecute(Sender: TObject);
var
  sl: TStrings;
begin
  {$IFDEF LINUX}
  try
  {$ENDIF}
    sl := TStringList.Create;
    try
      dlgFolder.Title := TitleWipe;
      if dlgFolder.Execute then
      begin
        prbProgress.Visible := True;
        lblInfo.Visible := True;
        ShredderTree(dlgFolder.FileName);
      end;
    finally
      prbProgress.Visible := False;
      lblInfo.Visible := False;
      sl.Free;
    end;
  {$IFDEF LINUX}
  finally
    KDE_Plasma_Repaint;
  end;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.btnDecryptClick(Sender: TObject);
var
  p: TPoint;
begin
  p := btnDecrypt.ClientToScreen(Point(0, 0));
  popDecrypt.PopUp(p.x, p.y + btnDecrypt.Height);
end;

//=================================================================================================
procedure TfrmMain.btnEncryptClick(Sender: TObject);
var
  p: TPoint;
begin
  p := btnEncrypt.ClientToScreen(Point(0, 0));
  popEncrypt.PopUp(p.x, p.y + btnEncrypt.Height);
end;

//=================================================================================================
procedure TfrmMain.btnEncryptMouseEnter(Sender: TObject);
begin
  (Sender as TExPanel).Color := $00CCCCCC;
end;

//=================================================================================================
procedure TfrmMain.btnEncryptMouseLeave(Sender: TObject);
begin
  (Sender as TExPanel).Color := $00E5E5E5;
end;

//=================================================================================================
procedure TfrmMain.btnWipeClick(Sender: TObject);
var
  p: TPoint;
begin
  p := btnWipe.ClientToScreen(Point(0, 0));
  popWipe.PopUp(p.x, p.y + btnWipe.Height);
end;

//=================================================================================================
procedure TfrmMain.btnViewClick(Sender: TObject);
begin
  actView.Execute;
end;

//=================================================================================================
procedure TfrmMain.FormActivate(Sender: TObject);
begin
  if ActivateCounter > 0 then
    Exit;  // Linux fires this event evertime another form opens, no idea why.
  Inc(ActivateCounter);

  if not isaac_selftest then
  begin
    MessageDlg('StrongCrypt-FE', 'ISAAC self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  if not SHA512SelfTest then
  begin
    MessageDlg('StrongCrypt-FE', 'SHA512 self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  if not Whirl_SelfTest then
  begin
    MessageDlg('StrongCrypt-FE', 'Whrilpool self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  if not AES_EAX_Selftest then
  begin
    MessageDlg('StrongCrypt-FE', 'AES self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  if not TF_EAX_Selftest then
  begin
    MessageDlg('StrongCrypt-FE', 'Twofish self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  if not SP_EAX_Selftest then
  begin
    MessageDlg('StrongCrypt-FE', 'Serpend self test failed!', mtError, [mbOK], 0);
    Exit;
  end;

  {$IFDEF CAMELLIA}
  if not CAM_EAX_Selftest then
  begin
    MessageDlg('StrongCrypt-FE', 'Camellia self test failed!', mtError, [mbOK], 0);
    Exit;
  end;
  {$ENDIF}


  LoadLanguage(Language);


  if (ParamStr(1) = '--enc=shell') or (ParamStr(1) = '--enc-copy=shell') then
    EncryptShell;

  if ParamStr(1) = '--dec=shell' then
    DecryptShell;

  if ParamStr(1) = '--ren=shell' then
    RenameShell;

  if ParamStr(1) = '--wipe=shell' then
    WipeShell;

end;

//=================================================================================================
procedure TfrmMain.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  fn: string;
begin
  fn := AddSlash(GetDesktopPath) + AddSlash('SCE_TMP');
  if DirectoryExistsUTF8(fn) then
    ShredderTree(fn);
end;

//=================================================================================================
function StrAfter(input, after: string): string;
begin
  Result := Copy(input, Pos(after, input) + 1, Length(input));
end;

//=================================================================================================
procedure TfrmMain.LoadLanguage(Lang: string);
var
  sl: TStrings;
  LangIni: TIniFile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'lang.dat';
  if FileExistsUTF8(Path) then
  begin
    LangIni := TIniFile.Create(Path);
    sl := TStringList.Create;
    try
      LangIni.ReadSectionValues(Lang, sl);

      btnEncrypt.Caption := StrAfter(sl.Strings[0], '=');
      btnDecrypt.Caption := StrAfter(sl.Strings[1], '=');
      btnView.Caption := StrAfter(sl.Strings[2], '=');
      btnWipe.Caption := StrAfter(sl.Strings[3], '=');
      lblTop.Caption := 'StrongCrypt-FE - ' + StrAfter(sl.Strings[4], '=');
      popConfig.Caption := StrAfter(sl.Strings[5], '=');
      popLanguage.Caption := StrAfter(sl.Strings[6], '=');
      popPasswd.Caption := StrAfter(sl.Strings[13], '=');
      popAbout.Caption := StrAfter(sl.Strings[40], '=');
      popEncryptFiles.Caption := StrAfter(sl.Strings[43], '=');
      popEncryptFolder.Caption := StrAfter(sl.Strings[44], '=');
      popDecryptFiles.Caption := StrAfter(sl.Strings[45], '=');
      popDecryptFolder.Caption := StrAfter(sl.Strings[46], '=');
      popWipeFiles.Caption := StrAfter(sl.Strings[47], '=');
      popWipeFolder.Caption := StrAfter(sl.Strings[48], '=');

      frmEncrypt.Caption := StrAfter(sl.Strings[7], '=');
      frmEncrypt.lblPasswd.Caption := StrAfter(sl.Strings[8], '=');
      frmEncrypt.lblConfirm.Caption := StrAfter(sl.Strings[9], '=');
      frmEncrypt.lblQuality.Caption := StrAfter(sl.Strings[10], '=');
      frmEncrypt.chkShowPwd.Caption := StrAfter(sl.Strings[12], '=');
      frmEncrypt.btnGenerate.Caption := StrAfter(sl.Strings[13], '=');
      frmEncrypt.chkKeyfile.Caption := StrAfter(sl.Strings[14], '=');
      frmEncrypt.lblKeyfile.Caption := StrAfter(sl.Strings[15], '=');
      frmEncrypt.btnOk.Caption := StrAfter(sl.Strings[16], '=');
      frmEncrypt.btnCancel.Caption := StrAfter(sl.Strings[17], '=');
      frmEncrypt.lblAlgo.Caption := StrAfter(sl.Strings[21], '=');

      frmDecrypt.Caption := StrAfter(sl.Strings[18], '=');
      frmDecrypt.lblPasswd.Caption := StrAfter(sl.Strings[8], '=');
      frmDecrypt.lblKeyfile.Caption := StrAfter(sl.Strings[15], '=');
      frmDecrypt.chkShowPwd.Caption := StrAfter(sl.Strings[12], '=');
      frmDecrypt.btnOK.Caption := StrAfter(sl.Strings[16], '=');
      frmDecrypt.btnCancel.Caption := StrAfter(sl.Strings[17], '=');

      frmConfig.Caption := StrAfter(sl.Strings[5], '=');
      frmConfig.tab1.Caption := StrAfter(sl.Strings[19], '=');
      frmConfig.gbAlgo.Caption := StrAfter(sl.Strings[20], '=');
      frmConfig.lblAlgo.Caption := StrAfter(sl.Strings[21], '=');
      frmConfig.gbKdf.Caption := StrAfter(sl.Strings[22], '=');
      frmConfig.lblRounds.Caption := StrAfter(sl.Strings[23], '=');
      frmConfig.gbCompression.Caption := StrAfter(sl.Strings[24], '=');
      frmConfig.chkCompression.Caption := StrAfter(sl.Strings[25], '=');
      frmConfig.lblLevel.Caption := StrAfter(sl.Strings[26], '=');
      frmConfig.tab2.Caption := StrAfter(sl.Strings[27], '=');
      frmConfig.gbLanguage.Caption := StrAfter(sl.Strings[28], '=');
      frmConfig.lblLanguage.Caption := StrAfter(sl.Strings[6], '=');
      frmConfig.gbWipe.Caption := StrAfter(sl.Strings[29], '=');
      frmConfig.lblMethod.Caption := StrAfter(sl.Strings[30], '=');
      frmConfig.btnOK.Caption := StrAfter(sl.Strings[16], '=');
      frmConfig.btnCancel.Caption := StrAfter(sl.Strings[17], '=');

      frmRnd.Caption := StrAfter(sl.Strings[13], '=');
      frmRnd.gbOptions.Caption := StrAfter(sl.Strings[31], '=');
      frmRnd.chkUpper.Caption := StrAfter(sl.Strings[32], '=');
      frmRnd.chkLower.Caption := StrAfter(sl.Strings[33], '=');
      frmRnd.chkDigits.Caption := StrAfter(sl.Strings[34], '=');
      frmRnd.chkSpecial.Caption := StrAfter(sl.Strings[35], '=');
      frmRnd.chkBrackets.Caption := StrAfter(sl.Strings[36], '=');
      frmRnd.chkSpace.Caption := StrAfter(sl.Strings[37], '=');
      frmRnd.lbllength.Caption := StrAfter(sl.Strings[38], '=');
      frmRnd.btnGenerate.Caption := StrAfter(sl.Strings[39], '=');
      frmRnd.lblQuality.Caption := StrAfter(sl.Strings[10], '=');
      frmRnd.btnOK.Caption := StrAfter(sl.Strings[16], '=');
      frmRnd.btnCancel.Caption := StrAfter(sl.Strings[17], '=');
      frmRnd.btnClipboard.Caption := StrAfter(sl.Strings[41], '=');

      frmAbout.Caption := StrAfter(sl.Strings[40], '=');

      Bits := StrAfter(sl.Strings[11], '=');
      Filter1 := StrAfter(sl.Strings[43], '=');
      Filter2 := StrAfter(sl.Strings[44], '=');

      ErrorSig := StrAfter(sl.Strings[45], '=');
      ErrorPwd := StrAfter(sl.Strings[46], '=');
      ErrorAut := StrAfter(sl.Strings[47], '=');

      strEnc := StrAfter(sl.Strings[48], '=');
      strDec := StrAfter(sl.Strings[49], '=');
      strWipe := StrAfter(sl.Strings[50], '=');

      TitleEnc := StrAfter(sl.Strings[0], '=');
      TitleDec := StrAfter(sl.Strings[1], '=');
      TitleView := StrAfter(sl.Strings[2], '=');
      TitleWipe := StrAfter(sl.Strings[3], '=');
      TitleOpen := StrAfter(sl.Strings[48], '=');

    finally
      sl.Free;
      LangIni.Free;
    end;
  end;
end;

//=================================================================================================
procedure TfrmMain.LangItemClick(Sender: TObject);
var
  LangIni: TIniFile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'lang.dat';
  LangIni := TIniFile.Create(Path);
  try
    if LangIni.SectionExists((Sender as TMenuItem).Caption) then
    begin
      Language := (Sender as TMenuItem).Caption;
      LoadLanguage(Language);
      SaveConfig;
    end;
  finally
    LangIni.Free;
  end;
end;

//=================================================================================================
procedure TfrmMain.AddLangMenu;
var
  sl: TStrings;
  i: integer;
  Item: TMenuItem;
  LangIni: TIniFile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'lang.dat';
  LangIni := TIniFile.Create(Path);
  sl := TStringList.Create;
  try
    LangIni.ReadSections(sl);

    for i := 0 to sl.Count - 1 do
    begin
      Item := TMenuItem.Create(self);
      Item.Caption := sl.Strings[i];
      Item.OnClick := LangItemClick;
      popMenu.Items[2].Add(Item);
    end;

  finally
    sl.Free;
    LangIni.Free;
  end;
end;


//=================================================================================================
procedure TfrmMain.LoadConfig;
var
  ConfigIni: TInifile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'config.ini';
  ConfigIni := TIniFile.Create(Path);
  try
    Iterations := ConfigIni.ReadInteger('Config', 'Iterations', 20000);
    CompressionLevel := ConfigIni.ReadInteger('Config', 'CompressionLevel', 1);
    case CompressionLevel of
      0: clevel := 9;
      1: clevel := 6;
      2: clevel := 1;
    end;
    Compression := ConfigIni.ReadBool('Config', 'Compression', True);
    if not Compression then
      clevel := 0;
    Wipe := ConfigIni.ReadInteger('Config', 'Wipe', 0);
    Language := ConfigIni.ReadString('Config', 'Language', 'English');
  finally
    ConfigIni.Free;
  end;
end;

//=================================================================================================
procedure TfrmMain.SaveConfig;
var
  ConfigIni: TInifile;
  Path: string;
begin
  Path := AddSlash(ExtractFilepath(Application.ExeName)) + 'config.ini';
  ConfigIni := TIniFile.Create(Path);
  try
    ConfigIni.WriteInteger('Config', 'Algorithm', Algorithm);
    ConfigIni.WriteInteger('Config', 'Iterations', Iterations);
    ConfigIni.WriteInteger('Config', 'CompressionLevel', CompressionLevel);
    ConfigIni.WriteBool('Config', 'Compression', Compression);
    ConfigIni.WriteInteger('Config', 'Wipe', Wipe);
    ConfigIni.WriteString('Config', 'Language', Language);
  finally
    ConfigIni.Free;
  end;
end;

//=================================================================================================
procedure TfrmMain.FormCreate(Sender: TObject);
begin
  //PrevWndProc := Windows.WNDPROC(SetWindowLong(Self.Handle, GWL_WNDPROC, PtrInt(@WndCallback)));
  frmMain.DoubleBuffered := True;
  Randomize;
  prbProgress.Visible := False;
  AddLangMenu;
  LoadConfig;
  lblInfo.Caption := '';
end;

//=================================================================================================
procedure TfrmMain.FormMouseEnter(Sender: TObject);
begin
  btnEncrypt.Color := clSilver;
end;

//=================================================================================================
procedure TfrmMain.imgDecryptClick(Sender: TObject);
begin
  actDecrypt.Execute;
end;

//=================================================================================================
procedure TfrmMain.imgInfoClick(Sender: TObject);
var
  p: TPoint;
begin
  p := imgInfo.ClientToScreen(Point(0, 0));
  popMenu.PopUp(p.x - 4, p.y + imgInfo.Height + 4);
end;

//=================================================================================================
procedure TfrmMain.popConfigClick(Sender: TObject);
begin
  frmConfig.ShowModal;
  LoadLanguage(frmConfig.cbolanguage.Caption);
  {$IFDEF LINUX}
  KDE_Plasma_Repaint;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.popAboutClick(Sender: TObject);
begin
  frmAbout.ShowModal;
  {$IFDEF LINUX}
  KDE_Plasma_Repaint;
  {$ENDIF}
end;

//=================================================================================================
procedure TfrmMain.popPasswdClick(Sender: TObject);
begin
  frmRnd.ShowModal;
  {$IFDEF LINUX}
  KDE_Plasma_Repaint;
  {$ENDIF}
end;

end.
