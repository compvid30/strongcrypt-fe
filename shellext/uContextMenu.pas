unit uContextMenu;

{$MODE DELPHI}

interface

uses
  Windows,
  SysUtils,
  Classes,
  ShlObj,
  ActiveX;

{$R .\icon.res}// Includes the bitmap

const
  SID_IShellExtInit = '{000214E8-0000-0000-C000-000000000046}';

type
    {$EXTERNALSYM IShellExtInit}
  IShellExtInit = interface(IUnknown)
    [SID_IShellExtInit]
    function Initialize(pidlFolder: PItemIDList; lpdobj: IDataObject; hKeyProgID: HKEY): HResult;
      stdcall;
  end;

type

  TContextMenu = class(TInterfacedObject, IShellExtInit, IContextMenu)
  private
    hBitmap: THandle;
    uMenuID: UInt;
    fFileName: WideString; // Unicode
    fShowDecrypt: boolean;
  public
    destructor Destroy; override;
    { IShellExtInit }
    function IShellExtInit.Initialize = SEIInitialize;
    function SEIInitialize(pidlFolder: PItemIDList; lpdobj: IDataObject; hKeyProgID: HKEY): HResult; stdcall;
    { IContextMenu }
    function QueryContextMenu(Menu: HMENU; indexMenu, idCmdFirst, idCmdLast, uFlags: UINT): HResult; stdcall;
    function InvokeCommand(var lpici: TCMInvokeCommandInfo): HResult; stdcall;
    function GetCommandString(idCmd: UINT_Ptr; uType: UINT; pwReserved: PUINT; pszName: LPSTR; cchMax: UINT): HResult; stdcall;
  end;

function DllGetClassObject(const CLSID, IID: TGUID; var Obj): HResult; stdcall;
function DllCanUnloadNow: HResult; stdcall;
function DllRegisterServer: HResult; stdcall;
function DllUnregisterServer: HResult; stdcall;

const
{$IFDEF WIN32}
  cClassName = 'SCFeShellExt32';
  Class_ContextMenu: TGUID = '{137D258B-7E2E-4D17-A9D8-D418360194A6}';
{$ELSE}
  cClassName = 'SCFeShellExt64';
  Class_ContextMenu: TGUID = '{137D258B-7E2E-4D17-A9D8-D418360194A8}';
{$ENDIF}

var
  WindowList: TList;

implementation

uses
  ShellApi,
  Registry;

type
  TContextMenuFactory = class(TInterfacedObject, IClassFactory)
    constructor Create;
    destructor Destroy; override;
    function CreateInstance(const unkOuter: IUnknown; const riid: TIID; out vObject): HResult; stdcall;
    function LockServer(fLock: Bool): HResult; stdcall;
  end;

var
  iDllRefCount: integer = 0;
  fFileList: TStrings;

constructor TContextMenuFactory.Create;
begin
  inherited;
  Inc(iDllRefCount);
end;


destructor TContextMenuFactory.Destroy;
begin
  Dec(iDllRefCount);
  inherited;
end;


function TContextMenuFactory.CreateInstance(const unkOuter: IUnknown; const riid: TIID; out vObject): HResult;
begin
  Pointer(vObject) := nil;

  if (unkOuter <> nil) then
    Result := CLASS_E_NOAGGREGATION
  else
    try
      Result := TContextMenu.Create.QueryInterface(riid, vObject);

    except
      Result := E_OUTOFMEMORY;
    end;
end;


function TContextMenuFactory.LockServer(fLock: Bool): HResult;
begin
  Result := S_OK;
end;


destructor TContextMenu.Destroy;
begin
  if (hBitmap <> 0) then
    if (DeleteObject(hBitmap)) then
      hBitmap := 0;

  inherited Destroy;
end;

function TContextMenu.SEIInitialize(pidlFolder: PItemIDList; lpdobj: IDataObject; hKeyProgID: HKEY): HResult;

  function DirectoryExistsW(const Directory: WideString): boolean;
  var
    Code: integer;
  begin
    Code := GetFileAttributesW(PWideChar(Directory));
    Result := (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0);
  end;

  function ExtractFileExtW(const FileName: WideString): WideString;
  var
    i: longint;
    EndSep: set of char;
  begin
    I := Length(FileName);
    EndSep := AllowDirectorySeparators + AllowDriveSeparators + [ExtensionSeparator];
    while (I > 0) and not (FileName[I] in EndSep) do
      Dec(I);
    if (I > 0) and (FileName[I] = ExtensionSeparator) then
      Result := Copy(FileName, I, MaxInt)
    else
      Result := '';
  end;

var
  StgMedium: TStgMedium;
  FormatEtc: TFormatEtc;
  i: integer;
  L: longword;
begin
  if (lpdobj = nil) then
  begin
    Result := E_INVALIDARG;
    exit;
  end;

  if (hBitmap = 0) then
    hBitmap := LoadBitmap(hInstance, MakeIntResource(101));

  fFileList.Clear;

  FormatEtc.cfFormat := CF_HDROP;
  FormatEtc.ptd := nil;
  FormatEtc.dwAspect := DVASPECT_CONTENT;
  FormatEtc.lindex := -1;
  FormatEtc.tymed := TYMED_HGLOBAL;

  Result := lpdobj.GetData(FormatEtc, StgMedium);

  if (Failed(Result)) then
    exit;

  if (DragQueryFile(StgMedium.hGlobal, $FFFFFFFF, nil, 0) >= 1) then
  begin
    fShowDecrypt := False;
    for i := 0 to DragQueryFile(StgMedium.hGlobal, $FFFFFFFF, nil, 0) - 1 do
    begin
      L := DragQueryFileW(StgMedium.hGlobal, i, nil, 0);
      SetLength(fFileName, L);
      L := DragQueryFileW(StgMedium.hGlobal, i, @fFileName[1], L + 1);
      SetLength(fFileName, L);
      fFileList.Add(Utf8Encode(fFileName));
      if not fShowDecrypt then
        fShowDecrypt := (DirectoryExistsW(FFileName)) or (ExtractFileExtW(FFileName) = '.cxenc');
    end;
    Result := NOERROR;
  end
  else
  begin
    fFileName := '';
    Result := E_FAIL;
  end;
  ReleaseStgMedium(@StgMedium);
end;



function TContextMenu.QueryContextMenu(Menu: HMENU; indexMenu, idCmdFirst, idCmdLast, uFlags: UINT): HResult;
var
  iCode: integer;
  i: integer;
begin
  Result := 0;

  uMenuID := indexMenu;

  if ((uFlags and $0000000F) = CMF_NORMAL) or ((uFlags and CMF_EXPLORE) <> 0) then
  begin
    i := CreateMenu;
    InsertMenuW(Menu, indexMenu, MF_BYPOSITION or MF_POPUP, i, 'StrongCrypt-FE');
    if (hBitmap <> 0) then
      SetMenuItemBitmaps(Menu, indexMenu, MF_BYPOSITION, hBitmap, hBitmap);
    Menu := i;
    InsertMenuW(Menu, 0, MF_STRING or MF_BYPOSITION, idCmdFirst, 'Encrypt');
    InsertMenuW(Menu, 1, MF_STRING or MF_BYPOSITION, idCmdFirst + 1, 'Encrypt Copy');
    if fShowDecrypt then
    begin
      InsertMenuW(Menu, 2, MF_STRING or MF_BYPOSITION, idCmdFirst + 2, 'Decrypt');
      InsertMenuW(Menu, 3, MF_BYPOSITION or MF_SEPARATOR, 0, nil);
      InsertMenuW(Menu, 4, MF_STRING or MF_BYPOSITION, idCmdFirst + 3, 'Rename');
    end;
    InsertMenuW(Menu, 5, MF_BYPOSITION or MF_SEPARATOR, 0, nil);
    InsertMenuW(Menu, 6, MF_STRING or MF_BYPOSITION, idCmdFirst + 4, 'Wipe');

    if fShowDecrypt then
      Result := 5
    else
      Result := 3;
  end;
end;

// Don't nest this Stuff or it will not work in FPC, no idea why. In Delphi it works nested.
function GetWindow(Handle: HWND; LParam: longint): bool; stdcall;
begin
  Result := True;
  WindowList.Add(Pointer(Handle));
end;

function GetHandles(ThreadID: longword): Hwnd;
var
  i: integer;
  Wnd, Hnd: HWND;
  CPid: DWord;
begin
  Result := 0;
  WindowList := TList.Create;
  EnumWindows(@GetWindow, Wnd);
  for i := 0 to WindowList.Count - 1 do
  begin
    Hnd := HWND(WindowList[i]);
    GetWindowThreadProcessID(Hnd, @CPid);
    if ThreadID = CPid then
    begin
      Result := Hnd;
      Exit;
    end;
  end;
end;

function StartApp(FileName, Parameter: string): Boolean;
var
  StartInfo: TStartupInfo;
  ProcInfo: TProcessInformation;
begin
  Result := False;
  FillChar(StartInfo, SizeOf(StartInfo), 0);
  StartInfo.cb := SizeOf(StartInfo);
  StartInfo.dwFlags := STARTF_USESHOWWINDOW;
  StartInfo.wShowWindow := SW_SHOW;
  if FileName <> '' then
    Result := CreateProcess(nil, PChar('"' + FileName + '" ' + Parameter), nil, nil, False, 0, nil, nil, StartInfo, ProcInfo);
  CloseHandle(ProcInfo.hProcess);
  CloseHandle(ProcInfo.hThread);
end;

function AddSlash(s: string): string;
begin
  Result := IncludeTrailingPathDelimiter(s);
end;

function ReturnTempFilename(strLen: integer): string;
var
  str: string;
begin
  randomize;
  str := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  Result := '';
  repeat
    Result := Result + str[Random(Length(str)) + 1];
  until (Length(Result) = strLen);

  Result := '$SC' + Result + '.TMP';
end;


function TContextMenu.InvokeCommand(var lpici: TCMInvokeCommandInfo): HResult;
const
  ErrorMessage = 'Error while starting StrongCrypt-FE!';
var
  AppHandle: integer;
  AppPath: string;
  TempFile: string;
begin
  AppPath := ExtractFilePath(GetModuleName(HInstance)) + 'strongcryptfe.exe';
  Result := E_FAIL;


  // Quick and Dirty. Could be done with SendMessage + WM_COPYDATA as well.
  // The createprocess commandline can only have 32767 charakters, so we do it via a temp file.
  if not DirectoryExists(fFileList.Strings[0]) then
    TempFile := ExtractFilePath(fFileList.Strings[0]) + ReturnTempFilename(7)
  else
    TempFile := AddSlash(fFileList.Strings[0]) + ReturnTempFilename(7);
  fFileList.SaveToFile(TempFile);
  fFileList.Clear;

  if (HiWord(integer(lpici.lpVerb)) <> 0) then
    exit;

  if (LoWord(integer(lpici.lpVerb)) > 4) then
  begin
    Result := E_INVALIDARG;
    exit;
  end;

  if (LoWord(integer(lpici.lpVerb)) = 0) then     // Encrypt
  begin

    if not StartApp(AppPath, '"--enc=shell" "@' + TempFile + '"') then
    begin
      MessageBox(lpici.HWND, PChar(ErrorMessage + IntToStr(AppHandle)+ AppPath), 'StrongCrypt-FE', MB_ICONERROR or MB_OK);
      exit;
    end;
  end;

  if (LoWord(integer(lpici.lpVerb)) = 1) then     // Encrypt Copy
  begin

    if not StartApp(AppPath, '"--enc-copy=shell" "@' + TempFile + '"') then
    begin
      MessageBox(lpici.HWND, PChar(ErrorMessage), 'StrongCrypt-FE', MB_ICONERROR or MB_OK);
      exit;
    end;
  end;

  if (LoWord(integer(lpici.lpVerb)) = 2) then     // Decrypt
  begin

    if not StartApp(AppPath, '"--dec=shell" "@' + TempFile + '"') then
    begin
      MessageBox(lpici.HWND, PChar(ErrorMessage), 'StrongCrypt-FE', MB_ICONERROR or MB_OK);
      exit;
    end;
  end;

  if (LoWord(integer(lpici.lpVerb)) = 3) then    // Rename
  begin

    if not StartApp(AppPath, '"--ren=shell" "@' + TempFile + '"') then
    begin
      MessageBox(lpici.HWND, PChar(ErrorMessage), 'StrongCrypt-FE', MB_ICONERROR or MB_OK);
      exit;
    end;
  end;

  if (LoWord(integer(lpici.lpVerb)) = 4) then    // Wipe
  begin

    if not StartApp(AppPath, '"--wipe=shell" "@' + TempFile + '"') then
    begin
      MessageBox(lpici.HWND, PChar(ErrorMessage), 'StrongCrypt-FE', MB_ICONERROR or MB_OK);
      exit;
    end;
  end;

  Result := S_OK;
end;



function TContextMenu.GetCommandString(idCmd: UINT_Ptr; uType: UINT; pwReserved: PUINT; pszName: LPSTR; cchMax: UINT): HResult; stdcall;
begin
  // Nothing to do here
end;



function DllCanUnloadNow: HResult;
begin
  if (iDllRefCount = 0) then
    Result := S_OK
  else
    Result := S_FALSE;
end;



function DllGetClassObject(const CLSID, IID: TGUID; var Obj): HResult;
begin
  Pointer(Obj) := nil;
  if (IsEqualGUID(CLSID, Class_ContextMenu)) then
    Result := TContextMenuFactory.Create.QueryInterface(IID, Obj)
  else
    Result := CLASS_E_CLASSNOTAVAILABLE;
end;



function UpdateRegistry(const bRegister: boolean; const sExt, sClassName, sClassID: string): boolean;
const
  cApprovedKey =
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved';

  function CreateRegKey(const sKey, sValueName, sValue: string; const ARootKey: HKEY = HKey_Classes_Root): boolean;
  begin
    Assert(sKey <> '');
    Result := False;
    with TRegistry.Create do
      try
        RootKey := ARootKey;

        if (OpenKey(sKey, True)) then
          try
            WriteString(sValueName, sValue);
            Result := True;
          finally
            CloseKey
          end;
      finally
        Free;
      end;
  end;

  function DeleteRegKey(const sKey: string): boolean;
  begin
    Assert(sKey <> '');
    with TRegistry.Create do
      try
        RootKey := HKey_Classes_Root;
        Result := DeleteKey(sKey);
      finally
        Free;
      end;
  end;

  function GetLibPath: TFileName;
  var
    iLen: integer;
  begin
    SetLength(Result, MAX_PATH);
    iLen := GetModuleFileName(hInstance, PChar(Result), MAX_PATH);
    SetLength(Result, iLen);
  end;

  function GetLibName(const sLibPath: TFileName): TFileName;
  begin
    Assert(FileExists(sLibPath));
    Result := ExtractFileName(sLibPath);
    SetLength(Result, Length(Result) - 4);
  end;

  function FormatPath(const sPath: TFileName): TFileName;
  begin
    Assert(sPath <> '');
    if (Pos(' ', sPath) > 0) then
      Result := ExtractShortPathName(sPath)
    else
      Result := sPath;
  end;

  procedure RemoveApprovedValue(const sGUID: string);
  begin
    Assert(sGUID <> '');
    with TRegistry.Create do
      try
        RootKey := HKey_Local_Machine;
        if (OpenKey(cApprovedKey, False)) then
          try
            if (ValueExists(sGUID)) then
              DeleteValue(sGUID);
          finally
            CloseKey;
          end;
      finally
        Free;
      end;
  end;

const
  cExtensionInfo = 'SCFe Shell Exension';
var
  sNameAndClass, sLibPath: string;
begin
  Assert(sExt <> '');
  Assert(sClassName <> '');
  Assert(sClassID <> '');

  Result := True;

  sLibPath := GetLibPath;
  sNameAndClass := GetLibName(sLibPath) + '.' + sClassName;

  if (bRegister) then
    try
      CreateRegKey(sExt + '\shellex\ContextMenuHandlers\' + sClassName, '', sClassID);
      CreateRegKey('CLSID\' + sClassID, '', cClassName);
      CreateRegKey('CLSID\' + sClassID + '\InprocServer32', '',
        FormatPath(sLibPath));
      CreateRegKey('CLSID\' + sClassID + '\InprocServer32',
        'ThreadingModel', 'Apartment');
      CreateRegKey('CLSID\' + sClassID + '\ProgID', '', sNameAndClass);
      CreateRegKey(sNameAndClass, '', '');
      CreateRegKey(sNameAndClass + '\CLSID', '', sClassID);

      CreateRegKey(cApprovedKey, sClassID, cExtensionInfo,
        HKey_Local_Machine);

    except
      DllUnregisterServer;
    end
  else
  begin
    DeleteRegKey(sExt + '\shellex\ContextMenuHandlers\' + sClassName);
    DeleteRegKey('CLSID\' + sClassID);
    DeleteRegKey(sNameAndClass);
    RemoveApprovedValue(sClassID);
  end;
end;



function DllRegisterServer: HResult;
begin
  Result := S_OK;
  try
    UpdateRegistry(True, '*', cClassName, GUIDToString(Class_ContextMenu));
    UpdateRegistry(True, 'Folder', cClassName, GUIDToString(Class_ContextMenu));
  except
    Result := E_FAIL;
  end;
end;



function DllUnregisterServer: HResult;
begin
  Result := S_OK;
  try
    UpdateRegistry(False, '*', cClassName, GUIDToString(Class_ContextMenu));
    UpdateRegistry(False, 'Folder', cClassName, GUIDToString(Class_ContextMenu));
  except
    Result := E_FAIL;
  end;
end;



initialization
  TContextMenuFactory.Create;
  fFileList := TStringList.Create;

finalization
  fFileList.Free;

end.
