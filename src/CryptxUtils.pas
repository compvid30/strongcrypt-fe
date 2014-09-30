unit CryptxUtils;

{$MODE DELPHI}

interface

uses
  Classes,
  SysUtils,
  Math,
  Forms,
  {$IFDEF WINDOWS}
  types,
  lclintf,
  Windows,
  tsc,
  dates,
  hash,
  whirl512,
  {$ENDIF}
  Controls;

{$IFDEF WINDOWS}
type
  TMemoryStatusEx = packed record
    dwLength: DWORD;
    dwMemoryLoad: DWORD;
    ullTotalPhys: Int64;
    ullAvailPhys: Int64;
    ullTotalPageFile: Int64;
    ullAvailPageFile: Int64;
    ullTotalVirtual: Int64;
    ullAvailVirtual: Int64;
    ullAvailExtendedVirtual: Int64;
  end;


function CollectRND(var WD: TWhirlDigest): boolean;

function GlobalMemoryStatusEx(var lpBuffer: TMemoryStatusEx): BOOL; stdcall; external kernel32;
function GetShellWindow: HWND; stdcall; external 'user32.dll' name 'GetShellWindow';
{$ENDIF}
function XorString(const strText: string; const intKey: longint): string;
procedure EstimatePasswordBits(var vPasswordChars: string; var b: cardinal);



implementation

{$IFDEF WINDOWS}
// Collect some random data for seeding our prng
function CollectRND(var WD: TWhirlDigest): boolean;
var
  sctx: THashContext;
  ctr: TCtrRec;
  tick: LongWord;
  msc: LongInt;
  pID: LongWord;
  tID: LongWord;
  Status: TMemoryStatusEx;
  pos: TPoint;
  PCreationTime: TFileTime;
  TCreationTime: TFileTime;
  ExitTime: TFileTime;
  PKernelTime: TFileTime;
  TKernelTime: TFileTime;
  UserTime: TFileTime;
  min: LongWord;
  max: LongWord;
  hwnd: LongWord;
  hwnd2: LongWord;
  hwnd3: LongWord;
  hwnd4: LongWord;
  hwnd5: LongWord;
  heaphwnd: LongWord;
  cp: LongWord;
  mt: LongInt;
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

function XorString(const strText: string; const intKey: longint): string;
var
  i: integer;
  strResult: string;
begin
  strResult := strText;
  RandSeed := intKey;
  for i := 1 to Length(strText) do
    strResult[i] := Chr(Ord(strResult[i]) xor Random(255));
  Result := strResult;
  Randomize; // Reset RandSeed
end;

procedure EstimatePasswordBits(var vPasswordChars: string; var b: cardinal);
var
  bChLower, bChUpper, bChNumber, bChSimpleSpecial, bChExtSpecial, bChHigh, bChEscape: boolean;
  vCharCounts: TStringList;
  vDifferences: TStringList;
  i, iDiff: integer;
  dblEffectiveLength, dblDiffFactor, dblBitsPerChar: double;
  charSpace: cardinal;
  key: char;
  j: integer;
begin
  bChLower := False;
  bChUpper := False;
  bChNumber := False;
  bChSimpleSpecial := False;
  bChExtSpecial := False;
  bChHigh := False;
  bChEscape := False;

  dblEffectiveLength := 0.0;

  vCharCounts := TStringList.Create;
  vDifferences := TStringList.Create;
  try
  for i := 1 to Length(vPasswordChars) do
  begin
    key := vPasswordChars[i];
    if (key < ' ') then
      bChEscape := True;
    if ((key >= 'A') and (key <= 'Z')) then
      bChUpper := True;
    if ((key >= 'a') and (key <= 'z')) then
      bChLower := True;
    if ((key >= '0') and (key <= '9')) then
      bChNumber := True;
    if ((key >= ' ') and (key <= '/')) then
      bChSimpleSpecial := True;
    if ((key >= ':') and (key <= '@')) then
      bChExtSpecial := True;
    if ((key >= '[') and (key <= '`')) then
      bChExtSpecial := True;
    if ((key >= '{') and (key <= '~')) then
      bChExtSpecial := True;
    if (key > '~') then
      bChHigh := True;
    dblDiffFactor := 1.0;
    if (i >= 1) then
    begin
      iDiff := (Ord(key) - Ord(vPasswordChars[i - 1]));
      if vDifferences.IndexOf(IntToStr(iDiff)) = -1 then
        vDifferences.AddObject(IntToStr(iDiff), TObject(1))
      else
      begin
        j := vDifferences.IndexOf(IntToStr(iDiff));
        vDifferences.Objects[j] := TObject(Integer(vDifferences.Objects[j]) + 1);
        dblDiffFactor := dblDiffFactor / (Integer(vDifferences.Objects[j]));
      end;
    end;

    if vCharCounts.IndexOf(key) = -1 then
    begin
      vCharCounts.AddObject(key, TObject(1));
      dblEffectiveLength := dblEffectiveLength + dblDiffFactor;
    end
    else
    begin
      j := vCharCounts.IndexOf(key);
      vCharCounts.Objects[j] := TObject(Integer(vCharCounts.Objects[j]) + 1);
      dblEffectiveLength := dblEffectiveLength + (dblDiffFactor * (1.0 / (Integer(vCharCounts.Objects[j]))));
    end;
  end;
  charSpace := 0;
  if (bChEscape) then
    Inc(charSpace, 60);
  if (bChUpper) then
    Inc(charSpace, 26);
  if (bChLower) then
    Inc(charSpace, 26);
  if (bChNumber) then
    Inc(charSpace, 10);
  if (bChSimpleSpecial) then
    Inc(charSpace, 16);
  if (bChExtSpecial) then
    Inc(charSpace, 17);
  if (bChHigh) then
    Inc(charSpace, 112);
  if (charSpace = 0) then
  begin
    b := 0;
    Exit;
  end;

  dblBitsPerChar := LN(charSpace) / LN(2.0);
  begin
    b := Math.Ceil(dblBitsPerChar * dblEffectiveLength);
    if vPasswordChars = '' then
      b := 0;
    Exit;
  end;

  finally
    vCharCounts.Free;
  vDifferences.Free;
  end;
end;

end.
