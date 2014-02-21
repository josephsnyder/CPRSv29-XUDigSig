//---------------------------------------------------------------------------
// Copyright 2014 The Open Source Electronic Health Record Agent
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------
unit XlfMime;

interface 

uses  Windows,SysUtils,Registry, Dialogs, Classes, Forms, Controls,
  StdCtrls;
function MimeEncodedSize(dwlen:DWORD):DWORD;
procedure MimeEncode(var hashVal;dwLen: DWORD;var hashStr);


implementation
  function MimeEncodedSize(dwlen:DWORD):DWORD;
  begin
    Result := (dwlen +2) div 3 * 4;
  end;

  // Code found from:
  // http://www.delphigeist.com/2009/09/get-integer-bits.html
  function GetBitState(Num, BitNum: Cardinal): Boolean;
  asm
      BT   Num, BitNum
      SETC al
  end;

  // Code found from:
  // http://www.delphigeist.com/2009/09/get-integer-bits.html
  function BoolToChar(Value: Boolean): Char;
  begin
    if Value then
      Result := '1' else
      Result := '0';
  end;

  // Code found from:
  // http://www.delphigeist.com/2009/09/get-integer-bits.html
  function GetIntBits(Value: Integer; Length: integer): String;
  var
    index: Integer;
  begin
    SetLength(Result, Length);
    for index := Length-1 downto 0 do
      Result[Length-index] := BoolToChar(GetBitState(Value, index));
  end;
  
  // Code found from:
  //http://www.delphipages.com/forum/showthread.php?t=193429
  function BinToInt(val : string): Integer;
  var
  i, buff : Integer;
  begin
  Result:=0;
  buff:=Length(val);
  for i:=buff downto 1 do
  if val[i]='1' then
  Result:=Result+(1 shl (buff-i));
  end;

  {This procedure takes a pointer to an array of byte values,
  the length of that array, and a pointer to an output string
  
  It will turn the array byte values into a string that represents
  the bit values using 8 bytes, then take 3 bytes at a time and use
  that to create the encoded string.
  
  }
  procedure MimeEncode(var hashVal;dwLen: DWORD;var hashStr);
  const
   Map: array[0..63] of Char = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz0123456789+/';
  var
    //Counter Variables
    i,k:integer;
    //Values to hold the bit representation and the length of that string    
    bitstrsize: integer;
    bitstring : string;
    //encodeval  used to hold each 3 byte pattern during encoding
    encodeval : string;
    // String to maintain length of encoded string
    sHashStr : string;
    //Pointers to each of the input
    pHashVal  : ^Byte;
    pHashStr  : ^char;
  begin
  //Initialize strings and pointers
  sHashStr := '';
  bitstring := '';
  pHashVal := @hashVal;
  pHashStr := @hashStr;
  // Capture each int from the input pointer,
  // transform it to a string representation,
  // and append it to the total message.
  // Increase the pointers position after each one.
  for i := 0 to dwLen -1 do
    begin
      bitstring := Concat(bitstring,GetIntBits(pHashVal^,8));
      Inc(pHashVal);
    end;
  //Calculate the length of the total representation
  bitstrsize := length(bitstring);
  //Reset count variable to start at the first position
  i:=1;
  //Ensure that i is less than the total string size
  // while incrementing by 6 at the end of each loop
  while i < bitstrsize do
  begin
    //reset encodeval after each loop of 6 values
    encodeval := '';
    //Capture the next 6 bit values
    for k:=0 to 5 do
      begin
        //if the queried bit goes beyond the total string length,
        // append a zero
        if i+k > bitstrsize then  encodeval := encodeval + '0'
        else      encodeval := encodeval + bitstring[i+k];
      end;
    //Set the character that the encodeval represents in both the output
    // pointer and append it to the local string representation
    //
    pHashStr^ := map[BinToInt(encodeval)];
    sHashStr := Concat(sHashStr,map[BinToInt(encodeval)]);
    //Move to the next place in the pointer, and move to the next 6 bit
    //starting point
    Inc(pHashStr);
    i := i + 6;
  end;
  //Append '=' to the encoded string with until it matches the expected output
  //length of the message, found as result of the MimeEncodedSize function
  while length(sHashStr) < MimeEncodedSize(dwLen) do
  begin
    sHashStr := Concat(sHashStr,'=');
    pHashStr^ := '=';
    Inc(pHashStr);
  end;

  end;
end.