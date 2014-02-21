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

unit WinSCard;

interface



uses  Windows;

const
  // All SCard functions are found in the Winscard dynamic link library
  WinSCardDLL = 'Winscard.dll';
  // Set all options to false, to 
  SCARD_LEAVE_CARD = True;
  SCARD_SCOPE_USER = True;
  SCARD_SHARE_SHARED = True;
  SCARD_UNPOWER_CARD = True;
  SCARD_S_SUCCESS=0;
type
  SCARDCONTEXT = ULONG;
  procedure SCardReleaseContext(fhSC: ULONG); stdcall;
  procedure SCardDisconnect(fhCard: LongInt; SCARD_LEAVE_CARD: boolean); stdcall;
  procedure SCardReconnect(fhCard: LongInt;SCARD_SHARE_SHARED:boolean;i: integer; SCARD_LEAVE_CARD: boolean;activeProtocol:LongInt); stdcall;
  function SCardEstablishContext(SCARD_SCOPE_USER:boolean;i:pointer;j:pointer;fhSC:pointer):DWORD; stdcall;
  function SCardListReadersA(fhSC:sCardContext;i:pointer;j:pointer;cch:integer):DWORD; stdcall;
  function SCardConnectA(fhSC:sCardContext;str:pointer;SCARD_SHARE_SHARED:boolean;flag:integer;fhCard:LongInt;activeProtocol:pointer):DWORD; stdcall;
  
implementation

procedure SCardReleaseContext(fhSC: ULONG); external WinSCardDLL name 'SCardReleaseContext';
procedure SCardDisconnect(fhCard: LongInt; SCARD_LEAVE_CARD: boolean); external WinSCardDLL name 'SCardDisconnect';
procedure SCardReconnect(fhCard: LongInt;SCARD_SHARE_SHARED:boolean;i: integer; SCARD_LEAVE_CARD: boolean;activeProtocol:LongInt); external WinSCardDLL name 'SCardReconnect';
function SCardEstablishContext(SCARD_SCOPE_USER:boolean;i:pointer;j:pointer;fhSC:pointer):DWORD; external WinSCardDLL name 'SCardEstablishContext';
  
function SCardListReadersA(fhSC:sCardContext;i:pointer;j:pointer;cch:integer):DWORD; external WinSCardDLL name 'SCardListReadersA';
  
function SCardConnectA(fhSC:sCardContext;str:pointer;SCARD_SHARE_SHARED:boolean;flag:integer;fhCard:LongInt;activeProtocol:pointer):DWORD; external WinSCardDLL name 'SCardConnectA';
function setPINValue(PinValue: String; handle: Dword): Boolean;
begin
  Result:=False;
end;

end.