// --- BEGIN COPYRIGHT BLOCK ---
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation;
// version 2.1 of the License.
// 
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor,
// Boston, MA  02110-1301  USA 
// 
// Copyright (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

#include <stdio.h>
#include <string.h>
#include "apdu/APDU.h"
#include "apdu/Clear_Key_Slots_APDU.h"
#include "main/Memory.h"

#ifdef XP_WIN32
#define TPS_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define TPS_PUBLIC
#endif /* !XP_WIN32 */

/**
 * Constructs SetIssuer APDU.
 *
 * Clear_Key_Slots_APDU format:
 * CLA    0x84
 * INS    0x55
 * P1     0x00
 * P2     0x00
 * lc     len of key indexes 
 * DATA   <<private-key-index><public-key-index> .... >
 *
 * Connection requirement:
 *   Secure Channel
 *
 */
TPS_PUBLIC Clear_Key_Slots_APDU::Clear_Key_Slots_APDU (Buffer &data)
{
    SetCLA(0x84);
    SetINS(0x55);
    SetP1(0x0);
    SetP2(0x0);
    SetData(data);
}

TPS_PUBLIC Clear_Key_Slots_APDU::~Clear_Key_Slots_APDU ()
{
}

/*
TPS_PUBLIC Buffer &Set_IssuerInfo_APDU::GetIssuerInfo()
{
    return GetData();
}

*/

TPS_PUBLIC APDU_Type Clear_Key_Slots_APDU::GetType()
{
        return APDU_CLEAR_KEY_SLOTS;
}
