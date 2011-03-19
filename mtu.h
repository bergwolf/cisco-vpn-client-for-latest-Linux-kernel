/**************************************************************************
*           Copyright (c) 2001, Cisco Systems, All Rights Reserved
***************************************************************************
*
*  File:    mtu.h
*  Date:    10/09/00
*
*  NOTE: THIS FILE IS INCLUDED BY THE INSTALLSHIELD SCRIPT FILE SETUP.RUL.
*        THEREFORE, THIS FILE MUST ONLY CONTAIN 'C' CONSTRUCTS THAT ARE
*        UNDERSTOOD BY THE INSTALLSHIELD SCRIPT COMPILER.  SO KEEP IT
*        SIMPLE IN HERE.
*
***************************************************************************/
#ifndef MTU_H
#define MTU_H

//constant used for reducing the interface MTU to account for
//the overhead introduced by tunneling.
//
//the value was produced by this calculation:
//  Outer IP Header + ESP packet header + ESP packet trailer +
//  max(UDP packet header (for ipsec over udp),
//      cTCP packet header + cTCP packet trailer) + Fudge factor.
//
// NOTE: If this value is ever increased, then the #define PPPoE_MTU_SLOP must
//       be decreased by the same amount, but never set to less than zero.
//
#define MTU_REDUCTION           144

// PPPoE_MTU_REDUCTION must, at the very least, account for the worst case PPPoE
// overhead.  The goal is for the maximum MTU of 1500 minus MTU_REDUCTION and 
// PPPoE_MTU_REDUCTION to equal 1300 (MTU_REDUCTION + PPPoE_MTU_REDUCTION = 200).
// Thus the PPPoE_MTU_SLOP.  PPPoE_MTU_SLOP must change along with MTU_REDUCTION
// in order to maintain that total of 1300, if possible (the PPPoE_MTU_SLOP can
// never be less than zero).  The hardcoded value added to PPPoE_MTU_SLOP to
// yield the PPPoE_MTU_REDUCTION must not be changed.  It is set according to
// information discovered about PPPoE overheads:
// http://www.microsoft.com/windowsxp/pro/using/howto/networking/pppoe.asp
//
#define PPPoE_MTU_SLOP          36
#define PPPoE_MTU_REDUCTION     (20 + PPPoE_MTU_SLOP)
#endif //MTU_H
