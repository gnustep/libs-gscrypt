/* GSMD5.h - GSCrypt: Class GSMD5
   Copyright (C) 2000 Free Software Foundation, Inc.
   
   Written by:	Manuel Guesdon <mguesdon@orange-concept.com>
   Date: 		Mar 2000
   
   This file is part of the GNUstep GSCrypt Library.
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// $Id$

#ifndef _GSMD5_h__
	#define _GSMD5_h__

#include <gscrypt/GSCryptCommon.h>

@interface GSMD5: GSHashObject
{
// protected:
  UINT32 ctxBuf[4];
  UINT32 ctxBits[2];
  BYTE	ctxIn[64];
}
-(id)init;
-(void)updateWithData:(NSData*)data_;
-(void)calculateDigest;
+(UINT)digestSize;

//Non Public
-(void)transform;

#ifdef DEBUG
+(BOOL)debugTest;
#endif
@end

#endif // _GSMD5_h__
