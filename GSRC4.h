/* GSRC4.h - GSCrypt: Class GSRC4
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

#ifndef _GSRC4_h__
	#define _GSRC4_h__

#include <gscrypt/GSCryptCommon.h>

@interface GSRC4: NSObject<GSCrypting,GSByteStreaming,GSStreamCyphering>
{
// protected:
  NSMutableData* state;
  BYTE x;
  BYTE y;
  BOOL		m_fInit;
};
+(id)rc4WithKey:(NSData*)key;
-(id)init;
-(id)initWithKey:(NSData*)key;//GSCrypting
-(BYTE)streamByte; //GSByteStreaming
-(BYTE)cypherByte:(BYTE)input_;//GSStreamCyphering	
-(NSData*)crypt:(NSData*)dataIn_;//GSCrypting
-(NSData*)decrypt:(NSData*)dataIn_;//GSCrypting
+(UINT)keyMinSize;//GSCrypting
+(UINT)keyMaxSize;//GSCrypting
+(UINT)blockSize;//GSCrypting
#ifdef DEBUG
+(BOOL)debugTest;
#endif
@end

#endif // _GSRC4_h__
