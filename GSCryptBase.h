/* GSCryptBase.h - GSCrypt
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

#ifndef _GSCryptBase_h__
	#define _GSCryptBase_h__

#include <gscrypt/GSCryptCommon.h>

//====================================================================
@protocol GSCryptBlockTransforming
-(NSData*)processBlock:(NSData*)blockData_;
-(UINT)blockSize;
@end

//====================================================================
@interface NSObject (GSBlockTransform) //<GSCryptBlockTransforming>
-(NSData*)processBufferForBlock:(NSData*)dataIn_;
@end

//====================================================================
@protocol GSCrypting
-(id)initWithKey:(NSData*)key;
+(UINT)keyMinSize;
+(UINT)keyMaxSize;
+(UINT)blockSize;
-(NSData*)crypt:(NSData*)dataIn_;
-(NSData*)decrypt:(NSData*)dataIn_;
@end

//====================================================================
@interface NSObject (GSCrypt) //<GSCrypting>
+(UINT)calculDstSizeWithSrcSize:(UINT)sourceSize_
					  blockSize:(UINT)blockSize_;
+(UINT)dstSizeWithSrcSize:(UINT)sourceSize_;
@end

//====================================================================
@interface GSHashObject: NSObject
{
// protected
  NSData* digest;
  BOOL done;
}
-(void)updateWithData:(NSData*)data_; //subClassResponsability
-(void)updateWithString:(NSString*)string_
		  usingEncoding:(NSStringEncoding)encoding_;
-(UINT)digestSize;
+(UINT)digestSize; //subClassResponsability
-(NSData*)digest;
-(void)calculateDigest;
+(NSData*)digestOfData:(NSData*)data_;
+(NSData*)digestOfString:(NSString*)string_
		   usingEncoding:(NSStringEncoding)encoding_;
@end

//====================================================================
@protocol GSByteStreaming
-(BYTE)streamByte;
@end

//====================================================================
@interface NSObject (GSRandomNbGen) //<GSByteStreaming>
// calls -streamByte and returns the parity of the byte
-(int)bit;
// get a random 32 bit word in the range min to max, inclusive
-(UINT32)longBetween:(UINT32)min_
				 and:(UINT32)max_;
-(UINT16)shortBetween:(UINT16)min_
				  and:(UINT16)max_;
// calls -streamByte length_ times
-(NSData*)blockOfLength:(UINT16)length_;
@end

//====================================================================
@protocol GSStreamCyphering
-(BYTE)cypherByte:(BYTE)input_;
@end

//====================================================================
@interface NSObject (GSStreamCypher) //<GSStreamCyphering>
-(NSData*)cypherBuffer:(NSData*)data_;
@end

//====================================================================
UINT16 BytePrecision(UINT32 value);
UINT16 BitPrecision(UINT32 value);
UINT32 CropValueToBitsNb(UINT32 value,UINT16 bitsNb);

void Swap_(void* a,int sizeOfa,void* b,int sizeOfb);

#define Swap(a,b);		Swap_((void*)&a,sizeof(a),(void*)&b,sizeof(b));


#ifdef DEBUG
BOOL TestEndianess();
#endif

NSString* DataToHexString(NSData* data);
NSData* HexStringToData(NSString* _string);

#endif //_GSCryptBase_h__
