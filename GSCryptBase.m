/* GSCryptBase.m - GSCrypt
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

#include <gscrypt/GSCryptBase.h>

//====================================================================
@implementation NSObject (GSBlockTransform)// <GSCryptBlockTransforming>
//--------------------------------------------------------------------
-(NSData*)processBufferForBlock:(NSData*)dataIn_
{
  NSMutableData* dataOut=[NSMutableData data];
  UINT blockSize=[(NSObject<GSCryptBlockTransforming>*)self blockSize];
  UINT dataInSize=[dataIn_ length];
  UINT	blockNb=	dataInSize/blockSize;
  UINT	modSize=	dataInSize%blockSize;
  UINT	blockN	=	blockNb;
  IMP impAppendData=OBJ_METHOD_FOR_SEL(dataOut,appendData:);
  IMP impProcessBlock=OBJ_METHOD_FOR_SEL((NSObject<GSCryptBlockTransforming>*)self,processBlock:);
  IMP impSubdataWithRange=OBJ_METHOD_FOR_SEL(dataIn_,impSubdataWithRange:);
  for(blockN=0;blockN<blockNb;blockN++)
	  impAppendData(dataOut,@selector(appendData:),
					impProcessBlock(self,@selector(processBlock:),
									impSubdataWithRange(dataIn_,@selector(subdataWithRange:),
														NSMakeRange(blockN*blockSize,blockSize))));
  if (modSize>0)
	{
	  NSMutableData* dataInTmp=[[impSubdataWithRange(dataIn_,@selector(subdataWithRange:),
													 NSMakeRange(blockNb*blockSize,modSize)) mutableCopy] autorelease];
	  [dataInTmp increaseLengthBy:blockSize-modSize];
	  impAppendData(dataOut,@selector(appendData:),
					impProcessBlock(self,@selector(processBlock:),
									dataInTmp));
	};
  return [NSData dataWithData:dataOut];
};
@end 

//====================================================================
@implementation NSObject (GSCrypt) //<GSCrypt>
	 
//--------------------------------------------------------------------
+(UINT)calculDstSizeWithSrcSize:(UINT)sourceSize_
					  blockSize:(UINT)blockSize_
{
  if ((sourceSize_%blockSize_)!=0)
	sourceSize_=((sourceSize_/blockSize_)+1)*blockSize_;
  return sourceSize_;
};

//--------------------------------------------------------------------
+(UINT)dstSizeWithSrcSize:(UINT)sourceSize_
{
  return [self calculDstSizeWithSrcSize:sourceSize_
			   blockSize:[self blockSize]];
};

@end

//====================================================================
@implementation GSHashObject

//--------------------------------------------------------------------
-(void)updateWithData:(NSData*)data_
{	
  [self subclassResponsibility:_cmd];
};

//--------------------------------------------------------------------
-(void)updateWithString:(NSString*)string_
		  usingEncoding:(NSStringEncoding)encoding_
{
  [self updateWithData:[string_ dataUsingEncoding:encoding_]];
};

//--------------------------------------------------------------------
-(UINT)digestSize
{
  return [[self class] digestSize];
};
//--------------------------------------------------------------------
+(UINT)digestSize
{
  return (UINT)[self subclassResponsibility:_cmd];
};

//--------------------------------------------------------------------
-(NSData*)digest
{
  if (!done)
	[self calculateDigest];
  NSAssert(done,@"Not caclulated");
  return [[digest copy] autorelease];
};

//--------------------------------------------------------------------
-(void)calculateDigest
{
  NSAssert(!done,@"Already caclulated");
  done=YES;
};

//--------------------------------------------------------------------
+(NSData*)digestOfData:(NSData*)data_
{
  NSData* _digest=nil;
  GSHashObject* hashObject=[self new];
  [hashObject updateWithData:data_];
  _digest=[hashObject digest];
  DESTROY(hashObject);
  return _digest;
};

//--------------------------------------------------------------------
+(NSData*)digestOfString:(NSString*)string_
		   usingEncoding:(NSStringEncoding)encoding_
{
  return [self digestOfData:[string_ dataUsingEncoding:encoding_]];
};

@end

#ifdef DEBUG
	BOOL TestEndianess()
	{
	    BOOL fOk;
/*
		#ifdef __BIG_ENDIAN
			#ifdef __LITTLE_ENDIAN
				#pragma	message ("Error: __BIG_ENDIAN && __LITTLE_ENDIAN defined !!!")
			#endif
		#else
			#ifndef __LITTLE_ENDIAN
				#pragma	message ("Error: __BIG_ENDIAN && __LITTLE_ENDIAN not defined !!!")
			#endif
		#endif
*/
	    NSLog(@"Testing Endianess...");
	    if (*(UINT32 *)"\x01\x00\x00\x00" == 1L)
	    {
			#ifdef __LITTLE_ENDIAN
				NSLog(@"PASSED:  ");
				fOk = YES;
			#else
				NSCAssert(NO,"FAILED");
				fOk = NO;
			#endif
	        NSLog(@"Your machine is little endian.");
	    }
	    else
	    	if (*(UINT32*)"\x01\x00\x00\x00" == 0x01000000L)
		    {
				#ifndef __LITTLE_ENDIAN
					NSLog(@"PASSED:  ");
					fOk = YES;
				#else
					NSCAssert(NO,@"Endianess Test Failed");
					NSLog(@"FAILED:  ");
					fOk = NO;
				#endif
		        NSLog(@"Your machine is big endian.");
		    }
		    else
		    {
			  NSCAssert(NO,@"Endianess Test Failed");
			  NSLog(@"FAILED:  Your machine is neither big endian nor little endian.");
			  fOk = NO;
		    };
	    return fOk;
	};
#endif

//====================================================================
@implementation NSObject (GSRandomNbGen) //<GSRandomNbGenerating>
// calls -byte and returns the parity of the random BYTE
-(int)bit
{
  int n = 0;
  int x = [(NSObject<GSByteStreaming>*)self streamByte];	
  if (x)
	do
	  n++;
	while (0 != (x = x&(x-1)));	
  return (n % 2);
};
	
//---------------------------------------------------------------------
// get a random 32 bit word in the range min to max, inclusive
-(UINT32)longBetween:(UINT32)min_
				 and:(UINT32)max_
{
  UINT32 range = max_-min_;
  const UINT16 maxBytes = BytePrecision(range);
  const UINT16 maxBits = BitPrecision(range);	
  UINT32 value=0;	
  do
    {
	  int i;
	  value = 0;
	  for (i=0; i<maxBytes; i++)
		value = (value << 8) | [(NSObject<GSByteStreaming>*)self streamByte];	
	  value = CropValueToBitsNb(value, maxBits);
    } while (value > range);	
  return value+min_;
};

//---------------------------------------------------------------------
-(UINT16)shortBetween:(UINT16)min_
				  and:(UINT16)max_
{
  return (UINT16)[self longBetween:min_
					   and:max_];
};

//---------------------------------------------------------------------
// calls -streamByte length_ times
-(NSData*)blockOfLength:(UINT16)length_
{
  NSMutableData* data=[NSMutableData dataWithLength:length_];
  BYTE* dataBytes=(BYTE*)[data mutableBytes];
  IMP impStreamByte=OBJ_METHOD_FOR_SEL(self,streamByte);	  
  while (length_--)
	*dataBytes++ = (BYTE)(impStreamByte((NSObject<GSByteStreaming>*)self,@selector(streamByte)));
  return [NSData dataWithData:data];
};
@end

//====================================================================
@implementation NSObject (GSStreamCypher) //<GSStreamCyphering>
-(NSData*)cypherBuffer:(NSData*)data_
{
  unsigned int dataLength=[data_ length];
  const BYTE* inDataBytes=(BYTE*)[data_ bytes];
  NSMutableData* data=[NSMutableData dataWithLength:dataLength];
  BYTE* outDataBytes=(BYTE*)[data mutableBytes];
  IMP impCypherByte=OBJ_METHOD_FOR_SEL(self,cypherByte:);
  while(dataLength--)
	*outDataBytes++ = (BYTE)(impCypherByte((NSObject<GSStreamCyphering>*)self,@selector(cypherByte:),*inDataBytes++));
  return [NSData dataWithData:data];
};
@end	

//--------------------------------------------------------------------
UINT16 BytePrecision(UINT32 value)
{
  UINT16 i=0;
  for (i=sizeof(value);i;--i)
	if (value >> (i-1)*8)
	  break;
  return i;
};

//--------------------------------------------------------------------
UINT16 BitPrecision(UINT32 value)
{
  UINT16 i=0;
  for (i=8*sizeof(value);i;i--)
	if (value >> (i-1))
	  break;
  return i;
};

//--------------------------------------------------------------------
UINT32 CropValueToBitsNb(UINT32 value,UINT16 bitsNb)
{
  return (value & ((1L << bitsNb) - 1));
};

void Swap_(void* a,int sizeOfa,void* b,int sizeOfb)
{
  BYTE temp[sizeOfa];
  NSCAssert2(sizeOfa==sizeOfb,@"Different Size: %d %d",sizeOfa,sizeOfb);
  memcpy(temp,a,sizeOfa);
  memcpy(a,b,sizeOfa);
  memcpy(b,temp,sizeOfa);
};

//--------------------------------------------------------------------
NSString* DataToHexString(NSData* data)
{
  unsigned int size=[data length];
  if (size)
	{
	  const unsigned char* pData=(const unsigned char*)[data bytes];
	  if (pData)
		{
		  NSMutableString* string=[[NSMutableString new] autorelease];
		  int i=0;
		  for(i=0;i<size;i++)
			{
			  [string appendFormat:@"%02x",(unsigned int)pData[i]];
			};
		  return string;
		};
	};
  return nil;
};

//--------------------------------------------------------------------
NSData* HexStringToData(NSString* _string)
{
  int size=[_string length];
  if (size>0)
	{
	  const char* pString=(const char*)[[_string uppercaseString]cString];
	  if (pString)
		{
		  NSMutableData* data=[NSMutableData dataWithLength:size/2];
		  unsigned char* pData=(unsigned char*)[data bytes];
		  int i=0;
		  for(i=0;i<size/2;i++)
			{
			  if (pString[i*2]>='0' && pString[i*2]<='9')
				pData[i]=(pString[i*2]-'0') << 4;
			  else if (pString[i*2]>='A' && pString[i*2]<='F')
				pData[i]=(pString[i*2]-'A') << 4;
			  else
				{
				  NSCAssert(NO,@"Bad hex String");
				};
			  if (pString[i*2+1]>='0' && pString[i*2+1]<='9')
				pData[i]=pData[i]|(pString[i*2+1]-'0');
			  else if (pString[i*2+1]>='A' && pString[i*2+1]<='F')
				pData[i]=pData[i]|(pString[i*2+1]-'A');
			  else
				{
				  NSCAssert(NO,@"Bad hex String");
				};
			};
		  return data;
		};
	};
  return nil;
};


