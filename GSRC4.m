/* GSRC4.m - GSCrypt: Class GSRC4
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

#include <gscrypt/GSRC4.h>

@implementation GSRC4

//--------------------------------------------------------------------
+(id)rc4WithKey:(NSData*)key
{
  return [[[self alloc]initWithKey:key]autorelease];
};

//--------------------------------------------------------------------
-(id)init
{
  if ((self=[super init]))
	{
	};
  return self;
};

//--------------------------------------------------------------------
-(id)initWithKey:(NSData*)key
{
  NSAssert([key length]>0,@"No Key or empty key");
  if ((self=[self init]))
	{
	  BYTE* stateBytes=NULL;
	  UINT16 	counter=0;
	  short	keyLength=[key length];
	  const BYTE* keyBytes=[key bytes];
	  BYTE	index1 = 0;
	  BYTE	index2 = 0;
	  ASSIGN(state,[NSMutableData dataWithLength:256]);
	  stateBytes=[state mutableBytes];
	  NSLog(@"Key Length=%d",keyLength);
	  for (counter=0;counter<256;counter++)
		stateBytes[counter]=(BYTE)counter;
	  x = 0;
	  y = 0;

	  for (counter=0;counter<256;counter++)
	    {
		  NSAssert(index1<keyLength,@"Pb");
		  index2 = (keyBytes[index1]+stateBytes[counter]+index2);
		  NSAssert(index2<256,@"Pb");
		  Swap(stateBytes[counter],stateBytes[index2]);
		  index1 =(index1+1)%keyLength;
	    };
	};
  return self;
};

//--------------------------------------------------------------------
-(BYTE)streamByte //GSByteStreaming
{
  BYTE* stateBytes=[state mutableBytes];
  NSAssert(state,@"Not initialized");
  x++;
  y+=stateBytes[x];
  Swap(stateBytes[x],stateBytes[y]);
  return (stateBytes[(stateBytes[x]+stateBytes[y])&255]);
};

//--------------------------------------------------------------------
-(BYTE)cypherByte:(BYTE)input_//GSStreamCyphering
{
  return (input_^[self streamByte]);
};

//--------------------------------------------------------------------
-(NSData*)crypt:(NSData*)dataIn_
{
  return [self cypherBuffer:dataIn_];
};

//--------------------------------------------------------------------
-(NSData*)decrypt:(NSData*)dataIn_//GSCrypting
{
  return [self cypherBuffer:dataIn_];
};

//--------------------------------------------------------------------
+(UINT)keyMinSize //GSCrypting
{
  return 1;
};

//--------------------------------------------------------------------
+(UINT)keyMaxSize //GSCrypting
{
  return 256;
};

//--------------------------------------------------------------------
+(UINT)blockSize //GSCrypting
{
  return 1;
};


#ifdef DEBUG
//--------------------------------------------------------------------
+(BOOL)debugTest
{
  BOOL	ok=YES;
  BYTE keyBytes0[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  BYTE keyBytes1[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  BYTE keyBytes2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  BYTE keyBytes3[]={0xef,0x01,0x23,0x45};
  BYTE keyBytes4[]={ 0x01,0x23,0x45,0x67,0x89,0xab, 0xcd,0xef};
  NSData* keyData[5]= { [NSData dataWithBytes:keyBytes0
								  length:sizeof(keyBytes0)],
						  [NSData dataWithBytes:keyBytes1
								  length:sizeof(keyBytes1)],
						  [NSData dataWithBytes:keyBytes2
								  length:sizeof(keyBytes2)],
						  [NSData dataWithBytes:keyBytes3
								  length:sizeof(keyBytes3)],
						  [NSData dataWithBytes:keyBytes4
								  length:sizeof(keyBytes4)]};
  BYTE inputBytes0[]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
  BYTE inputBytes1[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  BYTE inputBytes2[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  BYTE inputBytes3[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  BYTE inputBytes4[]={
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
	  0x01};
  NSData* inputData[5]= { [NSData dataWithBytes:inputBytes0
								  length:sizeof(inputBytes0)],
						  [NSData dataWithBytes:inputBytes1
								  length:sizeof(inputBytes1)],
						  [NSData dataWithBytes:inputBytes2
								  length:sizeof(inputBytes2)],
						  [NSData dataWithBytes:inputBytes3
								  length:sizeof(inputBytes3)],
						  [NSData dataWithBytes:inputBytes4
								  length:sizeof(inputBytes4)]};
  BYTE outputBytes0[]= {0x75,0xb7,0x87,0x80,0x99,0xe0,0xc5,0x96};
  BYTE outputBytes1[]= {0x74,0x94,0xc2,0xe7,0x10,0x4b,0x08,0x79};
  BYTE outputBytes2[]= {0xde,0x18,0x89,0x41,0xa3,0x37,0x5d,0x3a};
  BYTE outputBytes3[]= {0xd6,0xa1,0x41,0xa7,0xec,0x3c,0x38,0xdf,0xbd,0x61};
  BYTE outputBytes4[]= {
	  0x75,0x95,0xc3,0xe6,0x11,0x4a,0x09,0x78,0x0c,0x4a,0xd4,
	  0x52,0x33,0x8e,0x1f,0xfd,0x9a,0x1b,0xe9,0x49,0x8f,
	  0x81,0x3d,0x76,0x53,0x34,0x49,0xb6,0x77,0x8d,0xca,
	  0xd8,0xc7,0x8a,0x8d,0x2b,0xa9,0xac,0x66,0x08,0x5d,
	  0x0e,0x53,0xd5,0x9c,0x26,0xc2,0xd1,0xc4,0x90,0xc1,
	  0xeb,0xbe,0x0c,0xe6,0x6d,0x1b,0x6b,0x1b,0x13,0xb6,
	  0xb9,0x19,0xb8,0x47,0xc2,0x5a,0x91,0x44,0x7a,0x95,
	  0xe7,0x5e,0x4e,0xf1,0x67,0x79,0xcd,0xe8,0xbf,0x0a,
	  0x95,0x85,0x0e,0x32,0xaf,0x96,0x89,0x44,0x4f,0xd3,
	  0x77,0x10,0x8f,0x98,0xfd,0xcb,0xd4,0xe7,0x26,0x56,
	  0x75,0x00,0x99,0x0b,0xcc,0x7e,0x0c,0xa3,0xc4,0xaa,
	  0xa3,0x04,0xa3,0x87,0xd2,0x0f,0x3b,0x8f,0xbb,0xcd,
	  0x42,0xa1,0xbd,0x31,0x1d,0x7a,0x43,0x03,0xdd,0xa5,
	  0xab,0x07,0x88,0x96,0xae,0x80,0xc1,0x8b,0x0a,0xf6,
	  0x6d,0xff,0x31,0x96,0x16,0xeb,0x78,0x4e,0x49,0x5a,
	  0xd2,0xce,0x90,0xd7,0xf7,0x72,0xa8,0x17,0x47,0xb6,
	  0x5f,0x62,0x09,0x3b,0x1e,0x0d,0xb9,0xe5,0xba,0x53,
	  0x2f,0xaf,0xec,0x47,0x50,0x83,0x23,0xe6,0x71,0x32,
	  0x7d,0xf9,0x44,0x44,0x32,0xcb,0x73,0x67,0xce,0xc8,
	  0x2f,0x5d,0x44,0xc0,0xd0,0x0b,0x67,0xd6,0x50,0xa0,
	  0x75,0xcd,0x4b,0x70,0xde,0xdd,0x77,0xeb,0x9b,0x10,
	  0x23,0x1b,0x6b,0x5b,0x74,0x13,0x47,0x39,0x6d,0x62,
	  0x89,0x74,0x21,0xd4,0x3d,0xf9,0xb4,0x2e,0x44,0x6e,
	  0x35,0x8e,0x9c,0x11,0xa9,0xb2,0x18,0x4e,0xcb,0xef,
	  0x0c,0xd8,0xe7,0xa8,0x77,0xef,0x96,0x8f,0x13,0x90,
	  0xec,0x9b,0x3d,0x35,0xa5,0x58,0x5c,0xb0,0x09,0x29,
	  0x0e,0x2f,0xcd,0xe7,0xb5,0xec,0x66,0xd9,0x08,0x4b,
	  0xe4,0x40,0x55,0xa6,0x19,0xd9,0xdd,0x7f,0xc3,0x16,
	  0x6f,0x94,0x87,0xf7,0xcb,0x27,0x29,0x12,0x42,0x64,
	  0x45,0x99,0x85,0x14,0xc1,0x5d,0x53,0xa1,0x8c,0x86,
	  0x4c,0xe3,0xa2,0xb7,0x55,0x57,0x93,0x98,0x81,0x26,
	  0x52,0x0e,0xac,0xf2,0xe3,0x06,0x6e,0x23,0x0c,0x91,
	  0xbe,0xe4,0xdd,0x53,0x04,0xf5,0xfd,0x04,0x05,0xb3,
	  0x5b,0xd9,0x9c,0x73,0x13,0x5d,0x3d,0x9b,0xc3,0x35,
	  0xee,0x04,0x9e,0xf6,0x9b,0x38,0x67,0xbf,0x2d,0x7b,
	  0xd1,0xea,0xa5,0x95,0xd8,0xbf,0xc0,0x06,0x6f,0xf8,
	  0xd3,0x15,0x09,0xeb,0x0c,0x6c,0xaa,0x00,0x6c,0x80,
	  0x7a,0x62,0x3e,0xf8,0x4c,0x3d,0x33,0xc1,0x95,0xd2,
	  0x3e,0xe3,0x20,0xc4,0x0d,0xe0,0x55,0x81,0x57,0xc8,
	  0x22,0xd4,0xb8,0xc5,0x69,0xd8,0x49,0xae,0xd5,0x9d,
	  0x4e,0x0f,0xd7,0xf3,0x79,0x58,0x6b,0x4b,0x7f,0xf6,
	  0x84,0xed,0x6a,0x18,0x9f,0x74,0x86,0xd4,0x9b,0x9c,
	  0x4b,0xad,0x9b,0xa2,0x4b,0x96,0xab,0xf9,0x24,0x37,
	  0x2c,0x8a,0x8f,0xff,0xb1,0x0d,0x55,0x35,0x49,0x00,
	  0xa7,0x7a,0x3d,0xb5,0xf2,0x05,0xe1,0xb9,0x9f,0xcd,
	  0x86,0x60,0x86,0x3a,0x15,0x9a,0xd4,0xab,0xe4,0x0f,
	  0xa4,0x89,0x34,0x16,0x3d,0xdd,0xe5,0x42,0xa6,0x58,
	  0x55,0x40,0xfd,0x68,0x3c,0xbf,0xd8,0xc0,0x0f,0x12,
	  0x12,0x9a,0x28,0x4d,0xea,0xcc,0x4c,0xde,0xfe,0x58,
	  0xbe,0x71,0x37,0x54,0x1c,0x04,0x71,0x26,0xc8,0xd4,
	  0x9e,0x27,0x55,0xab,0x18,0x1a,0xb7,0xe9,0x40,0xb0,
		0xc0};
  NSData* outputData[5]= { [NSData dataWithBytes:outputBytes0
								   length:sizeof(outputBytes0)],
						   [NSData dataWithBytes:outputBytes1
								   length:sizeof(outputBytes1)],
						   [NSData dataWithBytes:outputBytes2
								   length:sizeof(outputBytes2)],
						   [NSData dataWithBytes:outputBytes3
								   length:sizeof(outputBytes3)],
						   [NSData dataWithBytes:outputBytes4
								   length:sizeof(outputBytes4)]};
  BOOL	fail=NO;
  int		i;
  NSLog(@"RC4 Test...");
  TestEndianess();
  for(i=0;i<5;i++)
	{
	  GSRC4* rc4=[GSRC4 rc4WithKey:keyData[i]];
	  NSData* in=inputData[i];
	  NSData* out=outputData[i];
	  NSData* resultOutput=[rc4 crypt:in];
	  NSString* outString=[DataToHexString(out)uppercaseString];
	  NSString* resultOutputString=[DataToHexString(resultOutput)uppercaseString];
	  fail=![resultOutput isEqualToData:out];
	  if (fail)
	    {
		  NSLog(@"RC4 Test %d FAILED: result=%@ len=%d instead of %@ len=%d",
				i,
				resultOutputString,
				[resultOutput length],
				outString,
				[out length]);
		  ok=NO;
		}
	  else
		{
		  NSLog(@"RC4 Test %d PASSED",i);
		};
	};
  NSLog(@"RC4 Tests %s",(ok ? "PASSED" : "FAILED"));
  NSAssert(ok,@"RC4 Tests Failed");
  return ok;
};
#endif

@end