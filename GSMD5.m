/* GSMD5.m - GSCrypt: Class GSMD5
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

#include <gscrypt/GSMD5.h>
#define MD5__DIGEST_SIZE	16
//--------------------------------------------------------------------
#ifdef __LITTLE_ENDIAN
	#define MD5_ByteReverse(buff,size)		{}	// Nothing
#else
	void MD5_ByteReverse(BYTE* buff,UINT16 size);	//	size in Machine Word
	{
	  if (size>0)
		{
		  UINT32 dwTemp;
		  do
		    {
			  dwTemp = (UINT32) 	(	((unsigned)buff[3] << 8 |	buff[2]) << 16	)
				|   (	(unsigned)buff[1] << 8	|	buff[0]			);
			  *(UINT32*)buff = dwTemp;
			  buff+=4;
		    } while (--size);
		};
	};
#endif	//__LITTLE_ENDIAN


@implementation GSMD5

//---------------------------------------------------------------------------------------
//	Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious initialization constants.
-(id)init
{
  if ((self=[super init]))
	{
	  ctxBuf[0] = 0x67452301;
	  ctxBuf[1] = 0xefcdab89;
	  ctxBuf[2] = 0x98badcfe;
	  ctxBuf[3] = 0x10325476;

	  ctxBits[0] = 0;
	  ctxBits[1] = 0;
    
	  memset(ctxIn,0,64);
	};
  return self;
};

//--------------------------------------------------------------------

//	Update context to reflect the concatenation of another buffer full of bytes.
-(void)updateWithData:(NSData*)data_
{
  UINT dataSize=0;
  const BYTE* dataBytes=NULL;
  UINT32 temp=0;
  IMP impTransform=OBJ_METHOD_FOR_SEL(self,transform);	
  NSAssert(!done,@"Already Calculated");
  dataSize=[data_ length];
  dataBytes=[data_ bytes];
  // Update bitcount
  temp=ctxBits[0];
  ctxBits[0] = temp + ((UINT32) dataSize << 3);
  if (ctxBits[0]<temp)
	ctxBits[1]++;		// Carry from low to high
  ctxBits[1] += dataSize >> 29;
  temp = (temp >> 3) & 0x3f;	// Bytes already in shsInfo->data
  // Handle any leading odd-sized chunks
  if (temp)
    {
	  BYTE* buff =(BYTE*)ctxIn+temp;	
	  temp = 64 - temp;
	  if (dataSize < temp)
		{
		  memcpy(buff,dataBytes,dataSize);
		  return;
		};
	  memcpy(buff,dataBytes,temp);
	  MD5_ByteReverse(ctxIn,16);
	  impTransform(self,@selector(transform));
	  dataBytes+=temp;
	  dataSize-=temp;
    };
    // Process data in 64-byte chunks
  while (dataSize >= 64)
    {
	  memcpy(ctxIn,dataBytes,64);
	  MD5_ByteReverse(ctxIn, 16);
	  impTransform(self,@selector(transform));
	  dataBytes += 64;
	  dataSize -= 64;
    };

    // Handle any remaining bytes of data.
    memcpy(ctxIn,dataBytes,dataSize);
};

//--------------------------------------------------------------------

//	Final wrapup - pad to 64-byte boundary with the bit pattern 1 0* (64-bit count of bits processed, MSB-first)
-(void)calculateDigest
{
  UINT16	count=0;
  BYTE*	buff=NULL;
  NSData* _digest=nil;
  [super calculateDigest];
  count=(UINT16)((ctxBits[0] >> 3) & 0x3F);		//	Compute number of bytes mod 64
  // Set the first char of padding to 0x80.  This is safe since there is always at least one byte free
  buff=ctxIn + count;
  *buff++ = 0x80;
  count = 64 - 1 - count;				//	Bytes of padding needed to make 64 bytes

  // Pad out to 56 mod 64
  if (count<8)
    {
	  //	Two lots of padding:  Pad the first block to 64 bytes
	  memset(buff, 0, count);
	  MD5_ByteReverse(ctxIn, 16);
	  [self transform];	
	  //	Now fill the next block with 56 bytes
	  memset(ctxIn, 0, 56);
    }
  else
    {
	  memset(buff, 0, count - 8);	//	Pad block to 56 bytes
    };
  MD5_ByteReverse(ctxIn, 14);

  // Append length in bits and transform
  ((UINT32 *)ctxIn)[14] = ctxBits[0];
  ((UINT32 *)ctxIn)[15] = ctxBits[1];
  
  [self transform];
  MD5_ByteReverse((BYTE*)ctxBuf, 4);
  _digest=[NSData dataWithBytes:ctxBuf
				  length:[self digestSize]];
  ASSIGN(digest,_digest);
};

//--------------------------------------------------------------------
// The four core functions - CMD5_F1 is optimized somewhat
// #define CMD5_F1(x, y, z) (x & y | ~x & z)
#define CMD5_F1(x, y, z) (z ^ (x & (y ^ z)))
#define CMD5_F2(x, y, z) CMD5_F1(z, x, y)
#define CMD5_F3(x, y, z) (x ^ y ^ z)
#define CMD5_F4(x, y, z) (y ^ (x | ~z))

// This is the central step in the MD5 algorithm.
#define CMD5_STEP(f, w, x, y, z, data, s)			( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )
	
//	The core of the MD5 algorithm, this alters an existing MD5 hash to reflect the addition of 16 longwords of new data.
//	Update blocks the data and converts bytes into longwords for this routine.
-(void)transform
{
  UINT32* dwCtxIn=(UINT32*)ctxIn;
  UINT32 a = ctxBuf[0];
  UINT32 b = ctxBuf[1];
  UINT32 c = ctxBuf[2];
  UINT32 d = ctxBuf[3];
  
  CMD5_STEP(CMD5_F1, a, b, c, d, dwCtxIn[0] + 0xd76aa478, 7);
  CMD5_STEP(CMD5_F1, d, a, b, c, dwCtxIn[1] + 0xe8c7b756, 12);
  CMD5_STEP(CMD5_F1, c, d, a, b, dwCtxIn[2] + 0x242070db, 17);
  CMD5_STEP(CMD5_F1, b, c, d, a, dwCtxIn[3] + 0xc1bdceee, 22);
  CMD5_STEP(CMD5_F1, a, b, c, d, dwCtxIn[4] + 0xf57c0faf, 7);
  CMD5_STEP(CMD5_F1, d, a, b, c, dwCtxIn[5] + 0x4787c62a, 12);
  CMD5_STEP(CMD5_F1, c, d, a, b, dwCtxIn[6] + 0xa8304613, 17);
  CMD5_STEP(CMD5_F1, b, c, d, a, dwCtxIn[7] + 0xfd469501, 22);
  CMD5_STEP(CMD5_F1, a, b, c, d, dwCtxIn[8] + 0x698098d8, 7);
  CMD5_STEP(CMD5_F1, d, a, b, c, dwCtxIn[9] + 0x8b44f7af, 12);
  CMD5_STEP(CMD5_F1, c, d, a, b, dwCtxIn[10] + 0xffff5bb1, 17);
  CMD5_STEP(CMD5_F1, b, c, d, a, dwCtxIn[11] + 0x895cd7be, 22);
  CMD5_STEP(CMD5_F1, a, b, c, d, dwCtxIn[12] + 0x6b901122, 7);
  CMD5_STEP(CMD5_F1, d, a, b, c, dwCtxIn[13] + 0xfd987193, 12);
  CMD5_STEP(CMD5_F1, c, d, a, b, dwCtxIn[14] + 0xa679438e, 17);
  CMD5_STEP(CMD5_F1, b, c, d, a, dwCtxIn[15] + 0x49b40821, 22);
	
  CMD5_STEP(CMD5_F2, a, b, c, d, dwCtxIn[1] + 0xf61e2562, 5);
  CMD5_STEP(CMD5_F2, d, a, b, c, dwCtxIn[6] + 0xc040b340, 9);
  CMD5_STEP(CMD5_F2, c, d, a, b, dwCtxIn[11] + 0x265e5a51, 14);
  CMD5_STEP(CMD5_F2, b, c, d, a, dwCtxIn[0] + 0xe9b6c7aa, 20);
  CMD5_STEP(CMD5_F2, a, b, c, d, dwCtxIn[5] + 0xd62f105d, 5);
  CMD5_STEP(CMD5_F2, d, a, b, c, dwCtxIn[10] + 0x02441453, 9);
  CMD5_STEP(CMD5_F2, c, d, a, b, dwCtxIn[15] + 0xd8a1e681, 14);
  CMD5_STEP(CMD5_F2, b, c, d, a, dwCtxIn[4] + 0xe7d3fbc8, 20);
  CMD5_STEP(CMD5_F2, a, b, c, d, dwCtxIn[9] + 0x21e1cde6, 5);
  CMD5_STEP(CMD5_F2, d, a, b, c, dwCtxIn[14] + 0xc33707d6, 9);
  CMD5_STEP(CMD5_F2, c, d, a, b, dwCtxIn[3] + 0xf4d50d87, 14);
  CMD5_STEP(CMD5_F2, b, c, d, a, dwCtxIn[8] + 0x455a14ed, 20);
  CMD5_STEP(CMD5_F2, a, b, c, d, dwCtxIn[13] + 0xa9e3e905, 5);
  CMD5_STEP(CMD5_F2, d, a, b, c, dwCtxIn[2] + 0xfcefa3f8, 9);
  CMD5_STEP(CMD5_F2, c, d, a, b, dwCtxIn[7] + 0x676f02d9, 14);
  CMD5_STEP(CMD5_F2, b, c, d, a, dwCtxIn[12] + 0x8d2a4c8a, 20);
	
  CMD5_STEP(CMD5_F3, a, b, c, d, dwCtxIn[5] + 0xfffa3942, 4);
  CMD5_STEP(CMD5_F3, d, a, b, c, dwCtxIn[8] + 0x8771f681, 11);
  CMD5_STEP(CMD5_F3, c, d, a, b, dwCtxIn[11] + 0x6d9d6122, 16);
  CMD5_STEP(CMD5_F3, b, c, d, a, dwCtxIn[14] + 0xfde5380c, 23);
  CMD5_STEP(CMD5_F3, a, b, c, d, dwCtxIn[1] + 0xa4beea44, 4);
  CMD5_STEP(CMD5_F3, d, a, b, c, dwCtxIn[4] + 0x4bdecfa9, 11);
  CMD5_STEP(CMD5_F3, c, d, a, b, dwCtxIn[7] + 0xf6bb4b60, 16);
  CMD5_STEP(CMD5_F3, b, c, d, a, dwCtxIn[10] + 0xbebfbc70, 23);
  CMD5_STEP(CMD5_F3, a, b, c, d, dwCtxIn[13] + 0x289b7ec6, 4);
  CMD5_STEP(CMD5_F3, d, a, b, c, dwCtxIn[0] + 0xeaa127fa, 11);
  CMD5_STEP(CMD5_F3, c, d, a, b, dwCtxIn[3] + 0xd4ef3085, 16);
  CMD5_STEP(CMD5_F3, b, c, d, a, dwCtxIn[6] + 0x04881d05, 23);
  CMD5_STEP(CMD5_F3, a, b, c, d, dwCtxIn[9] + 0xd9d4d039, 4);
  CMD5_STEP(CMD5_F3, d, a, b, c, dwCtxIn[12] + 0xe6db99e5, 11);
  CMD5_STEP(CMD5_F3, c, d, a, b, dwCtxIn[15] + 0x1fa27cf8, 16);
  CMD5_STEP(CMD5_F3, b, c, d, a, dwCtxIn[2] + 0xc4ac5665, 23);
	
  CMD5_STEP(CMD5_F4, a, b, c, d, dwCtxIn[0] + 0xf4292244, 6);
  CMD5_STEP(CMD5_F4, d, a, b, c, dwCtxIn[7] + 0x432aff97, 10);
  CMD5_STEP(CMD5_F4, c, d, a, b, dwCtxIn[14] + 0xab9423a7, 15);
  CMD5_STEP(CMD5_F4, b, c, d, a, dwCtxIn[5] + 0xfc93a039, 21);
  CMD5_STEP(CMD5_F4, a, b, c, d, dwCtxIn[12] + 0x655b59c3, 6);
  CMD5_STEP(CMD5_F4, d, a, b, c, dwCtxIn[3] + 0x8f0ccc92, 10);
  CMD5_STEP(CMD5_F4, c, d, a, b, dwCtxIn[10] + 0xffeff47d, 15);
  CMD5_STEP(CMD5_F4, b, c, d, a, dwCtxIn[1] + 0x85845dd1, 21);
  CMD5_STEP(CMD5_F4, a, b, c, d, dwCtxIn[8] + 0x6fa87e4f, 6);
  CMD5_STEP(CMD5_F4, d, a, b, c, dwCtxIn[15] + 0xfe2ce6e0, 10);
  CMD5_STEP(CMD5_F4, c, d, a, b, dwCtxIn[6] + 0xa3014314, 15);
  CMD5_STEP(CMD5_F4, b, c, d, a, dwCtxIn[13] + 0x4e0811a1, 21);
  CMD5_STEP(CMD5_F4, a, b, c, d, dwCtxIn[4] + 0xf7537e82, 6);
  CMD5_STEP(CMD5_F4, d, a, b, c, dwCtxIn[11] + 0xbd3af235, 10);
  CMD5_STEP(CMD5_F4, c, d, a, b, dwCtxIn[2] + 0x2ad7d2bb, 15);
  CMD5_STEP(CMD5_F4, b, c, d, a, dwCtxIn[9] + 0xeb86d391, 21);
	
  ctxBuf[0] += a;
  ctxBuf[1] += b;
  ctxBuf[2] += c;
  ctxBuf[3] += d;
};
	
//--------------------------------------------------------------------

+(UINT)digestSize
{
  return MD5__DIGEST_SIZE;
};

#ifdef DEBUG
//--------------------------------------------------------------------
+(BOOL)debugTest
{
  BOOL	ok=YES;
  GSMD5* md5=nil;
  NSArray* tests=[NSArray arrayWithObjects:@"",
						  @"a",
						  @"abc",
						  @"message digest",
						  @"abcdefghijklmnopqrstuvwxyz",
						  @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
						  @"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
						  nil];
  NSArray* results=[NSArray arrayWithObjects:@"D41D8CD98F00B204E9800998ECF8427E",		//	""
							@"0CC175B9C0F1B6A831C399E269772661",		//	"a"
							@"900150983CD24FB0D6963F7D28E17F72",		//	"abc"
							@"F96B697D7CB7938D525A2F31AAF161D0",		//	"message digest"
							@"C3FCD3D76192E4007DFB496CCA67E13B",		//	"abcdefghijklmnopqrstuvwxyz"
							@"D174AB98D277D9F5A5611C2C9F419D9F",		//	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
							@"57EDF4A22BE3C955AC49DA2E2107B67A",		//	"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
							nil];
  NSString* result=nil;
  int i=0;
  NSLog(@"MD5 Test...");
  TestEndianess();
  for(i=0;i<[tests count];i++)
	{
	  BOOL failed=NO;
	  md5=[[GSMD5 new]autorelease];
	  [md5 updateWithString:[tests objectAtIndex:i]
		   usingEncoding:NSASCIIStringEncoding];
	  result=[DataToHexString([md5 digest])uppercaseString];
	  failed=![result isEqualToString:[results objectAtIndex:i]];
	  if (failed)
		{
		  NSLog(@"i=%d result=%@ instead of %@",i,result,[results objectAtIndex:i]);
		}
	  else
		{
		  NSLog(@"MD5 Test %d PASSED",i);
		};
	};
  NSLog(@"MD5 Tests %s",(ok ? "PASSED" : "FAILED"));
  NSAssert(ok,@"MD5 Tests Failed");
  return ok;
};
#endif

@end
