/* GSCryptCommon.h - GSCrypt
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

#ifndef _GSCryptCommon_h__
	#define _GSCryptCommon_h__

#include <Foundation/NSObject.h>
#include <Foundation/NSValue.h>
#include <Foundation/NSString.h>
#include <Foundation/NSArray.h>
#include <Foundation/NSException.h>
#include <Foundation/NSData.h>

#ifndef BYTE_DEFINED
typedef unsigned char BYTE;
#define BYTE_DEFINED
#endif
#ifndef UINTs_DEFINED
typedef unsigned int UINT;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
#define UINTs_DEFINED
#endif
#include <gscrypt/GSCryptBase.h>

#define OBJ_METHOD_FOR_SEL(_obj, _sel) [(NSObject*)_obj methodForSelector:@selector(_sel)]

#endif // _GSCryptCommon_h__
