/* GSPam.h - GSCrypt: Class GSPam
   Copyright (C) 2000 Free Software Foundation, Inc.
   
   Written by:	Manuel Guesdon <mguesdon@orange-concept.com>
   Date: 		Feb 2000
   
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

//$Id$

#ifndef _GSPam_h__
	#define _GSPam_h__

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <gscrypt/GSCryptCommon.h>


//====================================================================
@interface GSPam: NSObject
{  
  pam_handle_t* _pamHandle;
  struct pam_conv _pamConv;
  int _lastStatus;
  NSString* _lastErrorMessage;
  NSString* _serviceName;
  NSString* _user;
  NSString* _password;
};

+(id)pam;
+(id)pamWithServiceName:(NSString*)serviceName;
+(id)pamWithServiceName:(NSString*)serviceName
					user:(NSString*)user
			   password:(NSString*)password;
-(id)init;
-(id)initWithServiceName:(NSString*)serviceName;
-(id)initWithServiceName:(NSString*)serviceName
					user:(NSString*)user
				password:(NSString*)password;
-(void)dealloc;
-(void)assignLastErrorMessage;
-(int)processMessages:(const struct pam_message**)messages
	   withMessagesNb:(int)numMessages
		 withResponse:(struct pam_response*)responses;
-(void)setServiceName:(NSString*)serviceName;
-(void)setUser:(NSString*)user;
-(void)setPassword:(NSString*)password;
-(NSString*)serviceName;
-(NSString*)user;
-(NSString*)password;
-(int)status;
-(NSString*)errorMessage;
-(BOOL)start;
-(BOOL)end;
-(BOOL)endWithStatus:(int)status;
-(BOOL)authenticateWithFlag:(int)flag
					silent:(BOOL)silentFlag;
-(BOOL)accountManagementWithFlag:(int)flag
						 silent:(BOOL)silentFlag;
-(BOOL)openSessionSilently:(BOOL)silentFlag;
-(BOOL)closeSessionSilently:(BOOL)silentFlag;

@end


#endif //_GSPam_h__
