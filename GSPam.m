/* GSPam.m - GSCrypt: Class GSPam
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

#include <gscrypt/GSPam.h>

//====================================================================
static int pam_exchange(int num_msg,
						const struct pam_message **msg,
						struct pam_response **resp,
						void *appdata_ptr)
{
  int retStatus=PAM_SUCCESS;
  struct pam_response* response=NULL;
  response = malloc(sizeof(struct pam_response)*num_msg);
  if(response == (struct pam_response *)0)
    retStatus=PAM_CONV_ERR;
  else
	{
	  int i=0;
	  memset((void*)response,0,sizeof(struct pam_response)*num_msg);
	  for(i=0;i<num_msg;i++)
		{
		  NSDebugFLog(@"PAM Message #%d: %d",i,msg[i]->msg_style);
		  response[i].resp_retcode = PAM_SUCCESS;
		  switch(msg[i]->msg_style)
			{
			case PAM_PROMPT_ECHO_ON:
			case PAM_PROMPT_ECHO_OFF:
			case PAM_TEXT_INFO:
			case PAM_ERROR_MSG:
			  //Handled by object !
			  break;
			case PAM_BINARY_PROMPT:
			  // Must be an error of some sort...
			  free(response);
			  retStatus=PAM_CONV_ERR;
			  NSCAssert(NO,@"Unattended PAM message Style PAM_BINARY_PROMPT");
			  break;
			default:
			  // Must be an error of some sort...
			  free(response);
			  retStatus=PAM_CONV_ERR;
			  NSCAssert1(NO,@"Unattended PAM message Style %d",msg[i]->msg_style);
			  break;
			};
		};  
	  *resp=response;
	  retStatus=[((GSPam*)appdata_ptr) processMessages:msg
									   withMessagesNb:num_msg
									   withResponse:response];
	};
  return retStatus;
};


//====================================================================
@implementation GSPam

//--------------------------------------------------------------------
+(id)pam
{
  return [[self new]autorelease];
};

//--------------------------------------------------------------------
+(id)pamWithServiceName:(NSString*)serviceName
{
  return [[[self alloc]initWithServiceName:serviceName]
		   autorelease];
};

//--------------------------------------------------------------------
+(id)pamWithServiceName:(NSString*)serviceName
					user:(NSString*)user
				password:(NSString*)password
{
  return [[[self alloc]initWithServiceName:serviceName
					   user:user
					   password:password]
		   autorelease];
};

//--------------------------------------------------------------------
-(id)init
{
  if ((self=[super init]))
	{
	  memset(&_pamConv,0,sizeof(_pamConv));
	  _pamConv.conv=&pam_exchange;
	  _pamConv.appdata_ptr=(void*)self;
	};
  return self;
};

//--------------------------------------------------------------------
-(id)initWithServiceName:(NSString*)serviceName
{
  if ((self=[self init]))
	{
	  [self setServiceName:serviceName];
	};
  return self;
};

//--------------------------------------------------------------------
-(id)initWithServiceName:(NSString*)serviceName
					user:(NSString*)user
				password:(NSString*)password
{
  if ((self=[self initWithServiceName:serviceName]))
	{
	  [self setUser:user];
	  [self setPassword:password];
	};
  return self;
};

//--------------------------------------------------------------------
-(void)dealloc
{
//  GSWLogC("Dealloc GSPam");
  [self endWithStatus:-1];
  DESTROY(_serviceName);
  DESTROY(_user);
  DESTROY(_password);
  DESTROY(_lastErrorMessage);
//  GSWLogC("Dealloc GSPam Super");
  [super dealloc];
//  GSWLogC("End Dealloc GSPam");
};

//--------------------------------------------------------------------
-(void)assignLastErrorMessage
{
  DESTROY(_lastErrorMessage);
  if (_lastStatus!=PAM_SUCCESS)
	{
	  ASSIGN(_lastErrorMessage,[NSString stringWithCString:pam_strerror(_pamHandle,_lastStatus)]);
	};
};

//--------------------------------------------------------------------
-(int)processMessages:(const struct pam_message**)messages
	   withMessagesNb:(int)numMessages
		 withResponse:(struct pam_response*)responses
{
  int retStatus=PAM_SUCCESS;
  int i=0;
  for(i=0;i<numMessages;i++)
	{
	  responses[i].resp_retcode=PAM_SUCCESS;
	  switch(messages[i]->msg_style)
		{
		case PAM_PROMPT_ECHO_ON:
		  NSDebugMLog(@"PAM Message #%d: PAM_PROMPT_ECHO_ON return: %@",i,[self user]);
		  responses[i].resp=strdup([[self user] cString]);
		  NSDebugMLog(@"==>%s",responses[i]);
		  // PAM frees resp
		  break;      
		case PAM_PROMPT_ECHO_OFF:
		  NSDebugMLog(@"PAM Message #%d: PAM_PROMPT_ECHO_OFF return: %@",i,[self password]);
		  responses[i].resp=strdup([[self password] cString]);
		  NSDebugMLog(@"==>%s",responses[i]);
		  // PAM frees resp
		  break;      
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
		  NSLog(@"PAM Ignore Message: %s",messages[i]->msg);
		  // ignore it, but pam still wants a NULL response...
		  responses[i].resp = NULL;
		  NSDebugMLog(@"==>%s",responses[i]);
		  break;		  
		default:
		  NSAssert1(NO,@"Unknown PAM message Style: %d",(int)messages[i]->msg_style);
		  retStatus=PAM_CONV_ERR;
		  break;
		};  
	};
  return retStatus;
};

//--------------------------------------------------------------------
-(void)setServiceName:(NSString*)serviceName
{
  ASSIGN(_serviceName,serviceName);
};

//--------------------------------------------------------------------
-(void)setUser:(NSString*)user
{
  ASSIGN(_user,user);
};

//--------------------------------------------------------------------
-(void)setPassword:(NSString*)password
{
  ASSIGN(_password,password);
};

//--------------------------------------------------------------------
-(NSString*)serviceName
{
  return _serviceName;
};

//--------------------------------------------------------------------
-(NSString*)user
{
  return _user;
};

//--------------------------------------------------------------------
-(NSString*)password
{
  return _password;
};

//--------------------------------------------------------------------
-(int)status
{
  return _lastStatus;
};

//--------------------------------------------------------------------
-(NSString*)errorMessage
{
  return _lastErrorMessage;
};

//--------------------------------------------------------------------
-(BOOL)start
{
  _lastStatus=PAM_SUCCESS;
  if (_pamHandle)
	{
	  [self endWithStatus:-1];
	};
  NSLog(@"PAM start: serviceName: [%@] user: [%@]",[self serviceName],[self user]);
  _lastStatus=pam_start([[self serviceName] cString],
				   [[self user] cString],
				   &_pamConv,
				   &_pamHandle);
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);
};

//--------------------------------------------------------------------
-(BOOL)end
{
  return [self endWithStatus:PAM_SUCCESS];
}

//--------------------------------------------------------------------
-(BOOL)endWithStatus:(int)status
{
  _lastStatus=PAM_SUCCESS;
  if (_pamHandle)
	{
	  _lastStatus=pam_end(_pamHandle,status);
	  _pamHandle=NULL;
	};
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);
};

//--------------------------------------------------------------------
/*
PAM_DISALLOW_NULL_AUTHTOK
     Instruct the authentication modules to return PAM_AUTH_ERR if the user does not have a registered authorization token---it is set to NULL in the system database. 
*/
-(BOOL)authenticateWithFlag:(int)flag
					silent:(BOOL)silentFlag
{
  _lastStatus=PAM_SUCCESS;
  if (silentFlag)
	flag|=PAM_SILENT;
  NSLog(@"PAM pam_authenticate: serviceName: [%@] user: [%@] lastStatus=%d",
		[self serviceName],
		[self user],
		_lastStatus);
  _lastStatus=pam_authenticate(_pamHandle,flag);
  NSLog(@"PAM pam_authenticate: lastStatus=%d",
		_lastStatus);
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);

};


//--------------------------------------------------------------------
/*
PAM_DISALLOW_NULL_AUTHTOK
     Instruct the authentication modules to return PAM_AUTH_ERR if the user does not have a registered authorization token---it is set to NULL in the system database. 
*/
-(BOOL)accountManagementWithFlag:(int)flag
						  silent:(BOOL)silentFlag
{
  _lastStatus=PAM_SUCCESS;
  if (silentFlag)
	flag|=PAM_SILENT;
  _lastStatus=pam_acct_mgmt(_pamHandle,flag);
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);

};

//--------------------------------------------------------------------
-(BOOL)openSessionSilently:(BOOL)silentFlag
{
  int flag=0;
  _lastStatus=PAM_SUCCESS;
  if (silentFlag)
	flag|=PAM_SILENT;
  _lastStatus=pam_open_session(_pamHandle,flag);
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);

};

//--------------------------------------------------------------------
-(BOOL)closeSessionSilently:(BOOL)silentFlag
{
  int flag=0;
  _lastStatus=PAM_SUCCESS;
  if (silentFlag)
	flag|=PAM_SILENT;
  _lastStatus=pam_close_session(_pamHandle,flag);
  [self assignLastErrorMessage];
  return (_lastStatus==PAM_SUCCESS);
};

@end
