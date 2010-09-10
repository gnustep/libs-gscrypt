#	GNUmakefila
#
#  Copyright (C) 2000 Free Software Foundation, Inc.
#
#  Written by:	Manuel Guesdon <mguesdon@orange-concept.com>
#
#  This file is part of the GNUstep GSCrypt Library.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Library General Public
#  License as published by the Free Software Foundation; either
#  version 2 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
#  Library General Public License for more details.
#
#  You should have received a copy of the GNU Library General Public
#  License along with this library; if not, write to the Free
#  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

ifeq ($(GNUSTEP_MAKEFILES),)
 GNUSTEP_MAKEFILES := $(shell gnustep-config --variable=GNUSTEP_MAKEFILES 2>/dev/null)
  ifeq ($(GNUSTEP_MAKEFILES),)
    $(warning )
    $(warning Unable to obtain GNUSTEP_MAKEFILES setting from gnustep-config!)
    $(warning Perhaps gnustep-make is not properly installed,)
    $(warning so gnustep-config is not in your PATH.)
    $(warning )
    $(warning Your PATH is currently $(PATH))
    $(warning )
  endif
endif

ifeq ($(GNUSTEP_MAKEFILES),)
  $(error You need to set GNUSTEP_MAKEFILES before compiling!)
endif

include $(GNUSTEP_MAKEFILES)/common.make


#include ../../Version
#include ../../config.mak

srcdir = .
PACKAGE_NAME = gscrypt

# The library to be compiled
LIBRARY_NAME=libgscrypt

# The Objective-C source files to be compiled
libgscrypt_OBJC_FILES = \
GSCryptBase.m \
GSMD5.m \
GSRC4.m \
GSPam.m \

libgscrypt_HEADER_FILES = \
GSCryptCommon.h \
GSCryptBase.h \
GSMD5.h \
GSRC4.h \
GSPam.h \


SRCS = $(LIBRARY_NAME:=.m)

HDRS = $(LIBRARY_NAME:=.h)

libgscrypt_HEADER_FILES_DIR = .
libgscrypt_HEADER_FILES_INSTALL_DIR = /$(GNUSTEP_FND_DIR)/gscrypt

#DIST_FILES = $(SRCS) $(HDRS) GNUmakefile Makefile.postamble Makefile.preamble

-include Makefile.preamble

-include GNUmakefile.local

include $(GNUSTEP_MAKEFILES)/library.make

-include Makefile.postamble
