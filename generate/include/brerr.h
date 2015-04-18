/*
 * Copyright (c) 1993-1995 by Argonaut Technologies Limited. All rights reserved.
 *
 * $Id: brerr.h 1.3 1995/02/22 21:36:58 sam Exp $
 * $Locker:  $
 *
 * Brender's interface to memory allocation
 */

#ifndef _BRERR_H_
#define _BRERR_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Instance of an error handler
 */
typedef void BR_CALLBACK br_err_warning_cbfn(char * message);
typedef void BR_CALLBACK br_err_error_cbfn(char * message);

typedef struct br_errorhandler {
	char *identifier;
	br_err_warning_cbfn *warning;
	br_err_error_cbfn *error;

} br_errorhandler;

/*
 * Macros for error handling
 */
#define BR_ERROR(s) BrError(s)
#define BR_ERROR0(s) BrError(s)
#define BR_ERROR1(s,a) BrError(s,a)
#define BR_ERROR2(s,a,b) BrError(s,a,b)
#define BR_ERROR3(s,a,b,c) BrError(s,a,b,c)
#define BR_ERROR4(s,a,b,c,d) BrError(s,a,b,c,d)
#define BR_ERROR5(s,a,b,c,d,e) BrError(s,a,b,c,d,e)
#define BR_ERROR6(s,a,b,c,d,e,f) BrError(s,a,b,c,d,e,f)

#define BR_WARNING(s) BrWarning(s)
#define BR_WARNING0(s) BrWarning(s)
#define BR_WARNING1(s,a) BrWarning(s,a)
#define BR_WARNING2(s,a,b) BrWarning(s,a,b)
#define BR_WARNING3(s,a,b,c) BrWarning(s,a,b,c)
#define BR_WARNING4(s,a,b,c,d) BrWarning(s,a,b,c,d)
#define BR_WARNING5(s,a,b,c,d,e) BrWarning(s,a,b,c,d,e)
#define BR_WARNING6(s,a,b,c,d,e,f) BrWarning(s,a,b,c,d,e,f)

#define BR_FATAL(s) BrFatal(__FILE__,__LINE__,s)
#define BR_FATAL0(s) BrFatal(__FILE__,__LINE__,s)
#define BR_FATAL1(s,a) BrFatal(__FILE__,__LINE__,s,a)
#define BR_FATAL2(s,a,b) BrFatal(__FILE__,__LINE__,s,a,b)
#define BR_FATAL3(s,a,b,c) BrFatal(__FILE__,__LINE__,s,a,b,c)
#define BR_FATAL4(s,a,b,c,d) BrFatal(__FILE__,__LINE__,s,a,b,c,d)
#define BR_FATAL5(s,a,b,c,d,e) BrFatal(__FILE__,__LINE__,s,a,b,c,d,e)
#define BR_FATAL6(s,a,b,c,d,e,f) BrFatal(__FILE__,__LINE__,s,a,b,c,d,e,f)

#ifdef __cplusplus
};
#endif
#endif

