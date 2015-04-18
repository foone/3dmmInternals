/*
 * Copyright (c) 1993-1995 by Argonaut Technologies Limited. All rights reserved.
 *
 * $Id: fmtproto.h 1.7 1995/03/01 16:08:12 sam Exp $
 * $Locker:  $
 *
 * Function prototypes for foreign file format support
 */
#ifndef _FMTPROTO_H_
#define _FMTPROTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Eric Haines' NFF format
 */
br_model * BR_PUBLIC_ENTRY BrFmtNFFLoad(char *name);

/*
 * 3D Studio .ASC files
 */
br_uint_32 BR_PUBLIC_ENTRY BrFmtASCLoad(char *name, br_model **mtable, br_uint_16 max_models);

/*
 * Script files
 */
br_uint_32 BR_PUBLIC_ENTRY BrFmtScriptMaterialLoadMany(char *filename,br_material **materials,br_uint_16 num);
br_material * BR_PUBLIC_ENTRY BrFmtScriptMaterialLoad(char *filename);

/*
 * Windows .BMP files
 */
br_pixelmap * BR_PUBLIC_ENTRY BrFmtBMPLoad(char *name,br_uint_32 flags);

/*
 * .TGA files
 */
br_pixelmap * BR_PUBLIC_ENTRY BrFmtTGALoad(char *name,br_uint_32 flags);

/*
 * .GIF files
 */
br_pixelmap * BR_PUBLIC_ENTRY BrFmtGIFLoad(char *name,br_uint_32 flags);

/*
 * .IFF/.LBM files
 */
br_pixelmap * BR_PUBLIC_ENTRY BrFmtIFFLoad(char *name,br_uint_32 flags);

#ifdef __cplusplus
};
#endif
#endif


